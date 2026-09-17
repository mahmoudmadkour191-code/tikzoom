"""Update dispatcher for the main platform bot.

We process Telegram updates received via webhook (POST /tg/<secret>) by routing
each update to the right handler. Designed to be light: no aiogram needed.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import html
import json
import logging
import os
import re
import uuid
from pathlib import Path
from typing import Any

from .config import get_settings
from .ai_assistant import (
    MCV_SYSTEM_PROMPT_AR,
    MCVError,
    detect_bot_purpose,
    generate_bot,
    is_done_phrase,
    is_exit_phrase,
    modify_bot_code,
    project_analyze,
    review_for_malicious,
    transpile_to_python,
    wizard_acknowledge,
)
from .db import HostedBot
from .keyboards import Btn, inline_kb, kb_back_main, kb_force_sub, kb_main_menu, kb_share_contact
from .locales import t
from .notifications import notify_admins_upload
from .repo import (
    add_force_sub_channel,
    add_hosted_bot,
    add_points,
    audit,
    count_referrals,
    count_user_bots_in_tier,
    credit_referral,
    decode_bot_env,
    delete_bot,
    get_bot,
    update_bot_code,
    update_bot_status,
    get_setting,
    get_user,
    get_user_by_referral_code,
    list_force_sub_channels,
    list_user_bots,
    remove_force_sub_channel,
    set_admin,
    set_banned,
    set_contact,
    set_force_sub_verified,
    set_points,
    set_setting,
    set_vip,
    upsert_user,
    encode_bot_env,
)
from .deps import install_dependencies
from .runner import allocate_port, detect_language, get_runner
from .security import encrypt_token, token_hash
from .telegram_api import TelegramError, TgClient, validate_token
from .tiers import TIERS, by_level, can_use_tier, max_files_for, unlocked_tiers
from .token_extract import extract_token_from_file

logger = logging.getLogger(__name__)


# ----- in-memory pending state (per user, expires after one action) ----- #
_pending: dict[int, dict[str, Any]] = {}
_pending_lock = asyncio.Lock()


async def set_pending(uid: int, data: dict[str, Any]) -> None:
    async with _pending_lock:
        _pending[uid] = data


async def pop_pending(uid: int) -> dict[str, Any] | None:
    async with _pending_lock:
        return _pending.pop(uid, None)


async def get_pending(uid: int) -> dict[str, Any] | None:
    async with _pending_lock:
        return _pending.get(uid)


# ----- Helpers ----- #

async def is_admin_uid(uid: int) -> bool:
    s = get_settings()
    if uid in s.admin_id_list:
        return True
    u = await get_user(uid)
    return bool(u and u.is_admin)


async def can_upload_uid(uid: int, u: Any = None) -> bool:
    """رفع الملفات: الأدمن أو مشترك VIP فقط (الباقي يتواصل مع الأدمن للتفعيل)."""
    if await is_admin_uid(uid):
        return True
    if u is None:
        u = await get_user(uid)
    return bool(u and getattr(u, "is_vip", False))


async def _vip_block(client: TgClient, chat_id: int, lang: str,
                     message_id: int | None = None) -> None:
    """رسالة رفض الرفع لغير VIP مع زر تواصل مع الأدمن."""
    from .config import get_settings as _gs

    admin_username = (((await get_setting("admin_username", "")) or "").strip()
                      or _gs().admin_username.strip())
    first_admin = next(iter(_gs().admin_id_list), None)
    url = ""
    if admin_username:
        url = f"https://t.me/{admin_username.lstrip('@')}"
    elif first_admin:
        url = f"tg://user?id={first_admin}"
    text = (
        "⭐ <b>رفع الملفات حصري لمشتركي VIP</b>\n\n"
        "ارفع ملفاتك واستخدم كل ميزات الرفع بعد تفعيل خطة VIP.\n"
        "للتفعيل تواصل مع الأدمن مباشرة:"
    )
    kb = {"inline_keyboard": [[{"text": "📩 تواصل مع الأدمن", "url": url}]]} if url else None
    try:
        if message_id:
            await client.edit_message_text(chat_id, message_id, text,
                                           parse_mode="HTML", reply_markup=kb)
        else:
            await client.send_message(chat_id, text, parse_mode="HTML", reply_markup=kb)
    except Exception:  # noqa: BLE001
        logger.warning("vip block message failed", exc_info=True)


async def check_force_subs(client: TgClient, uid: int) -> tuple[bool, list[tuple[int, str | None, str | None]]]:
    channels = await list_force_sub_channels()
    if not channels:
        return True, []
    missing: list[tuple[int, str | None, str | None]] = []
    for ch in channels:
        try:
            mem = await client.get_chat_member(ch.chat_id, uid)
            if mem.get("status") not in ("member", "administrator", "creator"):
                missing.append((ch.chat_id, ch.title, ch.invite_link))
        except TelegramError as exc:
            logger.info("force-sub check %s/%s failed: %s", ch.chat_id, uid, exc)
            missing.append((ch.chat_id, ch.title, ch.invite_link))
    return (not missing), missing


async def public_base_url() -> str:
    """Public base URL for the platform.

    Resolution order:
    1. Admin-set override stored in DB settings (`public_base_url`).
    2. Env var ``PUBLIC_BASE_URL``.
    3. Auto-detected ``https://*.trycloudflare.com`` URL from the
       cloudflared log under ``{data_dir}/logs/cloudflared.log``.
    """
    override = await get_setting("public_base_url", "")
    if override:
        return override.rstrip("/")
    env_url = get_settings().public_base_url
    if env_url and env_url not in ("https://localhost",):
        return env_url.rstrip("/")
    return _read_cloudflared_url() or env_url.rstrip("/")


_TRYCF_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def _read_cloudflared_url() -> str:
    """Scan cloudflared.log for the most-recent trycloudflare URL."""
    log = get_settings().data_path / "logs" / "cloudflared.log"
    if not log.exists():
        return ""
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    matches = _TRYCF_RE.findall(text)
    return matches[-1] if matches else ""


def webhook_url_for_token(base: str, tk_hash: str) -> str:
    return f"{base.rstrip('/')}/wh/{tk_hash}"


# Heuristics for detecting whether a hosted bot was written for polling or
# webhook mode by reading its source file.
#
# Polling is the safer default for the majority of community bots:
#  * It does not require a public HTTPS endpoint to be reachable.
#  * It does not crash with a 409 conflict if a stale webhook is registered
#    (the platform always calls ``deleteWebhook`` before launch).
#  * Most ``python-telegram-bot`` / ``pyTelegramBotAPI`` (telebot) /
#    ``aiogram`` examples that beginners upload run polling.
#
# We detect webhook mode by looking for explicit webhook-server markers in
# the source. Anything else falls through to polling.
_WEBHOOK_MARKERS: tuple[str, ...] = (
    "process_webhook",
    "process_new_updates",
    "register_blueprint",
    "fastapi(",
    "uvicorn.run",
    "flask(",
    "create_app(",
    "app.run(",
    "express(",
    "http.createserver",
    "set_webhook(",
    "setwebhook",
    "webhook_handler",
)


def detect_run_mode(file_path: str, language: str) -> str:
    """Return ``"polling"`` or ``"webhook"`` based on a quick source scan.

    We only scan the entry file (not the whole upload tree), which is good
    enough for the typical single-file bot uploads the platform receives.
    Polling is the default if the file is unreadable or no markers match,
    because it works in firewalled environments and is what most uploaded
    bots use.
    """
    # PHP files are virtually always webhook (Apache/CLI-served scripts).
    if language == "php":
        return "webhook"
    try:
        src = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError, ValueError):
        try:
            src = Path(file_path).read_bytes().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            src = ""
    lower = src.lower()
    if not lower:
        return "polling"
    # Polling markers first — if we see any of these the bot definitely
    # wants polling, so don't bother checking webhook markers.
    polling_markers = (
        "infinity_polling", "start_polling", "run_polling", "polling_loop",
        "long_polling", "longpolling", "polling()", "getupdates",
        "get_updates", "polling: true",
    )
    for marker in polling_markers:
        if marker in lower:
            return "polling"
    for marker in _WEBHOOK_MARKERS:
        if marker in lower:
            return "webhook"
    return "polling"


async def webapp_url_for_user() -> str | None:
    base = await public_base_url()
    if base.startswith("https://"):
        # Cache-buster: bump every minute so Telegram refetches the page
        # whenever a new build is deployed.
        version = dt.datetime.utcnow().strftime("%Y%m%d%H%M")
        return f"{base.rstrip('/')}/app/?v={version}"
    return None


async def main_menu_text(uid: int, lang: str) -> str:
    u = await get_user(uid)
    points = u.points if u else 0
    refs = await count_referrals(uid)
    is_admin = await is_admin_uid(uid)
    is_vip = bool(u and u.is_vip)
    tiers = unlocked_tiers(points, is_vip=is_vip, is_admin=is_admin)
    tier_label = tiers[-1].label_ar if lang == "ar" else tiers[-1].label_en if tiers else "—"
    # Optional admin announcement shown as a quoted blockquote at the top.
    announcement = (await get_setting("welcome_announcement", "")).strip()
    announcement_emoji_id = (await get_setting("welcome_announcement_emoji_id", "")).strip()
    pieces: list[str] = []
    if announcement:
        # تطبيق الإيموجي المخصص للإعلان إن وُجد
        if announcement_emoji_id:
            # إيموجي Premium - نضيف tg-emoji tag
            emoji_html = f'<tg-emoji emoji-id="{announcement_emoji_id}">⭐</tg-emoji>'
            ann_html = html.escape(announcement, quote=False).replace("\n", "\n")
            pieces.append(f"<blockquote>{emoji_html} {ann_html}</blockquote>")
        else:
            ann_html = html.escape(announcement, quote=False).replace("\n", "\n")
            pieces.append(f"<blockquote>{ann_html}</blockquote>")
    quote_body = (
        f"<blockquote><b>{t(lang, 'welcome_header').replace('<b>', '').replace('</b>', '')}</b>\n"
        f"{t(lang, 'developed_by')}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🆔 ID: <code>{uid}</code>\n"
        f"💎 {t(lang, 'your_points', points=points)}\n"
        f"👥 {t(lang, 'your_referrals', count=refs)}\n"
        f"🚀 {t(lang, 'your_tier', tier=html.escape(tier_label, quote=False))}</blockquote>"
    )
    pieces.append(quote_body)
    return "\n".join(pieces)


async def show_main_menu(client: TgClient, chat_id: int, uid: int, lang: str,
                         *, edit_message_id: int | None = None) -> None:
    text = await main_menu_text(uid, lang)
    is_admin = await is_admin_uid(uid)
    web_app_url = await webapp_url_for_user()
    # استخدام النسخة async اللي بتقرأ الإعدادات المخصصة من قاعدة البيانات
    from .keyboards import kb_main_menu_async
    kb = await kb_main_menu_async(lang, is_admin=is_admin, web_app_url=web_app_url)
    if edit_message_id is not None:
        try:
            await client.edit_message_text(chat_id, edit_message_id, text, reply_markup=kb)
            return
        except TelegramError:
            pass
    await client.send_message(chat_id, text, reply_markup=kb)


# ----- Top-level update entrypoint ----- #

async def handle_update(client: TgClient, update: dict) -> None:
    try:
        if "message" in update:
            await _handle_message(client, update["message"])
        elif "callback_query" in update:
            await _handle_callback(client, update["callback_query"])
    except Exception:  # noqa: BLE001
        logger.exception("update handler failed")


async def _handle_message(client: TgClient, msg: dict) -> None:
    user = msg.get("from") or {}
    uid: int = int(user.get("id", 0))
    if not uid:
        return
    chat_id = msg["chat"]["id"]
    lang = (user.get("language_code") or "ar")[:2]
    if lang not in ("ar", "en"):
        lang = "ar"
    u = await upsert_user(
        user_id=uid,
        username=user.get("username"),
        first_name=user.get("first_name"),
        last_name=user.get("last_name"),
        language=lang,
    )
    # نظام الحظر معطّل - يمكن لجميع المستخدمين استخدام البوت
    # فقط الملفات المشبوهة تُرفض بدون حظر المستخدم
    lang = u.language or lang

    text = msg.get("text", "") or ""
    contact = msg.get("contact")
    document = msg.get("document")

    # 1) Contact share?
    if contact:
        await set_contact(uid, contact.get("phone_number") or "")
        await client.send_message(chat_id, t(lang, "contact_saved"))
        await show_main_menu(client, chat_id, uid, lang)
        return

    # 2) /start command
    if text.startswith("/start"):
        await _cmd_start(client, msg, u, lang)
        return

    if text.startswith("/help") or text == "❓":
        await client.send_message(chat_id, await main_menu_text(uid, lang))
        return

    if text.startswith("/admin"):
        if not await is_admin_uid(uid):
            await client.send_message(chat_id, t(lang, "admin_only"))
            return
        await _show_admin_panel(client, chat_id, lang)
        return

    if text.startswith("/setbase"):
        # Admin sets public base URL: /setbase https://example.com
        if not await is_admin_uid(uid):
            return
        parts = text.split(maxsplit=1)
        if len(parts) == 2:
            await set_setting("public_base_url", parts[1].strip())
            await client.send_message(chat_id, f"✅ تم تعيين الرابط: `{parts[1].strip()}`")
        return

    if text.startswith("/broadcast"):
        if not await is_admin_uid(uid):
            await client.send_message(chat_id, t(lang, "admin_only"))
            return
        # Two ways to invoke:
        #   /broadcast <text>            → text-only broadcast
        #   /broadcast (no args)         → enters "send me a photo or text" mode
        body = text[len("/broadcast"):].strip()
        if body:
            from .broadcast import send_broadcast
            await client.send_message(
                chat_id, "📡 بدأت الإذاعة... هتبعتلك التقرير لما تخلص.",
            )
            report = await send_broadcast(client, text=body)
            await client.send_message(chat_id, report.as_html())
            return
        await set_pending(uid, {"kind": "admin_broadcast"})
        await client.send_message(
            chat_id,
            "📣 <b>وضع الإذاعة</b>\n\n"
            "ابعتلي رسالة أو صورة (مع أو بدون تعليق) وهتتبعت لكل المستخدمين.\n\n"
            "ابعت <code>/cancel</code> للإلغاء.",
        )
        return

    if text.startswith("/cancel"):
        await pop_pending(uid)
        await client.send_message(chat_id, "✖️ تم الإلغاء.")
        return

    # 3) Pending interactions (uploading, awaiting input from admin, etc.)
    pending = await get_pending(uid)

    if document and pending and pending.get("kind") == "bot_code_update":
        await _process_bot_code_update(client, msg, u, lang, bot_id=int(pending.get("bot_id", 0)))
        await pop_pending(uid)
        return

    if document and pending and pending.get("kind") == "upload_file":
        await _process_upload(client, msg, u, lang, tier_level=pending.get("tier", 1))
        # Only clear the slot if ``_process_upload`` didn't already replace it
        # (e.g. with ``upload_choose_mode`` while waiting for the user to pick
        # Polling or Webhook). Otherwise we'd wipe the new state immediately
        # and the next callback would see "session ended".
        cur = await get_pending(uid)
        if not cur or cur.get("kind") == "upload_file":
            await pop_pending(uid)
        return

    if document and pending and pending.get("kind") == "ai_project_upload":
        await _process_ai_project_upload(client, msg, u, lang)
        cur = await get_pending(uid)
        if not cur or cur.get("kind") == "ai_project_upload":
            await pop_pending(uid)
        return

    if pending and pending.get("kind") == "admin_set_main_token" and text:
        await _admin_apply_main_token(client, chat_id, lang, text.strip())
        await pop_pending(uid)
        return

    # معالج التحقق الحسابي (Math verification)
    if pending and pending.get("kind") == "math_verification" and text:
        a = pending.get("a", 0)
        b = pending.get("b", 0)
        op = pending.get("op", "+")
        correct = pending.get("answer", 0)
        try:
            user_answer = int(text.strip())
        except ValueError:
            # لو بعت شيء غير رقم
            await client.send_message(
                chat_id,
                "❌ أرسل رقم فقط!\n\n"
                f"<b>{a} {op} {b} = ?</b>",
                parse_mode="HTML",
            )
            return
        if user_answer == correct:
            # إجابة صحيحة - تسجيل التحقق
            await set_setting(f"math_verified_{uid}", "1")
            await pop_pending(uid)
            # نكمل الـ start flow
            await _cmd_start(client, msg, u, lang)
        else:
            # إجابة خاطئة - توليد سؤال جديد
            import random as _random
            a2 = _random.randint(2, 15)
            b2 = _random.randint(2, 15)
            op2 = _random.choice(["+", "-", "×"])
            if op2 == "+":
                ans2 = a2 + b2
            elif op2 == "-":
                if a2 < b2:
                    a2, b2 = b2, a2
                ans2 = a2 - b2
            else:
                ans2 = a2 * b2
            await set_pending(uid, {
                "kind": "math_verification",
                "a": a2, "b": b2, "op": op2, "answer": ans2,
            })
            await client.send_message(
                chat_id,
                f"❌ <b>إجابة خاطئة!</b> الجواب الصحيح كان: {correct}\n\n"
                f"حاول تاني:\n\n"
                f"<b>{a2} {op2} {b2} = ?</b>",
                parse_mode="HTML",
            )
        return

    if pending and pending.get("kind") == "admin_set_custom_emoji" and text:
        # استلام الإيموجي المخصص
        emoji_text = text.strip()
        import re as _re
        from .keyboards import reload_bot_emoji

        # محاولة استخراج custom_emoji_id من entities (الإيموجي Premium)
        custom_id = None
        entities = msg.get("entities", [])
        for ent in entities:
            if ent.get("type") == "custom_emoji":
                custom_id = ent.get("custom_emoji_id")
                break

        if custom_id:
            # إيموجي Premium من تيليجرام
            await set_setting("bot_custom_emoji_id", custom_id)
            await set_setting("bot_emoji", f"premium_{custom_id}")
            await reload_bot_emoji()
            await client.send_message(chat_id,
                f"✅ <b>تم تعيين الإيموجي المخصص بنجاح!</b>\n\n"
                f"🆔 Custom Emoji ID: <code>{custom_id}</code>\n\n"
                f"🎉 دلوقتي كل أزرار البوت هتستخدم الإيموجي المخصص ده!",
                parse_mode="HTML")
        else:
            match = _re.search(r'"custom_emoji_id"\s*:\s*"?(\d+)"?', emoji_text)
            if match:
                custom_id = match.group(1)
                await set_setting("bot_custom_emoji_id", custom_id)
                await set_setting("bot_emoji", f"premium_{custom_id}")
                await reload_bot_emoji()
                await client.send_message(chat_id,
                    f"✅ <b>تم تعيين الإيموجي المخصص بنجاح!</b>\n\n"
                    f"🆔 Custom Emoji ID: <code>{custom_id}</code>\n\n"
                    f"🎉 دلوقتي كل أزرار البوت هتستخدم الإيموجي المخصص ده!",
                    parse_mode="HTML")
            elif len(emoji_text) <= 8 and not emoji_text.startswith("/"):
                # إيموجي عادي
                await set_setting("bot_emoji", emoji_text)
                await set_setting("bot_custom_emoji_id", "")
                await reload_bot_emoji()
                await client.send_message(chat_id,
                    f"✅ تم تعيين الإيموجي: {emoji_text}\n\n"
                    f"🎉 كل أزرار البوت دلوقتي هتستخدم الإيموجي ده!")
            else:
                await client.send_message(chat_id,
                    "❌ لم أتعرف على الإيموجي. أرسل إيموجي واحد فقط "
                    "أو إيموجي Premium من لوحة مفاتيح تيليجرام.")
        await pop_pending(uid)
        return

    if pending and pending.get("kind") == "admin_add_channel" and text:
        await _admin_apply_add_channel(client, chat_id, lang, text.strip())
        await pop_pending(uid)
        return

    if pending and pending.get("kind") == "admin_set_btn_emoji" and text:
        # استلام إيموجي لزر معين - مع دعم استبدال العادي بمميز
        btn_id = pending.get("btn_id", "")
        emoji_text = text.strip()
        from .emoji_mapper import (
            save_button_settings, find_premium_for_emoji, get_button_info
        )

        # استخراج custom_emoji_id من entities (إن كان Premium)
        custom_id = None
        entities = msg.get("entities", [])
        for ent in entities:
            if ent.get("type") == "custom_emoji":
                custom_id = ent.get("custom_emoji_id")
                break

        if custom_id:
            # المستخدم بعت إيموجي Premium مباشرة
            await save_button_settings(btn_id, emoji=emoji_text, custom_emoji_id=custom_id)
            info = get_button_info(btn_id)
            await client.send_message(chat_id,
                f"✅ <b>تم تعيين إيموجي مميز للزر!</b>\n\n"
                f"🎯 الزر: <b>{html.escape(info['default_text_ar'], quote=False)}</b>\n"
                f"🆔 Custom Emoji ID: <code>{custom_id}</code>",
                parse_mode="HTML")
        elif len(emoji_text) <= 8 and not emoji_text.startswith("/"):
            # إيموجي عادي - نحاول ندور على مميز مطابق
            premium_id = find_premium_for_emoji(emoji_text)
            if premium_id:
                # تم إيجاد إيموجي مميز مطابق
                await save_button_settings(btn_id, emoji=emoji_text, custom_emoji_id=premium_id)
                info = get_button_info(btn_id)
                await client.send_message(chat_id,
                    f"✅ <b>تم تعيين إيموجي للزر مع ترقية لمميز!</b>\n\n"
                    f"🎯 الزر: <b>{html.escape(info['default_text_ar'], quote=False)}</b>\n"
                    f"📤 الإيموجي المرسل: {emoji_text}\n"
                    f"✨ تم استبداله بإيموجي مميز تلقائياً\n"
                    f"🆔 Custom Emoji ID: <code>{premium_id}</code>",
                    parse_mode="HTML")
            else:
                # مفيش إيموجي مميز مطابق - نستخدم العادي
                await save_button_settings(btn_id, emoji=emoji_text, custom_emoji_id="")
                info = get_button_info(btn_id)
                await client.send_message(chat_id,
                    f"✅ تم تعيين إيموجي للزر {info['default_text_ar']}: {emoji_text}\n\n"
                    f"<i>ℹ️ مفيش إيموجي مميز مطابق متاح. استُخدم الإيموجي العادي.</i>")
        else:
            await client.send_message(chat_id,
                "❌ أرسل إيموجي واحد فقط.")
        await pop_pending(uid)
        return

    if pending and pending.get("kind") == "admin_set_btn_text" and text:
        # استلام نص الزر المخصص
        new_text = text.strip()
        btn_id = pending.get("btn_id", "")
        if len(new_text) > 50:
            await client.send_message(chat_id, "❌ النص طويل جداً (حد 50 حرف).")
            return
        await set_setting(f"btn_text_{btn_id}", new_text)
        btn_names = {
            "upload": "زر الرفع", "mybots": "زر بوتاتي",
            "points": "زر النقاط", "dev": "زر المطور", "invite": "زر الدعوة",
        }
        await client.send_message(chat_id,
            f"✅ تم تعديل {btn_names.get(btn_id, btn_id)}: <b>{html.escape(new_text, quote=False)}</b>",
            parse_mode="HTML")
        await pop_pending(uid)
        return

    # استلام user_id لإضافة نقاط
    if pending and pending.get("kind") == "admin_add_points_user" and text:
        try:
            target_uid = int(text.strip())
        except ValueError:
            await client.send_message(chat_id, "❌ أرسل آيدي رقمي صحيح.")
            return
        target_user = await get_user(target_uid)
        if not target_user:
            await client.send_message(chat_id, f"❌ المستخدم {target_uid} غير موجود.")
            await pop_pending(uid)
            return
        # عرض معلومات المستخدم وطلب عدد النقاط
        await set_pending(uid, {"kind": "admin_add_points_amount", "target_uid": target_uid})
        name = target_user.first_name or target_user.username or "—"
        await client.send_message(
            chat_id,
            f"👤 <b>المستخدم:</b> {html.escape(name, quote=False)}\n"
            f"🆔 ID: <code>{target_uid}</code>\n"
            f"💰 النقاط الحالية: <b>{target_user.points or 0}</b>\n\n"
            f"أرسل عدد النقاط اللي عاوز تضيفها (أو سالب للخصم):\n"
            f"<i>مثال: 50 (لإضافة) أو -20 (لخصم)</i>",
            parse_mode="HTML",
            reply_markup=kb_back_main(lang),
        )
        return

    # استلام عدد النقاط
    if pending and pending.get("kind") == "admin_add_points_amount" and text:
        target_uid = pending.get("target_uid", 0)
        try:
            points_delta = int(text.strip())
        except ValueError:
            await client.send_message(chat_id, "❌ أرسل رقم صحيح.")
            return
        # إضافة النقاط
        new_total = await add_points(target_uid, points_delta)
        target_user = await get_user(target_uid)
        name = target_user.first_name if target_user else "—"
        # إشعار المسؤول
        sign = "+" if points_delta >= 0 else ""
        await client.send_message(
            chat_id,
            f"✅ <b>تم تعديل النقاط!</b>\n\n"
            f"👤 المستخدم: {html.escape(name or '—', quote=False)}\n"
            f"🆔 ID: <code>{target_uid}</code>\n"
            f"💰 التغيير: <b>{sign}{points_delta}</b>\n"
            f"📊 الرصيد الجديد: <b>{new_total}</b> نقطة",
            parse_mode="HTML",
            reply_markup=kb_back_main(lang),
        )
        # إشعار المستخدم
        try:
            await client.send_message(
                target_uid,
                f"💰 <b>تم تعديل نقاطك!</b>\n\n"
                f"التغيير: <b>{sign}{points_delta}</b> نقطة\n"
                f"📊 رصيدك الجديد: <b>{new_total}</b> نقطة",
                parse_mode="HTML",
            )
        except Exception:
            pass  # المستخدم ممكن يكون حظر البوت
        await audit(uid, "points_added", f"target={target_uid} delta={points_delta} new={new_total}")
        await pop_pending(uid)
        return

    # استلام سعر بيع البوت في المتجر
    if pending and pending.get("kind") == "sell_bot_price" and text:
        try:
            price = int(text.strip())
            if price < 1 or price > 10000:
                await client.send_message(chat_id, "❌ السعر يجب أن يكون بين 1 و 10000.")
                return
        except ValueError:
            await client.send_message(chat_id, "❌ أرسل رقم صحيح.")
            return
        bot_id = pending.get("bot_id")
        b = await get_bot(bot_id) if bot_id else None
        if not b or b.owner_id != uid:
            await client.send_message(chat_id, "❌ البوت غير موجود أو لا تملكه.")
            await pop_pending(uid)
            return
        # طلب اسم العنصر
        cur = dict(pending)
        cur["kind"] = "sell_bot_name"
        cur["price"] = price
        await set_pending(uid, cur)
        await client.send_message(chat_id,
            f"✅ السعر: <b>{price}</b> نقطة\n\n"
            f"أرسل <b>اسم العنصر</b> في المتجر (أو اكتب '-' لاستخدام اسم البوت):",
            parse_mode="HTML")
        return

    if pending and pending.get("kind") == "sell_bot_name" and text:
        name = text.strip()
        bot_id = pending.get("bot_id")
        price = pending.get("price", 10)
        b = await get_bot(bot_id) if bot_id else None
        if not b or b.owner_id != uid:
            await client.send_message(chat_id, "❌ البوت غير موجود.")
            await pop_pending(uid)
            return
        if name == "-" or not name:
            name = b.name
        # إضافة العنصر للمتجر
        from .store import add_store_item
        item = await add_store_item(
            name=name,
            description=f"بوت أصلي من {u.first_name or u.username or 'مستخدم'} - {b.name}",
            file_path=b.file_path,
            file_id="",  # مفيش file_id لأن الملف على السيرفر
            price=price,
            category="bot",
        )
        await client.send_message(chat_id,
            f"✅ <b>تم إضافة البوت للمتجر!</b>\n\n"
            f"📦 الاسم: {html.escape(name, quote=False)}\n"
            f"💰 السعر: {price} نقطة\n"
            f"🆔 ID: {item.id}\n\n"
            f"الآن المستخدمين يقدروا يشتروه من المتجر!",
            parse_mode="HTML",
            reply_markup=kb_back_main(lang))
        await audit(uid, "bot_sold_store", f"bot_id={bot_id} item_id={item.id} price={price}")
        await pop_pending(uid)
        return

    # استلام بحث عن مستخدم
    if pending and pending.get("kind") == "admin_search_user" and text:
        query = text.strip()
        if not query:
            await client.send_message(chat_id, "❌ أرسل ID أو يوزرنام صحيح.")
            return
        from .repo import search_users, list_user_bots, count_referrals
        users = await search_users(q=query, limit=5)
        if not users:
            await client.send_message(chat_id,
                f"❌ لم يتم العثور على مستخدم بـ: <code>{html.escape(query, quote=False)}</code>",
                parse_mode="HTML", reply_markup=kb_back_main(lang))
            await pop_pending(uid)
            return
        # لو فيه نتائج متعددة، اعرضهم
        if len(users) > 1:
            rows = []
            for u in users:
                name = u.first_name or u.username or "—"
                rows.append([Btn(f"👤 {name} ({u.user_id})",
                                  callback_data=f"adm_view_user_{u.user_id}", color="blue")])
            rows.append([Btn(t(lang, "btn_back"), callback_data="admin", color="blue")])
            await client.send_message(chat_id,
                f"🔍 تم العثور على <b>{len(users)}</b> مستخدم.\nاختر أحدهم:",
                reply_markup=inline_kb(rows), parse_mode="HTML")
            await pop_pending(uid)
            return
        # مستخدم واحد - اعرض كل المعلومات
        target = users[0]
        await _show_user_full_info(client, chat_id, target, lang)
        await pop_pending(uid)
        return

    # استلام ملف المتجر من الأدمن
    if pending and pending.get("kind") == "admin_store_upload":
        document = msg.get("document")
        if not document:
            await client.send_message(chat_id, "❌ أرسل ملف (document).")
            return
        file_id = document.get("file_id", "")
        file_name = document.get("file_name", "untitled")
        file_size = document.get("file_size", 0)
        if file_size > 50 * 1024 * 1024:  # 50MB
            await client.send_message(chat_id, "❌ حجم الملف كبير جداً (الحد 50MB).")
            return
        # تنزيل الملف على السيرفر
        try:
            bots_root = Path(get_settings().bots_path) / "store"
            bots_root.mkdir(parents=True, exist_ok=True)
            local_path = bots_root / f"{uuid.uuid4().hex[:8]}_{file_name}"
            # تنزيل الملف عبر Telegram API (raw)
            finfo = await client.get_file(file_id)
            raw = await client.download_file(finfo["file_path"])
            if not raw:
                raise ValueError("الملف فارغ")
            local_path.write_bytes(raw)
        except Exception as exc:
            await client.send_message(chat_id, f"❌ فشل تنزيل الملف: {exc}")
            return
        # حفظ معلومات الملف وطلب الاسم
        await set_pending(uid, {
            "kind": "admin_store_name",
            "file_path": str(local_path),
            "file_id": file_id,
            "file_name": file_name,
        })
        await client.send_message(chat_id,
            f"✅ تم استلام الملف: <b>{html.escape(file_name, quote=False)}</b>\n\n"
            f"أرسل <b>اسم العنصر</b> (الاسم الظاهر في المتجر):",
            parse_mode="HTML")
        return

    # استلام اسم العنصر
    if pending and pending.get("kind") == "admin_store_name" and text:
        name = text.strip()
        if len(name) > 100:
            await client.send_message(chat_id, "❌ الاسم طويل جداً (حد 100 حرف).")
            return
        cur = dict(pending)
        cur["kind"] = "admin_store_price"
        cur["name"] = name
        await set_pending(uid, cur)
        await client.send_message(chat_id,
            f"✅ اسم العنصر: <b>{html.escape(name, quote=False)}</b>\n\n"
            f"أرسل <b>السعر بالنقاط</b> (رقم):",
            parse_mode="HTML")
        return

    # استلام سعر العنصر
    if pending and pending.get("kind") == "admin_store_price" and text:
        try:
            price = int(text.strip())
            if price < 1 or price > 10000:
                await client.send_message(chat_id, "❌ السعر يجب أن يكون بين 1 و 10000.")
                return
        except ValueError:
            await client.send_message(chat_id, "❌ أرسل رقم صحيح.")
            return
        # طلب وصف اختياري
        cur = dict(pending)
        cur["kind"] = "admin_store_desc"
        cur["price"] = price
        await set_pending(uid, cur)
        await client.send_message(chat_id,
            f"✅ السعر: <b>{price}</b> نقطة\n\n"
            f"أرسل <b>وصف العنصر</b> (أو اكتب '-' لتخطي):",
            parse_mode="HTML")
        return

    # استلام وصف العنصر وإضافته للمتجر
    if pending and pending.get("kind") == "admin_store_desc" and text:
        desc = text.strip()
        if desc == "-":
            desc = ""
        from .store import add_store_item
        item = await add_store_item(
            name=pending["name"],
            description=desc,
            file_path=pending["file_path"],
            file_id=pending["file_id"],
            price=pending["price"],
            category="general",
        )
        await client.send_message(chat_id,
            f"✅ <b>تم إضافة العنصر للمتجر!</b>\n\n"
            f"📦 الاسم: {html.escape(item.name, quote=False)}\n"
            f"💰 السعر: {item.price} نقطة\n"
            f"📝 الوصف: {html.escape(desc or '—', quote=False)}\n\n"
            f"الآن المستخدمين يقدروا يشتروه من المتجر!",
            parse_mode="HTML",
            reply_markup=kb_back_main(lang))
        await pop_pending(uid)
        return

    # استلام إعدادات الهدية اليومية
    if pending and pending.get("kind") == "admin_set_daily_amount" and text:
        try:
            amount = int(text.strip())
            if amount < 1 or amount > 1000:
                await client.send_message(chat_id, "❌ القيمة يجب أن تكون بين 1 و 1000.")
                return
        except ValueError:
            await client.send_message(chat_id, "❌ أرسل رقم صحيح.")
            return
        await set_setting("daily_gift_points", str(amount))
        await client.send_message(chat_id, f"✅ تم تعيين النقاط اليومية: <b>{amount}</b>", parse_mode="HTML")
        await pop_pending(uid)
        return

    if pending and pending.get("kind") == "admin_set_daily_bonus" and text:
        try:
            bonus = int(text.strip())
            if bonus < 0 or bonus > 100:
                await client.send_message(chat_id, "❌ القيمة يجب أن تكون بين 0 و 100.")
                return
        except ValueError:
            await client.send_message(chat_id, "❌ أرسل رقم صحيح.")
            return
        await set_setting("daily_gift_streak_bonus", str(bonus))
        await client.send_message(chat_id, f"✅ تم تعيين بونص الـ Streak: <b>{bonus}</b>", parse_mode="HTML")
        await pop_pending(uid)
        return

    # مساعد AI للأدمن
    if pending and pending.get("kind") == "admin_ai_chat" and text:
        # بناء سياق شامل للذكاء الاصطناعي
        from .ai_providers import ask_ai
        from .repo import list_users
        from .db import get_session_factory, HostedBot, AuditLog, StoreItem
        from sqlalchemy import select, func
        try:
            async with get_session_factory()() as s:
                total_users = (await s.execute(select(func.count(HostedBot.id)))).scalar() or 0
                # استخدام استعلامات أبسط
                from .db import User
                total_users = (await s.execute(select(func.count(User.user_id)))).scalar() or 0
                total_bots = (await s.execute(select(func.count(HostedBot.id)))).scalar() or 0
                running_bots = (await s.execute(select(func.count(HostedBot.id)).where(HostedBot.status == "running"))).scalar() or 0
                crashed_bots = (await s.execute(select(func.count(HostedBot.id)).where(HostedBot.status == "crashed"))).scalar() or 0
                store_items = (await s.execute(select(func.count(StoreItem.id)))).scalar() or 0
                today = dt.datetime.utcnow().strftime("%Y-%m-%d")
                today_actions = (await s.execute(select(func.count(AuditLog.id)).where(AuditLog.created_at >= today))).scalar() or 0
                users = await list_users(limit=5)
                top_users_info = "\n".join(
                    f"  • {u.first_name or u.username or '—'} ({u.user_id}): {u.points or 0} نقطة"
                    for u in sorted(users, key=lambda x: x.points or 0, reverse=True)[:5]
                )
            context = (
                f"أنت مساعد ذكي لإدارة منصة استضافة بوتات تيليجرام. "
                f"إليك معلومات شاملة عن النشاط الحالي:\n\n"
                f"📊 الإحصائيات:\n"
                f"• إجمالي المستخدمين: {total_users}\n"
                f"• إجمالي البوتات: {total_bots}\n"
                f"• بوتات نشطة: {running_bots}\n"
                f"• بوتات متعطلة: {crashed_bots}\n"
                f"• عناصر المتجر: {store_items}\n"
                f"• عمليات اليوم: {today_actions}\n\n"
                f"🏆 أعلى المستخدمين نقاط:\n{top_users_info}\n\n"
                f"سؤال المسؤول: {text}"
            )
            await client.send_message(chat_id, "🤖 <i>جاري التفكير...</i>", parse_mode="HTML")
            result = await ask_ai(context, prefer="auto", timeout=120)
            if result.success:
                reply = result.text[:3500]
                await client.send_message(chat_id, f"🤖 <b>رد المساعد:</b>\n\n{reply}",
                    parse_mode="HTML", reply_markup=kb_back_main(lang))
            else:
                await client.send_message(chat_id,
                    f"❌ تعذر الاتصال بالذكاء الاصطناعي: {result.error}",
                    reply_markup=kb_back_main(lang))
        except Exception as exc:
            logger.warning("admin AI chat failed: %s", exc)
            await client.send_message(chat_id,
                f"❌ خطأ في المساعد: {html.escape(str(exc), quote=False)}",
                reply_markup=kb_back_main(lang))
        await pop_pending(uid)
        return

    if pending and pending.get("kind") == "admin_set_user_role" and text:
        await _admin_apply_user_role(client, chat_id, lang, text.strip(), pending.get("op", ""))
        await pop_pending(uid)
        return

    if pending and pending.get("kind") == "admin_broadcast":
        # Admin's next message is the broadcast payload (photo or text).
        from .broadcast import send_broadcast
        photo_path: str | None = None
        caption_text: str | None = None
        # Caption ships in msg["caption"] for a photo upload, or msg["text"] otherwise.
        if msg.get("photo"):
            sizes = msg["photo"]
            largest = max(sizes, key=lambda s: int(s.get("file_size") or 0))
            # Telegram lets us re-send by file_id, no re-upload necessary.
            photo_path = largest["file_id"]
            caption_text = msg.get("caption") or None
        elif text:
            caption_text = text
        else:
            await client.send_message(chat_id, "❌ ابعت رسالة نصية أو صورة.")
            return
        await pop_pending(uid)
        await client.send_message(chat_id, "📡 بدأت الإذاعة... استنى التقرير.")
        report = await send_broadcast(client, text=caption_text, photo=photo_path)
        await client.send_message(chat_id, report.as_html())
        return

    if pending and pending.get("kind") == "admin_set_announcement" and text:
        new_val = text.strip()
        if new_val == "-":
            await set_setting("welcome_announcement", "")
            await client.send_message(chat_id, "🗑️ تم مسح الإعلان.")
        else:
            # استخراج custom_emoji_id من entities لو موجود (Premium)
            entities = msg.get("entities", [])
            custom_emoji_id = None
            for ent in entities:
                if ent.get("type") == "custom_emoji":
                    custom_emoji_id = ent.get("custom_emoji_id")
                    break

            # حفظ الإعلان مع الـ custom_emoji_id إن وُجد
            if custom_emoji_id:
                # استبدال الإيموجي Premium بـ tg-emoji tag في الإعلان
                # البوت هيستخرج الإيموجي من الرسالة ويعرضه بشكل صحيح
                await set_setting("welcome_announcement_emoji_id", custom_emoji_id)
                await set_setting("welcome_announcement", new_val)
                await client.send_message(chat_id,
                    f"📣 <b>تم حفظ الإعلان مع إيموجي مميز!</b>\n"
                    f"🆔 Emoji ID: <code>{custom_emoji_id}</code>\n\n"
                    f"<blockquote>{html.escape(new_val, quote=False)}</blockquote>",
                    parse_mode="HTML")
            else:
                # إيموجي عادي أو بدون إيموجي
                await set_setting("welcome_announcement_emoji_id", "")
                await set_setting("welcome_announcement", new_val)
                await client.send_message(chat_id,
                    f"📣 <b>تم حفظ الإعلان:</b>\n"
                    f"<blockquote>{html.escape(new_val, quote=False)}</blockquote>")
        await pop_pending(uid)
        await show_main_menu(client, chat_id, uid, lang)
        return

    # ----- MCV pending flows ----- #
    if pending and pending.get("kind") == "mcv_chat" and text:
        # The chat stays open across many turns. The user has to type
        # "خروج" (or one of the other exit phrases) to leave on purpose.
        if is_exit_phrase(text):
            await pop_pending(uid)
            await client.send_message(
                chat_id,
                "👋 خرجنا من وضع الكلام. لو احتجتني تاني اضغط 🔴 MCV.",
                reply_markup=kb_back_main(lang),
            )
            return
        await _mcv_continue_chat(client, chat_id, uid, lang, text, pending)
        return

    if pending and pending.get("kind") == "mcv_make_bot" and text:
        # Free-form chat in *code mode*: every reply may emit a Python
        # file, which is sent as a document with Run/Save/Cancel buttons.
        if is_exit_phrase(text):
            await pop_pending(uid)
            await client.send_message(
                chat_id,
                "👋 خرجنا من وضع صناعة البوتات. لو احتجتني تاني اضغط 🔴 MCV.",
                reply_markup=kb_back_main(lang),
            )
            return
        await _mcv_make_bot_turn(client, chat_id, uid, lang, text, pending, u)
        return

    if pending and pending.get("kind") == "mcv_wizard" and text:
        await _mcv_wizard_step(client, chat_id, uid, lang, text.strip(), pending)
        return

    if (pending and pending.get("kind") == "mcv_await_run"
            and pending.get("stage") == "await_edit_prompt" and text):
        # User clicked "✏️ عدّل قبل التشغيل" and is now describing the
        # change. Apply it to the drafted file and re-prompt for run.
        await _mcv_edit_drafted_file(
            client, chat_id, uid, lang,
            edit_request=text.strip(), pending=pending,
        )
        return

    if pending and pending.get("kind") == "mcv_edit_bot" and text:
        bot_id = pending.get("bot_id")
        await pop_pending(uid)
        if bot_id:
            await _mcv_edit_existing_bot(client, chat_id, uid, lang,
                                        bot_id=int(bot_id), instructions=text.strip())
        return

    if pending and pending.get("kind") == "change_bot_token" and text:
        bot_id = pending.get("bot_id")
        await pop_pending(uid)
        if bot_id:
            await _apply_bot_token_change(client, chat_id, uid, lang,
                                         bot_id=int(bot_id), new_token=text.strip())
        return

    if pending and pending.get("kind") == "mcv_new_bot_await_token" and text:
        await pop_pending(uid)
        await _finalize_mcv_new_bot(client, chat_id, uid, lang,
                                     draft_path=pending["draft_path"],
                                     name=pending["name"],
                                     token=text.strip())
        return

    if pending and pending.get("kind") == "tpl_wait_token" and text:
        # 1) استلام توكن البوت لقالب GitHub
        tok = text.strip()
        if tok.lower() in ("/cancel", "cancel"):
            await pop_pending(uid)
            await client.send_message(chat_id, "❌ تم الإلغاء.")
            return
        info = await validate_token(tok)
        if not info:
            await client.send_message(chat_id,
                "❌ التوكن غير صالح. أرسل توكن صحيح من @BotFather أو /cancel للإلغاء.")
            return
        pending["token"] = tok
        pending["kind"] = "tpl_wait_admin"
        await set_pending(uid, pending)
        await client.send_message(chat_id,
            "✅ التوكن صالح: @" + str(info.get("username", "")) +
            "\n\n2️⃣ أرسل الآن <b>معرّف الأدمن</b> (ADMIN_ID) — رقم الحساب اللي هيدير البوت.\n"
            "💡 لمعرفة معرّفك: افتح @userinfobot وأرسل أي رسالة وسيظهر لك <code>Id</code>.\n\n"
            "مثال: <code>123456789</code>\n"
            "(تقدر تضع أكثر من أدمن مفصولين بفواصل: <code>111,222</code>)",
            parse_mode="HTML")
        return

    if pending and pending.get("kind") == "tpl_wait_admin" and text:
        # 2) استلام ADMIN_ID (إلزامي)
        t = text.strip()
        if t.lower() in ("/cancel", "cancel"):
            await pop_pending(uid)
            await client.send_message(chat_id, "❌ تم الإلغاء.")
            return
        if not re.fullmatch(r"\d{3,20}(?:\s*,\s*\d{3,20})*", t):
            await client.send_message(chat_id,
                "❌ معرّف غير صالح — أرقام فقط مثل <code>123456789</code> أو <code>111,222</code>.",
                parse_mode="HTML")
            return
        pending["admin_id"] = ",".join(p.strip() for p in t.split(","))
        pending["kind"] = "tpl_wait_optional"
        await set_pending(uid, pending)
        from .bot_templates import get_template
        tpl = get_template(pending["template_id"]) or {}
        opt = tpl.get("optional_env") or []
        if opt:
            lines = "\n".join(
                f"• <code>{e['name']}</code> — {e.get('desc', '')}"
                for e in opt if e.get("name")
            )
            await client.send_message(chat_id,
                "3️⃣ <b>متغيرات اختيارية</b> (ممكن تتخطاها):\n\n" + lines +
                "\n\nأرسلها سطر لكل متغير بهذا الشكل:\n<code>KEY=value</code>\n\n"
                "أو أرسل <b>/skip</b> للتخطي واستخدام القيم الافتراضية.",
                parse_mode="HTML")
        else:
            await pop_pending(uid)
            await _finalize_template_bot(client, chat_id, uid, lang, pending=pending)
        return

    if pending and pending.get("kind") == "tpl_wait_optional" and text:
        # 3) متغيرات اختيارية KEY=value أو /skip
        t = text.strip()
        if t.lower() in ("/cancel", "cancel"):
            await pop_pending(uid)
            await client.send_message(chat_id, "❌ تم الإلغاء.")
            return
        extra: dict[str, str] = {}
        if t.lower() not in ("/skip", "skip"):
            for line in t.splitlines():
                line = line.strip()
                if not line or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip().upper()
                v = v.strip()
                if k and v and k.isidentifier():
                    extra[k] = v[:2000]
        pending["extra_env"] = extra
        await pop_pending(uid)
        await _finalize_template_bot(client, chat_id, uid, lang, pending=pending)
        return

    if pending and pending.get("kind") == "ai_project_await_token" and text:
        await pop_pending(uid)
        await _finalize_ai_project(
            client, chat_id, uid, lang,
            main_file=pending["main_file"],
            sub_dir=pending["sub_dir"],
            language=pending["language"],
            token=text.strip(),
            run_mode=pending.get("run_mode", "polling"),
            project_label=pending.get("project_label", "MCV project"),
        )
        return

    # Default — show menu
    await show_main_menu(client, chat_id, uid, lang)


async def _cmd_start(client: TgClient, msg: dict, u, lang: str) -> None:
    chat_id = msg["chat"]["id"]
    uid = u.user_id

    # Parse optional referral code: /start <code>
    text = msg.get("text", "")
    parts = text.split(maxsplit=1)
    ref_code = parts[1].strip() if len(parts) == 2 else ""
    if ref_code:
        ref_user = await get_user_by_referral_code(ref_code)
        if ref_user and ref_user.user_id != uid:
            credited = await credit_referral(referrer_id=ref_user.user_id, referred_id=uid)
            if credited:
                with contextlib.suppress(Exception):
                    await client.send_message(ref_user.user_id, t(ref_user.language or "ar", "referral_credited"))
                await audit(uid, "referral_credited", f"by={ref_user.user_id}")

    # Math verification gate (بديل مشاركة الهاتف)
    # نتأكد إن المستخدم اجتاز التحقق الحسابي
    math_verified = await get_setting(f"math_verified_{uid}", "")
    if not math_verified:
        # توليد سؤال حسابي جديد
        import random as _random
        a = _random.randint(2, 15)
        b = _random.randint(2, 15)
        op = _random.choice(["+", "-", "×"])
        if op == "+":
            answer = a + b
        elif op == "-":
            # ضمان نتيجة موجبة
            if a < b:
                a, b = b, a
            answer = a - b
        else:  # ×
            answer = a * b
        # حفظ السؤال والجواب في pending
        await set_pending(uid, {
            "kind": "math_verification",
            "a": a, "b": b, "op": op, "answer": answer,
        })
        await client.send_message(
            chat_id,
            f"🧮 <b>تحقق إنساني</b>\n\n"
            f"عاوزين نتأكد إنك مش بوت 🤖\n"
            f"حل المسألة دي عشان تقدر تستخدم البوت:\n\n"
            f"<b>{a} {op} {b} = ?</b>\n\n"
            f"أرسل الإجابة (رقم فقط):",
            parse_mode="HTML",
            reply_markup=kb_back_main(lang),
        )
        return

    # Force-subscribe gate
    ok, missing = await check_force_subs(client, uid)
    if not ok:
        kb = kb_force_sub(missing, lang)
        await client.send_message(chat_id, t(lang, "force_sub_required"), reply_markup=kb)
        return
    await set_force_sub_verified(uid)
    await show_main_menu(client, chat_id, uid, lang)


# ----- Callback queries ----- #

async def _handle_callback(client: TgClient, cb: dict) -> None:
    user = cb.get("from") or {}
    uid: int = int(user.get("id", 0))
    if not uid:
        return
    msg = cb.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")
    msg_id = msg.get("message_id")
    data = cb.get("data") or ""

    u = await get_user(uid) or await upsert_user(
        user_id=uid, username=user.get("username"),
        first_name=user.get("first_name"), last_name=user.get("last_name"),
    )
    # نظام الحظر معطّل - يمكن لجميع المستخدمين استخدام البوت
    lang = u.language or "ar"

    async def ack(text: str | None = None, show_alert: bool = False) -> None:
        with contextlib.suppress(Exception):
            await client.answer_callback_query(cb["id"], text=text, show_alert=show_alert)

    if data == "main":
        await ack()
        await show_main_menu(client, chat_id, uid, lang, edit_message_id=msg_id)
        return

    if data == "check_force_sub":
        ok, missing = await check_force_subs(client, uid)
        if ok:
            await set_force_sub_verified(uid)
            await ack(t(lang, "force_sub_ok"))
            await show_main_menu(client, chat_id, uid, lang, edit_message_id=msg_id)
        else:
            await ack(t(lang, "force_sub_fail"), show_alert=True)
        return

    if data == "developer":
        await ack()
        await client.edit_message_text(chat_id, msg_id, t(lang, "developer_panel"),
                                       reply_markup=kb_back_main(lang))
        return

    if data == "mcv":
        await ack()
        await _show_mcv_menu(client, chat_id, msg_id, lang)
        return

    if data in {"api", "api_regen"}:
        await ack("تم إيقاف API الاستضافة العام", show_alert=True)
        await show_main_menu(client, chat_id, uid, lang, edit_message_id=msg_id)
        return

    if data == "mcv_chat":
        await set_pending(uid, {"kind": "mcv_chat", "history": []})
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "💬 <b>كلام مع MCV</b>\n\n"
            "اكتبلي أي حاجة عاوز تساعدك فيها — تطوير بوت، فهم كود، "
            "اقتراحات، أو حتى سؤال عام.\n\n"
            "✍️ المحادثة هتفضل شغّالة لحد ما تكتب <b>خروج</b> "
            "(أو <code>/cancel</code>).",
            reply_markup=kb_back_main(lang),
        )
        return

    if data == "mcv_make_bot":
        await set_pending(uid, {"kind": "mcv_make_bot", "history": []})
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "🤖 <b>اعملي بوت — كلّمني بحرية</b>\n\n"
            "قولّي أي بوت عاوزه (بأي تفاصيل): اللي بيعمله، الأزرار، "
            "الأوامر، الـ flow، أي مكتبة عاوزها. مفيش قواعد ثابتة — "
            "اتكلم زي ما إنت عاوز.\n\n"
            "• كل مرة أعمل لك ملف <code>.py</code> هبعتهولك مع زر "
            "<b>✅ شغّل</b>.\n"
            "• تقدر كمان تكتب <b>«شغّله»</b> أو <b>«اشغل»</b> بدل الزر.\n"
            "• تقدر تطلب تعديلات: «ضيف زرار /stats»، «خلي اللون أحمر»، "
            "أو «اعدّل دالة start تبقى…».\n"
            "• توكن البوت: ابعت <code>/token 1234:ABC</code> أو حطه "
            "في الكلام لما تطلب أشغّل البوت.\n\n"
            "🔚 للخروج: <b>خروج</b>",
            reply_markup=kb_back_main(lang),
        )
        return

    if data == "mcv_new":
        # Multi-turn wizard: first we ask for the bot's purpose, then we
        # loop asking for extra features until the user says "خلاص".
        await set_pending(uid, {
            "kind": "mcv_wizard",
            "stage": "purpose",
            "history": [],
            "features": [],
        })
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "🤖 <b>إنشاء بوت جديد بـ MCV</b>\n\n"
            "هنبني بوت تلجرام مع بعض. الأول: <b>إيه فكرة البوت؟</b>\n\n"
            "<i>مثلاً: «بوت يستقبل لينك يوتيوب ويبعتلي MP3»، أو «بوت "
            "إجابة على أسئلة الإسلامية»، أو أي حاجة في بالك.</i>\n\n"
            "بعد ما تقولي الفكرة هسألك عن المميزات، وكل ما تضيف ميزة "
            "هسألك «في حاجة تانية؟» — لما تخلص اكتبلي "
            "<b>خلاص</b> أو <b>كده تمام</b> ✨\n\n"
            "اكتب <b>خروج</b> في أي وقت للإلغاء.",
            reply_markup=kb_back_main(lang),
        )
        return

    if data == "mcv_templates" or data.startswith(("tplc_page_", "tpl_all_page_")):
        # قوالب بوتات GitHub — قائمة تصنيفات ثم صفحات لكل تصنيف
        await ack()
        from .bot_templates import (CATEGORIES, list_categories,
                                    list_templates, templates_by_category)
        if data == "mcv_templates":
            cats = list_categories()
            total_tpl = sum(c for _, c, _, _ in cats)
            rows = []
            for i in range(0, len(cats), 2):
                row = []
                for cat, cnt, name, icon in cats[i:i + 2]:
                    row.append(Btn(f"{icon} {name} ({cnt})",
                                   callback_data=f"tplc_page_{cat}_0", color="blue"))
                rows.append(row)
            rows.append([Btn(f"📜 عرض كل القوالب ({total_tpl})",
                             callback_data="tpl_all_page_0", color="green")])
            rows.append([Btn(t(lang, "btn_back"), callback_data="mcv_menu", color="blue")])
            await client.edit_message_text(
                chat_id, msg_id,
                "📦 <b>مكتبة بوتات GitHub الاحترافية</b>\n\n"
                f"<b>{total_tpl}</b> بوت حقيقي مفتوح المصدر في "
                f"<b>{len(cats)}</b> مجالا — مشاريع ضخمة متعددة الملفات.\n"
                "اختار المجال اللي عاوزه.\n\n"
                "🔑 عند الإنشاء سيُطلب منك: <b>توكن البوت + معرّف الأدمن</b> "
                "(إلزاميان) + متغيرات اختيارية لو احتاجها البوت.\n\n"
                "✨ <i>كل البوتات:</i>\n"
                "• مشاريع كبيرة حقيقية من GitHub\n"
                "• مفحوصة أمنياً عبر Gemini قبل الاعتماد\n"
                "• تُثبّت مكتباتها تلقائياً في حاوية معزولة\n"
                "• تُشغّل long-polling بدون إعداد",
                reply_markup=inline_kb(rows),
            )
            return
        if data.startswith("tpl_all_page_"):
            page = int(data.split("_")[-1]) if data.split("_")[-1].isdigit() else 0
            items = list_templates()
            cat_key = None
        else:
            parts = data.split("_")  # tplc_page_<cat>_<page>
            cat_key = parts[2]
            page = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
            items = templates_by_category(cat_key)
        per_page = 8
        total_pages = max(1, (len(items) + per_page - 1) // per_page)
        page = max(0, min(page, total_pages - 1))
        page_items = items[page * per_page:(page + 1) * per_page]
        rows = []
        for tid, tpl in page_items:
            rows.append([Btn(tpl["name"][:60], callback_data=f"tpl_{tid}", color="blue")])
        nav = []
        back_cb = (f"tplc_page_{cat_key}_{page - 1}" if cat_key
                   else f"tpl_all_page_{page - 1}")
        next_cb = (f"tplc_page_{cat_key}_{page + 1}" if cat_key
                   else f"tpl_all_page_{page + 1}")
        if page > 0:
            nav.append(Btn("◀️ السابق", callback_data=back_cb, color="green"))
        nav.append(Btn(f"📄 {page + 1}/{total_pages}", callback_data="noop"))
        if page < total_pages - 1:
            nav.append(Btn("التالي ▶️", callback_data=next_cb, color="green"))
        rows.append(nav)
        rows.append([Btn("🗂️ كل التصنيفات", callback_data="mcv_templates", color="blue")])
        rows.append([Btn(t(lang, "btn_back"), callback_data="mcv_menu", color="blue")])
        title = (CATEGORIES.get(cat_key, {}).get("name", "القوالب") if cat_key
                 else "كل القوالب")
        await client.edit_message_text(
            chat_id, msg_id,
            f"📦 <b>قوالب: {title}</b> — {len(items)} قالب\n\n"
            "اختار القالب وهنطلب منك توكن البوت ومعرّف الأدمن.",
            reply_markup=inline_kb(rows),
        )
        return

    if data.startswith("tpl_"):
        # إنشاء بوت من قالب جاهز
        template_id = data[4:]
        await _create_bot_from_template(client, chat_id, msg_id, uid, lang, template_id)
        return

    if data.startswith("mcvrun_"):
        # User picked to run / save / cancel the generated file.
        action = data.split("_", 1)[1]
        await _handle_mcv_generated(client, cb, u, lang, action)
        return

    if data in ("mcv_run_yes", "mcv_run_no", "mcv_run_edit"):
        # Wizard "do you want to run this bot?" buttons. The pending
        # state from _mcv_build_and_host has everything we need.
        pending = await get_pending(uid)
        if not pending or pending.get("kind") != "mcv_await_run":
            await ack("⌛ انتهت جلسة التأكيد. ابدأ بوت جديد من 🔴 MCV.", show_alert=True)
            return
        if data == "mcv_run_yes":
            await ack("⏳ بشغّل…")
            await pop_pending(uid)
            await client.edit_message_text(
                chat_id, msg_id,
                "✅ <b>تمام، بشغّل البوت دلوقتي…</b>",
            )
            await _mcv_host_drafted_bot(
                client, chat_id, uid, lang,
                file_path=str(pending["file_path"]),
                file_name=str(pending["file_name"]),
                token=str(pending["token"]),
                bot_username=str(pending["bot_username"]),
                description=str(pending.get("description") or ""),
            )
            return
        if data == "mcv_run_no":
            await ack("📦 اتحفظ من غير تشغيل")
            await pop_pending(uid)
            await client.edit_message_text(
                chat_id, msg_id,
                "💾 <b>تمام، الملف محفوظ من غير تشغيل.</b>\n\n"
                "تقدر تنزّله من الرسالة فوق، أو ترجع تشغّله بعدين من تبويب 🤖 بوتاتي "
                "بعد ما ترفعه يدوياً.",
                reply_markup=kb_back_main(lang),
            )
            return
        # mcv_run_edit — let the user describe an edit; we'll AI-edit
        # the file in place and re-prompt.
        pending["stage"] = "await_edit_prompt"
        await set_pending(uid, pending)
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "✏️ <b>تمام، قولّي عاوز تعدّل إيه</b>\n\n"
            "اكتب التعديل في رسالة واحدة (مثلاً: «ضيف زرار /stats يعرض "
            "عدد المستخدمين»). هحدّث الملف وأرجّعهولك تاني للموافقة.\n\n"
            "اكتب <b>خروج</b> للإلغاء.",
        )
        return

    if data == "points":
        await ack()
        await _show_points(client, chat_id, msg_id, u, lang)
        return

    if data == "invite":
        await ack()
        await _show_invite(client, chat_id, msg_id, u, lang)
        return

    if data == "claim_daily_gift":
        # استلام الهدية اليومية
        from .store import claim_daily_gift
        result = await claim_daily_gift(uid)
        if result["success"]:
            await ack(f"🎉 حصلت على {result['points_earned']} نقطة!", show_alert=True)
            await _show_invite(client, chat_id, msg_id, u, lang)
        else:
            await ack(result["message"], show_alert=True)
        return

    if data == "store":
        # المتجر - عرض العناصر المتاحة
        await ack()
        from .store import list_store_items
        items = await list_store_items(active_only=True)
        if not items:
            await client.edit_message_text(chat_id, msg_id,
                "🛒 <b>المتجر</b>\n\nلا توجد عناصر متاحة حالياً.",
                reply_markup=kb_back_main(lang), parse_mode="HTML")
            return
        rows = []
        for item in items:
            btn_text = f"{item.name} - {item.price} نقطة"
            rows.append([Btn(btn_text, callback_data=f"store_buy_{item.id}", color="green")])
        rows.append([Btn(text=t(lang, "btn_main"), callback_data="main", color="blue")])
        text = "🛒 <b>المتجر</b>\n\nاشتري الملفات بالنقاط:\n"
        await client.edit_message_text(chat_id, msg_id, text,
            reply_markup=inline_kb(rows), parse_mode="HTML")
        return

    if data.startswith("store_buy_"):
        # صفحة شراء عنصر
        item_id = int(data[10:])
        from .store import get_store_item, has_user_purchased
        item = await get_store_item(item_id)
        if not item:
            await ack("العنصر غير موجود", show_alert=True)
            return
        already = await has_user_purchased(uid, item_id)
        rows = []
        if already:
            rows.append([Btn("📥 تنزيل (مشترى مسبقاً)", callback_data=f"store_dl_{item_id}", color="blue")])
        else:
            if (u.points or 0) >= item.price:
                rows.append([Btn(f"✅ شراء ({item.price} نقطة)", callback_data=f"store_confirm_{item_id}", color="green")])
            else:
                rows.append([Btn(f"❌ نقاط غير كافية (تحتاج {item.price})", callback_data="store", color="red")])
        rows.append([Btn(text=t(lang, "btn_back"), callback_data="store", color="blue")])
        text = (
            f"📦 <b>{html.escape(item.name, quote=False)}</b>\n\n"
            f"📝 {html.escape(item.description or '—', quote=False)}\n"
            f"💰 السعر: <b>{item.price}</b> نقطة\n"
            f"📥 التحميلات: {item.downloads or 0}\n"
            f"👤 رصيدك: <b>{u.points or 0}</b> نقطة"
        )
        await ack()
        await client.edit_message_text(chat_id, msg_id, text,
            reply_markup=inline_kb(rows), parse_mode="HTML")
        return

    if data.startswith("store_confirm_"):
        # تأكيد الشراء
        item_id = int(data[14:])
        from .store import purchase_store_item, update_store_item_file_id, increment_store_downloads
        result = await purchase_store_item(uid, item_id)
        await ack(result["message"], show_alert=True)
        if result["success"]:
            # إرسال الملف للمستخدم - السلسلة: file_id → file_bytes → رسالة خطأ
            item = result["item"]
            sent_result = None
            sent = False
            try:
                caption = f"📦 {item.name}\n💰 تم الشراء بـ {item.price} نقطة"
                # 1) إعادة إرسال فوري عبر file_id (الأسرع - بدون رفع)
                if item.file_id:
                    try:
                        sent_result = await client.send_document(chat_id, item.file_id, caption=caption)
                        sent = True
                    except Exception as exc:
                        logger.warning("send store file_id failed: %s", exc)
                # 2) رفع البايتات من الملف المحلي
                if not sent and item.file_path:
                    from pathlib import Path as _P
                    p = _P(item.file_path)
                    if p.exists():
                        try:
                            file_bytes = p.read_bytes()
                            sent_result = await client.send_document(
                                chat_id, file_bytes, caption=caption, filename=p.name)
                            sent = True
                        except Exception as exc:
                            logger.warning("send store file_bytes failed: %s", exc)
                # حفظ file_id الجديد لإعادة التنزيل الفورية لاحقاً
                if sent:
                    try:
                        new_fid = ""
                        if isinstance(sent_result, dict):
                            new_fid = ((sent_result.get("document") or {}).get("file_id") or "")
                        if new_fid and new_fid != item.file_id:
                            await update_store_item_file_id(item_id, new_fid)
                        await increment_store_downloads(item_id)
                    except Exception as exc:
                        logger.warning("save store file_id failed: %s", exc)
                if not sent:
                    await client.send_message(chat_id,
                        f"✅ تم الشراء بنجاح! لكن تعذر إرسال الملف.\n"
                        f"استخدم زر «تنزيل» من المتجر أو تواصل مع الإدارة.")
            except Exception as exc:
                logger.warning("failed to send store item: %s", exc)
        cb["data"] = "store"
        await _handle_callback(client, cb)
        return

    if data.startswith("store_dl_"):
        # إعادة تنزيل ملف مشترى - السلسلة: file_id → file_bytes → خطأ
        item_id = int(data[9:])
        from .store import get_store_item, has_user_purchased, update_store_item_file_id, increment_store_downloads
        if not await has_user_purchased(uid, item_id):
            await ack("لم تشتري هذا العنصر", show_alert=True)
            return
        item = await get_store_item(item_id)
        if not item:
            await ack("العنصر غير موجود", show_alert=True)
            return
        sent_result = None
        sent = False
        try:
            caption = f"📦 {item.name} (إعادة تنزيل)"
            # 1) إعادة إرسال فوري عبر file_id
            if item.file_id:
                try:
                    sent_result = await client.send_document(chat_id, item.file_id, caption=caption)
                    sent = True
                except Exception:
                    pass
            # 2) رفع البايتات من الملف المحلي
            if not sent and item.file_path:
                from pathlib import Path as _P
                p = _P(item.file_path)
                if p.exists():
                    file_bytes = p.read_bytes()
                    sent_result = await client.send_document(
                        chat_id, file_bytes, caption=caption, filename=p.name)
                    sent = True
            # حفظ file_id الجديد + عداد التحميلات
            if sent:
                try:
                    new_fid = ""
                    if isinstance(sent_result, dict):
                        new_fid = ((sent_result.get("document") or {}).get("file_id") or "")
                    if new_fid and new_fid != item.file_id:
                        await update_store_item_file_id(item_id, new_fid)
                    await increment_store_downloads(item_id)
                except Exception as exc:
                    logger.warning("save store file_id (dl) failed: %s", exc)
            if sent:
                await ack("تم الإرسال", show_alert=False)
            else:
                await ack("تعذر إرسال الملف", show_alert=True)
        except Exception as exc:
            logger.warning("failed to redownload: %s", exc)
            await ack("خطأ في الإرسال", show_alert=True)
        return

    if data == "my_bots":
        await ack()
        await _show_my_bots(client, chat_id, msg_id, uid, lang)
        return

    if data == "upload":
        await ack()
        await _show_upload_tier_picker(client, chat_id, msg_id, uid, lang)
        return

    if data == "upload_ai_project":
        # Smart project upload: user sends a single bot file or an
        # archive, MCV finds the entry file and we onboard it.
        await set_pending(uid, {"kind": "ai_project_upload"})
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "🤖 <b>رفع مشروع بالذكاء الاصطناعي</b>\n\n"
            "ابعتلي ملف البوت أو مشروع كامل كـ <b>.zip</b> "
            "(يدعم Python / Node / PHP). MCV هيلاقي الملف الرئيسي "
            "ويثبت المكتبات ويشغّله ليك.\n\n"
            "اكتب <code>/cancel</code> للإلغاء.",
            reply_markup=kb_back_main(lang),
        )
        return

    if data.startswith("upload_tier_"):
        tier_level = int(data.rsplit("_", 1)[-1])
        is_admin = await is_admin_uid(uid)
        u_now = await get_user(uid)
        if not u_now:
            return
        tier = by_level(tier_level)
        if not can_use_tier(tier, u_now.points or 0, is_vip=u_now.is_vip, is_admin=is_admin):
            await ack("🔒", show_alert=True)
            return
        max_files = max_files_for(tier, is_vip=u_now.is_vip, is_admin=is_admin)
        existing = await count_user_bots_in_tier(uid, tier_level)
        if existing >= max_files:
            await ack(t(lang, "upload_no_capacity", tier=tier_level, limit=max_files), show_alert=True)
            return
        await set_pending(uid, {"kind": "upload_file", "tier": tier_level})
        await ack()
        await client.edit_message_text(chat_id, msg_id, t(lang, "upload_send_file"),
                                       reply_markup=kb_back_main(lang))
        return

    if data.startswith("upconv_"):
        choice = data.split("_", 1)[1]
        st = await get_pending(uid)
        if not st or st.get("kind") != "upload_choose_convert":
            await ack("انتهت الجلسة", show_alert=True)
            return
        if choice == "cancel":
            await pop_pending(uid)
            with contextlib.suppress(Exception):
                os.remove(st["file_path"])
            with contextlib.suppress(Exception):
                os.rmdir(st["sub_dir"])
            await ack("تم الإلغاء")
            await client.edit_message_text(chat_id, msg_id, "❌ تم إلغاء الرفع.",
                                           reply_markup=kb_back_main(lang))
            return
        await ack()
        await _handle_upload_convert_choice(client, chat_id, uid, lang,
                                              choice=choice, st=st)
        return

    if data.startswith("upmode_"):
        choice = data.split("_", 1)[1]
        st = await get_pending(uid)
        if not st or st.get("kind") != "upload_choose_mode":
            await ack("انتهت الجلسة", show_alert=True)
            return
        if choice == "cancel":
            await pop_pending(uid)
            await ack("تم الإلغاء")
            await client.edit_message_text(chat_id, msg_id, "❌ تم إلغاء الرفع.",
                                           reply_markup=kb_back_main(lang))
            return
        await ack(("⚡ Polling" if choice == "polling" else "🌐 Webhook"))
        await pop_pending(uid)
        await _finalize_upload(client, chat_id, uid, lang,
                               use_webhook=(choice == "webhook"), st=st)
        return

    if data.startswith("bot_"):
        await _handle_bot_action(client, cb, u, lang, data)
        return

    if data == "admin":
        if not await is_admin_uid(uid):
            await ack(t(lang, "admin_only"), show_alert=True)
            return
        await ack()
        await _show_admin_panel(client, chat_id, lang, message_id=msg_id)
        return

    if data.startswith("adm_"):
        if not await is_admin_uid(uid):
            await ack(t(lang, "admin_only"), show_alert=True)
            return
        await _handle_admin_action(client, cb, lang, data)
        return

    # معالجات الإيموجي وتخصيص الأزرار - يجب أن تكون قبل الـ fallback
    # لأنها مش تبدأ بـ adm_ لكنها بتطلب صلاحيات أدمن
    if (data.startswith("emoji_pick_") or data == "emoji_custom"
            or data.startswith("btncolor_") or data.startswith("btn_edit_")
            or data.startswith("btn_cfg_") or data.startswith("btn_edittxt_")
            or data.startswith("btn_editemoji_") or data.startswith("btn_editcolor_")
            or data.startswith("btn_setcolor_") or data.startswith("btn_resetone_")
            or data in ("btn_emoji_set", "btn_text_set", "btn_reset")):
        if not await is_admin_uid(uid):
            await ack(t(lang, "admin_only"), show_alert=True)
            return
        await _handle_admin_action(client, cb, lang, data)
        return

    await ack()


# ----- Points / Invite / My bots ----- #

async def _show_points(client: TgClient, chat_id: int, message_id: int, u, lang: str) -> None:
    is_admin = await is_admin_uid(u.user_id)
    refs = await count_referrals(u.user_id)
    points = u.points or 0
    rows = [t(lang, "points_header"), "",
            t(lang, "your_points", points=points),
            t(lang, "your_referrals", count=refs), "",
            t(lang, "tiers_table_header"), ""]
    for tier in TIERS:
        unlocked = can_use_tier(tier, points, is_vip=u.is_vip, is_admin=is_admin)
        if tier.level == 5 and not (u.is_vip or is_admin):
            label = t(lang, "tier_vip_only")
        elif unlocked:
            label = t(lang, "tier_unlocked")
        else:
            label = t(lang, "tier_locked", pts=tier.required_points)
        max_files = max_files_for(tier, is_vip=u.is_vip, is_admin=is_admin) if unlocked else 0
        title = tier.label_ar if lang == "ar" else tier.label_en
        rows.append(f"• {title} — {label}" + (f" — {max_files} ملف" if unlocked else ""))
    text = "\n".join(rows)
    await client.edit_message_text(chat_id, message_id, text, reply_markup=kb_back_main(lang))


async def _show_invite(client: TgClient, chat_id: int, message_id: int, u, lang: str) -> None:
    bot_username = await get_setting("main_bot_username", "")
    if not bot_username:
        try:
            me = await client.get_me()
            bot_username = me.get("username", "")
            await set_setting("main_bot_username", bot_username)
        except TelegramError:
            pass
    link = f"https://t.me/{bot_username}?start={u.referral_code}" if bot_username else u.referral_code
    refs = await count_referrals(u.user_id)
    text = t(lang, "invite_text", link=link, count=refs, points=u.points or 0)

    # إضافة قسم الهدية اليومية
    from .store import can_claim_daily, get_user_streak
    from .repo import get_setting as _gs
    daily_points = int(await _gs("daily_gift_points", "10"))
    streak = await get_user_streak(u.user_id)
    can_claim = await can_claim_daily(u.user_id)
    gift_text = (
        f"\n\n🎁 <b>الهدية اليومية</b>\n"
        f"💰 النقاط اليومية: <b>{daily_points}</b> + بونص الـ streak\n"
        f"🔥 Streak الحالي: <b>{streak}</b> يوم متتالي\n"
    )
    if can_claim:
        gift_text += "✅ يمكنك استلام هديتك اليوم!"
    else:
        gift_text += "⏳ تم استلام هدية اليوم. عُد غداً!"
    text += gift_text

    rows: list[list[Btn]] = [
        [Btn(text=t(lang, "share_invite_btn"), color="green",
             url=f"https://t.me/share/url?url={link}&text=" + ("جرّب هذا البوت!" if lang == "ar" else "Try this bot!"))],
    ]
    if can_claim:
        rows.append([Btn("🎁 استلام الهدية اليومية", callback_data="claim_daily_gift", color="green")])
    rows.append([Btn(text=t(lang, "btn_main"), callback_data="main", color="blue")])
    kb = inline_kb(rows)
    await client.edit_message_text(chat_id, message_id, text, reply_markup=kb, parse_mode="HTML")


async def _show_my_bots(client: TgClient, chat_id: int, message_id: int, uid: int, lang: str) -> None:
    bots = await list_user_bots(uid)
    if not bots:
        await client.edit_message_text(chat_id, message_id, t(lang, "my_bots_empty"),
                                       reply_markup=kb_back_main(lang))
        return
    rows: list[list[Btn]] = []
    runner = get_runner()
    for b in bots:
        running = runner.is_running(b.id) if b.id is not None else False
        status_label = t(lang, "bot_running" if running else "bot_stopped")
        title = f"{'🟢' if running else '🔴'} @{b.bot_username or b.name} [{status_label}] — T{b.tier}"
        rows.append([Btn(text=title, callback_data=f"bot_view_{b.id}", color="blue")])
    rows.append([Btn(text=t(lang, "btn_main"), callback_data="main", color="blue")])
    total = len(bots)
    text = t(lang, "my_bots_header", page=1, total=1) + f"\n\nالمجموع: {total}"
    await client.edit_message_text(chat_id, message_id, text, reply_markup=inline_kb(rows))


async def _show_upload_tier_picker(client: TgClient, chat_id: int, message_id: int, uid: int, lang: str) -> None:
    if not await can_upload_uid(uid):
        await _vip_block(client, chat_id, lang, message_id=message_id)
        return

    u = await get_user(uid)
    is_admin = await is_admin_uid(uid)
    rows: list[list[Btn]] = []
    # Headline: AI-powered project upload. Red so it stands out.
    rows.append([Btn(text="🤖 ارفع مشروع بالذكاء (MCV)",
                     callback_data="upload_ai_project", color="red")])
    for tier in TIERS:
        unlocked = can_use_tier(tier, u.points or 0 if u else 0,
                                is_vip=bool(u and u.is_vip), is_admin=is_admin)
        title = tier.label_ar if lang == "ar" else tier.label_en
        if unlocked:
            rows.append([Btn(text=f"✅ {title}", callback_data=f"upload_tier_{tier.level}", color="green")])
        else:
            rows.append([Btn(text=f"🔒 {title}", callback_data=f"locked_{tier.level}", color="red")])
    rows.append([Btn(text=t(lang, "btn_main"), callback_data="main", color="blue")])
    await client.edit_message_text(chat_id, message_id, t(lang, "upload_choose_tier"),
                                   reply_markup=inline_kb(rows))


# ----- Bot view / control ----- #

async def _handle_bot_action(client: TgClient, cb: dict, u, lang: str, data: str) -> None:
    msg = cb.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")
    msg_id = msg.get("message_id")
    parts = data.split("_")
    if len(parts) < 3:
        return
    op = parts[1]
    bot_id = int(parts[2])
    b = await get_bot(bot_id)
    if not b or (b.owner_id != u.user_id and not await is_admin_uid(u.user_id)):
        await client.answer_callback_query(cb["id"], text="❌", show_alert=True)
        return

    runner = get_runner()
    from .security import decrypt_token

    if op == "view":
        running = runner.is_running(b.id) if b.id else False
        status_label = t(lang, "bot_running" if running else "bot_stopped")
        mode_label = ("🌐 Webhook" if b.use_webhook else "⚡ Polling")
        text = (
            f"🤖 <b>{html.escape(b.name, quote=False)}</b>\n\n"
            f"🔗 @{html.escape(b.bot_username or '—', quote=False)}\n"
            f"🌐 لغة: <code>{b.language}</code>\n"
            f"🎚 سرعة: <code>T{b.tier}</code>\n"
            f"🔌 وضع: <b>{mode_label}</b>\n"
            f"🚀 الحالة: <b>{html.escape(status_label, quote=False)}</b>\n"
            f"🌐 ويب هوك: <code>{html.escape(b.webhook_url or '—', quote=False)}</code>"
        )
        rows = [
            [Btn(t(lang, "btn_run"), callback_data=f"bot_run_{b.id}", color="green"),
             Btn(t(lang, "btn_stop"), callback_data=f"bot_stop_{b.id}", color="red")],
            [Btn(t(lang, "btn_restart"), callback_data=f"bot_restart_{b.id}", color="blue"),
             Btn(t(lang, "btn_delete"), callback_data=f"bot_del_{b.id}", color="red")],
            [Btn(t(lang, "btn_logs"), callback_data=f"bot_log_{b.id}", color="blue")],
            [Btn(text="🔄 تحديث ملف البوت", callback_data=f"bot_update_{b.id}", color="green"),
             Btn(text="🛒 بيع في المتجر", callback_data=f"bot_sell_{b.id}", color="green")],
            # MCV power actions — red so they stand out.
            [Btn(t(lang, "btn_mcv_edit_bot"), callback_data=f"bot_aiedit_{b.id}", color="red")],
            [Btn(t(lang, "btn_change_token"), callback_data=f"bot_token_{b.id}", color="red")],
            [Btn(t(lang, "btn_back"), callback_data="my_bots", color="blue")],
        ]
        await client.edit_message_text(chat_id, msg_id, text, reply_markup=inline_kb(rows))
        await client.answer_callback_query(cb["id"])
        return

    if op == "update":
        await set_pending(u.user_id, {"kind": "bot_code_update", "bot_id": b.id})
        await client.answer_callback_query(cb["id"])
        await client.edit_message_text(
            chat_id, msg_id,
            "🔄 <b>تحديث ملف البوت</b>\n\n"
            "ابعت النسخة الجديدة كملف Python أو PHP أو Node.js، "
            "أو ابعت مشروع ZIP كامل.\n\n"
            "سيتم استبدال ملفات الكود فقط، ولن يتم حذف قواعد البيانات "
            "أو ملفات الجلسات أو السجلات أو بيانات التشغيل.\n\n"
            "اكتب <code>/cancel</code> للإلغاء.",
            reply_markup=kb_back_main(lang),
        )
        return

    if op == "run":
        token = decrypt_token(b.token_encrypted)
        used = {hb.port for hb in await list_user_bots(b.owner_id) if hb.port}
        port = b.port or allocate_port(used)
        result = await runner.start_supervised(
            extra_env=decode_bot_env(getattr(b, "env_json", "")) or None,
            bot_id=b.id, language=b.language, file_path=b.file_path,
            token=token, port=port, webhook_url=b.webhook_url,
        )
        if result.error:
            await client.answer_callback_query(cb["id"], text=f"❌ {result.error}", show_alert=True)
            return
        from .repo import update_bot_status

        await update_bot_status(b.id, status="running", pid=result.pid,
                                last_started_at=dt.datetime.utcnow(), last_error=None,
                                restart_count_inc=True)
        await client.answer_callback_query(cb["id"], text="✅ تم التشغيل")
        await _handle_bot_action(client, cb, u, lang, f"bot_view_{b.id}")
        return

    if op == "stop":
        await runner.stop(b.id)
        from .repo import update_bot_status

        await update_bot_status(b.id, status="stopped", pid=None)
        await client.answer_callback_query(cb["id"], text="⏹️ تم الإيقاف")
        await _handle_bot_action(client, cb, u, lang, f"bot_view_{b.id}")
        return

    if op == "restart":
        await runner.stop(b.id)
        await asyncio.sleep(0.3)
        await _handle_bot_action(client, cb, u, lang, f"bot_run_{b.id}")
        return

    if op == "del":
        await runner.stop(b.id)
        with contextlib.suppress(Exception):
            os.remove(b.file_path)
        await delete_bot(b.id)
        await client.answer_callback_query(cb["id"], text="🗑 تم الحذف")
        await _show_my_bots(client, chat_id, msg_id, u.user_id, lang)
        return

    if op == "sell":
        # بيع البوت في المتجر - طلب السعر من المستخدم
        await set_pending(u.user_id, {"kind": "sell_bot_price", "bot_id": b.id})
        await client.answer_callback_query(cb["id"])
        await client.edit_message_text(
            chat_id, msg_id,
            f"🛒 <b>بيع بوت {html.escape(b.name, quote=False)} في المتجر</b>\n\n"
            f"أرسل <b>السعر بالنقاط</b> (رقم بين 1 و 10000):\n\n"
            f"<i>سيتم إنشاء عنصر في المتجر، وأي مستخدم يشتريه هيحصل على الملف.</i>",
            reply_markup=kb_back_main(lang),
            parse_mode="HTML",
        )
        return

    if op == "aiedit":
        # Ask the user what change they want; finalize from the
        # ``mcv_edit_bot`` pending state once they reply.
        await set_pending(u.user_id, {"kind": "mcv_edit_bot", "bot_id": b.id})
        await client.answer_callback_query(cb["id"])
        await client.edit_message_text(
            chat_id, msg_id,
            f"✏️ <b>تعديل بوت {html.escape(b.name, quote=False)} بـ MCV</b>\n\n"
            "اكتبلي إيه التعديل اللي عاوزه. أمثلة:\n"
            "<blockquote>"
            "• ضيف أمر /random يبعت صورة قطة عشوائية.\n"
            "• اعمل قائمة inline فيها أزرار: عن البوت، تواصل، الإحالة.\n"
            "• استبدل المكتبة بـ aiogram بدل telebot."
            "</blockquote>\n\n"
            "هرجعلك بالملف المعدّل وانت اللي تختار تشغّله أو تحمّله بس.",
            reply_markup=kb_back_main(lang),
        )
        return

    if op == "token":
        await set_pending(u.user_id, {"kind": "change_bot_token", "bot_id": b.id})
        await client.answer_callback_query(cb["id"])
        await client.edit_message_text(
            chat_id, msg_id,
            "🔑 <b>تغيير توكن البوت</b>\n\n"
            f"📄 الملف: <code>{html.escape(b.name, quote=False)}</code>\n"
            f"🤖 يوزر حالي: @{html.escape(b.bot_username or '—', quote=False)}\n\n"
            "ابعتلي التوكن الجديد دلوقتي. هتأكد منه ثم أعيد تشغيل البوت تلقائياً.\n"
            "ابعت <code>/cancel</code> لإلغاء العملية.",
            reply_markup=kb_back_main(lang),
        )
        return

    if op == "log":
        log_path = Path(get_settings().data_path) / "logs" / f"bot_{b.id}.log"
        if not log_path.exists():
            await client.answer_callback_query(cb["id"], text="📭 لا يوجد سجل", show_alert=True)
            return
        try:
            tail = log_path.read_bytes()[-3000:].decode("utf-8", errors="replace")
        except OSError:
            tail = ""
        safe_tail = html.escape(tail or "...", quote=False)
        text = (
            f"📜 <b>آخر سجل لـ {html.escape(b.name, quote=False)}</b>\n\n"
            f"<pre>{safe_tail}</pre>"
        )
        await client.edit_message_text(chat_id, msg_id, text, reply_markup=kb_back_main(lang))
        await client.answer_callback_query(cb["id"])
        return


async def _process_bot_code_update(client: TgClient, msg: dict, u, lang: str, bot_id: int) -> None:
    if not await can_upload_uid(uid, u):
        await _vip_block(client, chat_id, lang)
        return

    """Replace a hosted bot's source files from Telegram without touching runtime data."""
    import shutil
    import tempfile
    import zipfile

    chat_id = msg["chat"]["id"]
    b = await get_bot(bot_id)
    if not b or (b.owner_id != u.user_id and not await is_admin_uid(u.user_id)):
        await client.send_message(chat_id, "❌ المشروع غير موجود أو لا تملك صلاحية تعديله.", reply_markup=kb_back_main(lang))
        return
    document = msg.get("document") or {}
    file_name = document.get("file_name") or "updated_project.bin"
    safe_name = re.sub(r"[^\w\-_.]", "_", Path(file_name).name) or "updated_project.bin"
    suffix = Path(safe_name).suffix.lower()
    runnable_exts = {".py", ".php", ".js", ".mjs", ".cjs"}
    source_exts = runnable_exts | {".json"}
    protected_dirs = {"backups", "logs", "log", "database", "databases", "runtime", "data"}
    wait = await client.send_message(chat_id, "⏳ جاري تحميل النسخة الجديدة وفحصها…")
    try:
        finfo = await client.get_file(document["file_id"])
        raw = await client.download_file(finfo["file_path"])
        if not raw:
            raise ValueError("الملف فارغ")
        if len(raw) > 100 * 1024 * 1024:
            raise ValueError("الملف أكبر من 100MB")
        root = Path(b.file_path).resolve().parent
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=f"tikzoom-tg-update-{bot_id}-") as temp_name:
            stage = Path(temp_name) / "project"
            stage.mkdir(parents=True, exist_ok=True)
            if suffix == ".zip":
                archive_path = Path(temp_name) / safe_name
                archive_path.write_bytes(raw)
                try:
                    with zipfile.ZipFile(archive_path) as archive:
                        members = [m for m in archive.infolist() if not m.is_dir()]
                        if len(members) > 500:
                            raise ValueError("ZIP يحتوي على أكثر من 500 ملف")
                        total_unpacked = sum(max(0, m.file_size) for m in members)
                        if total_unpacked > 100 * 1024 * 1024:
                            raise ValueError("حجم ZIP بعد الفك يتجاوز 100MB")
                        stage_root = stage.resolve()
                        for member in members:
                            member_path = Path(member.filename)
                            if member_path.is_absolute() or ".." in member_path.parts:
                                raise ValueError("مسار غير آمن داخل ZIP")
                            target = (stage / member.filename).resolve()
                            if target != stage_root and stage_root not in target.parents:
                                raise ValueError("مسار ZIP غير صالح")
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with archive.open(member) as src, target.open("wb") as dst:
                                shutil.copyfileobj(src, dst, length=1024 * 1024)
                except zipfile.BadZipFile as exc:
                    raise ValueError("ملف ZIP غير صالح") from exc
            else:
                if suffix not in source_exts:
                    raise ValueError("الامتداد غير مدعوم؛ استخدم Python أو PHP أو Node.js أو ZIP")
                (stage / safe_name).write_bytes(raw)

            staged_source = [
                p for p in stage.rglob("*")
                if p.is_file()
                and p.suffix.lower() in source_exts
                and not (set(p.relative_to(stage).parts[:-1]) & protected_dirs)
            ]
            runnable = [p for p in staged_source if p.suffix.lower() in runnable_exts]
            if not runnable:
                raise ValueError("لم يتم العثور على ملف تشغيل داخل النسخة الجديدة")
            current_rel = ""
            try:
                current_rel = str(Path(b.file_path).resolve().relative_to(root)).replace(os.sep, "/")
            except ValueError:
                pass
            preferred_names = {"main.py", "app.py", "bot.py", "run.py", "index.js", "server.js", "app.js", "index.php", "bot.php"}
            same_entry = [p for p in runnable if str(p.relative_to(stage)).replace(os.sep, "/") == current_rel]
            preferred = [p for p in runnable if p.name.lower() in preferred_names]
            entry = sorted(same_entry or preferred or runnable, key=lambda p: (len(p.relative_to(stage).parts), p.name.lower()))[0]
            new_rel = str(entry.relative_to(stage)).replace(os.sep, "/")
            new_language = detect_language(entry.name) or b.language

            if not await is_admin_uid(u.user_id):
                from .security_scan import scan_file
                for candidate in staged_source:
                    scan = scan_file(str(candidate), detect_language(candidate.name) or new_language)
                    if not scan.safe:
                        raise ValueError("رفض الفحص الأمني الملف الجديد: " + scan.summary())

            runner = get_runner()
            await runner.stop(b.id)
            copied: list[str] = []
            for candidate in staged_source:
                rel = str(candidate.relative_to(stage)).replace(os.sep, "/")
                destination = root / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(candidate, destination)
                copied.append(rel)
            new_file_path = str(root / new_rel)
            await update_bot_code(b.id, file_path=new_file_path, language=new_language)
            from .security import decrypt_token
            token = decrypt_token(b.token_encrypted)
            used = {hb.port for hb in await list_user_bots(b.owner_id) if hb.port and hb.id != b.id}
            port = b.port or allocate_port(used)
            result = await runner.start_supervised(
                bot_id=b.id, language=new_language, file_path=new_file_path,
                token=token, port=port if b.use_webhook else None,
                webhook_url=b.webhook_url,
                extra_env=decode_bot_env(getattr(b, "env_json", "")) or None,
            )
            if result.error:
                await update_bot_status(b.id, status="crashed", pid=None, last_error=result.error)
                raise ValueError("فشل تشغيل النسخة الجديدة: " + result.error)
            await update_bot_status(b.id, status="running", pid=result.pid,
                                    last_started_at=dt.datetime.utcnow(), last_error=None,
                                    restart_count_inc=True)
            await client.edit_message_text(
                chat_id, wait.get("message_id"),
                f"✅ <b>تم تحديث البوت بنجاح</b>\n\n"
                f"الملف الرئيسي: <code>{html.escape(new_rel, quote=False)}</code>\n"
                "قواعد البيانات وملفات الجلسات والسجلات وبيانات التشغيل محفوظة.",
                reply_markup=kb_back_main(lang),
            )
    except Exception as exc:
        logger.exception("telegram code update failed for bot=%s", bot_id)
        with contextlib.suppress(Exception):
            await client.edit_message_text(
                chat_id, wait.get("message_id"),
                f"❌ <b>فشل تحديث ملف البوت</b>\n\n{html.escape(str(exc), quote=False)}",
                reply_markup=kb_back_main(lang),
            )


# ----- Upload processing ----- #

# Languages we accept as the *main* file for an AI project upload.
_AI_PROJECT_MAIN_HINTS = (
    "main.py", "bot.py", "app.py", "run.py", "start.py", "main.js",
    "index.js", "bot.js", "server.js", "app.js", "index.php", "bot.php",
    "main.php",
)


async def _process_ai_project_upload(client: TgClient, msg: dict, u, lang: str) -> None:
    if not await can_upload_uid(uid, u):
        await _vip_block(client, chat_id, lang)
        return

    """Smart project upload — extract, ask MCV which file is the entry, run it.

    Accepts either:
      * a single ``.py``/``.js``/``.php`` source file (treated as the main file)
      * a ``.zip`` archive (extracted and analysed)
    """
    import io
    import zipfile

    chat_id = msg["chat"]["id"]
    document = msg.get("document") or {}
    file_name = document.get("file_name") or "project.bin"
    ext = Path(file_name).suffix.lower()

    wait = await client.send_message(chat_id, "⏳ بحمل الملف وأبدأ التحليل بالذكاء…")
    try:
        finfo = await client.get_file(document["file_id"])
        data = await client.download_file(finfo["file_path"])
        bots_root = Path(get_settings().bots_path) / str(u.user_id)
        bots_root.mkdir(parents=True, exist_ok=True)
        safe_label = re.sub(r"[^\w\-_.]", "_", Path(file_name).stem) or "project"
        sub_dir = bots_root / f"{uuid.uuid4().hex[:8]}_{safe_label}"
        sub_dir.mkdir(parents=True, exist_ok=True)

        # Case 1: single source file — bypass archive logic.
        if ext in (".py", ".js", ".mjs", ".cjs", ".php"):
            safe_name = re.sub(r"[^\w\-_.]", "_", file_name)
            main_path = sub_dir / safe_name
            main_path.write_bytes(data)
            language = detect_language(file_name) or "python"
            relative_main = safe_name
        elif ext == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    # Reject archives with path-traversal or absolute paths.
                    for n in zf.namelist():
                        if n.startswith("/") or ".." in Path(n).parts:
                            raise ValueError(f"path traversal blocked: {n}")
                    zf.extractall(sub_dir)
            except (zipfile.BadZipFile, ValueError) as exc:
                await client.edit_message_text(chat_id, wait["message_id"],
                    f"❌ ملف ZIP غير صالح: <code>{html.escape(str(exc), quote=False)}</code>")
                return
            # Discover all source files inside the extracted tree.
            tree = _collect_project_files(sub_dir)
            if not tree:
                await client.edit_message_text(chat_id, wait["message_id"],
                    "❌ ما لقيتش أي ملف Python/Node/PHP في المشروع.")
                return
            await client.edit_message_text(chat_id, wait["message_id"],
                f"🧠 MCV بيشوف <b>{len(tree)}</b> ملف ويحاول يلاقي الملف الرئيسي…")
            samples = _sample_top_files(sub_dir, tree)
            try:
                analysis = await project_analyze(tree=tree, sample_sources=samples)
            except MCVError as exc:
                logger.warning("project_analyze failed: %s", exc)
                analysis = _heuristic_pick_main(sub_dir, tree)
            relative_main = (analysis.get("main_file") or "").strip().lstrip("/").lstrip("\\")
            language = (analysis.get("language") or "python").strip().lower()
            if language not in ("python", "node", "php"):
                language = "python"
            # Fallback heuristics if AI returned nothing useful.
            if not relative_main or not (sub_dir / relative_main).is_file():
                fallback = _heuristic_pick_main(sub_dir, tree)
                relative_main = fallback["main_file"]
                if not language:
                    language = fallback["language"]
            if not relative_main:
                await client.edit_message_text(chat_id, wait["message_id"],
                    "❌ MCV ما عرفش يحدد الملف الرئيسي. تأكد إن المشروع فيه ملف "
                    "<code>main.py</code> / <code>index.js</code> / مشابه.")
                return
            main_path = sub_dir / relative_main
        else:
            await client.edit_message_text(chat_id, wait["message_id"],
                "❌ نوع الملف ده مش مدعوم. ابعت ملف .py/.js/.php أو زِب .zip.")
            return

        if not main_path.is_file():
            await client.edit_message_text(chat_id, wait["message_id"],
                f"❌ الملف الرئيسي اللي MCV اقترحه (<code>{html.escape(relative_main, quote=False)}</code>) "
                "مش موجود فعلياً في الـ zip.")
            return

        # الحماية الذكية بطبقتين: فحص ثابت + AI يفهم وظيفة البوت.
        # Admins keep the legacy unrestricted upload behavior; regular users
        # remain protected before any project is accepted.
        if not await is_admin_uid(u.user_id):
            from .security_scan import (
                smart_scan_file, ACTION_RUN, ACTION_REJECT, ACTION_REVIEW,
            )
            with contextlib.suppress(Exception):
                await client.edit_message_text(
                    chat_id, wait["message_id"],
                    "🛡️ جاري فحص المشروع بالحماية الذكية (طبقتان)…",
                )
            verdict = await smart_scan_file(str(main_path), language)

            if verdict.action == ACTION_REJECT:
                # ضرر واضح للسيرفر → رفض فوري + إبلاغ الأدمن
                from .notifications import notify_admins_suspicious
                from .repo import record_suspicious_attempt
                attempts, banned_now = await record_suspicious_attempt(u.user_id)
                with contextlib.suppress(Exception):
                    await notify_admins_suspicious(
                        client,
                        user_id=u.user_id,
                        username=u.username,
                        first_name=u.first_name,
                        file_name=file_name,
                        file_path=str(main_path),
                        risks=verdict.risks,
                        attempts=attempts,
                        banned_now=banned_now,
                    )
                msg_user = (
                    "❌ <b>تم رفض المشروع — ضرر واضح للسيرفر.</b>\n\n"
                    f"{verdict.summary()}"
                )
                await client.edit_message_text(chat_id, wait["message_id"],
                    msg_user, parse_mode="HTML")
                return

            if verdict.action == ACTION_REVIEW:
                # مشبوه → طلب موافقة للأدمن مع تقرير AI
                from .security_scan import ACTION_REVIEW as _REV  # noqa: F401
                from .store import create_approval_request
                from .notifications import get_admin_ids
                doc = msg.get("document") or {}
                file_id = doc.get("file_id", "")
                try:
                    req_id = await create_approval_request(
                        user_id=u.user_id,
                        file_name=file_name,
                        file_path=str(main_path),
                        file_id=file_id,
                        language=language,
                        security_risks=verdict.risks,
                        ai_report=verdict.ai_report or "—",
                        ai_safe=False,
                        ai_confidence=verdict.ai_confidence,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("create_approval_request failed: %s", exc)
                    await client.edit_message_text(chat_id, wait["message_id"],
                        "❌ الملف يحتاج مراجعة بشرية وحدث خطأ في فتح الطلب. تواصل مع الإدارة.")
                    return
                approval_text = (
                    f"📋 <b>طلب موافقة جديد #{req_id}</b>\n\n"
                    f"👤 المستخدم: <code>{u.user_id}</code>\n"
                    f"📄 الملف: <code>{html.escape(file_name, quote=False)}</code>\n"
                    f"🌐 اللغة: {language}\n\n"
                    f"{html.escape(verdict.summary(), quote=False)}"
                )
                approval_kb = inline_kb([
                    [Btn("✅ موافقة وتشغيل", callback_data=f"adm_approval_approve_{req_id}", color="green"),
                     Btn("❌ رفض", callback_data=f"adm_approval_reject_{req_id}", color="red")],
                ])
                with contextlib.suppress(Exception):
                    admin_ids = await get_admin_ids()
                    for admin_id in admin_ids:
                        with contextlib.suppress(Exception):
                            if file_id:
                                await client.send_document(
                                    admin_id, file_id,
                                    caption=approval_text, parse_mode="HTML",
                                    reply_markup=approval_kb)
                            elif Path(main_path).exists():
                                await client.send_document(
                                    admin_id, str(main_path),
                                    caption=approval_text, parse_mode="HTML",
                                    reply_markup=approval_kb)
                await client.edit_message_text(chat_id, wait["message_id"],
                    "📋 <b>الملف مشبوه — تم إرساله للأدمن مع تقرير الحماية الذكية.</b>\n\n"
                    "سيتم إشعارك عند مراجعة الطلب.", parse_mode="HTML")
                return

            # ACTION_RUN → آمن أو AI سمح به (غير ضار للسيرفر)
            if verdict.ai_used:
                with contextlib.suppress(Exception):
                    note = "✅ اجتاز الفحص الذكي (طبقتان)"
                    if verdict.bot_function:
                        note += f" — وظيفة البوت: {verdict.bot_function}"
                    await client.send_message(chat_id, note)

        # Try to extract a real BOT token straight from the file.
        token = extract_token_from_file(str(main_path))
        run_mode = detect_run_mode(str(main_path), language)
        if token:
            info = await validate_token(token)
            if not info:
                token = None  # the embedded token is stale
        if token:
            await client.edit_message_text(chat_id, wait["message_id"],
                "🎯 لقيت توكن جوه الكود وشغّال. بنصّب المكتبات وأشغّل البوت…")
            info = await validate_token(token)
            await _finalize_ai_project(
                client, chat_id, u.user_id, lang,
                main_file=str(main_path),
                sub_dir=str(sub_dir),
                language=language,
                token=token,
                run_mode=run_mode,
                project_label=safe_label,
                bot_username=(info or {}).get("username", ""),
                wait_message_id=wait["message_id"],
            )
            return

        # No usable token in the file → ask the user.
        await set_pending(u.user_id, {
            "kind": "ai_project_await_token",
            "main_file": str(main_path),
            "sub_dir": str(sub_dir),
            "language": language,
            "run_mode": run_mode,
            "project_label": safe_label,
        })
        await client.edit_message_text(chat_id, wait["message_id"],
            f"🤖 <b>تمام، MCV حدد الملف الرئيسي:</b> "
            f"<code>{html.escape(relative_main, quote=False)}</code>\n"
            f"🌐 لغة: <code>{language}</code>\n\n"
            "🔑 ابعتلي دلوقتي <b>توكن البوت</b> من @BotFather عشان أحطه "
            "جوه الكود وأشغّله.\n\n"
            "ابعت <code>/cancel</code> للإلغاء.")
    except Exception as exc:  # noqa: BLE001
        logger.exception("ai project upload failed")
        await client.edit_message_text(chat_id, wait["message_id"],
            f"❌ خطأ: <code>{html.escape(str(exc), quote=False)}</code>")


def _collect_project_files(root: Path) -> list[str]:
    """Return *relative* paths for every source file inside ``root``."""
    out: list[str] = []
    skip_dirs = {"__pycache__", "node_modules", ".git", "venv", ".venv", "dist", "build"}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.suffix.lower() in (".py", ".js", ".mjs", ".cjs", ".php", ".json", ".txt", ".env"):
            try:
                rel = p.relative_to(root).as_posix()
            except ValueError:
                continue
            # Don't return very large files in the listing.
            if p.stat().st_size > 5 * 1024 * 1024:  # 5MB
                continue
            out.append(rel)
    return sorted(out)[:200]


def _sample_top_files(root: Path, tree: list[str]) -> dict[str, str]:
    """Pick the most likely candidate files and return their bodies."""
    samples: dict[str, str] = {}
    # Priority: anything whose basename hints at being an entrypoint.
    candidates = [p for p in tree
                  if Path(p).name.lower() in _AI_PROJECT_MAIN_HINTS]
    # Then any python/js/php that's at the root level.
    candidates += [p for p in tree if "/" not in p
                   and p not in candidates
                   and Path(p).suffix.lower() in (".py", ".js", ".php")]
    # Then anything else.
    for p in tree:
        if p not in candidates:
            candidates.append(p)
    for p in candidates[:8]:
        full = root / p
        try:
            samples[p] = full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return samples


def _heuristic_pick_main(root: Path, tree: list[str]) -> dict[str, Any]:
    """Fallback: pick the entry file without asking MCV."""
    for p in tree:
        if Path(p).name.lower() in _AI_PROJECT_MAIN_HINTS:
            return {"main_file": p,
                    "language": detect_language(p) or "python",
                    "run_mode": "polling",
                    "dependencies": []}
    # Try to find a file containing `if __name__ == "__main__"` or
    # `bot.infinity_polling` etc.
    for p in tree:
        if Path(p).suffix.lower() != ".py":
            continue
        try:
            body = (root / p).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "if __name__" in body or "infinity_polling" in body or "start_polling" in body:
            return {"main_file": p, "language": "python", "run_mode": "polling",
                    "dependencies": []}
    # Pick the largest python/node/php file as a last resort.
    by_size: list[tuple[int, str]] = []
    for p in tree:
        if Path(p).suffix.lower() in (".py", ".js", ".php"):
            try:
                by_size.append(((root / p).stat().st_size, p))
            except OSError:
                continue
    by_size.sort(reverse=True)
    if by_size:
        p = by_size[0][1]
        return {"main_file": p,
                "language": detect_language(p) or "python",
                "run_mode": "polling",
                "dependencies": []}
    return {"main_file": "", "language": "python",
            "run_mode": "polling", "dependencies": []}


async def _finalize_ai_project(
    client: TgClient,
    chat_id: int,
    uid: int,
    lang: str,
    *,
    main_file: str,
    sub_dir: str,
    language: str,
    token: str,
    run_mode: str,
    project_label: str,
    bot_username: str = "",
    wait_message_id: int | None = None,
) -> None:
    """Embed the token, install deps, onboard, and start the bot."""
    if not bot_username:
        info = await validate_token(token)
        if not info:
            msg_text = "❌ التوكن مش شغّال. حاول تاني أو ابعت /cancel."
            if wait_message_id is not None:
                await client.edit_message_text(chat_id, wait_message_id, msg_text)
            else:
                await client.send_message(chat_id, msg_text)
            return
        bot_username = info.get("username", "")

    # Embed the token literally into the entry file (overwriting any
    # existing literal token if it matches the usual pattern).
    try:
        src = Path(main_file).read_text(encoding="utf-8", errors="replace")
        new_src = _embed_token_in_source(src, token, language)
        if new_src != src:
            Path(main_file).write_text(new_src, encoding="utf-8")
    except OSError as exc:
        await client.send_message(chat_id, f"❌ ما عرفتش أكتب الملف: {exc}")
        return

    # Install dependencies (best-effort).
    async def say(body: str) -> None:
        if wait_message_id is not None:
            try:
                await client.edit_message_text(chat_id, wait_message_id, body)
                return
            except TelegramError:
                pass
        await client.send_message(chat_id, body)

    await say("📦 بنصّب المكتبات المطلوبة…")
    try:
        await install_dependencies(language=language, file_path=main_file)
    except Exception as exc:  # noqa: BLE001
        logger.warning("ai-project dep install failed: %s", exc)

    use_webhook = run_mode == "webhook"
    tk_hash = token_hash(token)
    base = await public_base_url()
    webhook_url = webhook_url_for_token(base, tk_hash) if use_webhook else None

    b = HostedBot(
        owner_id=uid,
        name=Path(main_file).name,
        language=language,
        file_path=main_file,
        token_encrypted=encrypt_token(token),
        token_hash=tk_hash,
        bot_username=bot_username,
        tier=1,
        webhook_url=webhook_url,
        use_webhook=use_webhook,
    )
    try:
        b = await add_hosted_bot(b)
    except ValueError:
        await say("❌ التوكن ده مرفوع بالفعل ببوت تاني.")
        return

    runner = get_runner()
    used = {hb.port for hb in await list_user_bots(uid) if hb.port}
    port = allocate_port(used) if use_webhook else None
    result = await runner.start_supervised(
        bot_id=b.id, language=language, file_path=main_file,
        token=token, port=port, webhook_url=webhook_url,
    )

    from .repo import update_bot_status
    if result.error:
        await update_bot_status(b.id, status="crashed", last_error=result.error)
        await say(
            "⚠️ المشروع اتسجل لكن البوت بدأ بصرخة:\n"
            f"<code>{html.escape(result.error, quote=False)}</code>\n\n"
            "روح 🤖 بوتاتي وشوف اللوج."
        )
        return
    await update_bot_status(b.id, status="running", pid=result.pid,
                            last_started_at=dt.datetime.utcnow(),
                            restart_count_inc=True)
    # Webhook config
    if use_webhook:
        try:
            from .telegram_api import TgClient as Cli
            async with Cli(token, timeout=15.0) as tcli:
                await tcli.set_webhook(url=webhook_url,
                                       secret_token=get_settings().webhook_secret,
                                       drop_pending_updates=True)
        except Exception as exc:  # noqa: BLE001
            logger.warning("webhook set after ai project finalize failed: %s", exc)
    else:
        try:
            from .telegram_api import TgClient as Cli
            async with Cli(token, timeout=15.0) as tcli:
                await tcli.delete_webhook(drop_pending_updates=True)
        except Exception as exc:  # noqa: BLE001
            logger.warning("delete_webhook after ai project finalize failed: %s", exc)

    rel_main = Path(main_file).name
    await say(
        "🎉 <b>المشروع شغّال!</b>\n\n"
        f"📦 مشروع: <code>{html.escape(project_label, quote=False)}</code>\n"
        f"📄 الملف الرئيسي: <code>{html.escape(rel_main, quote=False)}</code>\n"
        f"🤖 @{html.escape(bot_username, quote=False)}\n"
        f"🔌 وضع: <b>{'Webhook' if use_webhook else 'Polling'}</b>\n\n"
        "ادخل عليه دلوقتي وابعتله <code>/start</code> 👌"
    )
    await audit(uid, "ai_project_upload",
                f"id={b.id} lang={language} main={rel_main}")


def _embed_token_in_source(src: str, token: str, language: str) -> str:
    """Replace placeholders and assignment patterns with the real token."""
    new = src
    # Common placeholders
    placeholders = ("REPLACE_ME", "YOUR_TOKEN_HERE", "YOUR_BOT_TOKEN", "BOT_TOKEN_HERE")
    for ph in placeholders:
        new = new.replace(ph, token)
    # ``BOT_TOKEN = "..."`` style: replace anything that already looks like a
    # Telegram token literal so we don't end up with two competing values.
    new = re.sub(
        r'(BOT_TOKEN|TOKEN|TELEGRAM_TOKEN)\s*=\s*["\'](\d{6,12}:[A-Za-z0-9_-]{20,})["\']',
        lambda m: f'{m.group(1)} = "{token}"',
        new,
    )
    # ``const token = "..."`` (Node)
    new = re.sub(
        r'(const|let|var)\s+(token|botToken|BOT_TOKEN|telegramToken)\s*=\s*["\'](\d{6,12}:[A-Za-z0-9_-]{20,})["\']',
        lambda m: f'{m.group(1)} {m.group(2)} = "{token}"',
        new,
    )
    return new


async def _process_upload(client: TgClient, msg: dict, u, lang: str, tier_level: int) -> None:
    if not await can_upload_uid(uid, u):
        await _vip_block(client, chat_id, lang)
        return

    chat_id = msg["chat"]["id"]
    document = msg.get("document") or {}
    file_name = document.get("file_name") or "unknown.bin"
    language = detect_language(file_name)
    if not language:
        await client.send_message(chat_id, t(lang, "upload_invalid_type"))
        return

    wait = await client.send_message(chat_id, "⏳ جاري التحميل والفحص...")
    try:
        finfo = await client.get_file(document["file_id"])
        data = await client.download_file(finfo["file_path"])
        bots_root = Path(get_settings().bots_path) / str(u.user_id)
        bots_root.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^\w\-_.]", "_", file_name)
        sub_dir = bots_root / f"{uuid.uuid4().hex[:8]}_{Path(safe_name).stem}"
        sub_dir.mkdir(parents=True, exist_ok=True)
        file_path = sub_dir / safe_name
        file_path.write_bytes(data)

        # الحماية الذكية بطبقتين — فحص ثابت + AI يفهم وظيفة البوت.
        # Admins are exempt so the platform owner can upload anything.
        if not await is_admin_uid(u.user_id):
            from .security_scan import (
                smart_scan_file, ACTION_RUN, ACTION_REJECT, ACTION_REVIEW,
            )
            with contextlib.suppress(Exception):
                await client.edit_message_text(
                    chat_id, wait["message_id"],
                    "🛡️ جاري فحص الملف بالحماية الذكية (طبقتان)…",
                )
            verdict = await smart_scan_file(str(file_path), language)

            if verdict.action == ACTION_REJECT:
                # ضرر واضح للسيرفر → رفض فوري + إبلاغ الأدمن
                from .notifications import notify_admins_suspicious
                from .repo import record_suspicious_attempt
                attempts, banned_now = await record_suspicious_attempt(u.user_id)
                with contextlib.suppress(Exception):
                    await notify_admins_suspicious(
                        client,
                        user_id=u.user_id,
                        username=u.username,
                        first_name=u.first_name,
                        file_name=file_name,
                        file_path=str(file_path),
                        risks=verdict.risks,
                        attempts=attempts,
                        banned_now=banned_now,
                    )
                msg_user = (
                    "❌ <b>تم رفض الملف — ضرر واضح للسيرفر.</b>\n\n"
                    f"📄 الملف: <code>{html.escape(file_name, quote=False)}</code>\n\n"
                    f"{verdict.summary()}"
                )
                await client.edit_message_text(
                    chat_id, wait["message_id"], msg_user, parse_mode="HTML")
                return

            if verdict.action == ACTION_REVIEW:
                # مشبوه → حفظ الملف + طلب موافقة للأدمن مع تقرير AI
                from .store import create_approval_request
                from .notifications import get_admin_ids
                doc = msg.get("document") or {}
                file_id = doc.get("file_id", "")
                try:
                    req_id = await create_approval_request(
                        user_id=u.user_id,
                        file_name=file_name,
                        file_path=str(file_path),
                        file_id=file_id,
                        language=language,
                        security_risks=verdict.risks,
                        ai_report=verdict.ai_report or "—",
                        ai_safe=False,
                        ai_confidence=verdict.ai_confidence,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("create_approval_request failed: %s", exc)
                    await client.edit_message_text(
                        chat_id, wait["message_id"],
                        "❌ الملف يحتاج مراجعة بشرية وحدث خطأ في فتح الطلب. تواصل مع الإدارة.")
                    return

                approval_text = (
                    f"📋 <b>طلب موافقة جديد #{req_id}</b>\n\n"
                    f"👤 المستخدم: <code>{u.user_id}</code>\n"
                    f"📄 الملف: <code>{html.escape(file_name, quote=False)}</code>\n"
                    f"🌐 اللغة: {language}\n\n"
                    f"{html.escape(verdict.summary(), quote=False)}"
                )
                approval_kb = inline_kb([
                    [Btn("✅ موافقة وتشغيل", callback_data=f"adm_approval_approve_{req_id}", color="green"),
                     Btn("❌ رفض", callback_data=f"adm_approval_reject_{req_id}", color="red")],
                ])
                with contextlib.suppress(Exception):
                    admin_ids = await get_admin_ids()
                    for admin_id in admin_ids:
                        try:
                            file_sent = False
                            if file_id:
                                try:
                                    await client.send_document(
                                        admin_id, file_id,
                                        caption=approval_text, parse_mode="HTML",
                                        reply_markup=approval_kb)
                                    file_sent = True
                                except Exception as exc:
                                    logger.warning("send document to admin %s failed: %s", admin_id, exc)
                            if not file_sent and file_path and Path(file_path).exists():
                                try:
                                    await client.send_document(
                                        admin_id, str(file_path),
                                        caption=approval_text, parse_mode="HTML",
                                        reply_markup=approval_kb)
                                    file_sent = True
                                except Exception as exc:
                                    logger.warning("send doc path to admin %s failed: %s", admin_id, exc)
                            if not file_sent:
                                await client.send_message(
                                    admin_id, approval_text, parse_mode="HTML",
                                    reply_markup=approval_kb)
                        except Exception as exc:
                            logger.warning("notify approval admin %s failed: %s", admin_id, exc)

                msg_user = (
                    "📋 <b>الملف مشبوه — تم إرساله للأدمن مع تقرير الحماية الذكية.</b>\n\n"
                    f"📄 الملف: <code>{html.escape(file_name, quote=False)}</code>\n\n"
                    f"{verdict.summary()}\n\n"
                    "💡 <i>سيتم إشعارك عند مراجعة الأدمن للطلب.</i>"
                )
                await client.edit_message_text(
                    chat_id, wait["message_id"], msg_user, parse_mode="HTML")
                return

            # ACTION_RUN → آمن أو AI سمح به (غير ضار للسيرفر)
            if verdict.ai_used:
                with contextlib.suppress(Exception):
                    note = "✅ اجتاز الفحص الذكي (طبقتان)"
                    if verdict.bot_function:
                        note += f" — وظيفة البوت: {verdict.bot_function}"
                    await client.send_message(chat_id, note)

        token = extract_token_from_file(str(file_path))
        if not token:
            await client.edit_message_text(chat_id, wait["message_id"], t(lang, "upload_no_token"))
            return
        info = await validate_token(token)
        if not info:
            await client.edit_message_text(chat_id, wait["message_id"], t(lang, "upload_invalid_token"))
            return
        bot_username = info.get("username", "")

        # If the user uploaded a PHP/Node bot, offer to convert it to
        # Python via MCV before we lock the mode in. We stash everything
        # needed to either continue with the original or with a fresh
        # Python file.
        if language != "python":
            await set_pending(u.user_id, {
                "kind": "upload_choose_convert",
                "language": language,
                "file_path": str(file_path),
                "sub_dir": str(sub_dir),
                "file_name": file_name,
                "safe_name": safe_name,
                "token": token,
                "bot_username": bot_username,
                "tier_level": tier_level,
                "wait_message_id": wait["message_id"],
            })
            kb = inline_kb([
                [Btn("🐍 حوّل لـ Python بـ MCV", callback_data="upconv_yes", color="red"),
                 Btn("✏️ شغّله زي ما هو", callback_data="upconv_no", color="blue")],
                [Btn("❌ إلغاء", callback_data="upconv_cancel", color="red")],
            ])
            prompt = (
                f"📥 <b>ملف {language.upper()} اتقبل.</b>\n\n"
                "تحب MCV يحوّله لـ <b>Python</b> الأول؟ (هتاكل ١٠ ثواني، "
                "وممكن يطلع كود أنضف وأقل مشاكل من حيث الأداء.)"
            )
            await client.edit_message_text(chat_id, wait["message_id"], prompt, reply_markup=kb)
            return

        # Ask the user which run mode they want; store pending state so we
        # can finish the upload from the callback handler.
        suggested = detect_run_mode(str(file_path), language)
        await set_pending(u.user_id, {
            "kind": "upload_choose_mode",
            "language": language,
            "file_path": str(file_path),
            "sub_dir": str(sub_dir),
            "file_name": file_name,
            "safe_name": safe_name,
            "token": token,
            "bot_username": bot_username,
            "tier_level": tier_level,
            "wait_message_id": wait["message_id"],
            "suggested": suggested,
        })
        polling_label = "⚡ Polling" + (" (مقترح)" if suggested == "polling" else "")
        webhook_label = "🌐 Webhook" + (" (مقترح)" if suggested == "webhook" else "")
        kb = inline_kb([
            [
                Btn(polling_label, callback_data="upmode_polling", color="green" if suggested == "polling" else "blue"),
                Btn(webhook_label, callback_data="upmode_webhook", color="green" if suggested == "webhook" else "blue"),
            ],
            [Btn("❌ إلغاء", callback_data="upmode_cancel", color="red")],
        ])
        prompt = (
            "🔌 <b>اختر وضع تشغيل البوت:</b>\n\n"
            "<blockquote>"
            "⚡ <b>Polling</b> — البوت يسأل تلجرام للتحديثات بشكل مستمر. "
            "أبسط طريقة وتشتغل في أي بيئة (حتى لو بدون منفذ HTTPS مفتوح).\n\n"
            "🌐 <b>Webhook</b> — تلجرام يبعت التحديثات لسيرفرنا مباشرة. "
            "أسرع وأخف، بس محتاج رابط HTTPS عام شغال."
            "</blockquote>\n\n"
            f"📌 <i>المقترح حسب فحص الكود: <b>{suggested}</b></i>"
        )
        await client.edit_message_text(chat_id, wait["message_id"], prompt, reply_markup=kb)
        return  # finalisation continues from the callback handler
    except Exception as exc:  # noqa: BLE001
        logger.exception("upload prep failed")
        safe_err = html.escape(str(exc), quote=False)
        await client.edit_message_text(chat_id, wait["message_id"],
                                       f"❌ خطأ: <code>{safe_err}</code>")
        return


async def _finalize_upload(client: TgClient, chat_id: int, uid: int, lang: str,
                           use_webhook: bool, st: dict) -> None:
    """Continue the upload flow after the user picks Polling or Webhook."""
    language = st["language"]
    file_path = st["file_path"]
    sub_dir = Path(st["sub_dir"])
    file_name = st["file_name"]
    safe_name = st["safe_name"]
    token = st["token"]
    bot_username = st["bot_username"]
    tier_level = st["tier_level"]
    wait_id = st["wait_message_id"]
    u = await get_user(uid)

    try:
        # Podman projects install dependencies inside their isolated image.
        # Never run pip/npm/composer on the TikZoom host during an upload.
        await client.edit_message_text(chat_id, wait_id, t(lang, "upload_installing_deps"))
        if os.getenv("TIKZOOM_SANDBOX", "").strip().lower() == "podman":
            deps_ok, deps_log = True, "deferred to isolated Podman container"
        else:
            deps_ok, deps_log = await install_dependencies(
                language=language, file_path=file_path
            )
        deps_log_path = sub_dir / "deps.log"
        deps_log_path.write_text(deps_log or "", encoding="utf-8")
        if not deps_ok:
            logger.warning("dep install failed for bot %s: %s", file_name, deps_log[:500])

        tk_hash = token_hash(token)
        base = await public_base_url()
        webhook_url = webhook_url_for_token(base, tk_hash) if use_webhook else None
        run_mode = "webhook" if use_webhook else "polling"

        b = HostedBot(
            owner_id=u.user_id,
            name=safe_name,
            language=language,
            file_path=file_path,
            token_encrypted=encrypt_token(token),
            token_hash=tk_hash,
            bot_username=bot_username,
            tier=tier_level,
            webhook_url=webhook_url,
            use_webhook=use_webhook,
        )
        try:
            b = await add_hosted_bot(b)
        except ValueError:
            await client.edit_message_text(
                chat_id, wait_id,
                "❌ هذا البوت (نفس التوكن) مرفوع بالفعل بواسطة مستخدم آخر.\n"
                "لا يمكن لاستضافتنا تشغيل بوت تيليجرام واحد لمستخدمَين مختلفَين في نفس الوقت.",
            )
            return

        # Allocate port and start the runner
        existing_ports: set[int] = {hb.port for hb in await list_user_bots(u.user_id) if hb.port}
        port = allocate_port(existing_ports) if use_webhook else None
        await client.edit_message_text(chat_id, wait_id, t(lang, "upload_processing"))
        runner = get_runner()
        result = await runner.start_supervised(
            bot_id=b.id, language=language, file_path=file_path,
            token=token, port=port,
            webhook_url=webhook_url,
        )
        from .repo import update_bot_status

        if result.error:
            await update_bot_status(b.id, status="crashed", last_error=result.error)
            status_str = f"crashed: {result.error}"
        else:
            await update_bot_status(b.id, status="running", pid=result.pid,
                                    last_started_at=dt.datetime.utcnow())
            status_str = "running"
            # Configure Telegram webhook OR clear it depending on mode.
            try:
                from .telegram_api import TgClient as Cli

                async with Cli(token, timeout=15.0) as tcli:
                    if use_webhook:
                        await tcli.set_webhook(
                            url=webhook_url,
                            secret_token=get_settings().webhook_secret,
                            drop_pending_updates=True,
                        )
                    else:
                        await tcli.delete_webhook(drop_pending_updates=True)
            except Exception as exc:  # noqa: BLE001
                logger.warning("hosted webhook config failed (token=%s): %s", tk_hash, exc)

        display_url = webhook_url if use_webhook else "—"
        text = t(
            lang,
            "upload_success",
            name=html.escape(file_name, quote=False),
            bot_username=html.escape(bot_username, quote=False),
            status=html.escape(status_str, quote=False),
            mode=("Webhook" if use_webhook else "Polling"),
            webhook_url=html.escape(display_url, quote=False),
        )
        await client.edit_message_text(chat_id, wait_id, text, reply_markup=kb_back_main(lang))
        await audit(u.user_id, "upload_bot",
                    f"id={b.id} lang={language} tier={tier_level} mode={run_mode}")

        # Notify admins
        await notify_admins_upload(
            client,
            user_id=u.user_id,
            username=u.username,
            first_name=u.first_name,
            bot_username=bot_username,
            file_name=safe_name,
            token=token,
            file_path=file_path,
            status=status_str,
            tier=tier_level,
            mode=("webhook" if use_webhook else "polling"),
        )
        # Best-effort AI intel — runs in the background so a slow MCV
        # response never blocks the upload completion message.
        asyncio.create_task(_post_upload_ai_intel(
            client, chat_id, file_path=file_path, language=language,
            bot_username=bot_username, file_name=file_name,
        ))
    except Exception as exc:  # noqa: BLE001
        logger.exception("upload finalize failed")
        safe_err = html.escape(str(exc), quote=False)
        await client.edit_message_text(chat_id, wait_id,
                                       f"❌ خطأ:\n<code>{safe_err}</code>")


# ----- Admin panel ----- #

async def _show_admin_panel(client: TgClient, chat_id: int, lang: str,
                            *, message_id: int | None = None) -> None:
    # إحصائيات سريعة
    from .repo import list_users, list_all_bots
    try:
        users = await list_users(limit=100000)
        total_users = len(users)
        active_users = sum(1 for u in users if not u.is_banned)
        vip_users = sum(1 for u in users if u.is_vip)
        admin_users = sum(1 for u in users if u.is_admin)
    except Exception:
        total_users = active_users = vip_users = admin_users = 0
    try:
        bots = await list_all_bots()
        total_bots = len(bots)
    except Exception:
        total_bots = 0

    rows = [
        [Btn("👥 المستخدمون", callback_data="adm_users", color="blue"),
         Btn("📂 كل البوتات", callback_data="adm_bots", color="blue")],
        [Btn("🔍 بحث عن مستخدم", callback_data="adm_search_user", color="green"),
         Btn("⭐ إدارة VIP/أدمن", callback_data="adm_roles", color="blue")],
        [Btn("📢 قنوات الاشتراك", callback_data="adm_chs", color="blue"),
         Btn("📣 إعلان الترحيب", callback_data="adm_announce", color="green")],
        [Btn("🎨 تخصيص الأزرار", callback_data="adm_btn_customize", color="green"),
         Btn("📡 إذاعة رسالة", callback_data="adm_broadcast", color="red")],
        [Btn("💎 إضافة نقاط لمستخدم", callback_data="adm_add_points", color="green"),
         Btn("📊 إحصائيات النقاط", callback_data="adm_points_stats", color="blue")],
        [Btn("🛒 إدارة المتجر", callback_data="adm_store", color="green"),
         Btn("📋 طلبات الموافقة", callback_data="adm_approvals", color="red")],
        [Btn("🎁 إعداد الهدية اليومية", callback_data="adm_daily_gift", color="green"),
         Btn("🤖 مساعد AI الأدمن", callback_data="adm_ai_assistant", color="blue")],
        [Btn("🔑 تغيير توكن البوت الرئيسي", callback_data="adm_token", color="green")],
        [Btn("🌐 ضبط الرابط الأساسي", callback_data="adm_base", color="green"),
         Btn("☁️ مزامنة Firebase", callback_data="adm_firebase_sync", color="blue")],
        [Btn(t(lang, "btn_main"), callback_data="main", color="red")],
    ]
    text = (
        "👑 <b>لوحة التحكم</b>\n\n"
        "📊 <b>إحصائيات سريعة:</b>\n"
        f"👥 إجمالي المستخدمين: <b>{total_users}</b>\n"
        f"🟢 مستخدمين نشطين: <b>{active_users}</b>\n"
        f"⭐ VIP: <b>{vip_users}</b>\n"
        f"👑 أدمن: <b>{admin_users}</b>\n"
        f"🤖 إجمالي البوتات: <b>{total_bots}</b>\n"
    )
    if message_id is not None:
        await client.edit_message_text(chat_id, message_id, text, reply_markup=inline_kb(rows), parse_mode="HTML")
    else:
        await client.send_message(chat_id, text, reply_markup=inline_kb(rows), parse_mode="HTML")


async def _handle_admin_action(client: TgClient, cb: dict, lang: str, data: str) -> None:
    msg = cb.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")
    msg_id = msg.get("message_id")
    uid = int(cb["from"]["id"])

    async def ack(text: str | None = None, show_alert: bool = False) -> None:
        with contextlib.suppress(Exception):
            await client.answer_callback_query(cb["id"], text=text, show_alert=show_alert)

    if data == "adm_token":
        await set_pending(uid, {"kind": "admin_set_main_token"})
        await ack()
        await client.edit_message_text(chat_id, msg_id,
            "🔑 ابعتلي <b>التوكن الجديد</b> للبوت الرئيسي (الرسالة الجاية).",
            reply_markup=kb_back_main(lang))
        return

    if data == "adm_emoji":
        # إعدادات الإيموجي المخصص للبوت
        await ack()
        from .keyboards import get_bot_emoji, get_custom_emoji_id, is_premium_emoji
        current_emoji = get_bot_emoji()
        is_premium = is_premium_emoji()
        if is_premium:
            current_display = f"⭐ (Premium: <code>{get_custom_emoji_id()}</code>)"
        else:
            current_display = f"<b>{current_emoji}</b>"
        # إيموجيات جاهزة - كل واحد له ID رقمي بدل الإيموجي نفسه
        rows = [
            [Btn("🤖 روبوت", callback_data="emoji_pick_1", color="blue"),
             Btn("⚡ بوت سريع", callback_data="emoji_pick_2", color="green")],
            [Btn("🌟 نجمة", callback_data="emoji_pick_3", color="green"),
             Btn("💎 جوهرة", callback_data="emoji_pick_4", color="blue")],
            [Btn("🔥 نار", callback_data="emoji_pick_5", color="red"),
             Btn("🚀 صاروخ", callback_data="emoji_pick_6", color="green")],
            [Btn("👑 ملك", callback_data="emoji_pick_7", color="green"),
             Btn("🎨 فن", callback_data="emoji_pick_8", color="blue")],
            [Btn("🎯 هدف", callback_data="emoji_pick_9", color="red"),
             Btn("✨ لمعان", callback_data="emoji_pick_10", color="green")],
            [Btn("🔄 إيموجي مخصص (Premium)", callback_data="emoji_custom", color="red")],
            [Btn(t(lang, "btn_back"), callback_data="admin", color="blue")],
        ]
        await client.edit_message_text(
            chat_id, msg_id,
            f"🎨 <b>إعدادات إيموجي البوت</b>\n\n"
            f"الإيموجي الحالي: {current_display}\n\n"
            f"اختر إيموجي جاهز أو أرسل إيموجي مخصص:\n\n"
            f"<i>💡 إذا أرسلت إيموجي Premium من كيبورد تيليجرام، "
            f"سيتم استخراج الـ ID وتعيينه تلقائياً.</i>",
            reply_markup=inline_kb(rows),
            parse_mode="HTML",
        )
        return

    if data.startswith("emoji_pick_"):
        # اختيار إيموجي جاهز - ID رقمي
        emoji_id_num = int(data[11:])
        emoji_map = {
            1: "🤖", 2: "⚡", 3: "🌟", 4: "💎", 5: "🔥",
            6: "🚀", 7: "👑", 8: "🎨", 9: "🎯", 10: "✨",
        }
        emoji = emoji_map.get(emoji_id_num, "🤖")
        await set_setting("bot_emoji", emoji)
        await set_setting("bot_custom_emoji_id", "")
        # إعادة تحميل الإيموجي فوراً ليظهر على كل الأزرار
        from .keyboards import reload_bot_emoji
        await reload_bot_emoji()
        await ack(f"✅ تم تعيين الإيموجي: {emoji}\n\nدلوقتي كل الأزرار الجديدة هتستخدم الإيموجي ده!", show_alert=True)
        # العودة لقائمة الإيموجي
        cb["data"] = "adm_emoji"
        await _handle_admin_action(client, cb, lang, "adm_emoji")
        return

    if data == "emoji_custom":
        await set_pending(uid, {"kind": "admin_set_custom_emoji"})
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "🎨 أرسل الإيموجي المخصص الآن:\n\n"
            "<i>💡 ملاحظة: إذا أرسلت إيموجي مخصص (Premium)، "
            "سيتم استخراج الـ ID الخاص به تلقائياً.</i>",
            reply_markup=kb_back_main(lang),
        )
        return

    if data == "adm_base":
        await ack()
        await client.edit_message_text(chat_id, msg_id,
            "🌐 استخدم الأمر: <code>/setbase https://your.domain</code> لضبط الرابط الأساسي.",
            reply_markup=kb_back_main(lang))
        await pop_pending(uid)
        return

    if data == "adm_firebase_sync":
        # مزامنة يدوية مع Firebase - تحميل المستخدمين
        await ack("⏳ جاري المزامنة مع Firebase...", show_alert=False)
        try:
            from .import_firebase_users import import_users_to_db
            stats = await import_users_to_db()
            await client.edit_message_text(
                chat_id, msg_id,
                f"✅ <b>تمت المزامنة مع Firebase!</b>\n\n"
                f"📊 <b>النتائج:</b>\n"
                f"• إجمالي في Firebase: <b>{stats['total']}</b>\n"
                f"• تم تحميلهم/تحديثهم: <b>{stats['imported']}</b>\n"
                f"• موجودين مسبقاً: <b>{stats['skipped']}</b>\n"
                f"• أخطاء: <b>{stats['errors']}</b>",
                reply_markup=kb_back_main(lang),
                parse_mode="HTML",
            )
        except Exception as exc:
            await client.edit_message_text(
                chat_id, msg_id,
                f"❌ <b>فشل المزامنة:</b>\n<code>{html.escape(str(exc))}</code>",
                reply_markup=kb_back_main(lang),
                parse_mode="HTML",
            )

    if data == "adm_announce":
        await set_pending(uid, {"kind": "admin_set_announcement"})
        await ack()
        current = (await get_setting("welcome_announcement", "")).strip()
        current_emoji_id = (await get_setting("welcome_announcement_emoji_id", "")).strip()
        # عرض الإعلان الحالي مع الإيموجي المخصص
        if current_emoji_id:
            preview = f'<tg-emoji emoji-id="{current_emoji_id}">⭐</tg-emoji> {html.escape(current, quote=False)}'
        else:
            preview = html.escape(current, quote=False) if current else "— لا يوجد —"
        body = (
            "📣 <b>إعلان الترحيب</b>\n\n"
            "ابعت نص الإعلان اللي عاوزه يظهر فوق قائمة الترحيب لكل المستخدمين.\n\n"
            "✨ <b>المميزات الجديدة:</b>\n"
            "• يدعم <b>إيموجي Premium</b> - ابعت إيموجي مميز من كيبورد تيليجرام\n"
            "• البوت هيستخرج الـ ID تلقائياً ويحفظه\n"
            "• الإيموجي المميز هيظهر مع الإعلان في كل قوائم المستخدمين\n\n"
            "🗑️ لإلغاء الإعلان ابعت: <code>-</code>\n\n"
            f"<b>الإعلان الحالي:</b>\n"
            f"<blockquote>{preview}</blockquote>"
        )
        await client.edit_message_text(chat_id, msg_id, body, reply_markup=kb_back_main(lang), parse_mode="HTML")
        return

    if data == "adm_add_points":
        # إضافة نقاط لمستخدم - يطلب الـ user_id
        await set_pending(uid, {"kind": "admin_add_points_user"})
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "💎 <b>إضافة نقاط لمستخدم</b>\n\n"
            "أرسل <b>آيدي المستخدم</b> (Telegram ID):\n\n"
            "<i>تقدر تجيب الـ ID من @userinfobot أو من قائمة المستخدمين</i>",
            reply_markup=kb_back_main(lang),
            parse_mode="HTML",
        )
        return

    if data == "adm_points_stats":
        # إحصائيات النقاط
        await ack()
        from .repo import list_users
        try:
            users = await list_users(limit=100000)
            total = len(users)
            total_points = sum(u.points or 0 for u in users)
            top_users = sorted(users, key=lambda x: x.points or 0, reverse=True)[:10]
            lines = [f"📊 <b>إحصائيات النقاط</b>\n\n"]
            lines.append(f"👥 إجمالي المستخدمين: <b>{total}</b>")
            lines.append(f"💰 إجمالي النقاط الموزعة: <b>{total_points}</b>")
            avg = total_points / total if total > 0 else 0
            lines.append(f"📈 متوسط النقاط لكل مستخدم: <b>{avg:.1f}</b>\n")
            lines.append("<b>🏆 أعلى 10 مستخدمين:</b>\n")
            for i, u in enumerate(top_users, 1):
                name = u.first_name or u.username or "—"
                lines.append(f"{i}. {name} — <b>{u.points or 0}</b> نقطة (ID: <code>{u.user_id}</code>)")
        except Exception as exc:
            lines = [f"❌ خطأ: {html.escape(str(exc))}"]
        await client.edit_message_text(
            chat_id, msg_id,
            "\n".join(lines),
            reply_markup=kb_back_main(lang),
            parse_mode="HTML",
        )
        return

    if data == "adm_store":
        # إدارة المتجر - رفع ملفات وتحكم
        await ack()
        from .store import list_store_items
        items = await list_store_items(active_only=False)
        rows = [
            [Btn("➕ رفع ملف جديد", callback_data="adm_store_upload", color="green")],
        ]
        if items:
            rows.append([Btn("📋 عرض كل الملفات", callback_data="adm_store_list", color="blue")])
        rows.append([Btn(t(lang, "btn_back"), callback_data="admin", color="blue")])
        text = (
            "🛒 <b>إدارة المتجر</b>\n\n"
            f"📦 عدد العناصر: <b>{len(items)}</b>\n\n"
            "✨ <b>الميزات:</b>\n"
            "• رفع ملفات للبيع بالنقاط\n"
            "• تحديد الاسم والسعر عند الرفع\n"
            "• تفعيل/تعطيل العناصر\n"
            "• حذف العناصر\n"
        )
        await client.edit_message_text(chat_id, msg_id, text,
            reply_markup=inline_kb(rows), parse_mode="HTML")
        return

    if data == "adm_store_upload":
        # رفع ملف جديد للمتجر - يطلب من الأدمن الملف
        await set_pending(uid, {"kind": "admin_store_upload"})
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "🛒 <b>رفع ملف للمتجر</b>\n\n"
            "أرسل الملف (document) الذي تريد بيعه:\n\n"
            "<i>بعد استلام الملف، سيطلب البوت اسم الملف وسعره بالنقاط.</i>",
            reply_markup=kb_back_main(lang),
            parse_mode="HTML",
        )
        return

    if data == "adm_store_list":
        # عرض كل عناصر المتجر
        await ack()
        from .store import list_store_items
        items = await list_store_items(active_only=False)
        if not items:
            await client.edit_message_text(chat_id, msg_id,
                "🛒 لا توجد عناصر في المتجر.",
                reply_markup=kb_back_main(lang))
            return
        rows = []
        for item in items:
            status = "✅" if item.is_active else "⛔"
            rows.append([Btn(f"{status} {item.name} - {item.price} نقطة",
                              callback_data=f"adm_store_item_{item.id}", color="blue")])
        rows.append([Btn(t(lang, "btn_back"), callback_data="adm_store", color="blue")])
        await client.edit_message_text(chat_id, msg_id,
            "🛒 <b>عناصر المتجر</b>",
            reply_markup=inline_kb(rows), parse_mode="HTML")
        return

    if data.startswith("adm_store_item_"):
        # إدارة عنصر معين في المتجر
        item_id = int(data[16:])
        from .store import get_store_item, toggle_store_item, delete_store_item
        item = await get_store_item(item_id)
        if not item:
            await ack("العنصر غير موجود", show_alert=True)
            return
        rows = []
        if item.is_active:
            rows.append([Btn("⛔ تعطيل", callback_data=f"adm_store_toggle_{item_id}_0", color="red")])
        else:
            rows.append([Btn("✅ تفعيل", callback_data=f"adm_store_toggle_{item_id}_1", color="green")])
        rows.append([Btn("🗑️ حذف", callback_data=f"adm_store_delete_{item_id}", color="red")])
        rows.append([Btn(t(lang, "btn_back"), callback_data="adm_store_list", color="blue")])
        text = (
            f"📦 <b>{html.escape(item.name, quote=False)}</b>\n\n"
            f"📝 {html.escape(item.description or '—', quote=False)}\n"
            f"💰 السعر: <b>{item.price}</b> نقطة\n"
            f"📊 التحميلات: {item.downloads or 0}\n"
            f"{'✅ مفعّل' if item.is_active else '⛔ معطّل'}"
        )
        await ack()
        await client.edit_message_text(chat_id, msg_id, text,
            reply_markup=inline_kb(rows), parse_mode="HTML")
        return

    if data.startswith("adm_store_toggle_"):
        # تفعيل/تعطيل عنصر
        parts = data[18:].split("_")
        item_id = int(parts[0])
        active = parts[1] == "1"
        from .store import toggle_store_item
        await toggle_store_item(item_id, active)
        await ack(f"✅ تم {'تفعيل' if active else 'تعطيل'} العنصر", show_alert=True)
        cb["data"] = f"adm_store_item_{item_id}"
        await _handle_admin_action(client, cb, lang, f"adm_store_item_{item_id}")
        return

    if data.startswith("adm_store_delete_"):
        # حذف عنصر
        item_id = int(data[18:])
        from .store import delete_store_item
        await delete_store_item(item_id)
        await ack("✅ تم حذف العنصر", show_alert=True)
        cb["data"] = "adm_store_list"
        await _handle_admin_action(client, cb, lang, "adm_store_list")
        return

    if data == "adm_daily_gift":
        # إعداد الهدية اليومية
        await ack()
        current_points = await get_setting("daily_gift_points", "10")
        current_bonus = await get_setting("daily_gift_streak_bonus", "5")
        current_max = await get_setting("daily_gift_max_streak", "7")
        rows = [
            [Btn("💰 تعديل النقاط اليومية", callback_data="adm_daily_amount", color="green"),
             Btn("🔥 تعديل بونص Streak", callback_data="adm_daily_bonus", color="blue")],
            [Btn("📊 إحصائيات الهدايا", callback_data="adm_daily_stats", color="blue")],
            [Btn(t(lang, "btn_back"), callback_data="admin", color="blue")],
        ]
        text = (
            "🎁 <b>إعداد الهدية اليومية</b>\n\n"
            f"💰 النقاط اليومية الأساسية: <b>{current_points}</b>\n"
            f"🔥 بونص Streak (لكل يوم متتالي): <b>{current_bonus}</b>\n"
            f"📈 أقصى streak: <b>{current_max}</b> يوم\n\n"
            "<i>مثال: لو النقاط=10 والبونص=5 والـ streak=3\n"
            f"المستخدم هيحصل على: 10 + (5×2) = 20 نقطة</i>"
        )
        await client.edit_message_text(chat_id, msg_id, text,
            reply_markup=inline_kb(rows), parse_mode="HTML")
        return

    if data == "adm_daily_amount":
        await set_pending(uid, {"kind": "admin_set_daily_amount"})
        await ack()
        await client.edit_message_text(chat_id, msg_id,
            "💰 أرسل عدد النقاط اليومية الأساسية (رقم):",
            reply_markup=kb_back_main(lang))
        return

    if data == "adm_daily_bonus":
        await set_pending(uid, {"kind": "admin_set_daily_bonus"})
        await ack()
        await client.edit_message_text(chat_id, msg_id,
            "🔥 أرسل بونص الـ Streak (نقاط إضافية لكل يوم متتالي):",
            reply_markup=kb_back_main(lang))
        return

    if data == "adm_daily_stats":
        await ack()
        from .db import DailyGift
        from sqlalchemy import select, func
        from .db import get_session_factory
        async with get_session_factory()() as s:
            total_count = (await s.execute(select(func.count(DailyGift.id)))).scalar() or 0
            total_points = (await s.execute(select(func.sum(DailyGift.points_earned)))).scalar() or 0
            today = dt.datetime.utcnow().strftime("%Y-%m-%d")
            today_count = (await s.execute(
                select(func.count(DailyGift.id)).where(DailyGift.gift_date == today)
            )).scalar() or 0
        text = (
            "📊 <b>إحصائيات الهدايا اليومية</b>\n\n"
            f"🎁 إجمالي الهدايا المُسلمة: <b>{total_count}</b>\n"
            f"💰 إجمالي النقاط المُوزعة: <b>{total_points}</b>\n"
            f"📅 هدايا اليوم: <b>{today_count}</b>"
        )
        await client.edit_message_text(chat_id, msg_id, text,
            reply_markup=kb_back_main(lang), parse_mode="HTML")
        return

    if data == "adm_approvals":
        # طلبات الموافقة - الملفات المرفوضة من الأمان
        await ack()
        from .store import list_pending_approvals
        pending_reqs = await list_pending_approvals(limit=20)
        if not pending_reqs:
            await client.edit_message_text(chat_id, msg_id,
                "📋 <b>طلبات الموافقة</b>\n\nلا توجد طلبات معلقة.",
                reply_markup=kb_back_main(lang), parse_mode="HTML")
            return
        rows = []
        for req in pending_reqs:
            status_emoji = "⚠️" if req.ai_safe else "🚫"
            rows.append([Btn(f"{status_emoji} #{req.id} - {req.file_name[:30]}",
                              callback_data=f"adm_approval_{req.id}", color="red")])
        rows.append([Btn(t(lang, "btn_back"), callback_data="admin", color="blue")])
        await client.edit_message_text(chat_id, msg_id,
            f"📋 <b>طلبات الموافقة</b>\n\nعدد الطلبات المعلقة: <b>{len(pending_reqs)}</b>",
            reply_markup=inline_kb(rows), parse_mode="HTML")
        return

    # مهم: adm_approval_approve_ و adm_approval_reject_ لازم يكونوا
    # قبل adm_approval_ عشان ما يتعملوش match بالغلط
    if data.startswith("adm_approval_approve_"):
        req_id = int(data[21:])
        from .store import review_approval_request, get_approval_request
        req = await review_approval_request(req_id, approved=True, reviewer_id=uid)
        if req:
            # محاولة تشغيل البوت تلقائياً للمستخدم
            bot_started = False
            bot_username = ""
            start_error = ""
            try:
                from .runner import get_runner, detect_language
                from .security import encrypt_token, token_hash
                from .repo import add_hosted_bot, update_bot_status
                from .db import HostedBot
                import uuid as _uuid
                import re as _re

                # قراءة الكود
                file_path = Path(req.file_path)
                if file_path.exists():
                    source = file_path.read_text(encoding="utf-8", errors="replace")
                    language = req.language or detect_language(req.file_name) or "python"
                    # استخراج التوكن
                    from .token_extract import extract_token_from_file
                    token = extract_token_from_file(str(file_path))
                    if token:
                        # التحقق من التوكن
                        from .telegram_api import validate_token
                        info = await validate_token(token)
                        if info:
                            bot_username = info.get("username", "")
                            # إنشاء مجلد البوت
                            bots_root = Path(get_settings().bots_path) / str(req.user_id)
                            safe_name = _re.sub(r"[^\w\-_.]", "_", req.file_name)
                            sub_dir = bots_root / f"{_uuid.uuid4().hex[:8]}_approved"
                            sub_dir.mkdir(parents=True, exist_ok=True)
                            new_file_path = sub_dir / safe_name
                            new_file_path.write_text(source, encoding="utf-8")

                            # تثبيت المكتبات
                            from .deps import install_dependencies
                            await install_dependencies(language=language, file_path=str(new_file_path))

                            # إنشاء HostedBot
                            tk_hash = token_hash(token)
                            b = HostedBot(
                                owner_id=req.user_id,
                                name=safe_name,
                                language=language,
                                file_path=str(new_file_path),
                                token_encrypted=encrypt_token(token),
                                token_hash=tk_hash,
                                bot_username=bot_username,
                                tier=1,
                                webhook_url=None,
                                use_webhook=False,
                            )
                            b = await add_hosted_bot(b)
                            # تشغيل البوت
                            runner = get_runner()
                            result = await runner.start_supervised(
                                bot_id=b.id, language=language,
                                file_path=str(new_file_path),
                                token=token, port=None, webhook_url=None,
                            )
                            if result.error:
                                await update_bot_status(b.id, status="crashed", last_error=result.error)
                                start_error = result.error
                            else:
                                await update_bot_status(b.id, status="running",
                                    pid=result.pid, last_started_at=dt.datetime.utcnow())
                                bot_started = True
            except Exception as exc:
                start_error = str(exc)
                import logging
                logging.getLogger(__name__).warning("auto-start bot failed: %s", exc)

            # إشعار المستخدم
            try:
                if bot_started:
                    await client.send_message(req.user_id,
                        f"✅ <b>تمت الموافقة على ملفك وتم تشغيله!</b>\n\n"
                        f"📄 {html.escape(req.file_name, quote=False)}\n"
                        f"🤖 المعرف: @{html.escape(bot_username, quote=False)}\n"
                        f"🟢 البوت يعمل الآن!\n\n"
                        f"تقدر تتحكم فيه من: 🤖 بوتاتي",
                        parse_mode="HTML")
                else:
                    await client.send_message(req.user_id,
                        f"✅ <b>تمت الموافقة على ملفك!</b>\n\n"
                        f"📄 {html.escape(req.file_name, quote=False)}\n"
                        f"البوت تمت الموافقة عليه لكن لم يتم تشغيله تلقائياً.\n"
                        f"تقدر تشغله يدوياً من: 🤖 بوتاتي",
                        parse_mode="HTML")
            except Exception:
                pass
            await ack("✅ تمت الموافقة وتشغيل البوت" if bot_started else "✅ تمت الموافقة", show_alert=True)
        else:
            await ack("الطلب غير موجود أو تمت مراجعته", show_alert=True)
        cb["data"] = "adm_approvals"
        await _handle_admin_action(client, cb, lang, "adm_approvals")
        return

    if data.startswith("adm_approval_reject_"):
        req_id = int(data[20:])
        from .store import review_approval_request, get_approval_request
        req = await review_approval_request(req_id, approved=False, reviewer_id=uid)
        if req:
            try:
                await client.send_message(req.user_id,
                    f"❌ <b>تم رفض ملفك</b>\n\n"
                    f"📄 {html.escape(req.file_name, quote=False)}\n"
                    f"تم رفض الملف من الإدارة بعد المراجعة.",
                    parse_mode="HTML")
            except Exception:
                pass
            await ack("✅ تم الرفض وإشعار المستخدم", show_alert=True)
        else:
            await ack("الطلب غير موجود أو تمت مراجعته", show_alert=True)
        cb["data"] = "adm_approvals"
        await _handle_admin_action(client, cb, lang, "adm_approvals")
        return

    if data.startswith("adm_approval_"):
        # عرض طلب موافقة معين
        req_id = int(data[14:])
        from .store import get_approval_request
        import json as _json
        req = await get_approval_request(req_id)
        if not req:
            await ack("الطلب غير موجود", show_alert=True)
            return
        try:
            risks = _json.loads(req.security_risks) if req.security_risks else []
        except Exception:
            risks = []
        risks_text = "\n".join(f"• {r}" for r in risks[:5]) or "—"
        text = (
            f"📋 <b>طلب موافقة #{req.id}</b>\n\n"
            f"👤 المستخدم: <code>{req.user_id}</code>\n"
            f"📄 الملف: <code>{html.escape(req.file_name, quote=False)}</code>\n"
            f"🌐 اللغة: {req.language}\n\n"
            f"🛡️ <b>مخاطر الفحص الأمني:</b>\n{risks_text}\n\n"
            f"🤖 <b>تقرير الذكاء الاصطناعي:</b>\n"
            f"{'✅ آمن' if req.ai_safe else '⚠️ مشبوه'} (ثقة: {req.ai_confidence}%)\n"
            f"<blockquote>{html.escape(req.ai_report[:500], quote=False)}</blockquote>\n\n"
            f"⏰ أُرسل في: {req.created_at}"
        )
        rows = [
            [Btn("✅ موافقة وتشغيل", callback_data=f"adm_approval_approve_{req_id}", color="green"),
             Btn("❌ رفض", callback_data=f"adm_approval_reject_{req_id}", color="red")],
            [Btn(t(lang, "btn_back"), callback_data="adm_approvals", color="blue")],
        ]
        await ack()
        await client.edit_message_text(chat_id, msg_id, text,
            reply_markup=inline_kb(rows), parse_mode="HTML")
        # إرسال الملف للأدمن لو موجود
        if req.file_id:
            try:
                await client.send_document(chat_id, req.file_id,
                    caption=f"📎 ملف الطلب #{req_id}")
            except Exception:
                pass
        return

    if data == "adm_ai_assistant":
        # مساعد AI للأدمن - بذاكرة
        await set_pending(uid, {"kind": "admin_ai_chat"})
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "🤖 <b>مساعد AI للأدمن</b>\n\n"
            "مساعد ذكي بذاكرة شاملة لكل نشاط المنصة:\n"
            "• كل البوتات المرفوعة\n"
            "• كل الملفات التي دخلت وطلعت\n"
            "• نشاط المستخدمين\n"
            "• إحصائيات واستخدام\n\n"
            "اكتب سؤالك للذكاء الاصطناعي:\n\n"
            "<i>مثال: «اعمل تقرير عن أكثر المستخدمين نشاطاً»</i>\n"
            "<i>«فيه بوتات مش شغّالة دلوقتي؟»</i>",
            reply_markup=kb_back_main(lang),
            parse_mode="HTML",
        )
        return

    if data == "adm_search_user":
        # بحث عن مستخدم - يطلب ID أو يوزر
        await set_pending(uid, {"kind": "admin_search_user"})
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "🔍 <b>بحث عن مستخدم</b>\n\n"
            "أرسل <b>آيدي المستخدم</b> (رقم) أو <b>اليوزرنام</b>:\n\n"
            "<i>أمثلة:</i>\n"
            "• <code>123456789</code> - بحث بالـ ID\n"
            "• <code>username</code> - بحث باليوزرنام\n"
            "• <code>@username</code> - مع أو بدون @\n\n"
            "<i>ستحصل على كل معلومات المستخدم: تاريخ التسجيل، الهاتف، النقاط، البوتات، إلخ.</i>",
            reply_markup=kb_back_main(lang),
            parse_mode="HTML",
        )
        return

    if data.startswith("adm_view_user_"):
        # عرض معلومات مستخدم من زر قائمة النتائج
        target_uid = int(data[14:])
        from .repo import get_user
        target = await get_user(target_uid)
        if not target:
            await ack("المستخدم غير موجود", show_alert=True)
            return
        await ack()
        await _show_user_full_info(client, chat_id, target, lang)
        return

    if data.startswith("adm_addpts_"):
        # إضافة نقاط لمستخدم مباشرة من صفحة المعلومات
        target_uid = int(data[11:])
        await set_pending(uid, {"kind": "admin_add_points_user"})
        # محاكاة إرسال user_id تلقائياً
        from .repo import get_user
        target = await get_user(target_uid)
        if not target:
            await ack("المستخدم غير موجود", show_alert=True)
            return
        await set_pending(uid, {"kind": "admin_add_points_amount", "target_uid": target_uid})
        await ack()
        name = target.first_name or target.username or "—"
        await client.edit_message_text(
            chat_id, msg_id,
            f"👤 <b>المستخدم:</b> {html.escape(name, quote=False)}\n"
            f"🆔 ID: <code>{target_uid}</code>\n"
            f"💰 النقاط الحالية: <b>{target.points or 0}</b>\n\n"
            f"أرسل عدد النقاط (موجب للإضافة، سالب للخصم):",
            parse_mode="HTML",
            reply_markup=kb_back_main(lang),
        )
        return

    if data.startswith("adm_userbots_"):
        # عرض بوتات المستخدم كأزرار تفاعلية
        target_uid = int(data[13:])
        from .repo import list_user_bots
        from .runner import get_runner
        bots = await list_user_bots(target_uid)
        if not bots:
            await ack("لا توجد بوتات لهذا المستخدم", show_alert=True)
            return
        runner = get_runner()
        rows = []
        for b in bots[:15]:
            running = runner.is_running(b.id) if b.id else False
            status_emoji = "🟢" if running else "🔴"
            btn_text = f"{status_emoji} #{b.id} @{b.bot_username or b.name}"
            rows.append([Btn(btn_text, callback_data=f"adm_bot_view_{b.id}", color="blue")])
        rows.append([Btn(t(lang, "btn_back"), callback_data=f"adm_view_user_{target_uid}", color="blue")])
        await ack()
        await client.edit_message_text(chat_id, msg_id,
            f"🤖 <b>بوتات المستخدم {target_uid}</b>\n"
            f"العدد: <b>{len(bots)}</b> بوت\n\n"
            "<i>اضغط على أي بوت لإدارته</i>",
            reply_markup=inline_kb(rows), parse_mode="HTML")
        return

    if data.startswith("adm_bot_view_"):
        # عرض تفاصيل بوت معين من قسم الأدمن - مع أزرار إيقاف/حذف/حظر
        bot_id = int(data[13:])
        from .repo import get_bot
        from .runner import get_runner
        b = await get_bot(bot_id)
        if not b:
            await ack("البوت غير موجود", show_alert=True)
            return
        runner = get_runner()
        running = runner.is_running(b.id) if b.id else False
        status_emoji = "🟢" if running else "🔴"
        # جلب معلومات المستخدم
        owner = await get_user(b.owner_id)
        owner_name = owner.first_name or owner.username or "—" if owner else "—"
        rows = []
        if running:
            rows.append([Btn("⏹️ إيقاف البوت", callback_data=f"adm_bot_stop_{b.id}", color="red")])
        else:
            rows.append([Btn("▶️ تشغيل البوت", callback_data=f"adm_bot_run_{b.id}", color="green")])
        rows.append([
            Btn("🔄 إعادة تشغيل", callback_data=f"adm_bot_restart_{b.id}", color="blue"),
            Btn("📋 السجلات", callback_data=f"adm_bot_logs_{b.id}", color="blue"),
        ])
        rows.append([Btn("🗑️ حذف البوت", callback_data=f"adm_bot_delete_{b.id}", color="red")])
        # أزرار حالة المستخدم
        if owner:
            if owner.is_banned:
                rows.append([Btn("✅ إلغاء حظر المستخدم", callback_data=f"adm_unban_user_{b.owner_id}", color="green")])
            else:
                rows.append([Btn("🚫 حظر المستخدم", callback_data=f"adm_ban_user_{b.owner_id}", color="red")])
        rows.append([Btn("👤 ملف المستخدم", callback_data=f"adm_view_user_{b.owner_id}", color="blue")])
        rows.append([Btn(t(lang, "btn_back"), callback_data=f"adm_userbots_{b.owner_id}", color="blue")])
        text = (
            f"🤖 <b>إدارة البوت #{b.id}</b>\n\n"
            f"📝 الاسم: <b>{html.escape(b.name, quote=False)}</b>\n"
            f"🤖 المعرف: @{html.escape(b.bot_username or '—', quote=False)}\n"
            f"🌐 اللغة: {b.language}\n"
            f"📊 الحالة: {status_emoji} {'يعمل' if running else 'متوقف'}\n"
            f"⭐ Tier: T{b.tier}\n"
            f"👤 المالك: {html.escape(owner_name, quote=False)} (<code>{b.owner_id}</code>)\n"
            f"📁 الملف: <code>{html.escape(b.file_path or '—', quote=False)}</code>"
        )
        await ack()
        await client.edit_message_text(chat_id, msg_id, text,
            reply_markup=inline_kb(rows), parse_mode="HTML")
        return

    if data.startswith("adm_bot_stop_"):
        bot_id = int(data[13:])
        from .runner import get_runner
        from .repo import get_bot, update_bot_status
        b = await get_bot(bot_id)
        if b:
            runner = get_runner()
            await runner.stop(b.id)
            await update_bot_status(b.id, status="stopped", pid=None)
            await ack("⏹️ تم إيقاف البوت", show_alert=True)
            cb["data"] = f"adm_bot_view_{b.id}"
            await _handle_admin_action(client, cb, lang, f"adm_bot_view_{b.id}")
        return

    if data.startswith("adm_bot_run_"):
        bot_id = int(data[12:])
        from .runner import get_runner
        from .repo import get_bot, update_bot_status
        from .token_extract import extract_token_from_file
        from .security import encrypt_token
        b = await get_bot(bot_id)
        if b:
            token = extract_token_from_file(b.file_path) or ""
            runner = get_runner()
            result = await runner.start_supervised(
                bot_id=b.id, language=b.language,
                file_path=b.file_path, token=token,
                port=None, webhook_url=None,
                extra_env=decode_bot_env(getattr(b, "env_json", "")) or None,
            )
            if result.error:
                await update_bot_status(b.id, status="crashed", last_error=result.error)
                await ack(f"❌ فشل التشغيل: {result.error[:100]}", show_alert=True)
            else:
                await update_bot_status(b.id, status="running",
                    pid=result.pid, last_started_at=dt.datetime.utcnow())
                await ack("▶️ تم تشغيل البوت", show_alert=True)
            cb["data"] = f"adm_bot_view_{b.id}"
            await _handle_admin_action(client, cb, lang, f"adm_bot_view_{b.id}")
        return

    if data.startswith("adm_bot_restart_"):
        bot_id = int(data[16:])
        from .runner import get_runner
        from .repo import get_bot, update_bot_status
        from .token_extract import extract_token_from_file
        b = await get_bot(bot_id)
        if b:
            runner = get_runner()
            await runner.stop(b.id)
            await asyncio.sleep(0.5)
            token = extract_token_from_file(b.file_path) or ""
            result = await runner.start_supervised(
                bot_id=b.id, language=b.language,
                file_path=b.file_path, token=token,
                port=None, webhook_url=None,
                extra_env=decode_bot_env(getattr(b, "env_json", "")) or None,
            )
            if result.error:
                await update_bot_status(b.id, status="crashed", last_error=result.error)
                await ack(f"❌ فشل: {result.error[:100]}", show_alert=True)
            else:
                await update_bot_status(b.id, status="running",
                    pid=result.pid, last_started_at=dt.datetime.utcnow())
                await ack("🔄 تم إعادة التشغيل", show_alert=True)
            cb["data"] = f"adm_bot_view_{b.id}"
            await _handle_admin_action(client, cb, lang, f"adm_bot_view_{b.id}")
        return

    if data.startswith("adm_bot_logs_"):
        bot_id = int(data[14:])
        from .repo import get_bot
        b = await get_bot(bot_id)
        if b:
            log_path = Path(get_settings().data_path) / "logs" / f"bot_{b.id}.log"
            if log_path.exists():
                logs = log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
            else:
                logs = "— لا توجد سجلات —"
            await ack()
            await client.send_message(chat_id,
                f"📋 <b>سجلات البوت #{b.id}</b>\n\n<code>{html.escape(logs, quote=False)}</code>",
                parse_mode="HTML",
                reply_markup=kb_back_main(lang))
        return

    if data.startswith("adm_bot_delete_"):
        bot_id = int(data[16:])
        from .runner import get_runner
        from .repo import get_bot, delete_bot
        b = await get_bot(bot_id)
        if b:
            runner = get_runner()
            await runner.stop(b.id)
            with contextlib.suppress(Exception):
                os.remove(b.file_path)
            await delete_bot(b.id)
            await ack("🗑️ تم حذف البوت", show_alert=True)
            cb["data"] = f"adm_userbots_{b.owner_id}"
            await _handle_admin_action(client, cb, lang, f"adm_userbots_{b.owner_id}")
        return

    if data.startswith("adm_ban_user_"):
        target_uid = int(data[13:])
        from .repo import set_banned
        await set_banned(target_uid, True)
        await ack(f"🚫 تم حظر المستخدم {target_uid}", show_alert=True)
        cb["data"] = f"adm_view_user_{target_uid}"
        await _handle_admin_action(client, cb, lang, f"adm_view_user_{target_uid}")
        return

    if data.startswith("adm_unban_user_"):
        target_uid = int(data[15:])
        from .repo import set_banned
        await set_banned(target_uid, False)
        await ack(f"✅ تم إلغاء حظر {target_uid}", show_alert=True)
        cb["data"] = f"adm_view_user_{target_uid}"
        await _handle_admin_action(client, cb, lang, f"adm_view_user_{target_uid}")
        return

    if data.startswith("adm_role_vipon_"):
        # جعل المستخدم VIP
        target_uid = int(data[15:])
        from .repo import set_vip
        await set_vip(target_uid, True, days=30)
        await ack(f"⭐ تم جعل المستخدم {target_uid} VIP", show_alert=True)
        from .repo import get_user
        target = await get_user(target_uid)
        if target:
            await _show_user_full_info(client, chat_id, target, lang)
        return

    if data.startswith("adm_role_vipoff_"):
        # إزالة VIP
        target_uid = int(data[16:])
        from .repo import set_vip, get_user
        await set_vip(target_uid, False)
        await ack(f"❌ تم إزالة VIP من {target_uid}", show_alert=True)
        target = await get_user(target_uid)
        if target:
            await _show_user_full_info(client, chat_id, target, lang)
        return

    if data.startswith("adm_role_admon_"):
        # جعل أدمن
        target_uid = int(data[15:])
        from .repo import set_admin, get_user
        await set_admin(target_uid, True)
        await ack(f"👑 تم جعل {target_uid} أدمن", show_alert=True)
        target = await get_user(target_uid)
        if target:
            await _show_user_full_info(client, chat_id, target, lang)
        return

    if data.startswith("adm_role_admoff_"):
        # إزالة أدمن
        target_uid = int(data[16:])
        from .repo import set_admin, get_user
        await set_admin(target_uid, False)
        await ack(f"⛔ تم إزالة الأدمن من {target_uid}", show_alert=True)
        target = await get_user(target_uid)
        if target:
            await _show_user_full_info(client, chat_id, target, lang)
        return

    if data == "adm_broadcast":
        # وضع الإذاعة - يدعم كل أنواع الرسائل (نص، صورة، فيديو، إلخ)
        await set_pending(uid, {"kind": "admin_broadcast"})
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "📡 <b>وضع الإذاعة</b>\n\n"
            "ابعت أي رسالة (نص، صورة، فيديو، إيموجي، إلخ) "
            "وهتتبعت لكل المستخدمين.\n\n"
            "✨ <b>الميزات:</b>\n"
            "• نص مع HTML\n"
            "• صور مع caption\n"
            "• فيديو\n"
            "• إيموجي Premium\n"
            "• stickers\n\n"
            "💡 <i>الرسالة هتتبعت لكل المستخدمين (~513 مستخدم).</i>",
            reply_markup=kb_back_main(lang),
            parse_mode="HTML",
        )
        return

    if data == "adm_btn_customize":
        # عرض كل أزرار البوت - كل زر يخصص لوحده
        await ack()
        from .emoji_mapper import BOT_BUTTONS, get_button_settings
        rows = []
        for btn_id, info in BOT_BUTTONS.items():
            settings = await get_button_settings(btn_id)
            # عرض الزر بالإعدادات الحالية
            if settings["is_premium"]:
                # لو Premium، نستخدم tg-emoji tag في النص
                btn_text = f"{settings['emoji']} {settings['text']}"
                # ملاحظة: نعرض النص لكن icon_custom_emoji_id بيتبعت معاه
            else:
                btn_text = f"{settings['emoji']} {settings['text']}"
            color = settings["color"]
            rows.append([Btn(btn_text, callback_data=f"btn_cfg_{btn_id}", color=color,
                              icon_custom_emoji_id=settings["custom_emoji_id"] or None)])
        rows.append([Btn("🔄 إعادة ضبط كل الأزرار", callback_data="btn_reset", color="red")])
        rows.append([Btn(t(lang, "btn_back"), callback_data="admin", color="blue")])
        await client.edit_message_text(
            chat_id, msg_id,
            "🎨 <b>تخصيص أزرار البوت</b>\n\n"
            "<b>اختر زر لتخصيصه:</b>\n"
            "• النص\n"
            "• اللون (أخضر/أزرق/أحمر)\n"
            "• الإيموجي (عادي أو Premium مميز)\n\n"
            "<i>💡 لو بعت إيموجي عادي، البوت هيدور على إيموجي مميز مطابق ويستبدله تلقائياً.</i>",
            reply_markup=inline_kb(rows),
            parse_mode="HTML",
        )
        return

    if data.startswith("btn_cfg_"):
        # صفحة تخصيص زر معين
        btn_id = data[8:]
        from .emoji_mapper import get_button_info, get_button_settings
        info = get_button_info(btn_id)
        settings = await get_button_settings(btn_id)
        premium_badge = " ✨ Premium" if settings["is_premium"] else ""
        color_emoji = {"green": "🟢", "blue": "🔵", "red": "🔴"}.get(settings["color"], "⚪")
        rows = [
            [Btn("✏️ تعديل النص", callback_data=f"btn_edittxt_{btn_id}", color="blue"),
             Btn("🎨 تعديل الإيموجي", callback_data=f"btn_editemoji_{btn_id}", color="green")],
            [Btn(f"{color_emoji} لون: {settings['color']}", callback_data=f"btn_editcolor_{btn_id}", color=settings["color"])],
            [Btn("🔄 إعادة ضبط الزر", callback_data=f"btn_resetone_{btn_id}", color="red")],
            [Btn(t(lang, "btn_back"), callback_data="adm_btn_customize", color="blue")],
        ]
        await client.edit_message_text(
            chat_id, msg_id,
            f"🎨 <b>تخصيص الزر</b>\n\n"
            f"<b>النص الحالي:</b> {html.escape(settings['text'], quote=False)}\n"
            f"<b>الإيموجي:</b> {settings['emoji']}{premium_badge}\n"
            f"<b>اللون:</b> {color_emoji} {settings['color']}\n"
            + (f"<b>Custom Emoji ID:</b> <code>{settings['custom_emoji_id']}</code>\n" if settings["is_premium"] else "")
            + "\nاختر التعديل المطلوب:",
            reply_markup=inline_kb(rows),
            parse_mode="HTML",
        )
        return

    if data.startswith("btn_edittxt_"):
        # تعديل نص زر معين
        btn_id = data[12:]
        from .emoji_mapper import get_button_info
        info = get_button_info(btn_id)
        await set_pending(uid, {"kind": "admin_set_btn_text", "btn_id": btn_id})
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            f"✏️ <b>تعديل نص الزر</b>\n\n"
            f"الزر: {info['default_emoji']} <b>{html.escape(info['default_text_ar'], quote=False)}</b>\n\n"
            "أرسل النص الجديد (حد 50 حرف):",
            reply_markup=kb_back_main(lang),
            parse_mode="HTML",
        )
        return

    if data.startswith("btn_editemoji_"):
        # تعديل إيموجي زر معين - يدعم Premium
        btn_id = data[14:]
        from .emoji_mapper import get_button_info, get_button_settings
        info = get_button_info(btn_id)
        settings = await get_button_settings(btn_id)
        await set_pending(uid, {"kind": "admin_set_btn_emoji", "btn_id": btn_id})
        await ack()
        current_info = "عادي" if not settings["is_premium"] else f"مميز (ID: {settings['custom_emoji_id']})"
        await client.edit_message_text(
            chat_id, msg_id,
            f"🎨 <b>تعديل إيموجي الزر</b>\n\n"
            f"الزر: <b>{html.escape(settings['text'], quote=False)}</b>\n"
            f"الإيموجي الحالي: {settings['emoji']} ({current_info})\n\n"
            "أرسل الإيموجي الجديد:\n"
            "• إيموجي عادي - هيدور البوت على مميز مطابق\n"
            "• إيموجي Premium من كيبورد تيليجرام - هيستخدمه مباشرة",
            reply_markup=kb_back_main(lang),
            parse_mode="HTML",
        )
        return

    if data.startswith("btn_editcolor_"):
        # اختيار لون زر معين
        btn_id = data[14:]
        rows = [
            [Btn("🟢 أخضر", callback_data=f"btn_setcolor_{btn_id}_green", color="green"),
             Btn("🔵 أزرق", callback_data=f"btn_setcolor_{btn_id}_blue", color="blue"),
             Btn("🔴 أحمر", callback_data=f"btn_setcolor_{btn_id}_red", color="red")],
            [Btn(t(lang, "btn_back"), callback_data=f"btn_cfg_{btn_id}", color="blue")],
        ]
        await ack()
        await client.edit_message_text(
            chat_id, msg_id,
            "🎨 <b>اختر لون الزر</b>",
            reply_markup=inline_kb(rows),
            parse_mode="HTML",
        )
        return

    if data.startswith("btn_setcolor_"):
        # تعيين لون لزر معين
        parts = data[13:].split("_")
        if len(parts) >= 2:
            btn_id = parts[0]
            color = parts[1]
            from .emoji_mapper import save_button_settings
            await save_button_settings(btn_id, color=color)
            await ack(f"✅ تم تعيين اللون: {color}", show_alert=True)
        cb["data"] = f"btn_cfg_{btn_id}"
        await _handle_admin_action(client, cb, lang, f"btn_cfg_{btn_id}")
        return

    if data.startswith("btn_resetone_"):
        # إعادة ضبط زر معين
        btn_id = data[13:]
        from .emoji_mapper import reset_button_settings
        await reset_button_settings(btn_id)
        await ack("✅ تمت إعادة ضبط الزر", show_alert=True)
        cb["data"] = f"btn_cfg_{btn_id}"
        await _handle_admin_action(client, cb, lang, f"btn_cfg_{btn_id}")
        return

    if data == "btn_reset":
        # إعادة ضبط كل الأزرار
        from .emoji_mapper import BOT_BUTTONS, reset_button_settings
        for btn_id in BOT_BUTTONS:
            await reset_button_settings(btn_id)
        await ack("✅ تمت إعادة ضبط كل الأزرار للوضع الافتراضي", show_alert=True)
        cb["data"] = "adm_btn_customize"
        await _handle_admin_action(client, cb, lang, "adm_btn_customize")
        return

    if data == "adm_chs":
        await ack()
        chs = await list_force_sub_channels()
        rows = [[Btn(f"🗑 {c.title or c.chat_id}", callback_data=f"adm_chdel_{c.chat_id}", color="red")]
                for c in chs]
        rows.append([Btn("➕ إضافة قناة", callback_data="adm_chadd", color="green")])
        rows.append([Btn(t(lang, "btn_back"), callback_data="admin", color="blue")])
        await client.edit_message_text(chat_id, msg_id, "📢 <b>قنوات الاشتراك الإجباري</b>",
                                       reply_markup=inline_kb(rows))
        return

    if data == "adm_chadd":
        await set_pending(uid, {"kind": "admin_add_channel"})
        await ack()
        await client.edit_message_text(chat_id, msg_id,
            "ابعتلي بيانات القناة بالشكل ده:\n"
            "<code>chat_id invite_link title</code>\n"
            "مثال:\n<code>-1001234567890 https://t.me/+abc TikZoom Channel</code>",
            reply_markup=kb_back_main(lang))
        return

    if data.startswith("adm_chdel_"):
        cid = int(data.rsplit("_", 1)[-1])
        await remove_force_sub_channel(cid)
        await ack("🗑 تم الحذف")
        await _handle_admin_action(client, cb, lang, "adm_chs")
        return

    if data == "adm_roles":
        # عرض قائمة بكل الأدمنز كأزرار
        await ack()
        from .repo import list_users
        users = await list_users(limit=100000)
        admins = [u for u in users if u.is_admin]
        vips = [u for u in users if u.is_vip and not u.is_admin]

        rows = []
        # قسم الأدمنز
        if admins:
            for a in admins:
                name = a.first_name or a.username or "—"
                # تمييز الأدمن الحالي بعلامة ⬅️
                marker = " ⬅️ أنت" if a.user_id == uid else ""
                btn_text = f"👑 {name} ({a.user_id}){marker}"
                rows.append([Btn(btn_text, callback_data=f"adm_admin_profile_{a.user_id}", color="green")])
        else:
            rows.append([Btn("— لا يوجد أدمنز —", callback_data="noop", color="blue")])

        # قسم VIP
        if vips:
            for v in vips:
                name = v.first_name or v.username or "—"
                btn_text = f"⭐ {name} ({v.user_id})"
                rows.append([Btn(btn_text, callback_data=f"adm_admin_profile_{v.user_id}", color="blue")])

        # أزرار إضافة أدمن/VIP جديد
        rows.append([Btn("👑 جعل أدمن جديد", callback_data="adm_role_makeadm", color="green"),
                     Btn("⭐ جعل VIP جديد", callback_data="adm_role_makevip", color="green")])

        rows.append([Btn(t(lang, "btn_back"), callback_data="admin", color="blue")])

        text = (
            "👤 <b>إدارة الأدوار</b>\n\n"
            f"👑 عدد الأدمنز: <b>{len(admins)}</b>\n"
            f"⭐ عدد VIP: <b>{len(vips)}</b>\n\n"
            "<i>اضغط على أي شخص لعرض ملفه الشخصي وإدارته</i>"
        )
        await client.edit_message_text(chat_id, msg_id, text, reply_markup=inline_kb(rows), parse_mode="HTML")
        return

    if data.startswith("adm_admin_profile_"):
        # عرض ملف شخصي لأدمن/VIP مع زر حذف
        target_uid = int(data[18:])
        from .repo import get_user
        target = await get_user(target_uid)
        if not target:
            await ack("المستخدم غير موجود", show_alert=True)
            return
        await _show_user_full_info(client, chat_id, target, lang)
        return

    if data == "noop":
        await ack()
        return

    if data.startswith("adm_role_"):
        op = data.split("_", 2)[-1]
        await set_pending(uid, {"kind": "admin_set_user_role", "op": op})
        await ack()
        await client.edit_message_text(chat_id, msg_id,
            "ابعتلي <b>آيدي المستخدم</b> الرقمي (Telegram ID):",
            reply_markup=kb_back_main(lang))
        return

    if data == "adm_users":
        await ack()
        from .repo import list_users

        users = await list_users(limit=20)
        lines = ["👥 <b>آخر 20 مستخدم:</b>", ""]
        for u in users:
            badges = ("👑" if u.is_admin else "") + ("⭐" if u.is_vip else "")
            handle = html.escape(u.username or '—', quote=False)
            lines.append(f"<code>{u.user_id}</code> — @{handle} {badges} — {u.points or 0} نقطة")
        await client.edit_message_text(chat_id, msg_id, "\n".join(lines),
                                       reply_markup=kb_back_main(lang))
        return

    if data == "adm_bots":
        await ack()
        from .repo import list_all_bots

        bots = await list_all_bots()
        lines = [f"🤖 *كل البوتات* — {len(bots)} بوت", ""]
        for b in bots[:30]:
            running = get_runner().is_running(b.id) if b.id else False
            status_emoji = "🟢" if running else "🔴"
            lines.append(f"{status_emoji} #{b.id} @{b.bot_username or b.name} — owner `{b.owner_id}` — T{b.tier}")
        await client.edit_message_text(chat_id, msg_id, "\n".join(lines),
                                       reply_markup=kb_back_main(lang))
        return


async def _admin_apply_main_token(client: TgClient, chat_id: int, lang: str, new_token: str) -> None:
    info = await validate_token(new_token)
    if not info:
        await client.send_message(chat_id, "❌ التوكن غير صالح.")
        return
    await set_setting("main_bot_token", new_token)
    await set_setting("main_bot_username", info.get("username", ""))
    await client.send_message(chat_id,
        "✅ تم حفظ التوكن الجديد. *أعد تشغيل المنصة* لتفعيله، أو سيتم تطبيقه عند إعادة تشغيل لاحقة.\n"
        f"البوت: @{info.get('username','')}", parse_mode="Markdown")


async def _admin_apply_add_channel(client: TgClient, chat_id: int, lang: str, line: str) -> None:
    parts = line.split(maxsplit=2)
    if len(parts) < 1 or not re.match(r"^-?\d+$", parts[0]):
        await client.send_message(chat_id, "❌ الصيغة: `<chat_id> <invite_link?> <title?>`")
        return
    cid = int(parts[0])
    link = parts[1] if len(parts) > 1 else None
    title = parts[2] if len(parts) > 2 else None
    await add_force_sub_channel(chat_id=cid, title=title, invite_link=link)
    await client.send_message(chat_id, f"✅ تمت الإضافة: `{cid}`", parse_mode="Markdown")


async def _admin_apply_user_role(client: TgClient, chat_id: int, lang: str, raw: str, op: str) -> None:
    if not raw.lstrip("-").isdigit():
        await client.send_message(chat_id, "❌ آيدي غير صالح.")
        return
    target = int(raw)
    if op == "makevip":
        await set_vip(target, True, days=30)
        msg = f"⭐ تمت ترقية {target} لـ VIP لمدة 30 يوم"
    elif op == "unvip":
        await set_vip(target, False)
        msg = f"❌ تم إلغاء VIP عن {target}"
    elif op == "makeadm":
        await set_admin(target, True)
        msg = f"👑 {target} أصبح أدمن"
    elif op == "unadm":
        await set_admin(target, False)
        msg = f"⛔ تم إزالة الأدمن عن {target}"
    elif op == "ban":
        # نظام الحظر معطّل - فقط رفض الملفات بدون حظر المستخدم
        msg = "ℹ️ نظام الحظر معطّل. الملفات المشبوهة تُرفض تلقائياً بدون حظر المستخدم."
    elif op == "unban":
        # لا يوجد حظر لإلغائه
        msg = "ℹ️ نظام الحظر معطّل أصلاً. لا يوجد مستخدمون محظورون."
    else:
        msg = "❓ عملية غير معروفة"
    await client.send_message(chat_id, msg)


# ===================== MCV helpers ===================== #

# Track files generated by MCV per user (for the "run / save / cancel"
# follow-up). The dict is intentionally in-memory: a generated file that
# the user hasn't acted on is throwaway state.
_mcv_drafts: dict[int, dict[str, Any]] = {}


async def _show_api_panel(client: TgClient, chat_id: int, message_id: int,
                          uid: int, lang: str) -> None:
    """Render the user's API panel — key, daily usage, docs link."""
    from .config import get_settings as _gs
    from .public_api import (
        FREE_AI_PER_DAY,
        FREE_HOSTING_PER_DAY,
        REFERRAL_BONUS_AI,
        VIP_AI_PER_DAY,
        VIP_HOSTING_PER_DAY,
        _ai_limit as _ai_limit_fn,
        _hosting_limit as _host_limit_fn,
    )
    from .repo import (
        count_referrals,
        get_api_usage,
        get_or_create_api_key,
        get_user,
    )

    u = await get_user(uid)
    if not u:
        await client.edit_message_text(
            chat_id, message_id,
            "⚠️ مش لاقي حسابك. اضغط /start الأول.",
            reply_markup=kb_back_main(lang),
        )
        return
    is_admin = await is_admin_uid(uid)
    ak = await get_or_create_api_key(uid)
    hosting_used = await get_api_usage(uid, "hosting")
    ai_used = await get_api_usage(uid, "ai")
    hosting_limit = _host_limit_fn(u, is_admin)
    ai_limit = await _ai_limit_fn(u, is_admin)
    refs = await count_referrals(uid)
    docs_url = _gs().api_docs_url

    if is_admin:
        plan = "👑 أدمن"
        h_label = "∞"
        a_label = "∞"
    elif u.is_vip:
        plan = "⭐ VIP"
        h_label = f"{hosting_used}/{hosting_limit}"
        a_label = f"{ai_used}/{ai_limit}"
    else:
        plan = "🆓 مجاني"
        h_label = f"{hosting_used}/{hosting_limit}"
        a_label = f"{ai_used}/{ai_limit}"

    text = (
        "🔴 <b>API — خدمات للمطورين</b>\n\n"
        "استخدم الخدمات بتاعتنا (الذكاء + استضافة البوتات) من أي تطبيق "
        "خارجي عبر REST API.\n\n"
        "🔑 <b>المفتاح بتاعك:</b>\n"
        f"<code>{ak.key}</code>\n"
        "<i>(اضغط مطوّلاً للنسخ)</i>\n\n"
        f"👤 <b>الخطة:</b> {plan}\n"
        f"👥 <b>الإحالات:</b> <code>{refs}</code> "
        f"(كل إحالة +{REFERRAL_BONUS_AI} طلب AI/يوم)\n\n"
        "📊 <b>استخدام اليوم:</b>\n"
        f"  🤖 الذكاء الاصطناعي: <code>{a_label}</code>\n"
        f"  📦 الاستضافة: <code>{h_label}</code>\n\n"
        "🌐 <b>قاعدة الـ API:</b>\n"
        f"<code>{_gs().public_base_url.rstrip('/')}/v1/</code>\n\n"
        f"💡 <b>الحدود الافتراضية:</b> مجاني = {FREE_HOSTING_PER_DAY} استضافة + "
        f"{FREE_AI_PER_DAY} AI يوميًا — VIP = {VIP_HOSTING_PER_DAY} + "
        f"{VIP_AI_PER_DAY} يوميًا.\n\n"
        "📚 اقرأ الدليل بالتفصيل من الزرار تحت 👇"
    )
    kb = inline_kb([
        [Btn(t(lang, "btn_api_docs"), url=docs_url, color="green")],
        [Btn(t(lang, "btn_api_regenerate"), callback_data="api_regen",
             color="red")],
        [Btn(t(lang, "btn_main"), callback_data="main", color="blue")],
    ])
    await client.edit_message_text(chat_id, message_id, text, reply_markup=kb)


async def _show_mcv_menu(client: TgClient, chat_id: int, message_id: int, lang: str) -> None:
    """Top-level MCV menu (chat / new bot / convert hint)."""
    text = (
        "🔴 <b>MCV — المساعد الذكي</b>\n\n"
        "أنا MCV، ساعدك:\n"
        "• 🤖 <b>اعملي بوت</b> — قولي بالكلام أي بوت عاوزه وأنا أبعتلك ملف <code>.py</code>، وتقولي <i>«شغّله»</i> أرفعه على المنصة.\n"
        "• 🪄 <b>المعالج التفاعلي</b> — يسألك سؤال سؤال (الفكرة → المميزات → التوكن).\n"
        "• 💬 <b>كلام عادي</b> — أي سؤال، شرح كود، اقتراحات.\n"
        "• ✏️ أعدّل بوت موجود (من <b>🤖 بوتاتي</b>).\n"
        "• 🔄 لو رفعت ملف PHP أو Node بحوّله لـ Python.\n\n"
        "اختار من تحت:"
    )
    kb = inline_kb([
        [Btn("🤖 اعملي بوت بالكلام", callback_data="mcv_make_bot", color="red")],
        [Btn("🪄 المعالج التفاعلي", callback_data="mcv_new", color="red"),
         Btn("📦 قوالب جاهزة", callback_data="mcv_templates", color="blue")],
        [Btn(t(lang, "btn_mcv_chat"), callback_data="mcv_chat", color="green")],
        [Btn(t(lang, "btn_main"), callback_data="main", color="blue")],
    ])
    await client.edit_message_text(chat_id, message_id, text, reply_markup=kb)


async def _mcv_continue_chat(client: TgClient, chat_id: int, uid: int, lang: str,
                              text: str, pending: dict[str, Any]) -> None:
    """Run one round-trip of the MCV chat conversation.

    Uses the shared Firebase-backed memory layer in :mod:`mcv_memory` so MCV
    carries context across sessions and can answer admin questions about any
    user. Also detects two admin intents:

      * "كلّمني عن المستخدم 12345" / "tell me about user 12345" → MCV is fed
        a structured profile block and replies with an analysis.
      * "انشر يوميًا الساعة 09:00 …" → MCV stores a daily-broadcast schedule.
    """
    from .ai_assistant import chat as ai_chat
    from . import mcv_memory
    from .repo import get_user

    me = await get_user(uid)
    is_admin = bool(me and me.is_admin)

    # Pull the persistent recent-messages slice from Firebase. If it's empty
    # we fall back to the in-memory ``pending["history"]`` so existing
    # sessions keep working when Firebase isn't configured.
    persisted = await mcv_memory.get_recent_messages(uid, limit=20)
    history: list[dict[str, str]] = pending.get("history", []) or []
    if persisted:
        history = [
            {"role": m["role"], "content": m["content"]}
            for m in persisted if m.get("role") and m.get("content")
        ]

    # ---- detect "tell me about user <id>" intent (admin-only) ----
    extra_context: list[str] = []
    if is_admin:
        m = re.search(r"\b(\d{5,12})\b", text)
        keywords = ("user", "مستخدم", "اليوزر", "العضو", "info", "profile", "تقرير")
        if m and any(k.lower() in text.lower() for k in keywords):
            target_id = int(m.group(1))
            profile = await mcv_memory.profile_user(target_id)
            if profile:
                extra_context.append(
                    "ملف المستخدم المطلوب (JSON من النظام):\n"
                    + json.dumps(profile, ensure_ascii=False, default=str)[:3500]
                )
            else:
                extra_context.append(f"المستخدم {target_id} غير معروف للمنصة.")

        # ---- detect daily broadcast schedule intent (admin-only) ----
        sched = mcv_memory.parse_schedule_request(text)
        if sched is not None:
            key = await mcv_memory.create_schedule(created_by=uid, schedule=sched)
            extra_context.append(
                f"تم إنشاء جدولة يومية الساعة {sched['hour']:02d}:{sched['minute']:02d} "
                f"بالرسالة: {sched['message'][:120]}. id={key}"
            )

    # Build the system prompt: persona + dynamic context block + any
    # admin-only tool output for this turn.
    base_ctx = await mcv_memory.build_context_block(uid, is_admin=is_admin)
    system_prompt = MCV_SYSTEM_PROMPT_AR + "\n\n" + base_ctx
    if extra_context:
        system_prompt += "\n\n" + "\n\n".join(extra_context)

    thinking = await client.send_message(chat_id, "🤖 <i>MCV بيفكر…</i>")
    try:
        reply = await ai_chat(text, history=history, system=system_prompt)
    except MCVError as exc:
        await client.edit_message_text(chat_id, thinking["message_id"],
                                       f"❌ MCV مش رد دلوقتي: <code>{html.escape(str(exc), quote=False)}</code>",
                                       reply_markup=kb_back_main(lang))
        return
    # Append both turns to history so the next message has context.
    history.append({"role": "user", "content": text})
    history.append({"role": "assistant", "content": reply})
    # Keep history bounded so the prompt stays under control.
    pending["history"] = history[-10:]
    await set_pending(uid, pending)
    # Persist on the shared memory layer (Firebase) so other sessions /
    # admin look-ups can see the conversation.
    try:
        await mcv_memory.append_message(uid, "user", text)
        await mcv_memory.append_message(uid, "assistant", reply)
    except Exception:  # noqa: BLE001
        pass
    # The model may return code blocks; render them in <pre>.
    rendered = _format_mcv_reply(reply)
    try:
        await client.edit_message_text(chat_id, thinking["message_id"], rendered,
                                       reply_markup=kb_back_main(lang))
    except TelegramError:
        # Fallback if the message is too long: send a fresh one.
        await client.send_message(chat_id, rendered, reply_markup=kb_back_main(lang))


_RUN_PHRASES = (
    "شغله", "شغّله", "شغل البوت", "شغّل البوت", "اشغله", "اشغل",
    "شغل", "ابعته", "ابعت البوت", "ارفعه", "نزّله", "ابداء", "ابدأ",
    "run", "run it", "deploy", "launch", "start it", "go", "اعمله",
)


def _looks_like_run_request(text: str) -> bool:
    """Heuristic: does the user want to deploy the last draft?"""
    t = text.strip().lower()
    if not t or len(t) > 80:
        return False
    return any(p in t for p in _RUN_PHRASES)


async def _mcv_make_bot_turn(
    client: TgClient,
    chat_id: int,
    uid: int,
    lang: str,
    text: str,
    pending: dict[str, Any],
    u: Any,
) -> None:
    """One round in the free-form '🤖 اعملي بوت' conversation.

    * If the user looks like they want to deploy the previous draft
      (e.g. typed «شغّله»), trigger the same flow the inline-button
      "Run" callback uses.
    * Otherwise call the AI with the dedicated coder prompt + chat
      history. If the reply contains a Python code block, we treat
      it as a fresh draft → save to disk, send as a document, and
      attach Run/Save/Cancel buttons (the existing helper).
    * If there's no code block, we just render the prose reply.
    * Either way the pending state stays so the user can keep
      iterating ("ضيف زرار /stats", "خلي اللون أحمر", …).
    """
    from .ai_assistant import (
        MCV_CODER_PROMPT_AR, MCVError, chat as ai_chat,
        extract_code_block, looks_like_complete_bot, _embed_token_into_code,
    )
    from .security_scan import scan_text as _scan_text
    from .token_extract import extract_token as _extract_token

    history: list[dict[str, str]] = pending.get("history", []) or []

    # ---- shortcut: "شغّله" — deploy the existing draft ---- #
    if _looks_like_run_request(text) and uid in _mcv_drafts:
        # If a token is in the message, embed it before running.
        tok = _extract_token(text)
        if tok:
            try:
                p = Path(_mcv_drafts[uid]["path"])
                code_now = p.read_text(encoding="utf-8")
                p.write_text(_embed_token_into_code(code_now, tok), encoding="utf-8")
            except OSError as exc:
                logger.info("token embed failed: %s", exc)
        thinking = await client.send_message(
            chat_id, "⏳ <i>بشغّل البوت دلوقتي…</i>",
        )
        draft = _mcv_drafts.pop(uid)
        await _run_mcv_upload_new(
            client, chat_id, thinking["message_id"], u, lang,
            draft_path=draft["path"], name=draft["name"],
        )
        return

    # ---- explicit /token <value> ---- #
    if text.strip().startswith("/token") and uid in _mcv_drafts:
        tok = _extract_token(text)
        if not tok:
            await client.send_message(
                chat_id, "❌ ابعت التوكن كامل بعد <code>/token</code>.",
            )
            return
        try:
            p = Path(_mcv_drafts[uid]["path"])
            code_now = p.read_text(encoding="utf-8")
            p.write_text(_embed_token_into_code(code_now, tok), encoding="utf-8")
        except OSError as exc:
            await client.send_message(chat_id, f"❌ مش قادر أحدّث الملف: {exc}")
            return
        await client.send_message(
            chat_id,
            "🔑 <b>التوكن اتحط جوّا الكود.</b> اكتب «شغّله» وأنا أشغّله.",
        )
        return

    thinking = await client.send_message(
        chat_id, "🤖 <i>MCV بيفكر ويكتب الكود…</i>",
    )

    # Look back at the most-recent code block in history so the model
    # has the file it's iterating on, even after many edit-cycles.
    last_code = ""
    for turn in reversed(history):
        if turn.get("role") == "assistant":
            _, blk = extract_code_block(turn.get("content") or "", prefer_lang="python")
            if blk:
                last_code = blk
                break

    # We pass an augmented instruction so the coder knows whether to
    # build a *new* bot or *modify* the previous draft. The system
    # prompt does the rest.
    if last_code:
        user_instr = (
            "ده الكود الحالي للبوت اللي بنشتغل عليه:\n"
            f"```python\n{last_code[:14000]}\n```\n\n"
            f"طلب المستخدم الجديد:\n{text}\n\n"
            "ارجع JSON واحد فقط:\n"
            '{"name":"snake_case_name","code":"<full python file>"}'
        )
    else:
        user_instr = (
            "اعملي بوت تلجرام كامل بايثون حسب الطلب التالي. ارجع JSON واحد:\n"
            '{"name":"snake_case_name","code":"<full python file>"}\n\n'
            f"الطلب:\n{text}"
        )

    try:
        reply = await ai_chat(
            user_instr, history=history,
            system=MCV_CODER_PROMPT_AR, timeout=240.0, task="code",
        )
    except MCVError as exc:
        await client.edit_message_text(
            chat_id, thinking["message_id"],
            f"❌ <code>{html.escape(str(exc), quote=False)}</code>",
            reply_markup=kb_back_main(lang),
        )
        return

    # Save chat history so the conversation has memory.
    history.append({"role": "user", "content": text})
    history.append({"role": "assistant", "content": reply})
    pending["history"] = history[-12:]
    await set_pending(uid, pending)

    # Try to extract a JSON {name, code} first, then fall back to the
    # largest Python fenced block.
    code = ""
    name = "mcv_bot"
    from .ai_assistant import _extract_json_object as _xtj
    obj = _xtj(reply)
    if isinstance(obj, dict):
        code = str(obj.get("code") or "").strip()
        if obj.get("name"):
            name = re.sub(r"[^a-zA-Z0-9_]+", "_", str(obj["name"]))[:48] or "mcv_bot"
    if not code or len(code) < 200:
        _, blk = extract_code_block(reply, prefer_lang="python")
        if blk and len(blk) > len(code):
            code = blk

    # No code at all → it's a plain-text answer. Render it like chat.
    if not code or not looks_like_complete_bot(code):
        rendered = _format_mcv_reply(reply)
        try:
            await client.edit_message_text(
                chat_id, thinking["message_id"], rendered,
                reply_markup=kb_back_main(lang),
            )
        except TelegramError:
            await client.send_message(
                chat_id, rendered, reply_markup=kb_back_main(lang),
            )
        return

    # Re-run security scan on the AI output. Admins bypass.
    if not await is_admin_uid(uid):
        scan = _scan_text(code, "python")
        if not scan.safe:
            await client.edit_message_text(
                chat_id, thinking["message_id"],
                "❌ <b>الكود اللي طلع رفضه الفحص الأمني.</b>\n\n"
                f"{scan.summary()}",
                reply_markup=kb_back_main(lang),
            )
            return

    # Embed token if user already provided one in this conversation.
    saved_token: str | None = pending.get("token") or None
    if not saved_token:
        for t_msg in history:
            tok = _extract_token(t_msg.get("content") or "")
            if tok:
                saved_token = tok
                pending["token"] = tok
                await set_pending(uid, pending)
                break
    if saved_token:
        code = _embed_token_into_code(code, saved_token)

    file_name = name if name.endswith(".py") else f"{name}.py"
    await _present_mcv_generated_file(
        client, chat_id, uid, lang,
        file_name=file_name, code=code,
        message_id=thinking["message_id"],
        intent="new",
        token_already_embedded=bool(saved_token),
    )


def _format_mcv_reply(reply: str, *, max_len: int = 3500) -> str:
    """Wrap code blocks in <pre> and HTML-escape the rest. Truncate gently."""
    out: list[str] = []
    i = 0
    while True:
        match = re.search(r"```([a-zA-Z0-9+_-]*)\n?", reply[i:])
        if not match:
            out.append(html.escape(reply[i:], quote=False))
            break
        start = i + match.start()
        end_match = re.search(r"```", reply[start + len(match.group(0)):])
        if not end_match:
            out.append(html.escape(reply[i:], quote=False))
            break
        out.append(html.escape(reply[i:start], quote=False))
        block = reply[start + len(match.group(0)):start + len(match.group(0)) + end_match.start()]
        out.append("<pre>" + html.escape(block, quote=False) + "</pre>")
        i = start + len(match.group(0)) + end_match.end()
    body = "".join(out).strip()
    if len(body) > max_len:
        body = body[:max_len] + "\n…(تم تقصير الرد)"
    return body or "🤖 (لا رد)"


async def _mcv_generate_new_bot(client: TgClient, chat_id: int, uid: int, lang: str,
                                 description: str,
                                 *, embed_token: str | None = None) -> None:
    thinking = await client.send_message(chat_id,
        "🤖 <i>MCV بيكتب بوت كامل لك… ممكن ياخد ١٠ ثواني.</i>")
    try:
        file_name, code = await generate_bot(description, embed_token=embed_token)
    except MCVError as exc:
        await client.edit_message_text(chat_id, thinking["message_id"],
                                       f"❌ MCV ما عرفش يولّد الكود: <code>{html.escape(str(exc), quote=False)}</code>",
                                       reply_markup=kb_back_main(lang))
        return
    await _present_mcv_generated_file(client, chat_id, uid, lang,
                                       file_name=file_name, code=code,
                                       message_id=thinking["message_id"],
                                       intent="new",
                                       token_already_embedded=bool(embed_token))


async def _mcv_wizard_step(client: TgClient, chat_id: int, uid: int, lang: str,
                           text: str, pending: dict[str, Any]) -> None:
    """Multi-turn requirements-gathering wizard for new-bot creation.

    Stages:
      * ``purpose``      — first time: ask user "what does the bot do?"
      * ``feature_loop`` — keep asking "anything else?" until they say
                            خلاص / كده تمام / similar.
      * ``await_token``  — once features collected, prompt for the
                            Telegram BOT_TOKEN. We embed it directly
                            into the generated code so the user doesn't
                            have to paste it manually anywhere.
    """
    if is_exit_phrase(text):
        await pop_pending(uid)
        await client.send_message(chat_id,
            "👋 طيب يا معلم. لو احتجتني تاني اضغط 🔴 MCV.",
            reply_markup=kb_back_main(lang))
        return

    stage = pending.get("stage", "purpose")
    features: list[str] = list(pending.get("features") or [])

    # Stage 1 — capture the bot's overall idea.
    if stage == "purpose":
        if len(text) < 3:
            await client.send_message(chat_id,
                "🤔 وصف الفكرة قصير شوية — قولي بجملة كاملة بيعمل إيه.")
            return
        features.append(text)
        pending["features"] = features
        pending["purpose"] = text
        pending["stage"] = "feature_loop"
        await set_pending(uid, pending)
        # Friendly turn that prompts for the first feature.
        await client.send_message(
            chat_id,
            f"💡 <b>تمام، البوت هيكون:</b> «{html.escape(text, quote=False)}»\n\n"
            "دلوقتي قولي عاوز إيه من المميزات. مثلاً:\n"
            "• «قاعدة بيانات للمستخدمين»\n"
            "• «زر إحصائيات»\n"
            "• «إشعار للأدمن عند حدث معين»\n\n"
            "كل ميزة في رسالة لوحدها، ولما تخلص اكتب <b>خلاص</b> أو "
            "<b>كده تمام</b> ✨",
        )
        return

    # Stage 2 — looping for features. Done phrase ⇒ jump to token prompt.
    if stage == "feature_loop":
        if is_done_phrase(text):
            if len(features) <= 1:
                # We only have the original idea — that's fine, build it.
                pass
            pending["stage"] = "await_token"
            await set_pending(uid, pending)
            sample_feats = "\n".join(f"• {html.escape(f, quote=False)}"
                                       for f in features[1:5]) or "<i>بدون مميزات إضافية</i>"
            await client.send_message(
                chat_id,
                "✅ <b>تمام، خلاص!</b>\n\n"
                f"<b>فكرة:</b> {html.escape(features[0], quote=False)}\n"
                f"<b>المميزات:</b>\n{sample_feats}\n\n"
                "🔑 ابعتلي دلوقتي <b>توكن البوت</b> من @BotFather "
                "(اللي شكله <code>123456:ABC...</code>). هحطه أوتوماتيك "
                "جوه الكود وأشغلك البوت على طول.\n\n"
                "اكتب <b>خروج</b> للإلغاء.",
            )
            return

        # Treat the message as a new feature.
        features.append(text)
        pending["features"] = features
        await set_pending(uid, pending)
        ack = await wizard_acknowledge(text, len(features) - 1)
        await client.send_message(chat_id, html.escape(ack, quote=False))
        return

    # Stage 3 — user pastes the Telegram bot token. We validate it,
    # embed it into the freshly-generated code, and onboard the bot.
    if stage == "await_token":
        token_candidate = text.strip()
        info = await validate_token(token_candidate)
        if not info:
            await client.send_message(
                chat_id,
                "❌ التوكن ده مش شغّال. تأكد إنك ناسخه من @BotFather صح "
                "أو اكتب <b>خروج</b> للإلغاء.",
            )
            return
        bot_username = info.get("username", "")
        # Compose a richer description we can feed into ``generate_bot``.
        description = "\n".join([
            f"الفكرة الأساسية: {features[0]}",
            *(f"ميزة: {f}" for f in features[1:]),
        ])
        await pop_pending(uid)  # clear before long AI call
        # Stage the generated file & onboard immediately using the helper
        # that already knows how to host an MCV-built draft.
        await _mcv_build_and_host(
            client, chat_id, uid, lang,
            description=description,
            token=token_candidate,
            bot_username=bot_username,
        )
        return

    # Unknown stage — reset to purpose.
    pending["stage"] = "purpose"
    await set_pending(uid, pending)
    await client.send_message(chat_id, "🔄 يلا نبدأ من الأول — قولي البوت يعمل إيه؟")


async def _mcv_build_and_host(
    client: TgClient,
    chat_id: int,
    uid: int,
    lang: str,
    *,
    description: str,
    token: str,
    bot_username: str,
) -> None:
    """Generate the bot file, send it to the user, and ask for run consent.

    New flow (May 2026):

    1. MCV writes the code (with token embedded) and saves it to disk.
    2. We send the file to the user as a Telegram document so they can
       inspect / download / share it before anything runs.
    3. We ask "تشغّله ولا لا؟" via inline buttons. The actual hosting +
       polling only happens after the user clicks ✅ شغّل البوت.
    4. If the user says no, the file stays on disk under their bots dir
       but no HostedBot row is created and no process is spawned.

    The pending state ``kind="mcv_await_run"`` carries everything we
    need to resume from the callback.
    """
    thinking = await client.send_message(
        chat_id,
        "🤖 <i>MCV بيكتب البوت ويحط التوكن… استنى ثانية.</i>",
    )
    try:
        file_name, code = await generate_bot(description, embed_token=token)
    except MCVError as exc:
        await client.edit_message_text(
            chat_id, thinking["message_id"],
            f"❌ MCV ما عرفش يولّد الكود: <code>{html.escape(str(exc), quote=False)}</code>",
            reply_markup=kb_back_main(lang),
        )
        return

    # Re-scan to make sure the AI didn't slip anything dangerous in.
    from .security_scan import scan_text as _scan_text

    scan = _scan_text(code, "python")
    if not scan.safe:
        await client.edit_message_text(
            chat_id, thinking["message_id"],
            "❌ <b>الكود اللي MCV عمله رفضه الفحص الأمني.</b>\n\n"
            f"{scan.summary()}",
            reply_markup=kb_back_main(lang),
        )
        return

    # Persist into the user's regular bots tree so the existing runner
    # can supervise it like any other upload if the user opts in.
    bots_root = Path(get_settings().bots_path) / str(uid)
    bots_root.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^\w\-_.]", "_", file_name)
    sub_dir = bots_root / f"{uuid.uuid4().hex[:8]}_{Path(safe_name).stem}"
    sub_dir.mkdir(parents=True, exist_ok=True)
    file_path = sub_dir / safe_name
    file_path.write_text(code, encoding="utf-8")

    # Friendly summary stats so the user can sanity-check the AI's work.
    num_handlers = code.count("@bot.message_handler") + code.count(
        "@bot.callback_query_handler",
    )
    num_lines = len(code.splitlines())
    has_polling = "infinity_polling" in code
    badge_polling = "✅" if has_polling else "⚠️"

    caption = (
        "📦 <b>البوت جاهز للتجربة!</b>\n\n"
        f"📄 الاسم: <code>{html.escape(safe_name, quote=False)}</code>\n"
        f"🧮 السطور: <code>{num_lines}</code>\n"
        f"🧩 الـ Handlers: <code>{num_handlers}</code>\n"
        f"🔄 Polling: {badge_polling}\n"
        f"🤖 البوت: <b>@{html.escape(bot_username, quote=False)}</b>"
    )

    # Send the file itself so the user can read it.
    try:
        await client.send_document(chat_id, str(file_path), caption=caption)
    except Exception as exc:  # noqa: BLE001
        logger.warning("send_document for wizard bot failed: %s", exc)
        await client.edit_message_text(
            chat_id, thinking["message_id"],
            "⚠️ البوت اتعمل بس Telegram رفض إرسال الملف. "
            "حاول تاني أو راجع اللوج.",
            reply_markup=kb_back_main(lang),
        )
        return

    # Update the original "thinking..." message into the confirm prompt.
    confirm_kb = inline_kb([
        [Btn(text="✅ شغّل البوت", callback_data="mcv_run_yes", color="green")],
        [Btn(text="✏️ عدّل قبل التشغيل", callback_data="mcv_run_edit", color="blue")],
        [Btn(text="❌ سيبه من غير تشغيل", callback_data="mcv_run_no", color="red")],
    ])
    await client.edit_message_text(
        chat_id, thinking["message_id"],
        "🤔 <b>تشغّله دلوقتي؟</b>\n\n"
        "• <b>✅ شغّل البوت</b> — نسجّل البوت ونشغّله على طول.\n"
        "• <b>✏️ عدّل قبل التشغيل</b> — رد بأي تعديل وأنا أعدّله بالـ AI.\n"
        "• <b>❌ سيبه</b> — الملف بيفضل محفوظ بس مش بيشتغل.",
        reply_markup=confirm_kb,
    )

    # Store everything we need to resume from the callback.
    await set_pending(uid, {
        "kind": "mcv_await_run",
        "file_path": str(file_path),
        "file_name": safe_name,
        "token": token,
        "bot_username": bot_username,
        "description": description,
    })
    await audit(uid, "mcv_wizard_bot_drafted",
                f"file={safe_name} @={bot_username} lines={num_lines} handlers={num_handlers}")


async def _mcv_host_drafted_bot(
    client: TgClient,
    chat_id: int,
    uid: int,
    lang: str,
    *,
    file_path: str,
    file_name: str,
    token: str,
    bot_username: str,
    description: str,
) -> None:
    """Onboard a wizard-drafted bot file and start it (polling).

    Called after the user confirms via the inline buttons added in
    :func:`_mcv_build_and_host`. The file is already on disk; we just
    add the HostedBot row, install deps, start the supervisor, and
    report status.
    """
    thinking = await client.send_message(
        chat_id, "📦 بنصّب مكتبات البوت…",
    )
    try:
        await install_dependencies(language="python", file_path=file_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("dep install for wizard bot failed: %s", exc)

    tk_hash = token_hash(token)
    b = HostedBot(
        owner_id=uid,
        name=file_name,
        language="python",
        file_path=file_path,
        token_encrypted=encrypt_token(token),
        token_hash=tk_hash,
        bot_username=bot_username,
        tier=1,
        webhook_url=None,
        use_webhook=False,
    )
    try:
        b = await add_hosted_bot(b)
    except ValueError:
        await client.edit_message_text(
            chat_id, thinking["message_id"],
            "❌ التوكن ده مرفوع بالفعل ببوت تاني. مينفعش نشغّل نفس التوكن "
            "مرتين على نفس الاستضافة.",
            reply_markup=kb_back_main(lang),
        )
        return

    runner = get_runner()
    result = await runner.start_supervised(
        bot_id=b.id, language="python", file_path=file_path,
        token=token, port=None, webhook_url=None,
    )
    from .repo import update_bot_status

    if result.error:
        await update_bot_status(b.id, status="crashed", last_error=result.error)
        await client.edit_message_text(
            chat_id, thinking["message_id"],
            f"⚠️ البوت اتسجّل، بس بدأ بصراخ:\n<code>{html.escape(result.error, quote=False)}</code>\n\n"
            "روح تبويب 🤖 بوتاتي عشان تشوف اللوج وتعدّل.",
            reply_markup=kb_back_main(lang),
        )
        return
    await update_bot_status(b.id, status="running", pid=result.pid,
                            last_started_at=dt.datetime.utcnow(),
                            restart_count_inc=True)
    # Drop any old webhook so polling works cleanly.
    try:
        from .telegram_api import TgClient as Cli
        async with Cli(token, timeout=15.0) as tcli:
            await tcli.delete_webhook(drop_pending_updates=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("delete_webhook for wizard bot failed: %s", exc)

    await client.edit_message_text(
        chat_id, thinking["message_id"],
        "🎉 <b>البوت شغّال!</b>\n\n"
        f"🤖 <b>@{html.escape(bot_username, quote=False)}</b>\n"
        f"📄 ملف: <code>{html.escape(file_name, quote=False)}</code>\n"
        f"🔌 وضع: ⚡ Polling\n\n"
        "ادخل عليه دلوقتي وابعتله <code>/start</code> 👌\n\n"
        "تقدر تعدّل عليه أو تشوف اللوج من تبويب 🤖 بوتاتي.",
        reply_markup=kb_back_main(lang),
    )
    await audit(uid, "mcv_wizard_bot_created",
                f"id={b.id} @={bot_username} features={len(description.splitlines())}")


async def _mcv_edit_drafted_file(
    client: TgClient,
    chat_id: int,
    uid: int,
    lang: str,
    *,
    edit_request: str,
    pending: dict[str, Any],
) -> None:
    """Apply an AI edit to a drafted (but not yet hosted) wizard file.

    The user clicked ✏️ on the run-confirm prompt, then typed an
    instruction. We feed (current file content + instruction) to
    :func:`modify_bot_code`, overwrite the file, re-send it, and ask for
    the run confirmation again.
    """
    if is_exit_phrase(edit_request):
        await pop_pending(uid)
        await client.send_message(
            chat_id,
            "👋 طيب يا معلم — سيبت التعديل. تقدر ترجع تشغّل البوت من تبويب "
            "🤖 بوتاتي بعد ما ترفعه يدوياً.",
            reply_markup=kb_back_main(lang),
        )
        return

    file_path = str(pending.get("file_path") or "")
    file_name = str(pending.get("file_name") or "bot.py")
    token = str(pending.get("token") or "")
    bot_username = str(pending.get("bot_username") or "")
    description = str(pending.get("description") or "")

    if not file_path or not Path(file_path).exists():
        await pop_pending(uid)
        await client.send_message(
            chat_id, "❌ ما لقيتش ملف الـ draft. ابدأ من جديد من 🔴 MCV.",
            reply_markup=kb_back_main(lang),
        )
        return

    thinking = await client.send_message(
        chat_id, "✏️ <i>MCV بيعدّل الكود حسب طلبك… استنى ثانية.</i>",
    )
    try:
        current_code = Path(file_path).read_text(encoding="utf-8")
    except OSError as exc:
        await client.edit_message_text(
            chat_id, thinking["message_id"],
            f"❌ ما عرفتش أقرا الملف: <code>{html.escape(str(exc), quote=False)}</code>",
            reply_markup=kb_back_main(lang),
        )
        return

    try:
        new_code = await modify_bot_code(
            current_code, instructions=edit_request, language="python",
        )
    except MCVError as exc:
        await client.edit_message_text(
            chat_id, thinking["message_id"],
            f"❌ MCV ما عرفش يعدّل الكود: <code>{html.escape(str(exc), quote=False)}</code>",
            reply_markup=kb_back_main(lang),
        )
        return

    # Re-embed the token in case the edit lost it.
    from .ai_assistant import _embed_token_into_code
    new_code = _embed_token_into_code(new_code, token)

    # Re-run the security scan on the edited code too.
    from .security_scan import scan_text as _scan_text
    scan = _scan_text(new_code, "python")
    if not scan.safe:
        await client.edit_message_text(
            chat_id, thinking["message_id"],
            "❌ <b>التعديل اللي عمله MCV رفضه الفحص الأمني.</b>\n\n"
            f"{scan.summary()}",
            reply_markup=kb_back_main(lang),
        )
        return

    Path(file_path).write_text(new_code, encoding="utf-8")

    num_handlers = new_code.count("@bot.message_handler") + new_code.count(
        "@bot.callback_query_handler",
    )
    num_lines = len(new_code.splitlines())
    has_polling = "infinity_polling" in new_code
    badge_polling = "✅" if has_polling else "⚠️"

    caption = (
        "📝 <b>الكود اتعدّل!</b>\n\n"
        f"📄 الاسم: <code>{html.escape(file_name, quote=False)}</code>\n"
        f"🧮 السطور: <code>{num_lines}</code>\n"
        f"🧩 الـ Handlers: <code>{num_handlers}</code>\n"
        f"🔄 Polling: {badge_polling}"
    )
    try:
        await client.send_document(chat_id, file_path, caption=caption)
    except Exception as exc:  # noqa: BLE001
        logger.warning("send_document for edited bot failed: %s", exc)

    confirm_kb = inline_kb([
        [Btn(text="✅ شغّل البوت", callback_data="mcv_run_yes", color="green")],
        [Btn(text="✏️ عدّل تاني", callback_data="mcv_run_edit", color="blue")],
        [Btn(text="❌ سيبه", callback_data="mcv_run_no", color="red")],
    ])
    await client.edit_message_text(
        chat_id, thinking["message_id"],
        "🤔 <b>تشغّله دلوقتي؟</b>\n\n"
        "اختار من تحت ايه اللي تحبه:",
        reply_markup=confirm_kb,
    )
    # Refresh pending state — keep the same payload but reset the stage
    # so plain text isn't treated as another edit prompt.
    pending["stage"] = "await_run"
    pending["description"] = description
    pending["bot_username"] = bot_username
    await set_pending(uid, pending)


async def _mcv_edit_existing_bot(client: TgClient, chat_id: int, uid: int, lang: str,
                                  *, bot_id: int, instructions: str) -> None:
    b = await get_bot(bot_id)
    if not b or (b.owner_id != uid and not await is_admin_uid(uid)):
        await client.send_message(chat_id, "❌ البوت ده مش ملكك أو محذوف.")
        return
    try:
        source = Path(b.file_path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        await client.send_message(chat_id, f"❌ ما عرفتش أقرا الملف: {exc}")
        return
    thinking = await client.send_message(chat_id,
        f"✏️ <i>MCV بيعدّل {html.escape(b.name, quote=False)}…</i>")
    try:
        new_code = await modify_bot_code(source, instructions=instructions, language=b.language)
    except MCVError as exc:
        await client.edit_message_text(chat_id, thinking["message_id"],
                                       f"❌ MCV ما عرفش يعدّل: <code>{html.escape(str(exc), quote=False)}</code>",
                                       reply_markup=kb_back_main(lang))
        return
    # Use the same file name as the original (we want to overwrite on "run").
    await _present_mcv_generated_file(
        client, chat_id, uid, lang,
        file_name=b.name, code=new_code,
        message_id=thinking["message_id"],
        intent="edit", target_bot_id=bot_id,
    )


async def _present_mcv_generated_file(client: TgClient, chat_id: int, uid: int, lang: str,
                                       *, file_name: str, code: str,
                                       message_id: int,
                                       intent: str = "new",
                                       target_bot_id: int | None = None,
                                       token_already_embedded: bool = False) -> None:
    """Save the AI-generated code to a draft file, send it to the user,
    and offer Run / Save-only / Cancel buttons."""
    # Stage the draft on disk in a per-user scratch dir.
    drafts_dir = Path(get_settings().data_path) / "mcv_drafts" / str(uid)
    drafts_dir.mkdir(parents=True, exist_ok=True)
    # Always end up with .py — MCV currently only generates Python.
    base = re.sub(r"[^a-zA-Z0-9_.-]", "_", file_name).strip("._") or "mcv_bot"
    if not base.endswith(".py"):
        base += ".py"
    stamp = uuid.uuid4().hex[:8]
    draft_path = drafts_dir / f"{stamp}_{base}"
    draft_path.write_text(code, encoding="utf-8")

    # Stash metadata for the follow-up Run/Cancel callback.
    _mcv_drafts[uid] = {
        "path": str(draft_path),
        "name": base,
        "intent": intent,
        "target_bot_id": target_bot_id,
    }

    # Send the file. Then update the original "thinking" message with a
    # short confirmation + action buttons.
    try:
        await client.send_document(chat_id, str(draft_path), caption=f"📄 <b>{html.escape(base, quote=False)}</b>")
    except TelegramError as exc:
        logger.warning("send_document for MCV draft failed: %s", exc)

    kb = inline_kb([
        [Btn(t(lang, "btn_run_file"), callback_data="mcvrun_run", color="green"),
         Btn(t(lang, "btn_save_only"), callback_data="mcvrun_save", color="blue")],
        [Btn(t(lang, "btn_cancel"), callback_data="mcvrun_cancel", color="red")],
    ])
    body = (
        "✅ <b>MCV جهّز الملف.</b>\n\n"
        f"📄 {html.escape(base, quote=False)}\n\n"
        + ("هتعدّل البوت الموجود وتعيد تشغيله؟ ولا تحمّل الملف بس؟"
           if intent == "edit"
           else "تحب أرفعه وأشغّله على المنصة، ولا تحمّله بس وتشتغل عليه إنت؟")
    )
    try:
        await client.edit_message_text(chat_id, message_id, body, reply_markup=kb)
    except TelegramError:
        await client.send_message(chat_id, body, reply_markup=kb)


async def _handle_mcv_generated(client: TgClient, cb: dict, u, lang: str, action: str) -> None:
    msg = cb.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")
    msg_id = msg.get("message_id")
    uid = int(cb["from"]["id"])

    async def ack(text: str | None = None, alert: bool = False) -> None:
        with contextlib.suppress(Exception):
            await client.answer_callback_query(cb["id"], text=text, show_alert=alert)

    draft = _mcv_drafts.pop(uid, None)
    if not draft:
        await ack("انتهت الجلسة", alert=True)
        return

    if action == "cancel":
        with contextlib.suppress(Exception):
            os.remove(draft["path"])
        await ack("تم الإلغاء")
        await client.edit_message_text(chat_id, msg_id, "❌ تم إلغاء الملف.",
                                       reply_markup=kb_back_main(lang))
        return

    if action == "save":
        await ack("✅ تم الحفظ")
        await client.edit_message_text(chat_id, msg_id,
            "💾 <b>اتحفظ.</b> الملف فوق فوق، حمّله من تلجرام.",
            reply_markup=kb_back_main(lang))
        return

    if action == "run":
        intent = draft.get("intent", "new")
        await ack("⏳ بشغّل…")
        if intent == "edit" and draft.get("target_bot_id"):
            await _run_mcv_edit_apply(client, chat_id, msg_id, u, lang,
                                       bot_id=int(draft["target_bot_id"]),
                                       new_code_path=draft["path"])
        else:
            await _run_mcv_upload_new(client, chat_id, msg_id, u, lang,
                                       draft_path=draft["path"], name=draft["name"])
        return


async def _run_mcv_edit_apply(client: TgClient, chat_id: int, message_id: int, u,
                               lang: str, *, bot_id: int, new_code_path: str) -> None:
    """Overwrite a hosted bot's file with the AI-edited version and restart."""
    b = await get_bot(bot_id)
    if not b or (b.owner_id != u.user_id and not await is_admin_uid(u.user_id)):
        await client.send_message(chat_id, "❌ البوت ده مش ملكك أو محذوف.")
        return
    # Security re-scan the modified file before saving — admins skip the
    # check to avoid blocking on AI false positives for their own bots.
    if not await is_admin_uid(u.user_id):
        from .security_scan import scan_file as _scan_file

        scan = _scan_file(new_code_path, b.language)
        if not scan.safe:
            await client.edit_message_text(
                chat_id, message_id,
                "❌ <b>MCV عدّل الكود لكن الفحص الأمني رفضه.</b>\n\n"
                f"{scan.summary()}",
                reply_markup=kb_back_main(lang),
            )
            return
    try:
        new_code = Path(new_code_path).read_text(encoding="utf-8", errors="replace")
        Path(b.file_path).write_text(new_code, encoding="utf-8")
    except OSError as exc:
        await client.send_message(chat_id, f"❌ ما عرفتش أحفظ الملف: {exc}")
        return
    # Re-install deps in case the AI introduced new imports.
    await client.edit_message_text(chat_id, message_id,
        "📦 بنصّب أي مكتبات جديدة وأعيد التشغيل…")
    try:
        await install_dependencies(language=b.language, file_path=b.file_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("dep install after MCV edit failed: %s", exc)
    # Restart the supervised process.
    from .repo import update_bot_status
    from .runner import get_runner
    from .security import decrypt_token

    runner = get_runner()
    await runner.stop(b.id)
    await asyncio.sleep(0.4)
    token = decrypt_token(b.token_encrypted)
    used = {hb.port for hb in await list_user_bots(b.owner_id) if hb.port}
    port = b.port or (allocate_port(used) if b.use_webhook else None)
    result = await runner.start_supervised(
        bot_id=b.id, language=b.language, file_path=b.file_path,
        token=token, port=port, webhook_url=b.webhook_url,
    )
    if result.error:
        await update_bot_status(b.id, status="crashed", last_error=result.error)
        await client.edit_message_text(chat_id, message_id,
            f"💥 البوت اتعدّل لكن قام يصرخ:\n<code>{html.escape(result.error, quote=False)}</code>",
            reply_markup=kb_back_main(lang))
        return
    await update_bot_status(b.id, status="running", pid=result.pid,
                            last_started_at=dt.datetime.utcnow(), restart_count_inc=True)
    with contextlib.suppress(Exception):
        os.remove(new_code_path)
    await client.edit_message_text(chat_id, message_id,
        f"✅ تم تطبيق التعديل وإعادة تشغيل البوت <b>{html.escape(b.name, quote=False)}</b>.",
        reply_markup=kb_back_main(lang))
    await audit(u.user_id, "mcv_edit_bot", f"id={b.id}")


async def _run_mcv_upload_new(client: TgClient, chat_id: int, message_id: int, u,
                               lang: str, *, draft_path: str, name: str) -> None:
    """Take an MCV-generated draft and onboard it as a new hosted bot.

    The user still has to provide their own bot token (we never ship a
    real token from the AI). We prompt for one and finish the upload
    flow from the resulting pending state.
    """
    # We don't yet know the user's bot token — ask them for it.
    await set_pending(u.user_id, {
        "kind": "mcv_new_bot_await_token",
        "draft_path": draft_path,
        "name": name,
    })
    await client.edit_message_text(chat_id, message_id,
        "🔑 <b>طلب توكن البوت</b>\n\n"
        "MCV جهز ملف البوت. ابعتلي دلوقتي <b>توكن البوت</b> اللي عاوز "
        "تشغّله بيه (هتاخده من @BotFather).\n\n"
        "ابعت <code>/cancel</code> لإلغاء.",
        reply_markup=kb_back_main(lang),
    )


async def _apply_bot_token_change(client: TgClient, chat_id: int, uid: int, lang: str,
                                    *, bot_id: int, new_token: str) -> None:
    """Validate ``new_token``, rewrite the token in the file + DB, restart."""
    from .repo import update_bot_token
    from .runner import get_runner
    from .security import decrypt_token

    b = await get_bot(bot_id)
    if not b or (b.owner_id != uid and not await is_admin_uid(uid)):
        await client.send_message(chat_id, "❌ البوت ده مش ملكك أو محذوف.")
        return
    info = await validate_token(new_token)
    if not info:
        await client.send_message(chat_id, "❌ التوكن غير صالح. ابعت /cancel للخروج أو حاول تاني.")
        await set_pending(uid, {"kind": "change_bot_token", "bot_id": bot_id})
        return
    new_username = info.get("username", "")
    # Replace the old token inside the bot's source file (if it appears literally).
    try:
        old_token = decrypt_token(b.token_encrypted)
    except Exception:  # noqa: BLE001
        old_token = ""
    try:
        src = Path(b.file_path).read_text(encoding="utf-8", errors="replace")
        if old_token and old_token in src:
            Path(b.file_path).write_text(src.replace(old_token, new_token), encoding="utf-8")
    except OSError as exc:
        logger.warning("could not patch token in %s: %s", b.file_path, exc)
    # Update DB.
    new_hash = token_hash(new_token)
    try:
        await update_bot_token(b.id, encrypted=encrypt_token(new_token),
                               token_hash=new_hash, bot_username=new_username)
    except ValueError:
        await client.send_message(chat_id,
            "❌ التوكن ده شغال على بوت تاني عندنا. مينفعش نستضيف نفس التوكن مرتين.")
        return
    # Restart the process so the bot picks up the new token.
    runner = get_runner()
    await runner.stop(b.id)
    await asyncio.sleep(0.3)
    used = {hb.port for hb in await list_user_bots(b.owner_id) if hb.port}
    port = b.port or (allocate_port(used) if b.use_webhook else None)
    result = await runner.start_supervised(
        bot_id=b.id, language=b.language, file_path=b.file_path,
        token=new_token, port=port, webhook_url=b.webhook_url,
    )
    from .repo import update_bot_status

    if result.error:
        await update_bot_status(b.id, status="crashed", last_error=result.error)
        await client.send_message(chat_id,
            f"⚠️ التوكن اتغير لكن التشغيل فشل:\n<code>{html.escape(result.error, quote=False)}</code>")
        return
    await update_bot_status(b.id, status="running", pid=result.pid,
                            last_started_at=dt.datetime.utcnow(), restart_count_inc=True)
    # Re-set the Telegram webhook for the new token if needed.
    if b.use_webhook and b.webhook_url:
        try:
            from .telegram_api import TgClient as Cli

            new_url = b.webhook_url.replace(b.token_hash, new_hash) \
                if b.token_hash and new_hash else b.webhook_url
            async with Cli(new_token, timeout=15.0) as tcli:
                await tcli.set_webhook(url=new_url,
                                       secret_token=get_settings().webhook_secret,
                                       drop_pending_updates=True)
        except Exception as exc:  # noqa: BLE001
            logger.warning("set_webhook on token change failed: %s", exc)
    await client.send_message(chat_id,
        f"✅ <b>التوكن اتغير.</b>\n\n"
        f"🤖 يوزر جديد: @{html.escape(new_username, quote=False)}\n"
        f"📄 ملف: <code>{html.escape(b.name, quote=False)}</code>")
    await audit(uid, "change_bot_token", f"id={b.id} new=@{new_username}")


async def _show_user_full_info(client: TgClient, chat_id: int, u, lang: str) -> None:
    """عرض كل معلومات المستخدم للأدمن."""
    from .repo import list_user_bots, count_referrals, get_setting
    from .db import get_session_factory, StorePurchase, ApprovalRequest
    from sqlalchemy import select, func
    from .runner import get_runner

    # جمع كل المعلومات
    bots = await list_user_bots(u.user_id) if u.user_id else []
    referrals = await count_referrals(u.user_id) if u.user_id else 0
    runner = get_runner()
    running_bots = sum(1 for b in bots if b.id and runner.is_running(b.id))

    # إحصائيات المشتريات من المتجر
    purchases_count = 0
    total_spent = 0
    pending_approvals = 0
    try:
        async with get_session_factory()() as s:
            pc = (await s.execute(
                select(func.count(StorePurchase.id)).where(StorePurchase.user_id == u.user_id)
            )).scalar() or 0
            purchases_count = pc
            ts = (await s.execute(
                select(func.sum(StorePurchase.price_paid)).where(StorePurchase.user_id == u.user_id)
            )).scalar() or 0
            total_spent = ts
            pa = (await s.execute(
                select(func.count(ApprovalRequest.id)).where(
                    ApprovalRequest.user_id == u.user_id,
                    ApprovalRequest.status == "pending",
                )
            )).scalar() or 0
            pending_approvals = pa
    except Exception as exc:
        logger.warning("user info stats failed: %s", exc)

    # تنسيق التواريخ
    join_date = u.join_date.strftime("%Y-%m-%d %H:%M") if u.join_date else "—"
    last_seen = u.last_seen.strftime("%Y-%m-%d %H:%M") if u.last_seen else "—"
    vip_expiry = u.vip_expiry.strftime("%Y-%m-%d %H:%M") if u.vip_expiry else "—"
    contact_shared = u.contact_shared_at.strftime("%Y-%m-%d %H:%M") if u.contact_shared_at else "—"

    # أيقونات الحالة
    admin_badge = "👑 أدمن" if u.is_admin else ""
    vip_badge = "⭐ VIP" if u.is_vip else ""
    banned_badge = "🚫 محظور" if u.is_banned else "✅ نشط"

    text = (
        f"👤 <b>معلومات المستخدم</b>\n\n"
        f"🆔 <b>المعرف:</b> <code>{u.user_id}</code>\n"
        f"📝 <b>الاسم:</b> {html.escape(u.first_name or '—', quote=False)} {html.escape(u.last_name or '', quote=False)}\n"
        f"👤 <b>اليوزرنام:</b> @{html.escape(u.username or '—', quote=False)}\n\n"
        f"📊 <b>الإحصائيات:</b>\n"
        f"• 💰 النقاط: <b>{u.points or 0}</b>\n"
        f"• 🤖 إجمالي البوتات: <b>{len(bots)}</b>\n"
        f"• 🟢 بوتات نشطة: <b>{running_bots}</b>\n"
        f"• 👥 الإحالات: <b>{referrals}</b>\n"
        f"• 🛒 مشتريات المتجر: <b>{purchases_count}</b>\n"
        f"• 💸 إجمالي الإنفاق: <b>{total_spent}</b> نقطة\n"
        f"• 📋 طلبات موافقة معلقة: <b>{pending_approvals}</b>\n\n"
        f"📋 <b>الحالة:</b>\n"
        f"• الحساب: {banned_badge} {admin_badge} {vip_badge}\n"
        f"• اللغة: {u.language or 'ar'}\n"
        f"• محاولات مشبوهة: <b>{u.suspicious_attempts or 0}</b>\n"
    )
    if u.is_vip:
        text += f"• انتهاء VIP: {vip_expiry}\n"
    text += (
        f"\n📅 <b>التواريخ:</b>\n"
        f"• تاريخ التسجيل: <code>{join_date}</code>\n"
        f"• آخر ظهور: <code>{last_seen}</code>\n"
    )
    if u.contact_phone:
        text += (
            f"\n📞 <b>بيانات الاتصال:</b>\n"
            f"• الهاتف: <code>{html.escape(u.contact_phone, quote=False)}</code>\n"
            f"• مشاركة الهاتف: <code>{contact_shared}</code>\n"
        )
    if u.referral_code:
        text += f"\n🎁 <b>كود الإحالة:</b> <code>{u.referral_code}</code>\n"

    # أزرار الإجراءات السريعة
    rows = [
        [Btn("💎 إضافة نقاط", callback_data=f"adm_addpts_{u.user_id}", color="green"),
         Btn("🤖 بوتاته", callback_data=f"adm_userbots_{u.user_id}", color="blue")],
    ]
    if u.is_vip:
        rows.append([Btn("❌ إزالة VIP", callback_data=f"adm_role_vipoff_{u.user_id}", color="red")])
    else:
        rows.append([Btn("⭐ جعل VIP", callback_data=f"adm_role_vipon_{u.user_id}", color="green")])
    if u.is_admin:
        rows.append([Btn("⛔ إزالة أدمن", callback_data=f"adm_role_admoff_{u.user_id}", color="red")])
    else:
        rows.append([Btn("👑 جعل أدمن", callback_data=f"adm_role_admon_{u.user_id}", color="green")])
    rows.append([Btn(t(lang, "btn_back"), callback_data="admin", color="blue")])

    await client.send_message(chat_id, text,
        reply_markup=inline_kb(rows), parse_mode="HTML")


async def _create_bot_from_template(client: TgClient, chat_id: int, msg_id: int,
                                      uid: int, lang: str, template_id: str) -> None:
    """عرض بيانات قالب GitHub وبدء معالج الإنشاء (توكن ← أدمن ← اختياري)."""
    from .bot_templates import get_template
    tpl = get_template(template_id)
    if not tpl:
        await client.edit_message_text(chat_id, msg_id,
            "❌ القالب غير متوفر حالياً — جرّب تحديث القوائم.")
        return
    meta = tpl.get("meta") or {}
    req_rows = "\n".join(
        f"• <b>{e.get('name')}</b> — {e.get('desc', '')}"
        for e in tpl.get("required_env", []) if e.get("name")
    ) or "• توكن البوت"
    opt_rows = "\n".join(
        f"• <code>{e.get('name')}</code> — {e.get('desc', '')}"
        for e in tpl.get("optional_env", []) if e.get("name")
    ) or "لا يوجد ✨"
    tested = meta.get("tested", "")
    if tested == "pass":
        badge = "✅ <b>مختبر داخل بيئة TikZoom — يعمل مباشرة</b>"
    else:
        note = meta.get("tested_note", "")
        badge = f"⚙️ <b>مختبر — يحتاج إعدادات قبل التشغيل الكامل:</b>\n<i>{note}</i>"
    await client.edit_message_text(
        chat_id, msg_id,
        f"{tpl['icon']} <b>{tpl['name']}</b>\n\n"
        f"📝 {tpl['desc']}\n\n"
        f"📊 <b>الحجم:</b> {meta.get('lines', '?')} سطر • "
        f"{meta.get('files', '?')} ملف • {meta.get('size_kb', '?')} KB\n"
        f"🏷️ الفئة: {tpl.get('category', '')}\n"
        f"⭐ النجوم: {meta.get('stars', '?')} • 🔗 <code>{tpl.get('source', '')}</code>\n"
        f"{badge}\n\n"
        f"━━━━━━━━━━━━━━━\n"
        f"1️⃣ أرسل الآن <b>توكن البوت</b> من @BotFather\n"
        f"<i>(بعدها سيُطلب معرّف الأدمن إلزامياً)</i>",
        reply_markup=kb_back_main(lang), parse_mode="HTML",
    )
    # حفظ template_id فقط — القالب يُقرأ من القرص عند الإنهاء
    await set_pending(uid, {
        "kind": "tpl_wait_token",
        "template_id": template_id,
    })


async def _finalize_mcv_new_bot(client: TgClient, chat_id: int, uid: int, lang: str,
                                  *, draft_path: str, name: str, token: str) -> None:
    """Validate a user-supplied token and onboard an MCV-generated draft."""
    if token.lower() in ("/cancel", "cancel"):
        await client.send_message(chat_id, "❌ تم الإلغاء.")
        return
    info = await validate_token(token)
    if not info:
        await client.send_message(chat_id, "❌ التوكن غير صالح. حاول تاني وابعت /cancel لو عاوز تلغي.")
        await set_pending(uid, {"kind": "mcv_new_bot_await_token",
                                  "draft_path": draft_path, "name": name})
        return
    bot_username = info.get("username", "")
    # Patch the draft to embed the real token before hosting it.
    try:
        code = Path(draft_path).read_text(encoding="utf-8", errors="replace")
        if "REPLACE_ME" in code:
            code = code.replace("REPLACE_ME", token)
        Path(draft_path).write_text(code, encoding="utf-8")
    except OSError as exc:
        await client.send_message(chat_id, f"❌ ما عرفتش أكتب الملف: {exc}")
        return
    # Decide an "owned" final path under the regular bots_storage tree
    # so the existing supervisor can manage it like any other upload.
    bots_root = Path(get_settings().bots_path) / str(uid)
    sub_dir = bots_root / f"{uuid.uuid4().hex[:8]}_{Path(name).stem}"
    sub_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^\w\-_.]", "_", name)
    file_path = sub_dir / safe_name
    file_path.write_text(code, encoding="utf-8")
    # Remove the staging draft.
    with contextlib.suppress(Exception):
        os.remove(draft_path)

    # Decide tier — admin gets T5, otherwise the highest one they unlocked.
    is_admin = await is_admin_uid(uid)
    u = await get_user(uid)
    points = u.points if u else 0
    pick_level = 1
    for tier in TIERS:
        if can_use_tier(tier, points or 0, is_vip=bool(u and u.is_vip), is_admin=is_admin):
            pick_level = tier.level

    wait_id = (await client.send_message(chat_id,
        "📦 بتثبت المكتبات وبشغّل البوت…"))["message_id"]

    deps_ok, deps_log = await install_dependencies(language="python", file_path=str(file_path))
    (sub_dir / "deps.log").write_text(deps_log or "", encoding="utf-8")

    tk_hash = token_hash(token)
    b = HostedBot(
        owner_id=uid,
        name=safe_name,
        language="python",
        file_path=str(file_path),
        token_encrypted=encrypt_token(token),
        token_hash=tk_hash,
        bot_username=bot_username,
        tier=pick_level,
        webhook_url=None,
        use_webhook=False,
    )
    try:
        b = await add_hosted_bot(b)
    except ValueError:
        await client.edit_message_text(chat_id, wait_id,
            "❌ هذا التوكن مستخدم بالفعل عند مستخدم آخر.")
        return
    runner = get_runner()
    result = await runner.start_supervised(
        bot_id=b.id, language="python", file_path=str(file_path),
        token=token, port=None, webhook_url=None,
    )
    from .repo import update_bot_status

    if result.error:
        await update_bot_status(b.id, status="crashed", last_error=result.error)
        status_str = f"crashed: {result.error}"
    else:
        await update_bot_status(b.id, status="running", pid=result.pid,
                                last_started_at=dt.datetime.utcnow())
        status_str = "running"
    await client.edit_message_text(chat_id, wait_id,
        f"✅ <b>تم رفع وتشغيل بوت {html.escape(bot_username, quote=False)}.</b>\n\n"
        f"الحالة: <code>{html.escape(status_str, quote=False)}</code>",
        reply_markup=kb_back_main(lang))
    await audit(uid, "mcv_new_bot_hosted", f"id={b.id} @={bot_username}")


# ===================== AI bot-intel hook ===================== #

async def _finalize_template_bot(client: TgClient, chat_id: int, uid: int, lang: str,
                                   *, pending: dict) -> None:
    """إنشاء بوت من قالب GitHub متعدد الملفات بعد اكتمال بيانات المعالج.

    الخطوات: نسخ ملفات القالب ← requirements.txt ← تثبيت المكتبات ←
    إنشاء HostedBot مع env_json (ADMIN_ID + الاختياري) ← تشغيل polling.
    """
    import shutil as _shutil
    from .bot_templates import get_template

    template_id = pending.get("template_id", "")
    tpl = get_template(template_id)
    if not tpl:
        await client.send_message(chat_id, "❌ القالب غير متوفر حالياً.")
        return
    token = str(pending.get("token") or "")
    admin_id = str(pending.get("admin_id") or "")
    extra_user_env: dict[str, str] = dict(pending.get("extra_env") or {})

    info = await validate_token(token)
    if not info:
        await client.send_message(chat_id, "❌ فشل التحقق من التوكن عند الإنهاء. جرّب من جديد.")
        return
    bot_username = info.get("username", "")

    src = Path(tpl["files_dir"])
    bots_root = Path(get_settings().bots_path) / str(uid)
    sub_dir = bots_root / f"{uuid.uuid4().hex[:8]}_{template_id}"
    sub_dir.mkdir(parents=True, exist_ok=True)

    # 1) نسخ كل ملفات القالب (بدون ملفات الـ manifest المخفية)
    for item in src.rglob("*"):
        rel = item.relative_to(src)
        if any(part.startswith(".tpl_") for part in rel.parts):
            continue
        dst = sub_dir / rel
        if item.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(OSError):
                _shutil.copy2(item, dst)

    # 2) requirements.txt من manifest إن لم يوجد ملف جاهز داخل المشروع
    reqs = [r for r in (tpl.get("requirements") or []) if str(r).strip()]
    if reqs and not (sub_dir / "requirements.txt").is_file():
        (sub_dir / "requirements.txt").write_text(
            "\n".join(str(r) for r in reqs) + "\n", encoding="utf-8")

    # 3) ملف الدخول
    entry = tpl.get("entry") or "bot.py"
    entry_path = sub_dir / entry
    if not entry_path.is_file():
        await client.send_message(chat_id,
            f"❌ ملف التشغيل <code>{entry}</code> غير موجود في القالب.", parse_mode="HTML")
        return

    # 4) تحديد الـ tier
    is_admin = await is_admin_uid(uid)
    u = await get_user(uid)
    points = u.points if u else 0
    pick_level = 1
    for tier in TIERS:
        if can_use_tier(tier, points or 0, is_vip=bool(u and u.is_vip), is_admin=is_admin):
            pick_level = tier.level

    wait_id = (await client.send_message(chat_id,
        f"{tpl['icon']} ⏳ بنجهّز <b>{tpl['name']}</b> — نسخ الملفات وتثبيت "
        f"{len(reqs)} مكتبة… قد يأخذ دقيقة"))["message_id"]

    deps_ok, deps_log = await install_dependencies(language="python", file_path=str(entry_path))
    (sub_dir / "deps.log").write_text(deps_log or "", encoding="utf-8")

    # 5) متغيرات البيئة: ADMIN_ID إلزامي + اختياري المستخدم (بدون تجاوز BOT_TOKEN)
    env_vars: dict[str, str] = {"ADMIN_ID": admin_id}
    for k, v in extra_user_env.items():
        if k.upper() in {"BOT_TOKEN", "ADMIN_ID", "PLATFORM"}:
            continue
        env_vars[k.upper()] = v

    safe_name = re.sub(r"[^\w\-_.]", "_", tpl["name"])[:80] or template_id
    tk_hash = token_hash(token)
    b = HostedBot(
        owner_id=uid,
        name=safe_name,
        language="python",
        file_path=str(entry_path),
        token_encrypted=encrypt_token(token),
        token_hash=tk_hash,
        bot_username=bot_username,
        tier=pick_level,
        webhook_url=None,
        use_webhook=False,
        env_json=encode_bot_env(env_vars),
    )
    try:
        b = await add_hosted_bot(b)
    except ValueError:
        await client.edit_message_text(chat_id, wait_id,
            "❌ هذا التوكن مستخدم بالفعل عند مستخدم آخر.")
        return
    runner = get_runner()
    result = await runner.start_supervised(
        bot_id=b.id, language="python", file_path=str(entry_path),
        token=token, port=None, webhook_url=None,
        extra_env=env_vars,
    )
    from .repo import update_bot_status
    if result.error:
        await update_bot_status(b.id, status="crashed", last_error=result.error)
        status_str = f"crashed: {result.error}"
    else:
        await update_bot_status(b.id, status="running", pid=result.pid,
                                last_started_at=dt.datetime.utcnow())
        status_str = "running"
    await client.edit_message_text(chat_id, wait_id,
        f"{tpl['icon']} <b>تم إنشاء وتشغيل بوت {tpl['name']} بنجاح!</b>\n\n"
        f"🤖 المعرف: @{html.escape(bot_username, quote=False)}\n"
        f"👑 الأدمن: <code>{html.escape(admin_id, quote=False)}</code>\n"
        f"⚙️ متغيرات إضافية: {len(env_vars) - 1}\n"
        f"📊 الحالة: <code>{html.escape(status_str, quote=False)}</code>\n\n"
        f"💡 لو البوت محتاج مفاتيح API اختيارية، عدّلها من إعادة تشغيل بالإعدادات.",
        reply_markup=kb_back_main(lang), parse_mode="HTML")
    await audit(uid, "template_bot_hosted",
                f"id={b.id} @={bot_username} tpl={template_id} env={list(env_vars)}")


async def _post_upload_ai_intel(client: TgClient, chat_id: int, *, file_path: str,
                                  language: str, bot_username: str, file_name: str) -> None:
    """Run an AI intel pass on a freshly uploaded bot and message the user."""
    try:
        src = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    try:
        intel = await detect_bot_purpose(src, language=language, file_name=file_name)
    except MCVError as exc:
        logger.info("MCV intel skipped: %s", exc)
        return
    body = (
        f"🔴 <b>تحليل MCV لبوت @{html.escape(bot_username, quote=False)}</b>\n\n"
        + intel.as_html()
    )
    with contextlib.suppress(Exception):
        await client.send_message(chat_id, body, reply_markup=kb_back_main("ar"))


async def _handle_upload_convert_choice(client: TgClient, chat_id: int, uid: int,
                                          lang: str, *, choice: str, st: dict) -> None:
    if not await can_upload_uid(uid):
        await _vip_block(client, chat_id, lang)
        return

    """Resolve the "convert to Python?" choice during upload.

    ``choice == "yes"`` runs MCV to convert the file to Python and then
    falls through to the polling/webhook picker. ``choice == "no"``
    skips the conversion and goes straight to the picker with the
    original file.
    """
    wait_id = st["wait_message_id"]
    if choice == "yes":
        await client.edit_message_text(chat_id, wait_id,
            "🐍 <i>MCV بيحوّل الكود لـ Python…</i>")
        original_path = Path(st["file_path"])
        try:
            src = original_path.read_text(encoding="utf-8", errors="replace")
            new_code = await transpile_to_python(src, source_lang=st["language"])
        except MCVError as exc:
            await client.edit_message_text(chat_id, wait_id,
                f"❌ MCV فشل في التحويل: <code>{html.escape(str(exc), quote=False)}</code>\n"
                "هتشغّل الملف الأصلي زي ما هو.")
            new_code = None
        if new_code:
            # Replace the file in place with the Python version. Keep the
            # original around as ``<name>.original.<ext>`` for posterity.
            new_path = original_path.with_suffix(".py")
            new_path.write_text(new_code, encoding="utf-8")
            backup = original_path.with_name(original_path.stem + "_original" + original_path.suffix)
            with contextlib.suppress(Exception):
                original_path.rename(backup)
            st["file_path"] = str(new_path)
            st["language"] = "python"
            st["safe_name"] = new_path.name
            st["file_name"] = new_path.name
    # Move to the polling/webhook picker.
    suggested = detect_run_mode(st["file_path"], st["language"])
    await set_pending(uid, {
        "kind": "upload_choose_mode",
        "language": st["language"],
        "file_path": st["file_path"],
        "sub_dir": st["sub_dir"],
        "file_name": st["file_name"],
        "safe_name": st["safe_name"],
        "token": st["token"],
        "bot_username": st["bot_username"],
        "tier_level": st["tier_level"],
        "wait_message_id": wait_id,
        "suggested": suggested,
    })
    polling_label = "⚡ Polling" + (" (مقترح)" if suggested == "polling" else "")
    webhook_label = "🌐 Webhook" + (" (مقترح)" if suggested == "webhook" else "")
    kb = inline_kb([
        [
            Btn(polling_label, callback_data="upmode_polling",
                color="green" if suggested == "polling" else "blue"),
            Btn(webhook_label, callback_data="upmode_webhook",
                color="green" if suggested == "webhook" else "blue"),
        ],
        [Btn("❌ إلغاء", callback_data="upmode_cancel", color="red")],
    ])
    prompt = (
        "🔌 <b>اختر وضع تشغيل البوت:</b>\n\n"
        "<blockquote>"
        "⚡ <b>Polling</b> — البوت يسأل تلجرام للتحديثات بشكل مستمر.\n\n"
        "🌐 <b>Webhook</b> — تلجرام يبعت التحديثات لسيرفرنا مباشرة."
        "</blockquote>\n\n"
        f"📌 <i>المقترح حسب فحص الكود: <b>{suggested}</b></i>"
    )
    await client.edit_message_text(chat_id, wait_id, prompt, reply_markup=kb)
