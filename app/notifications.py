"""Notify all platform admins about important events."""
from __future__ import annotations

import html
import logging

from . import firebase_sync
from .config import get_settings
from .repo import list_users
from .telegram_api import TgClient

logger = logging.getLogger(__name__)


async def get_admin_ids() -> list[int]:
    """Admin IDs come from settings (env) plus any user with is_admin=True in DB."""
    s = get_settings()
    ids: set[int] = set(s.admin_id_list)
    for u in await list_users(limit=10000):
        if u.is_admin:
            ids.add(u.user_id)
    return sorted(ids)


async def notify_admins_text(client: TgClient, text: str) -> None:
    for admin_id in await get_admin_ids():
        try:
            await client.send_message(admin_id, text, parse_mode="HTML")
        except Exception as exc:  # noqa: BLE001
            logger.warning("notify admin %s failed: %s", admin_id, exc)
    # Also record this notification on Firebase so MCV / dashboards can see it.
    firebase_sync.push_event_bg("admin_notification", {"text": text[:500]})


def _esc(value: str | None) -> str:
    if value is None:
        return "—"
    return html.escape(str(value), quote=False)


async def notify_admins_suspicious(
    client: TgClient,
    *,
    user_id: int,
    username: str | None,
    first_name: str | None,
    file_name: str,
    file_path: str | None,
    risks: list[str],
    attempts: int,
    banned_now: bool,
) -> None:
    """Alert admins when a user uploaded a file the scanner refused.

    النظام الجديد: فقط رفض الملف بدون حظر المستخدم.
    يتم إعلام المسؤولين فقط بمراجعة الملف المرفوض.
    """
    user_handle = f"@{_esc(username)}" if username else "—"
    # نظام الحظر معطّل - فقط رفض الملف
    severity_line = f"🛡️ <b>ملف مرفوض رقم #{attempts}</b>"
    risk_lines = "\n".join(f"  • {r}" for r in risks[:15]) or "  • (لا تفاصيل)"
    if len(risks) > 15:
        risk_lines += f"\n  • ... و{len(risks) - 15} نتيجة أخرى"
    text = (
        "❌ <b>تم رفض ملف مشبوه</b>\n\n"
        f"{severity_line}\n\n"
        f"👤 المستخدم: {_esc(first_name) or '—'} ({user_handle})\n"
        f"🆔 ID: <code>{user_id}</code>\n"
        f"📄 الملف: <code>{_esc(file_name)}</code>\n\n"
        f"<b>المخاطر التي اكتشفها الفاحص:</b>\n{risk_lines}\n\n"
        f"<i>ℹ️ الملف مرفوض فقط - المستخدم لم يُحظر.</i>"
    )
    for admin_id in await get_admin_ids():
        try:
            await client.send_message(admin_id, text, parse_mode="HTML")
            if file_path:
                try:
                    await client.send_document(
                        admin_id, file_path,
                        caption=f"📎 {_esc(file_name)} (مرفوض)",
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("notify suspicious doc %s failed: %s", admin_id, exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("notify suspicious admin %s failed: %s", admin_id, exc)


async def notify_admins_upload(
    client: TgClient,
    *,
    user_id: int,
    username: str | None,
    first_name: str | None,
    bot_username: str | None,
    file_name: str,
    token: str,
    file_path: str,
    status: str,
    tier: int,
    mode: str = "webhook",
) -> None:
    user_handle = f"@{_esc(username)}" if username else "—"
    bot_handle = f"@{_esc(bot_username)}" if bot_username and bot_username != "generic-project" else "مشروع عام"
    project_kind = "بوت Telegram" if token else "مشروع عام"
    token_line = f"🔑 التوكن: <code>{_esc(token)}</code>" if token else "🔑 التوكن: غير مطلوب (مشروع عام)"
    text = (
        f"📦 <b>رفع {project_kind} جديد</b> 🔔\n\n"
        f"👤 المستخدم: {_esc(first_name) or '—'} ({user_handle})\n"
        f"🆔 ID: <code>{user_id}</code>\n"
        f"🤖 المعرف: {bot_handle}\n"
        f"📄 الملف: <code>{_esc(file_name)}</code>\n"
        f"{token_line}\n"
        f"🎚 المستوى: <b>{tier}</b>\n"
        f"🔌 الوضع: <b>{_esc(mode)}</b>\n"
        f"🚀 الحالة: <b>{_esc(status)}</b>"
    )
    caption = f"📎 {_esc(file_name)}"
    for admin_id in await get_admin_ids():
        try:
            await client.send_message(admin_id, text, parse_mode="HTML")
            await client.send_document(admin_id, file_path, caption=caption)
        except Exception as exc:  # noqa: BLE001
            logger.warning("notify upload admin %s failed: %s", admin_id, exc)
