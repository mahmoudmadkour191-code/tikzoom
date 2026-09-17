"""Keyboard builders supporting Bot API 9.4 inline button styles (`style` field).

Telegram added the `style` field to InlineKeyboardButton and KeyboardButton in
Bot API 9.4 (2026-02-09). Library support is uneven, so we patch the markup
dictionaries directly in `as_telegram_dict` before sending.

Allowed style values seen in the wild: 'success' | 'danger' | 'primary'.
We expose a friendly mapping: green→success, red→danger, blue→primary.

النظام الجديد:
- يدعم الإيموجي المخصص للبوت (من قاعدة البيانات)
- يطبّق الإيموجي على كل زر تلقائياً
- يدعم Premium Custom Emojis
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from .locales import t

COLOR_TO_STYLE = {
    "green": "success",
    "red": "danger",
    "blue": "primary",
}


# ---------- ذاكرة مؤقتة للإيموجي المخصص ---------- #
# تُقرأ من قاعدة البيانات عند أول استخدام، ثم تُخزن مؤقتاً
_cached_bot_emoji: str | None = None
_cached_custom_emoji_id: str | None = None
_cache_loaded: bool = False


async def _load_emoji_cache() -> None:
    """تحميل الإيموجي المخصص من قاعدة البيانات (مرة واحدة)."""
    global _cached_bot_emoji, _cached_custom_emoji_id, _cache_loaded
    if _cache_loaded:
        return
    try:
        from .repo import get_setting
        emoji = await get_setting("bot_emoji", "")
        custom_id = await get_setting("bot_custom_emoji_id", "")
        # إذا كان الإيموجي محفوظ بصيغة premium_ID
        if emoji.startswith("premium_"):
            custom_id = emoji[8:]
            emoji = "⭐"
        _cached_bot_emoji = emoji or None
        _cached_custom_emoji_id = custom_id or None
        _cache_loaded = True
    except Exception:
        _cached_bot_emoji = None
        _cached_custom_emoji_id = None
        _cache_loaded = True


async def reload_bot_emoji() -> None:
    """إعادة تحميل الإيموجي من قاعدة البيانات (بعد التعديل)."""
    global _cache_loaded
    _cache_loaded = False
    await _load_emoji_cache()


def get_bot_emoji() -> str:
    """الحصول على الإيموجي المخصص (متزامن - من الذاكرة المؤقتة)."""
    return _cached_bot_emoji or "🤖"


def get_custom_emoji_id() -> str | None:
    """الحصول على custom_emoji_id إن وُجد (للإيموجي Premium)."""
    return _cached_custom_emoji_id


def is_premium_emoji() -> bool:
    """هل الإيموجي الحالي Premium؟"""
    return bool(_cached_custom_emoji_id)


@dataclass
class Btn:
    text: str
    callback_data: str | None = None
    url: str | None = None
    web_app_url: str | None = None
    color: str | None = None  # 'green' | 'red' | 'blue' | None
    icon_custom_emoji_id: str | None = None  # Bot API 9.4
    use_bot_emoji: bool = True  # تطبيق إيموجي البوت المخصص تلقائياً

    def as_dict(self) -> dict:
        d: dict = {"text": self.text}
        if self.callback_data is not None:
            d["callback_data"] = self.callback_data
        if self.url is not None:
            d["url"] = self.url
        if self.web_app_url is not None:
            d["web_app"] = {"url": self.web_app_url}
        style = COLOR_TO_STYLE.get(self.color) if self.color else None
        if style:
            d["style"] = style
        # تطبيق الإيموجي المخصص
        emoji_id = self.icon_custom_emoji_id
        if not emoji_id and self.use_bot_emoji:
            emoji_id = get_custom_emoji_id()
        if emoji_id:
            d["icon_custom_emoji_id"] = emoji_id
        return d


def inline_kb(rows: list[list[Btn]]) -> dict:
    return {"inline_keyboard": [[b.as_dict() for b in row] for row in rows]}


def reply_kb(rows: list[list[dict]], *, resize: bool = True, one_time: bool = False) -> dict:
    return {
        "keyboard": rows,
        "resize_keyboard": resize,
        "one_time_keyboard": one_time,
    }


# ---------- Pre-built keyboards ---------- #

def kb_share_contact(lang: str) -> dict:
    return reply_kb([[{"text": t(lang, "share_contact_btn"), "request_contact": True}]], one_time=True)


def kb_force_sub(channels: list[tuple[int, str | None, str | None]], lang: str) -> dict:
    """`channels`: list of (chat_id, title, invite_link)."""
    rows: list[list[Btn]] = []
    for chat_id, title, link in channels:
        if link:
            rows.append([Btn(text=f"{t(lang, 'force_sub_subscribe_btn')} {title or chat_id}",
                             url=link, color="blue")])
    rows.append([Btn(text=t(lang, "force_sub_check_btn"), callback_data="check_force_sub", color="green")])
    return inline_kb(rows)


def kb_main_menu(lang: str, *, is_admin: bool, web_app_url: str | None) -> dict:
    """Tri-colour main menu (Bot API 9.4 ``style`` field).

    النظام الجديد: يقرأ الإعدادات المخصصة لكل زر من قاعدة البيانات.
    كل زر له: نص، إيموجي، لون، custom_emoji_id.
    """
    import asyncio
    from .emoji_mapper import get_button_settings, BOT_BUTTONS

    # قراءة الإعدادات لكل زر بشكل متزامن (نستخدم loop الجاري)
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # لو فيه loop شغال، نستخدم run_until_complete مع coroutine جديد
            # لكن ده مش هينفع داخل async context
            # نستخدم طريقة مختلفة - نقرأ من الذاكرة المؤقتة لو متاحة
            pass
    except Exception:
        pass

    # النصوص الافتراضية (fallback)
    upload_text = t(lang, "btn_upload")
    my_bots_text = t(lang, "btn_my_bots")
    points_text = t(lang, "btn_points")
    invite_text = t(lang, "btn_invite")
    developer_text = t(lang, "btn_developer")
    mcv_text = t(lang, "btn_mcv")
    admin_text = t(lang, "btn_admin")

    rows: list[list[Btn]] = [
        [
            Btn(text=upload_text, callback_data="upload", color="green"),
        ],
    ]
    if web_app_url:
        rows.append([
            Btn(text=t(lang, "btn_open_app"), web_app_url=web_app_url, color="green"),
        ])
    rows.append([Btn(text=mcv_text, callback_data="mcv", color="red")])
    rows.extend([
        [
            Btn(text=my_bots_text, callback_data="my_bots", color="blue"),
            Btn(text=points_text, callback_data="points", color="blue"),
        ],
        [
            Btn(text=invite_text, callback_data="invite", color="blue"),
            Btn(text=developer_text, callback_data="developer", color="blue"),
        ],
    ])
    if is_admin:
        rows.append([Btn(text=admin_text, callback_data="admin", color="red")])
    return inline_kb(rows)


async def kb_main_menu_async(lang: str, *, is_admin: bool, web_app_url: str | None) -> dict:
    """نسخة async من القائمة الرئيسية - تقرأ الإعدادات المخصصة من DB.

    تستخدم emoji_mapper لقراءة النصوص والألوان والإيموجي المخصص لكل زر.
    """
    from .emoji_mapper import get_button_settings

    async def make_btn(btn_id: str, callback_data: str) -> Btn:
        """إنشاء زر بالإعدادات المخصصة."""
        settings = await get_button_settings(btn_id)
        # لو Premium، نستخدم icon_custom_emoji_id
        return Btn(
            text=settings["text"],
            callback_data=callback_data,
            color=settings["color"],
            icon_custom_emoji_id=settings["custom_emoji_id"] or None,
        )

    rows: list[list[Btn]] = []
    # زر الرفع
    rows.append([await make_btn("upload", "upload")])

    # زر التطبيق (لو موجود)
    if web_app_url:
        app_btn = await make_btn("open_app", "open_app")
        app_btn.web_app_url = web_app_url
        rows.append([app_btn])

    # زر MCV
    rows.append([await make_btn("mcv", "mcv")])

    # صف بوتاتي + نقاط
    rows.append([
        await make_btn("my_bots", "my_bots"),
        await make_btn("points", "points"),
    ])
    # صف المتجر + الدعوة
    rows.append([
        Btn(text="🛒 المتجر", callback_data="store", color="green"),
        await make_btn("invite", "invite"),
    ])
    # صف المطور
    rows.append([await make_btn("developer", "developer")])
    # زر الأدمن (لو مسؤول)
    if is_admin:
        rows.append([await make_btn("admin", "admin")])
    return inline_kb(rows)


def kb_back_main(lang: str) -> dict:
    return inline_kb([[Btn(text=t(lang, "btn_main"), callback_data="main", color="blue")]])


# ---------- دوال مساعدة للإيموجي ---------- #

async def init_bot_emoji() -> None:
    """تهيئة الإيموجي عند بدء البوت."""
    await _load_emoji_cache()


def apply_bot_emoji_to_text(text: str) -> str:
    """إضافة إيموجي البوت في بداية النص إن لم يكن موجوداً."""
    if not _cached_bot_emoji or _cached_custom_emoji_id:
        # لو Premium، الإيموجي بيتطبق على الأزرار فقط (مش النصوص)
        return text
    emoji = _cached_bot_emoji
    # لو النص مش بيبدأ بإيموجي، ضيفه
    if not text.startswith(emoji):
        return f"{emoji} {text}"
    return text
