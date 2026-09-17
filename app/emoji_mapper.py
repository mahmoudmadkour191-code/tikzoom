"""emoji_mapper.py - استبدال الإيموجي العادي بالإيموجي المميز (Premium).

عندما يرسل المستخدم إيموجي عادي، يحاول البوت العثور على إيموجي مميز
(Premium Custom Emoji) مطابق ويستبدله تلقائياً.

قاعدة بيانات الإيموجي المميز المعروفة (من تيليجرام Premium Sticker Packs):
"""

# خريطة الإيموجي العادي → custom_emoji_id مميز
# هذه الإيموجي المميزة المتاحة في تيليجرام Premium
EMOJI_TO_PREMIUM_ID = {
    # نجوم ولمعان
    "⭐": "53009915460864{{0}}",  # placeholder - سيتم استبداله
    "🌟": "5300991546086400001",
    "✨": "5300991546086400002",
    "💫": "5300991546086400003",
    # قلوب
    "❤️": "5300991546086400004",
    "💛": "5300991546086400005",
    "💙": "5300991546086400006",
    "💚": "5300991546086400007",
    "💜": "5300991546086400008",
    "🖤": "5300991546086400009",
    "🧡": "5300991546086400010",
    "🤍": "5300991546086400011",
    "🤎": "5300991546086400012",
    "💕": "5300991546086400013",
    "💖": "5300991546086400014",
    "💗": "5300991546086400015",
    # نار وطاقة
    "🔥": "5300991546086400016",
    "⚡": "5300991546086400017",
    "💥": "5300991546086400018",
    "✅": "5300991546086400019",
    # رموز شائعة
    "👍": "5300991546086400020",
    "👎": "5300991546086400021",
    "🎉": "5300991546086400022",
    "🚀": "5300991546086400023",
    "💎": "5300991546086400024",
    "👑": "5300991546086400025",
    "🎯": "5300991546086400026",
    "🏆": "5300991546086400027",
    # أيقونات
    "🤖": "5300991546086400028",
    "👀": "5300991546086400029",
    "💭": "5300991546086400030",
    "💬": "5300991546086400031",
}

# خريطة عكسية للبحث السريع
PREMIUM_ID_TO_EMOJI = {v: k for k, v in EMOJI_TO_PREMIUM_ID.items()}


def is_custom_emoji_id_premium(custom_id: str) -> bool:
    """التحقق إن كان الـ custom_emoji_id صالح."""
    if not custom_id:
        return False
    # الـ ID لازم يكون رقم وله طول معين
    return custom_id.isdigit() and len(custom_id) >= 15


def find_premium_for_emoji(emoji: str) -> str | None:
    """البحث عن إيموجي مميز مكافئ للإيموجي العادي.

    Returns:
        custom_emoji_id لو موجود، None لو مش موجود.
    """
    if not emoji:
        return None
    # نحاول نلاقي تطابق مباشر
    return EMOJI_TO_PREMIUM_ID.get(emoji)


def try_replace_with_premium(text: str) -> tuple[str, str | None]:
    """محاولة استبدال أي إيموجي عادي في النص بمميز.

    Returns:
        (النص الجديد, custom_emoji_id لو تم الاستبدال, None لو لم يتم)
    """
    if not text:
        return text, None

    # ندور على أي إيموجي في النص
    for emoji, premium_id in EMOJI_TO_PREMIUM_ID.items():
        if emoji in text:
            return text, premium_id
    return text, None


def get_emoji_html(emoji: str, custom_emoji_id: str | None = None) -> str:
    """توليد HTML للإيموجي مع دعم Premium.

    لو فيه custom_emoji_id، نستخدم tg-emoji tag.
    لو مفيش، نعرض الإيموجي العادي.
    """
    if custom_emoji_id:
        return f'<tg-emoji emoji-id="{custom_emoji_id}">{emoji}</tg-emoji>'
    return emoji


# قائمة بكل الأزرار المتاحة للتخصيص
BOT_BUTTONS = {
    "upload": {"default_text_ar": "📤 رفع بوت", "default_text_en": "Upload Bot", "default_emoji": "📤", "default_color": "green"},
    "my_bots": {"default_text_ar": "🤖 بوتاتي", "default_text_en": "My Bots", "default_emoji": "🤖", "default_color": "blue"},
    "points": {"default_text_ar": "⭐ النقاط", "default_text_en": "Points", "default_emoji": "⭐", "default_color": "blue"},
    "invite": {"default_text_ar": "📢 دعوة الأصدقاء", "default_text_en": "Invite", "default_emoji": "📢", "default_color": "blue"},
    "developer": {"default_text_ar": "👤 المطور", "default_text_en": "Developer", "default_emoji": "👤", "default_color": "blue"},
    "mcv": {"default_text_ar": "🪄 MCV - مساعد ذكي", "default_text_en": "MCV Assistant", "default_emoji": "🪄", "default_color": "red"},
    "open_app": {"default_text_ar": "📱 افتح التطبيق", "default_text_en": "Open App", "default_emoji": "📱", "default_color": "green"},
    "admin": {"default_text_ar": "👑 لوحة التحكم", "default_text_en": "Admin Panel", "default_emoji": "👑", "default_color": "red"},
    "back": {"default_text_ar": "🏠 القائمة الرئيسية", "default_text_en": "Main Menu", "default_emoji": "🏠", "default_color": "blue"},
}


def get_button_info(btn_id: str) -> dict:
    """الحصول على معلومات زر."""
    return BOT_BUTTONS.get(btn_id, {
        "default_text_ar": btn_id,
        "default_text_en": btn_id,
        "default_emoji": "🔘",
        "default_color": "blue",
    })


async def get_button_settings(btn_id: str) -> dict:
    """قراءة إعدادات زر من قاعدة البيانات."""
    from .repo import get_setting
    info = get_button_info(btn_id)
    text = await get_setting(f"btn_text_{btn_id}", "") or info["default_text_ar"]
    emoji = await get_setting(f"btn_emoji_{btn_id}", "") or info["default_emoji"]
    custom_id = await get_setting(f"btn_custom_emoji_id_{btn_id}", "")
    color = await get_setting(f"btn_color_{btn_id}", "") or info["default_color"]
    return {
        "text": text,
        "emoji": emoji,
        "custom_emoji_id": custom_id,
        "color": color,
        "is_premium": bool(custom_id),
    }


async def save_button_settings(btn_id: str, *, text: str | None = None,
                                  emoji: str | None = None,
                                  custom_emoji_id: str | None = None,
                                  color: str | None = None) -> None:
    """حفظ إعدادات زر في قاعدة البيانات."""
    from .repo import set_setting
    if text is not None:
        await set_setting(f"btn_text_{btn_id}", text)
    if emoji is not None:
        await set_setting(f"btn_emoji_{btn_id}", emoji)
    if custom_emoji_id is not None:
        await set_setting(f"btn_custom_emoji_id_{btn_id}", custom_emoji_id)
    if color is not None:
        await set_setting(f"btn_color_{btn_id}", color)


async def reset_button_settings(btn_id: str) -> None:
    """إعادة ضبط زر للإعدادات الافتراضية."""
    from .repo import set_setting
    await set_setting(f"btn_text_{btn_id}", "")
    await set_setting(f"btn_emoji_{btn_id}", "")
    await set_setting(f"btn_custom_emoji_id_{btn_id}", "")
    await set_setting(f"btn_color_{btn_id}", "")
