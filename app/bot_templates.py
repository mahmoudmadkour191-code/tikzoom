"""bot_templates.py — سجل قوالب بوتات تيليجرام حقيقية من مشاريع GitHub مفتوحة المصدر.

ملفات المشاريع الكاملة في مجلد templates_data/<id>/، والبيانات الوصفية في
templates_data/manifest.json (اسم عربي + وصف حقيقي + متغيرات مطلوبة/اختيارية).

مخطط القالب المتوقع من المنصة:
  {id, name, icon, desc, category, source, files_dir, entry, requirements,
   required_env: [{name, desc}], optional_env: [{name, desc}],
   meta: {lines, files, size_kb, stars, tested, tested_note}}

قواعد كل القوالب:
  • توكن البوت من متغير البيئة BOT_TOKEN (توفره المنصة تلقائياً مع أسماء بديلة)
  • ADMIN_ID إجباري عند الإنشاء — يُخزن في env_json الخاص بالبوت
  • كل قالب مرّ بفحص Gemini API قبل اعتماده
"""
from __future__ import annotations

import json
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent / "templates_data"
_MANIFEST: dict | None = None

# التصنيفات المعروضة في القائمة — الترتيب هنا هو ترتيب العرض
CATEGORIES: dict[str, dict] = {
    "shop":       {"name": "متاجر وتجارة", "icon": "🛍️"},
    "files":      {"name": "ملفات وتخزين", "icon": "📦"},
    "downloader": {"name": "تحميل وسائط", "icon": "⬇️"},
    "music":      {"name": "موسيقى", "icon": "🎵"},
    "movies":     {"name": "أفلام ومسلسلات", "icon": "🎬"},
    "groupmgmt":  {"name": "إدارة جروبات", "icon": "👥"},
    "antispam":   {"name": "حماية جروبات", "icon": "🛡️"},
    "ai":         {"name": "ذكاء اصطناعي", "icon": "🤖"},
    "ai_image":   {"name": "توليد صور", "icon": "🎨"},
    "games":      {"name": "ألعاب", "icon": "🎮"},
    "economy":    {"name": "اقتصاد ومحافظ", "icon": "💰"},
    "crypto":     {"name": "عملات رقمية", "icon": "🪙"},
    "tickets":    {"name": "تذاكر ودعم", "icon": "🎫"},
    "tools":      {"name": "أدوات متنوعة", "icon": "🔧"},
    "cybersec":   {"name": "أمن سيبراني (للباحثين)", "icon": "🔐"},
    "education":  {"name": "تعليم", "icon": "📚"},
    "reminders":  {"name": "تذكيرات", "icon": "⏰"},
    "translate":  {"name": "ترجمة", "icon": "🌐"},
    "notes":      {"name": "ملاحظات", "icon": "📝"},
    "autofilter": {"name": "فلترة تلقائية", "icon": "🔎"},
    "torrent":    {"name": "تورنت", "icon": "🌀"},
    "shorturl":   {"name": "اختصار روابط", "icon": "🔗"},
    "vpn":        {"name": "إدارة VPN", "icon": "🛰️"},
    "coding":     {"name": "برمجة", "icon": "💻"},
    "islamic":    {"name": "إسلامي", "icon": "🕌"},
    "weather":    {"name": "طقس", "icon": "🌤️"},
    "smm":        {"name": "سوشيال ميديا", "icon": "📣"},
    "stream":     {"name": "بث وتشغيل", "icon": "📡"},
    "robot":      {"name": "مساعدات شخصية", "icon": "🧠"},
    "phone":      {"name": "استعلامات", "icon": "🔎"},
    "market":     {"name": "سوق وإعلانات", "icon": "🏪"},
    "voice":      {"name": "صوتيات", "icon": "🎙️"},
    "currency":   {"name": "أسعار العملات", "icon": "💱"},
    "lottery":    {"name": "سحوبات", "icon": "🎁"},
    "poll":       {"name": "تصويت", "icon": "📊"},
    "subscribe":  {"name": "اشتراكات", "icon": "⭐"},
}


def _load_manifest() -> dict:
    global _MANIFEST
    if _MANIFEST is None:
        try:
            _MANIFEST = json.loads(
                (_DATA_DIR / "manifest.json").read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _MANIFEST = {"templates": []}
    return _MANIFEST


def _hydrate(raw: dict) -> dict:
    """تحويل ملف manifest إلى مخطط القالب الكامل المتوقع من المنصة."""
    tid = raw["id"]
    proj = _DATA_DIR / tid
    # requirements من ملف المشروع نفسه (حد أقصى 60 سطراً)
    reqs: list[str] = []
    rf = proj / "requirements.txt"
    if rf.is_file():
        try:
            reqs = [ln.strip() for ln in rf.read_text(encoding="utf-8",
                                                      errors="replace").splitlines()
                    if ln.strip() and not ln.startswith("#")][:60]
        except OSError:
            reqs = []
    meta = raw.get("meta") or {}
    return {
        "id": tid,
        "name": raw.get("name") or tid,
        "icon": raw.get("icon") or "🤖",
        "desc": raw.get("desc") or "",
        "category": raw.get("category") or "tools",
        "source": raw.get("source") or "",
        "files_dir": str(proj),
        "entry": raw.get("entry_file") or "main.py",
        "requirements": reqs,
        "required_env": raw.get("required_env") or [{"name": "ADMIN_ID",
                                                     "desc": "معرّف الأدمن (إجباري)"}],
        "optional_env": raw.get("optional_env") or [],
        "meta": meta,
    }


def get_template(template_id: str) -> dict | None:
    """الحصول على قالب بالمعرف (بكل بياناته الكاملة)."""
    for raw in _load_manifest().get("templates", []):
        if raw.get("id") == template_id:
            return _hydrate(raw)
    return None


def list_templates() -> list[tuple[str, dict]]:
    """كل القوالب مرتبة — (id, tpl)."""
    out = [(r["id"], _hydrate(r)) for r in _load_manifest().get("templates", [])
           if r.get("id")]
    return sorted(out, key=lambda x: x[0])


def list_categories() -> list[tuple[str, int, str, str]]:
    """(category, count, name, icon) للتصنيفات التي فيها قوالب."""
    counts: dict[str, int] = {}
    for r in _load_manifest().get("templates", []):
        cat = r.get("category")
        if cat:
            counts[cat] = counts.get(cat, 0) + 1
    out = []
    for cat, info in CATEGORIES.items():
        if counts.get(cat):
            out.append((cat, counts[cat], info["name"], info["icon"]))
    return out


def templates_by_category(cat: str) -> list[tuple[str, dict]]:
    out = [(r["id"], _hydrate(r)) for r in _load_manifest().get("templates", [])
           if r.get("id") and r.get("category") == cat]
    return sorted(out, key=lambda x: x[0])


def template_project_dir(template_id: str) -> Path | None:
    """مجلد ملفات مشروع القالب."""
    d = _DATA_DIR / template_id
    return d if d.is_dir() else None


def stats() -> dict:
    tpls = _load_manifest().get("templates", [])
    return {
        "count": len(tpls),
        "total_lines": sum((t.get("meta") or {}).get("lines", 0) for t in tpls),
        "categories": len({t.get("category") for t in tpls}),
    }
