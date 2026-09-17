"""Apply TikZoom free-edition patches: host runner mode + VIP upload gating."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APPLIED: list[str] = []
FAILED: list[str] = []


def patch(path: str, old: str, new: str, label: str, count: int = 1) -> None:
    p = ROOT / path
    src = p.read_text(encoding="utf-8")
    n = src.count(old)
    if n != count:
        FAILED.append(f"{label}: anchor found {n}x (expected {count})")
        return
    p.write_text(src.replace(old, new, count), encoding="utf-8")
    APPLIED.append(label)


def insert_after_def(path: str, def_prefix: str, block: str, label: str) -> None:
    """Insert block right after the line starting with def_prefix."""
    p = ROOT / path
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    for i, ln in enumerate(lines):
        if ln.startswith(def_prefix):
            lines.insert(i + 1, block)
            p.write_text("".join(lines), encoding="utf-8")
            APPLIED.append(label)
            return
    FAILED.append(f"{label}: def line not found: {def_prefix[:60]}")


# ---------- 1) config.py: ADMIN_USERNAME ----------
patch("app/config.py",
      '        alias="GEMINI_API_KEY",\n    )\n',
      '        alias="GEMINI_API_KEY",\n    )\n\n'
      '    # يوزر الأدمن للتواصل بخصوص تفعيل VIP (اختياري — أو إعداد admin_username في DB)\n'
      '    admin_username: str = Field(default="", alias="ADMIN_USERNAME")\n',
      "config: admin_username field")

# ---------- 2) runner.py: host mode ----------
patch("app/runner.py",
      '''def get_runner() -> BotRunner:
    """Return the only supported production runner.

    User code must never silently fall back to a host subprocess. A missing
    Podman setting is a deployment error and fails closed instead of weakening
    the isolation guarantee.
    """
    global _runner
    if _runner is None:
        if os.environ.get("TIKZOOM_SANDBOX", "").strip().lower() != "podman":
            raise RuntimeError("TIKZOOM_SANDBOX=podman is required; refusing host execution")
        from .container_runner import get_container_runner
        _runner = get_container_runner()  # type: ignore[assignment]
    return _runner''',
      '''def get_runner() -> BotRunner:
    """Return the configured runner.

    TIKZOOM_SANDBOX=podman -> rootless podman containers (server deployment).
    TIKZOOM_SANDBOX=host  -> supervised host subprocesses + sandbox_shim
    (used on ephemeral runners like GitHub Actions where the VM is disposable).
    Unset                 -> host mode as well (local development).
    """
    global _runner
    if _runner is None:
        mode = os.environ.get("TIKZOOM_SANDBOX", "").strip().lower()
        if mode == "podman":
            from .container_runner import get_container_runner
            _runner = get_container_runner()  # type: ignore[assignment]
        elif mode in ("", "host", "local", "subprocess"):
            logger.warning(
                "TIKZOOM_SANDBOX=%r -> host subprocess runner (sandbox_shim active)",
                mode or "unset",
            )
            _runner = BotRunner()
        else:
            raise RuntimeError(f"unknown TIKZOOM_SANDBOX mode: {mode!r}")
    return _runner''',
      "runner: host mode support")

# ---------- 3) bot_handlers.py: VIP helpers ----------
VIP_HELPERS = '''async def can_upload_uid(uid: int, u: Any = None) -> bool:
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
        "⭐ <b>رفع الملفات حصري لمشتركي VIP</b>\\n\\n"
        "ارفع ملفاتك واستخدم كل ميزات الرفع بعد تفعيل خطة VIP.\\n"
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


'''
patch("app/bot_handlers.py",
      "async def check_force_subs(client: TgClient, uid: int)",
      VIP_HELPERS + "async def check_force_subs(client: TgClient, uid: int)",
      "bot_handlers: vip helpers")

# ---------- 4) bot_handlers.py: gates ----------
insert_after_def("app/bot_handlers.py",
                 "async def _show_upload_tier_picker(client: TgClient, chat_id: int, message_id: int, uid: int, lang: str) -> None:",
                 "    if not await can_upload_uid(uid):\n"
                 "        await _vip_block(client, chat_id, lang, message_id=message_id)\n"
                 "        return\n\n",
                 "gate: tier picker")

for label, prefix in [
    ("gate: process_upload", "async def _process_upload(client: TgClient, msg: dict, u, lang: str, tier_level: int) -> None:"),
    ("gate: ai_project_upload", "async def _process_ai_project_upload(client: TgClient, msg: dict, u, lang: str) -> None:"),
    ("gate: bot_code_update", "async def _process_bot_code_update(client: TgClient, msg: dict, u, lang: str, bot_id: int) -> None:"),
]:
    insert_after_def("app/bot_handlers.py", prefix,
                     "    if not await can_upload_uid(uid, u):\n"
                     "        await _vip_block(client, chat_id, lang)\n"
                     "        return\n\n", label)

# convert-choice gate: detect signature dynamically
bh = (ROOT / "app" / "bot_handlers.py").read_text(encoding="utf-8")
m = re.search(r"async def (_handle_upload_convert_choice\([^\n]*)", bh)
if m:
    sig = m.group(1)
    has_u = re.search(r"\,\s*u\b|\bu\s*,", sig.split(")")[0]) is not None
    gate = ("    if not await can_upload_uid(uid, u):\n"
            "        await _vip_block(client, chat_id, lang)\n"
            "        return\n\n" if has_u else
            "    if not await can_upload_uid(uid):\n"
            "        await _vip_block(client, chat_id, lang)\n"
            "        return\n\n")
    insert_after_def("app/bot_handlers.py",
                     "async def " + sig.split("(")[0] + "(",
                     gate, "gate: convert choice (u=" + str(has_u) + ")")
else:
    FAILED.append("gate: convert choice — def not found")

# ---------- 5) main.py gates ----------
patch("app/main.py",
      '''    u = await get_user(uid)
    if not u:
        raise HTTPException(403, detail="user unknown")
    is_admin = await is_admin_uid(uid)
''',
      '''    u = await get_user(uid)
    if not u:
        raise HTTPException(403, detail="user unknown")
    is_admin = await is_admin_uid(uid)
    if not is_admin and not u.is_vip:
        raise HTTPException(status_code=403, detail={
            "error": "vip_required",
            "message": "رفع الملفات حصري لمشتركي VIP — تواصل مع الأدمن للتفعيل",
        })
''',
      "main: app_upload vip gate")

MINIAPP_GATE = ('    from .bot_handlers import is_admin_uid as _is_admin_uid\n\n'
                '    if not await _is_admin_uid(_uid):\n'
                '        from .repo import get_user as _get_user\n\n'
                '        _owner = await _get_user(_uid)\n'
                '        if not (_owner and _owner.is_vip):\n'
                '            raise HTTPException(status_code=403, detail={\n'
                '                "error": "vip_required",\n'
                '                "message": "رفع الملفات حصري لمشتركي VIP — تواصل مع الأدمن للتفعيل",\n'
                '            })\n')
insert_after_def("app/main.py",
                 "async def app_project_upload_files(bot_id: int, request: Request, files: list[UploadFile] = File(...)) -> Any:",
                 MINIAPP_GATE, "main: miniapp files/upload gate")
insert_after_def("app/main.py",
                 "async def app_project_update_code(bot_id: int, request: Request, file: UploadFile = File(...)) -> Any:",
                 MINIAPP_GATE, "main: miniapp update-code gate")

# ---------- report ----------
print("APPLIED:", len(APPLIED))
for a in APPLIED:
    print("  ✓", a)
if FAILED:
    print("FAILED:", len(FAILED))
    for f in FAILED:
        print("  ✗", f)
    sys.exit(1)
print("ALL PATCHES OK")
