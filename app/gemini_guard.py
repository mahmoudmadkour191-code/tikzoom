"""gemini_guard.py — طبقة الفحص الأمني الذكي عبر Google Gemini API.

يستخدم أحدث نموذج Gemini متاح مع سلسلة احتياطية، ويفحص كود البوتات
القادمة من المستخدمين أو من قوالب GitHub قبل التشغيل على السيرفر.

معايير الرفض (حسب سياسة المنصة):
  1. سحب/تسريب ملفات السيرفر أو إرسالها لجهة خارجية
  2. الوصول غير المصرح به لمجلدات السيرفر خارج مجلد البوت نفسه
  3. تدمير/حذف/تخريب ملفات السيرفر أو بياناته
  4. الثغرات الخلفية: reverse shell / RCE / تثبيت باب خلفي
  5. سرقة الأسرار: BOT_TOKEN / ADMIN_ID / مفاتيح المنصة وإرسالها خارجياً

النتيجة: {"action": "allow"|"reject"|"review", "confidence": 0-100,
          "bot_function": "...", "reasons": [...], "patterns": [...], "model": "..."}
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time

import aiohttp

log = logging.getLogger(__name__)

# سلسلة النماذج: الأحدث أولاً ثم بدائل أقل طلباً (تم اختبارها كلها فعلياً)
MODEL_CHAIN = [
    "gemini-3.8-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
]

_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

_SYSTEM_PROMPT = (
    "You are the security auditor of a Telegram-bot hosting platform (TikZoom). "
    "Untrusted user bots run inside isolated rootless Podman containers on a "
    "production Ubuntu server. Each container only has its own /workspace "
    "folder (the bot project) and receives BOT_TOKEN legitimately.\n\n"
    "REJECT (action=reject) code whose real purpose is ANY of:\n"
    "1. server_file_exfiltration — reading/copying/sending server files or "
    "directories OUTSIDE its own /workspace (e.g. /etc, /home, platform DBs, "
    "other bots' folders) to an external host, chat, webhook or attacker.\n"
    "2. unauthorized_server_access — accessing server folders/system resources "
    "it doesn't own: listing platform directories, reading other bots' tokens, "
    "poking host network services, mounting host paths.\n"
    "3. server_destruction — deleting, corrupting, wiping or overwriting "
    "server/platform files or other bots' data; rm -rf outside /workspace.\n"
    "4. backdoors — reverse shells, remote code execution for third parties, "
    "scheduled payload downloads and exec, self-update mechanisms.\n"
    "5. credential_theft — stealing BOT_TOKEN/ADMIN_ID/platform secrets and "
    "sending them to any external endpoint.\n\n"
    "ALLOW (action=allow) everything else. Normal bot features are fine: "
    "SQLite/JSON storage inside /workspace, downloading media (YouTube, "
    "music), web scraping public sites, admin commands, user data, calling "
    "external APIs the bot needs, its own group admin features, penetration-"
    "testing/CTF LEARNING tools that only scan targets the user passes "
    "explicitly (nmap/whois/dns lookups) — these are educational and allowed.\n"
    "Use action=review ONLY when genuinely ambiguous after careful reading.\n\n"
    "Answer ONLY with compact JSON, no markdown fences:\n"
    '{"action": "allow|reject|review", "confidence": 0-100, '
    '"bot_function": "<one line what this bot does>", '
    '"reasons": ["<short arabic reasons>"], '
    '"patterns": ["matched threat names from the list above"]}'
)

_VERDICT_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 6 * 3600


def _cache_get(key: str) -> dict | None:
    hit = _VERDICT_CACHE.get(key)
    if hit and time.time() - hit[0] < _CACHE_TTL:
        return dict(hit[1])
    return None


def gemini_api_key() -> str:
    """مفتاح Gemini — من الإعدادات أو القيمة الافتراضية للمنصة."""
    try:
        from .config import get_settings
        k = getattr(get_settings(), "gemini_api_key", "")
        if k:
            return k
    except Exception:  # noqa: BLE001
        pass
    return _DEFAULT_KEY


_DEFAULT_KEY = ""  # injected at runtime via GEMINI_API_KEY env/secret


def _extract_json(reply: str) -> dict | None:
    reply = reply.strip().strip("`")
    m = re.search(r"\{.*\}", reply, re.S)
    if not m:
        return None
    try:
        obj = __import__("json").loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except Exception:  # noqa: BLE001
        return None


async def _call_model(session: aiohttp.ClientSession, model: str, key: str,
                      prompt: str, timeout: float) -> dict | None:
    url = f"{_API_BASE}/{model}:generateContent?key={key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 900},
    }
    try:
        async with session.post(url, json=payload,
                                timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status == 429:
                log.info("gemini %s: rate limited", model)
                return None
            if resp.status in (403, 404):
                log.info("gemini %s: model unavailable (%s)", model, resp.status)
                return None
            resp.raise_for_status()
            data = await resp.json()
        cand = (data.get("candidates") or [{}])[0]
        text = (cand.get("content", {}).get("parts") or [{}])[0].get("text", "")
        obj = _extract_json(text or "")
        if obj and "action" in obj:
            obj["model"] = model
            return obj
        return None
    except Exception as exc:  # noqa: BLE001
        log.info("gemini %s call failed: %s", model, exc)
        return None


async def gemini_scan_text(code: str, language: str = "python",
                           layer1_risks: list[str] | None = None,
                           timeout: float = 75.0) -> dict | None:
    """فحص أمني لنص كود عبر Gemini. يرجع قاموس الحكم أو None عند الفشل الكلي."""
    if not code or not code.strip():
        return None
    cache_key = hashlib.sha256(f"{language}:{code[:200000]}".encode()).hexdigest()
    cached = _cache_get(cache_key)
    if cached:
        return cached

    risks = "\n".join(f"- {r}" for r in (layer1_risks or [])) or "- none"
    # كود طويل: أهم الملفات أولاً — المدخل والإعدادات ثم باقي الملفات
    sample = code[:70000]
    prompt = (
        f"Security-audit this Telegram bot ({language}). Decide its REAL "
        f"purpose and verdict.\n\n"
        f"Static layer-1 regex flags (may be false positives):\n{risks}\n\n"
        f"```{language}\n{sample}\n```\n\n"
        "Respond ONLY with the JSON object described in the system prompt."
    )
    key = gemini_api_key()
    if not key:
        return None
    async with aiohttp.ClientSession(
            headers={"User-Agent": "TikZoom-Guard/1.0"}) as session:
        for model in MODEL_CHAIN:
            obj = await _call_model(session, model, key, prompt, timeout)
            if obj is not None:
                action = str(obj.get("action", "review")).lower()
                if action not in {"allow", "reject", "review"}:
                    action = "review"
                try:
                    conf = max(0, min(100, int(obj.get("confidence") or 0)))
                except (TypeError, ValueError):
                    conf = 0
                verdict = {
                    "action": action,
                    "confidence": conf,
                    "bot_function": str(obj.get("bot_function") or "")[:300],
                    "reasons": [str(x) for x in (obj.get("reasons") or [])][:8],
                    "patterns": [str(x) for x in (obj.get("patterns") or [])][:8],
                    "model": obj.get("model", model),
                }
                _VERDICT_CACHE[cache_key] = (time.time(), verdict)
                return verdict
            await asyncio.sleep(0.6)
    return None
