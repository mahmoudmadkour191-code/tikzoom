"""ai_providers.py - مزودي الذكاء الاصطناعي المجانيون.

يستخدم APIs مجانية بدون قيود:
  1. KILWA Claude (Claude Haiku 3.5) - للردود السريعة والمحادثة
  2. VIBE Claude Fable-5 - للمهام المتقدمة وتوليد الأكواد

بدلاً من الاعتماد على zeneath proxy القديم، يستخدم النظام الآن
مزودين متعددين مع fallback تلقائي.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# ---------- إعدادات المزودين ---------- #

KILWA_API_URL = "https://kilwaapi.vercel.app/kilwa-claude"
VIBE_API_URL = "https://vibe-api-nu.vercel.app/VibeAPI-claude-fable-5"


@dataclass
class AIResponse:
    """نتيجة موحدة من أي مزود."""
    text: str
    model: str
    provider: str
    success: bool
    error: str | None = None


# ---------- مزود KILWA (Claude Haiku 3.5) ---------- #

async def ask_kilwa(prompt: str, *, timeout: float = 90.0) -> AIResponse:
    """استدعاء KILWA Claude API.

    سريع ومناسب للمحادثة العامة والردود السريعة.
    """
    if not prompt.strip():
        return AIResponse("", "claude-haiku-3.5", "kilwa", False, "empty prompt")

    # استخدام quote آمن للـ URL
    from urllib.parse import quote
    # تقليل حجم الـ prompt لو طويل جداً (KILWA لها حد URL)
    if len(prompt) > 8000:
        prompt = prompt[:8000] + "\n\n[... مقطوع ...]"
    url = f"{KILWA_API_URL}?text={quote(prompt, safe='')}"

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as cli:
            resp = await cli.get(url)
            if resp.status_code != 200:
                return AIResponse(
                    "", "claude-haiku-3.5", "kilwa", False,
                    f"HTTP {resp.status_code}: {resp.text[:200]}",
                )
            try:
                data = resp.json()
            except Exception as e:
                return AIResponse(
                    "", "claude-haiku-3.5", "kilwa", False,
                    f"JSON parse error: {e}; body: {resp.text[:200]}",
                )
            if data.get("status") == "success":
                reply = data.get("reply", "").strip()
                if not reply:
                    return AIResponse(
                        "", "claude-haiku-3.5", "kilwa", False,
                        "empty reply from kilwa",
                    )
                return AIResponse(
                    text=reply,
                    model=data.get("model", "claude-haiku-3.5"),
                    provider="kilwa",
                    success=True,
                )
            return AIResponse(
                "", "claude-haiku-3.5", "kilwa", False,
                data.get("message", "unknown error"),
            )
    except httpx.TimeoutException:
        return AIResponse("", "claude-haiku-3.5", "kilwa", False, "timeout")
    except Exception as exc:
        logger.warning("kilwa error: %s", exc)
        return AIResponse("", "claude-haiku-3.5", "kilwa", False, str(exc))


# ---------- مزود VIBE (Claude Fable-5) ---------- #

async def ask_vibe(prompt: str, *, timeout: float = 90.0) -> AIResponse:
    """استدعاء VIBE Claude Fable-5 API.

    أقوى للمهام المعقدة: توليد الأكواد، التحليل، التحويل بين اللغات.
    """
    if not prompt.strip():
        return AIResponse("", "claude-fable-5", "vibe", False, "empty prompt")

    from urllib.parse import quote
    url = f"{VIBE_API_URL}?text={quote(prompt, safe='')}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as cli:
            resp = await cli.get(url)
            if resp.status_code != 200:
                return AIResponse(
                    "", "claude-fable-5", "vibe", False,
                    f"HTTP {resp.status_code}: {resp.text[:200]}",
                )
            data = resp.json()
            if data.get("status") == "success":
                return AIResponse(
                    text=data.get("response", "").strip(),
                    model=data.get("model", "claude-fable-5"),
                    provider="vibe",
                    success=True,
                )
            return AIResponse(
                "", "claude-fable-5", "vibe", False,
                data.get("message", "unknown error"),
            )
    except httpx.TimeoutException:
        return AIResponse("", "claude-fable-5", "vibe", False, "timeout")
    except Exception as exc:
        logger.warning("vibe error: %s", exc)
        return AIResponse("", "claude-fable-5", "vibe", False, str(exc))


# ---------- موزّع ذكي يختار أفضل مزود ---------- #

async def ask_ai(
    prompt: str,
    *,
    prefer: str = "auto",
    timeout: float = 60.0,
) -> AIResponse:
    """اختيار أفضل مزود آلياً مع fallback.

    :param prefer: "auto" | "kilwa" | "vibe"
        - auto: جرّب كلاهما بالتوازي وارجع أول رد ناجح
        - kilwa: ابدأ بـ KILWA، ولو فشل جرّب VIBE
        - vibe: ابدأ بـ VIBE، ولو فشل جرّب KILWA
    """
    if prefer == "kilwa":
        order = [ask_kilwa, ask_vibe]
    elif prefer == "vibe":
        order = [ask_vibe, ask_kilwa]
    else:  # auto
        # للردود السريعة جرّب KILWA أولاً (أسرع)
        # إذا فشل جرّب VIBE
        order = [ask_kilwa, ask_vibe]

    last_error: str | None = None
    for fn in order:
        result = await fn(prompt, timeout=timeout)
        if result.success:
            return result
        last_error = result.error
        logger.info("provider %s failed (%s), trying next...", fn.__name__, result.error)

    return AIResponse("", "unknown", "none", False, last_error or "all providers failed")


# ---------- نسخة تدعم المحادثة متعددة الأدوار ---------- #

def build_prompt_with_history(
    user_text: str,
    history: list[dict[str, str]] | None = None,
    system: str | None = None,
) -> str:
    """بناء prompt موحد من سجل المحادثة.

    الـ APIs المجانية لا تدعم messages array، لذا ندمجها في نص واحد.
    """
    parts: list[str] = []
    if system:
        parts.append(f"[التعليمات]\n{system}\n")
    if history:
        for msg in history[-10:]:  # آخر 10 رسائل فقط لتوفير الـ tokens
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "user":
                parts.append(f"[المستخدم]: {content}")
            elif role == "assistant":
                parts.append(f"[المساعد]: {content}")
    parts.append(f"[المستخدم]: {user_text}")
    parts.append("[المساعد]: ")
    return "\n\n".join(parts)


async def chat(
    user_text: str,
    *,
    history: list[dict[str, str]] | None = None,
    system: str | None = None,
    timeout: float = 60.0,
    prefer: str = "auto",
) -> str:
    """محادثة مع AI مع دعم السجل التاريخي."""
    full_prompt = build_prompt_with_history(user_text, history, system)
    result = await ask_ai(full_prompt, prefer=prefer, timeout=timeout)
    if result.success:
        return result.text
    raise MCVError(result.error or "AI request failed")


# ---------- استخراج الكود من الرد ---------- #

_CODE_BLOCK_RE = re.compile(
    r"```(?P<lang>[a-zA-Z0-9_+-]*)\s*\n(?P<body>.*?)```",
    re.DOTALL,
)


def extract_code_block(text: str, prefer_lang: str | None = None) -> tuple[str, str]:
    """استخراج أكبر كتلة كود من النص."""
    if not text:
        return "", ""
    blocks = list(_CODE_BLOCK_RE.finditer(text))
    if not blocks:
        # محاولة إيجاد كود بدون fencing
        if "def " in text or "import " in text or "async def" in text:
            return "python", text.strip()
        return "", text.strip()

    best = max(
        blocks,
        key=lambda m: (
            1 if prefer_lang and m.group("lang").lower() == prefer_lang.lower() else 0,
            len(m.group("body")),
        ),
    )
    return best.group("lang") or "python", best.group("body").strip()


class MCVError(Exception):
    """خطأ في MCV."""
    pass


# ---------- دوال مساعدة للتكامل مع الكود القديم ---------- #

async def resolve_model_for(task: str) -> str:
    """إرجاع اسم الموديل المناسب للمهمة."""
    models = {
        "chat": "claude-haiku-3.5",
        "code": "claude-fable-5",
        "review": "claude-fable-5",
        "transpile": "claude-fable-5",
        "detect": "claude-haiku-3.5",
    }
    return models.get(task, "claude-haiku-3.5")


async def set_task_model(task: str, model: str) -> None:
    """محفوظة للتوافق مع الكود القديم - لا تفعل شيء."""
    pass


async def update_credentials(*, id_token: str | None = None,
                              bearer: str | None = None,
                              api_url: str | None = None,
                              model: str | None = None) -> None:
    """محفوظة للتوافق - الـ APIs المجانية لا تحتاج credentials."""
    pass


async def get_credentials_status() -> dict[str, Any]:
    """حالة الـ APIs - دائماً متاحة."""
    return {
        "configured": True,
        "model": "claude-haiku-3.5 / claude-fable-5",
        "api_url": f"{KILWA_API_URL} + {VIBE_API_URL}",
        "free_apis": True,
        "message": "نظام AI جديد يستخدم APIs مجانية بدون قيود",
    }


def is_valid_model(name: str | None) -> bool:
    """التأكد من صحة الموديل."""
    if not name:
        return False
    valid_models = {
        "claude-haiku-3.5", "claude-fable-5", "auto",
        "kilwa", "vibe",
    }
    return name.lower() in valid_models
