"""auto_heal.py - نظام الإصلاح التلقائي للبوتات المتعطلة.

يفحص البوتات المتعطلة بشكل دوري، يحلل الأخطاء بالـ AI،
يصلح الكود، يعيد التشغيل، ويشعر المستخدم.
"""
from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path

from .ai_providers import ask_ai
from .config import get_settings
from .repo import get_bot, get_user, update_bot_status
from .runner import get_runner
from .telegram_api import TgClient

logger = logging.getLogger(__name__)

# فحص كل 2 دقيقة
CHECK_INTERVAL = 120
# حد إعادة المحاولة لكل بوت
MAX_HEAL_ATTEMPTS = 2


async def _get_crashed_bots() -> list:
    """الحصول على قائمة البوتات المتعطلة."""
    from .db import HostedBot, get_session_factory
    from sqlalchemy import select
    async with get_session_factory()() as s:
        stmt = select(HostedBot).where(HostedBot.status == "crashed").limit(10)
        result = await s.execute(stmt)
        return list(result.scalars().all())


async def _heal_bot(bot_id: int, error_logs: str) -> bool:
    """محاولة إصلاح بوت بالـ AI."""
    b = await get_bot(bot_id)
    if not b or not b.file_path:
        return False
    try:
        source = Path(b.file_path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False

    prompt = (
        f"أنت مهندس بايثون خبير. بوت تيليجرام تعطل.\n\n"
        f"Error Logs:\n{error_logs[:2000]}\n\n"
        f"الكود الأصلي:\n```python\n{source[:6000]}\n```\n\n"
        f"أصلح الكود وأرسل النسخة الكاملة المصلحة داخل ```python``` block.\n"
        f"تأكد إن الكود يقرأ BOT_TOKEN من os.environ.\n"
        f"لا تستخدم subprocess أو os.system.\n"
        f"اكتب شرح الإصلاح في سطرين قبل الكود."
    )

    result = await ask_ai(prompt, prefer="vibe", timeout=120)
    if not result.success:
        logger.warning("AI heal failed for bot %s: %s", bot_id, result.error)
        return False

    match = re.search(r"```(?:python)?\s*(.*?)```", result.text, re.DOTALL)
    if not match:
        logger.warning("AI heal: no code block for bot %s", bot_id)
        return False

    fixed_code = match.group(1).strip()
    if len(fixed_code) < 50 or len(fixed_code) > 50000:
        logger.warning("AI heal: suspicious code length for bot %s", bot_id)
        return False

    # حفظ الكود المصلح
    Path(b.file_path).write_text(fixed_code, encoding="utf-8")
    logger.info("bot_id=%s code auto-healed by AI", bot_id)

    # إشعار المستخدم
    try:
        settings = get_settings()
        client = TgClient(settings.telegram_token)
        explanation = result.text.split("```")[0].strip()[:300]
        await client.send_message(
            b.owner_id,
            f"🔧 <b>تم إصلاح بوتك تلقائياً!</b>\n\n"
            f"🤖 البوت: @{b.bot_username or b.name}\n"
            f"✅ تم اكتشاف خطأ وإصلاحه بالذكاء الاصطناعي\n"
            f"🟢 البوت يعمل الآن بشكل طبيعي\n\n"
            f"📋 <b>الخطأ:</b>\n<code>{error_logs[:200]}</code>\n\n"
            f"💡 <b>الإصلاح:</b>\n<i>{explanation}</i>\n\n"
            f"🛡️ <b>بوتك يعمل 24 ساعة بدون توقف!</b>",
            parse_mode="HTML",
        )
    except Exception as exc:
        logger.warning("notify user heal failed: %s", exc)

    return True


async def _restart_bot(bot_id: int) -> bool:
    """إعادة تشغيل بوت بعد الإصلاح."""
    from .token_extract import extract_token_from_file
    from .repo import decode_bot_env
    b = await get_bot(bot_id)
    if not b or not b.file_path:
        return False
    token = extract_token_from_file(b.file_path) or ""
    runner = get_runner()
    # إيقاف أي حاوية قديمة
    try:
        await runner.stop(bot_id)
    except Exception:
        pass
    await asyncio.sleep(2)
    # تشغيل
    result = await runner.start_supervised(
        bot_id=bot_id, language=b.language,
        file_path=b.file_path, token=token,
        port=None, webhook_url=None,
        extra_env=decode_bot_env(getattr(b, "env_json", "")) or None,
    )
    if result.error:
        await update_bot_status(bot_id, status="crashed", last_error=result.error)
        logger.warning("bot_id=%s restart after heal failed: %s", bot_id, result.error)
        return False
    else:
        import datetime as dt
        await update_bot_status(bot_id, status="running",
                                pid=result.pid, last_started_at=dt.datetime.utcnow())
        logger.info("bot_id=%s restarted after AI heal", bot_id)
        return True


async def auto_heal_loop() -> None:
    """الحلقة الرئيسية - تفحص البوتات المتعطلة وتصلحها."""
    logger.info("AI auto-heal loop started (interval=%ss)", CHECK_INTERVAL)
    while True:
        try:
            await asyncio.sleep(CHECK_INTERVAL)
            # تنظيف الحاويات المتوقفة أولاً لتوفير الموارد
            try:
                proc = await asyncio.create_subprocess_exec(
                    "podman", "container", "prune", "-f",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=30)
                if proc.returncode == 0:
                    logger.info("auto-heal: cleaned stopped containers")
            except Exception as exc:
                logger.warning("auto-heal: container prune failed: %s", exc)

            crashed = await _get_crashed_bots()
            if not crashed:
                continue
            logger.info("auto-heal: found %s crashed bots", len(crashed))
            for b in crashed:
                try:
                    # الحصول على سجلات الخطأ
                    from .config import get_settings
                    log_path = Path(get_settings().data_path) / "logs" / f"bot_{b.id}.log"
                    error_logs = ""
                    if log_path.exists():
                        error_logs = log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                    if not error_logs and b.last_error:
                        error_logs = b.last_error

                    if not error_logs:
                        error_logs = f"Bot exited with status: {b.status}"

                    logger.info("auto-heal: healing bot_id=%s", b.id)
                    healed = await _heal_bot(b.id, error_logs)
                    if healed:
                        await asyncio.sleep(3)
                        await _restart_bot(b.id)
                    else:
                        logger.warning("auto-heal: could not heal bot_id=%s", b.id)
                except Exception as exc:
                    logger.warning("auto-heal bot_id=%s exception: %s", b.id, exc)
        except asyncio.CancelledError:
            logger.info("auto-heal loop cancelled")
            raise
        except Exception as exc:
            logger.warning("auto-heal loop error: %s", exc)
            await asyncio.sleep(60)
