"""Repository layer for TikZoom — async SQLModel data access.

إعادة بناء كاملة. كل الدوال المستخدمة في main.py / bot_handlers.py /
store.py / mcv_memory.py / public_api.py معتمدة هنا بنفس التواقيع والدلالات.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from .db import (
    ApiKey,
    ApiUsage,
    AuditLog,
    ForceSubChannel,
    HostedBot,
    Referral,
    Setting,
    User,
    get_session_factory,
)
from .security import decrypt_token, encrypt_token

logger = logging.getLogger(__name__)

_UNSET: Any = object()


def _now() -> dt.datetime:
    return dt.datetime.utcnow()


def _fb_push(method: str, *args: Any) -> None:
    """Fire-and-forget firebase push — يفشل بصمت إذا كان Firebase غير مفعّل."""
    try:
        from . import firebase_sync

        fn = getattr(firebase_sync, method, None)
        if fn is not None:
            fn(*args)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------- users


async def upsert_user(*, user_id: int, username: str | None = None,
                      first_name: str | None = None,
                      last_name: str | None = None,
                      language: str = "ar") -> User:
    async with get_session_factory()() as s:
        u = await s.get(User, user_id)
        if u is None:
            u = User(user_id=user_id, username=username, first_name=first_name,
                     last_name=last_name, language=language)
            s.add(u)
        else:
            if username is not None:
                u.username = username
            if first_name is not None:
                u.first_name = first_name
            if last_name is not None:
                u.last_name = last_name
            if language:
                u.language = language
        u.last_seen = _now()
        await s.commit()
        await s.refresh(u)
        _fb_push("push_user_bg", u)
        return u


async def get_user(user_id: int) -> User | None:
    async with get_session_factory()() as s:
        return await s.get(User, user_id)


async def set_admin(user_id: int, value: bool) -> None:
    async with get_session_factory()() as s:
        u = await s.get(User, user_id)
        if u:
            u.is_admin = value
            await s.commit()


async def set_banned(user_id: int, value: bool) -> None:
    async with get_session_factory()() as s:
        u = await s.get(User, user_id)
        if u:
            u.is_banned = value
            await s.commit()


async def set_vip(user_id: int, value: bool, days: int | None = None) -> None:
    async with get_session_factory()() as s:
        u = await s.get(User, user_id)
        if u:
            u.is_vip = value
            if value:
                u.vip_expiry = (_now() + dt.timedelta(days=days)) if days else u.vip_expiry
            else:
                u.vip_expiry = None
            await s.commit()
            _fb_push("push_user_bg", u)


async def set_contact(user_id: int, phone: str) -> None:
    async with get_session_factory()() as s:
        u = await s.get(User, user_id)
        if u:
            u.contact_phone = phone or None
            u.contact_shared_at = _now() if phone else u.contact_shared_at
            await s.commit()


async def set_points(user_id: int, points: int) -> None:
    async with get_session_factory()() as s:
        u = await s.get(User, user_id)
        if u:
            u.points = max(0, int(points))
            await s.commit()
            _fb_push("push_user_bg", u)


async def add_points(user_id: int, delta: int) -> int:
    async with get_session_factory()() as s:
        u = await s.get(User, user_id)
        if not u:
            return 0
        u.points = max(0, (u.points or 0) + int(delta))
        await s.commit()
        _fb_push("push_user_bg", u)
        return u.points


async def set_force_sub_verified(user_id: int) -> None:
    async with get_session_factory()() as s:
        u = await s.get(User, user_id)
        if u:
            u.force_sub_verified_at = _now()
            await s.commit()


async def record_suspicious_attempt(user_id: int) -> tuple[int, bool]:
    """يزيد عداد المحاولات المشبوهة. الحظر معطّل — يرجع (العدد, False)."""
    async with get_session_factory()() as s:
        u = await s.get(User, user_id)
        if not u:
            return 1, False
        u.suspicious_attempts = (u.suspicious_attempts or 0) + 1
        attempts = u.suspicious_attempts
        await s.commit()
        # نظام الحظر معطّل — فقط رفض الملف بدون حظر المستخدم
        return attempts, False


async def list_users(limit: int = 10000) -> list[User]:
    async with get_session_factory()() as s:
        res = await s.execute(
            select(User).order_by(User.last_seen.desc()).limit(limit))
        return list(res.scalars().all())


async def search_users(q: str = "", limit: int = 100) -> list[User]:
    async with get_session_factory()() as s:
        stmt = select(User)
        q = (q or "").strip()
        if q:
            if q.isdigit():
                stmt = stmt.where(User.user_id == int(q))
            else:
                like = f"%{q.lower()}%"
                stmt = stmt.where(or_(
                    func.lower(User.username).like(like),
                    func.lower(User.first_name).like(like),
                    func.lower(User.last_name).like(like),
                ))
        stmt = stmt.order_by(User.last_seen.desc()).limit(limit)
        res = await s.execute(stmt)
        return list(res.scalars().all())


# ---------------------------------------------------------------- referrals


async def get_user_by_referral_code(code: str) -> User | None:
    async with get_session_factory()() as s:
        res = await s.execute(select(User).where(User.referral_code == code))
        return res.scalars().first()


async def credit_referral(*, referrer_id: int, referred_id: int) -> bool:
    """يسجل إحالة جديدة (مرة واحدة لكل مستخدم مُحال). يعود True إذا نُسبت."""
    async with get_session_factory()() as s:
        exists = await s.execute(
            select(Referral).where(Referral.referred_id == referred_id))
        if exists.scalars().first() is not None:
            return False
        ref = Referral(referrer_id=referrer_id, referred_id=referred_id)
        s.add(ref)
        try:
            await s.commit()
        except IntegrityError:
            await s.rollback()
            return False
        _fb_push("push_referral_bg", ref)
    await add_points(referrer_id, 1)
    return True


async def count_referrals(user_id: int) -> int:
    async with get_session_factory()() as s:
        res = await s.execute(
            select(func.count()).select_from(Referral)
            .where(Referral.referrer_id == user_id))
        return int(res.scalar() or 0)


# ---------------------------------------------------------------- hosted bots


async def add_hosted_bot(bot: HostedBot) -> HostedBot:
    async with get_session_factory()() as s:
        s.add(bot)
        try:
            await s.commit()
        except IntegrityError as exc:
            await s.rollback()
            raise ValueError("duplicate token_hash or invalid unique field") from exc
        await s.refresh(bot)
        _fb_push("push_bot_bg", bot)
        return bot


async def get_bot(bot_id: int) -> HostedBot | None:
    async with get_session_factory()() as s:
        return await s.get(HostedBot, bot_id)


async def get_bot_by_token_hash(token_hash_value: str) -> HostedBot | None:
    async with get_session_factory()() as s:
        res = await s.execute(
            select(HostedBot).where(HostedBot.token_hash == token_hash_value))
        return res.scalars().first()


async def list_all_bots() -> list[HostedBot]:
    async with get_session_factory()() as s:
        res = await s.execute(select(HostedBot).order_by(HostedBot.id))
        return list(res.scalars().all())


async def list_user_bots(owner_id: int) -> list[HostedBot]:
    async with get_session_factory()() as s:
        res = await s.execute(
            select(HostedBot).where(HostedBot.owner_id == owner_id)
            .order_by(HostedBot.id))
        return list(res.scalars().all())


async def count_user_bots_in_tier(owner_id: int, tier: int) -> int:
    async with get_session_factory()() as s:
        res = await s.execute(
            select(func.count()).select_from(HostedBot)
            .where(HostedBot.owner_id == owner_id, HostedBot.tier == tier))
        return int(res.scalar() or 0)


async def update_bot_status(bot_id: int, *, status: str | None = _UNSET,
                            pid: int | None = _UNSET,
                            last_started_at: dt.datetime | None = _UNSET,
                            last_error: str | None = _UNSET,
                            restart_count_inc: bool = False) -> None:
    async with get_session_factory()() as s:
        b = await s.get(HostedBot, bot_id)
        if not b:
            return
        if status is not _UNSET:
            b.status = status
        if pid is not _UNSET:
            b.pid = pid
        if last_started_at is not _UNSET:
            b.last_started_at = last_started_at
        if last_error is not _UNSET:
            b.last_error = last_error
        if restart_count_inc:
            b.restart_count = (b.restart_count or 0) + 1
        await s.commit()
        _fb_push("push_bot_bg", b)


async def update_bot_mode(bot_id: int, *, use_webhook: bool) -> None:
    async with get_session_factory()() as s:
        b = await s.get(HostedBot, bot_id)
        if b:
            b.use_webhook = bool(use_webhook)
            await s.commit()
            _fb_push("push_bot_bg", b)


async def update_bot_code(bot_id: int, *, file_path: str, language: str) -> None:
    async with get_session_factory()() as s:
        b = await s.get(HostedBot, bot_id)
        if b:
            b.file_path = file_path
            b.language = language
            await s.commit()
            _fb_push("push_bot_bg", b)


async def update_bot_token(bot_id: int, *, encrypted: str, token_hash_value: str,
                           bot_username: str | None = None) -> None:
    async with get_session_factory()() as s:
        dup = await s.execute(select(HostedBot).where(
            HostedBot.token_hash == token_hash_value, HostedBot.id != bot_id))
        if dup.scalars().first() is not None:
            raise ValueError("token already used by another bot")
        b = await s.get(HostedBot, bot_id)
        if not b:
            raise ValueError("bot not found")
        b.token_encrypted = encrypted
        b.token_hash = token_hash_value
        b.bot_username = bot_username
        await s.commit()
        _fb_push("push_bot_bg", b)


async def delete_bot(bot_id: int) -> bool:
    async with get_session_factory()() as s:
        b = await s.get(HostedBot, bot_id)
        if not b:
            return False
        await s.delete(b)
        await s.commit()
        _fb_push("delete_bot_bg", bot_id)
        return True


# ---------------------------------------------------------------- force sub


async def list_force_sub_channels() -> list[ForceSubChannel]:
    async with get_session_factory()() as s:
        res = await s.execute(
            select(ForceSubChannel).order_by(ForceSubChannel.id))
        return list(res.scalars().all())


async def add_force_sub_channel(*, chat_id: int, title: str | None = None,
                                invite_link: str | None = None) -> ForceSubChannel:
    async with get_session_factory()() as s:
        res = await s.execute(
            select(ForceSubChannel).where(ForceSubChannel.chat_id == chat_id))
        ch = res.scalars().first()
        if ch:
            if title is not None:
                ch.title = title
            if invite_link is not None:
                ch.invite_link = invite_link
            await s.commit()
            return ch
        ch = ForceSubChannel(chat_id=chat_id, title=title, invite_link=invite_link)
        s.add(ch)
        await s.commit()
        await s.refresh(ch)
        return ch


async def remove_force_sub_channel(chat_id: int) -> bool:
    async with get_session_factory()() as s:
        res = await s.execute(
            select(ForceSubChannel).where(ForceSubChannel.chat_id == chat_id))
        ch = res.scalars().first()
        if not ch:
            return False
        await s.delete(ch)
        await s.commit()
        return True


# ---------------------------------------------------------------- settings


async def get_setting(key: str, default: str = "") -> str:
    async with get_session_factory()() as s:
        row = await s.get(Setting, key)
        return row.value if row else default


async def set_setting(key: str, value: str) -> None:
    async with get_session_factory()() as s:
        row = await s.get(Setting, key)
        if row:
            row.value = value
            row.updated_at = _now()
        else:
            s.add(Setting(key=key, value=value))
        await s.commit()


# ---------------------------------------------------------------- bot env


def encode_bot_env(env: dict[str, str]) -> str:
    """JSON مشفّر Fernet لمتغيرات بيئة البوت (ADMIN_ID + اختياري)."""
    if not env:
        return ""
    try:
        return encrypt_token(json.dumps(env, ensure_ascii=False))
    except Exception:  # noqa: BLE001
        logger.exception("encode_bot_env failed")
        return ""


def decode_bot_env(env_json: str) -> dict[str, str]:
    """فك تشفير env_json — يرجع {} عند أي فشل (مثلاً تغيّر FERNET_KEY)."""
    if not env_json:
        return {}
    try:
        plain = decrypt_token(env_json)
        data = json.loads(plain)
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        logger.warning("decode_bot_env failed (wrong FERNET_KEY?)")
        return {}


# ---------------------------------------------------------------- audit


async def audit(actor_tg_id: int | None, action: str, details: str = "") -> None:
    async with get_session_factory()() as s:
        s.add(AuditLog(user_id=actor_tg_id, action=action, payload=details or ""))
        await s.commit()


# ---------------------------------------------------------------- api keys (mini app / public api)


async def get_or_create_api_key(user_id: int) -> ApiKey:
    async with get_session_factory()() as s:
        res = await s.execute(select(ApiKey).where(ApiKey.user_id == user_id))
        k = res.scalars().first()
        if k:
            return k
        k = ApiKey(user_id=user_id)
        s.add(k)
        try:
            await s.commit()
        except IntegrityError:
            await s.rollback()
            res = await s.execute(select(ApiKey).where(ApiKey.user_id == user_id))
            return res.scalars().first()  # type: ignore[return-value]
        await s.refresh(k)
        _fb_push("push_api_key_bg", k)
        return k


async def get_api_key_with_user(key: str) -> tuple[ApiKey, User] | None:
    async with get_session_factory()() as s:
        res = await s.execute(
            select(ApiKey, User).join(User, User.user_id == ApiKey.user_id)
            .where(ApiKey.key == key, ApiKey.is_revoked == False))  # noqa: E712
        row = res.first()
        return (row[0], row[1]) if row else None


async def touch_api_key(key: str) -> None:
    async with get_session_factory()() as s:
        res = await s.execute(select(ApiKey).where(ApiKey.key == key))
        k = res.scalars().first()
        if k:
            k.last_used_at = _now()
            await s.commit()


# ---------------------------------------------------------------- api usage


def _today() -> str:
    return _now().strftime("%Y-%m-%d")


async def get_api_usage(user_id: int, category: str) -> int:
    async with get_session_factory()() as s:
        res = await s.execute(select(ApiUsage).where(
            ApiUsage.user_id == user_id, ApiUsage.day == _today(),
            ApiUsage.category == category))
        row = res.scalars().first()
        return row.count if row else 0


async def incr_api_usage(user_id: int, category: str, by: int = 1) -> int:
    async with get_session_factory()() as s:
        res = await s.execute(select(ApiUsage).where(
            ApiUsage.user_id == user_id, ApiUsage.day == _today(),
            ApiUsage.category == category))
        row = res.scalars().first()
        if row is None:
            row = ApiUsage(user_id=user_id, day=_today(), category=category, count=by)
            s.add(row)
            try:
                await s.commit()
            except IntegrityError:
                await s.rollback()
                res = await s.execute(select(ApiUsage).where(
                    ApiUsage.user_id == user_id, ApiUsage.day == _today(),
                    ApiUsage.category == category))
                row = res.scalars().first()
                if row is None:
                    return by
        else:
            row.count = (row.count or 0) + by
            await s.commit()
        _fb_push("push_usage_bg", row)
        return row.count
