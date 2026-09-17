"""import_firebase_users.py - تحميل بيانات المستخدمين من Firebase.

يقوم بقراءة كل المستخدمين من Firebase Realtime Database
ويضيفهم لقاعدة البيانات المحلية لو مش موجودين.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# إضافة المسار
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

FIREBASE_DB_URL = "https://m-c-v-m-bot-default-rtdb.asia-southeast1.firebasedatabase.app"


async def fetch_all_users() -> dict:
    """جلب كل المستخدمين من Firebase."""
    url = f"{FIREBASE_DB_URL}/users.json"
    async with httpx.AsyncClient(timeout=120) as cli:
        resp = await cli.get(url)
        if resp.status_code != 200:
            logger.error(f"Firebase HTTP {resp.status_code}: {resp.text[:200]}")
            return {}
        return resp.json() or {}


async def import_users_to_db() -> dict:
    """إضافة المستخدمين لقاعدة البيانات المحلية."""
    # استيراد داخل الدالة عشان نستخدم venv السيرفر
    from app.db import User, get_session_factory
    from sqlalchemy import select
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    users_data = await fetch_all_users()
    if not users_data:
        return {"total": 0, "imported": 0, "skipped": 0, "errors": 0}

    stats = {"total": len(users_data), "imported": 0, "skipped": 0, "errors": 0}
    logger.info(f"Firebase users found: {stats['total']}")

    session_factory = get_session_factory()
    async with session_factory() as session:
        for uid_str, udata in users_data.items():
            try:
                uid = int(uid_str)
                # التحقق إن كان المستخدم موجود
                existing = await session.get(User, uid)
                if existing:
                    stats["skipped"] += 1
                    # تحديث آخر زيارة لو أحدث
                    last_seen_str = udata.get("last_seen", "")
                    if last_seen_str:
                        try:
                            last_seen = datetime.fromisoformat(
                                last_seen_str.replace("Z", "+00:00")
                            )
                            if not existing.last_seen or last_seen > existing.last_seen:
                                existing.last_seen = last_seen
                                existing.points = udata.get("points", existing.points)
                                existing.is_admin = udata.get("is_admin", existing.is_admin)
                                existing.is_vip = udata.get("is_vip", existing.is_vip)
                                existing.username = udata.get("username") or existing.username
                                existing.first_name = udata.get("first_name") or existing.first_name
                                existing.last_name = udata.get("last_name") or existing.last_name
                                existing.contact_phone = udata.get("contact_phone") or existing.contact_phone
                                stats["imported"] += 1
                        except (ValueError, TypeError):
                            pass
                    continue

                # إنشاء مستخدم جديد
                join_date_str = udata.get("join_date", "")
                last_seen_str = udata.get("last_seen", "")
                try:
                    join_date = datetime.fromisoformat(join_date_str.replace("Z", "+00:00")) if join_date_str else datetime.utcnow()
                except (ValueError, TypeError):
                    join_date = datetime.utcnow()
                try:
                    last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00")) if last_seen_str else datetime.utcnow()
                except (ValueError, TypeError):
                    last_seen = datetime.utcnow()

                new_user = User(
                    user_id=uid,
                    username=udata.get("username", ""),
                    first_name=udata.get("first_name", ""),
                    last_name=udata.get("last_name", ""),
                    language=udata.get("language", "ar"),
                    contact_phone=udata.get("contact_phone", ""),
                    is_admin=bool(udata.get("is_admin", False)),
                    is_vip=bool(udata.get("is_vip", False)),
                    is_banned=bool(udata.get("is_banned", False)),
                    points=udata.get("points", 0),
                    referral_code=udata.get("referral_code", ""),
                    suspicious_attempts=udata.get("suspicious_attempts", 0),
                    join_date=join_date,
                    last_seen=last_seen,
                )
                session.add(new_user)
                stats["imported"] += 1
                await session.commit()
                logger.info(f"Added user {uid}: @{udata.get('username', '-')}")

            except Exception as exc:
                stats["errors"] += 1
                logger.warning(f"Failed user {uid_str}: {exc}")
                await session.rollback()

    return stats


async def main():
    logger.info("=" * 60)
    logger.info("📦 Firebase Users Import")
    logger.info("=" * 60)

    stats = await import_users_to_db()

    logger.info("=" * 60)
    logger.info("📊 Import Summary:")
    logger.info(f"  Total in Firebase: {stats['total']}")
    logger.info(f"  Imported/Updated: {stats['imported']}")
    logger.info(f"  Already existed: {stats['skipped']}")
    logger.info(f"  Errors: {stats['errors']}")
    logger.info("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
