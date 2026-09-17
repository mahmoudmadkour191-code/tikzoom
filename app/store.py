"""store.py - نظام المتجر والهدايا اليومية.

يدير:
  - رفع ملفات المتجر من الأدمن (مع اسم وسعر)
  - شراء الملفات بالنقاط
  - الهدايا اليومية للمستخدمين (يتحكم بها الأدمن)
"""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import (
    ApprovalRequest,
    DailyGift,
    StoreItem,
    StorePurchase,
    User,
    get_session_factory,
)
from .repo import add_points, get_user

logger = logging.getLogger(__name__)


# ---------- المتجر ---------- #

async def add_store_item(*, name: str, description: str, file_path: str,
                          file_id: str, price: int, category: str = "general") -> StoreItem:
    """إضافة عنصر جديد للمتجر."""
    async with get_session_factory()() as s:
        item = StoreItem(
            name=name,
            description=description,
            file_path=file_path,
            file_id=file_id,
            price=price,
            category=category,
            is_active=True,
        )
        s.add(item)
        await s.commit()
        await s.refresh(item)
        logger.info("store item added: id=%s name=%s price=%s", item.id, name, price)
        return item


async def list_store_items(category: str | None = None, active_only: bool = True) -> list[StoreItem]:
    """عرض عناصر المتجر."""
    async with get_session_factory()() as s:
        stmt = select(StoreItem).order_by(StoreItem.created_at.desc())
        if active_only:
            stmt = stmt.where(StoreItem.is_active == True)  # noqa: E712
        if category:
            stmt = stmt.where(StoreItem.category == category)
        result = await s.execute(stmt.limit(100))
        return list(result.scalars().all())


async def get_store_item(item_id: int) -> StoreItem | None:
    """الحصول على عنصر بالمعرف."""
    async with get_session_factory()() as s:
        return await s.get(StoreItem, item_id)


async def delete_store_item(item_id: int) -> bool:
    """حذف عنصر من المتجر."""
    async with get_session_factory()() as s:
        item = await s.get(StoreItem, item_id)
        if not item:
            return False
        # حذف الملف من القرص
        try:
            p = Path(item.file_path)
            if p.exists():
                p.unlink()
        except Exception:
            pass
        await s.delete(item)
        await s.commit()
        return True


async def toggle_store_item(item_id: int, active: bool) -> bool:
    """تفعيل/تعطيل عنصر."""
    async with get_session_factory()() as s:
        item = await s.get(StoreItem, item_id)
        if not item:
            return False
        item.is_active = active
        await s.commit()
        return True


async def update_store_item_file_id(item_id: int, file_id: str) -> bool:
    """حفظ file_id بعد أول إرسال ناجح — لتسريع كل الإرسالات القادمة.

    بعد الرفع الأول من الملف المحلي يرجع تلجرام file_id جديد؛ حفظه يجعل
    إعادة التنزيل لاحقاً فورية بدون رفع الملف مرة أخرى.
    """
    if not file_id:
        return False
    async with get_session_factory()() as s:
        item = await s.get(StoreItem, item_id)
        if not item:
            return False
        item.file_id = file_id
        await s.commit()
        logger.info("store item %s: file_id saved for fast redelivery", item_id)
        return True


async def increment_store_downloads(item_id: int) -> None:
    """زيادة عداد التحميلات بعد إرسال ناجح."""
    async with get_session_factory()() as s:
        item = await s.get(StoreItem, item_id)
        if not item:
            return
        item.downloads = (item.downloads or 0) + 1
        await s.commit()


async def purchase_store_item(user_id: int, item_id: int) -> dict:
    """شراء عنصر من المتجر.

    Returns:
        dict with success, message, item (StoreItem | None)
    """
    user = await get_user(user_id)
    if not user:
        return {"success": False, "message": "المستخدم غير موجود"}

    item = await get_store_item(item_id)
    if not item or not item.is_active:
        return {"success": False, "message": "العنصر غير متاح"}

    if (user.points or 0) < item.price:
        return {
            "success": False,
            "message": f"نقاطك غير كافية. تحتاج {item.price} نقطة، لديك {user.points or 0}",
            "points_needed": item.price - (user.points or 0),
        }

    # خصم النقاط
    new_points = await add_points(user_id, -item.price)
    # تسجيل المشترى
    async with get_session_factory()() as s:
        purchase = StorePurchase(
            user_id=user_id,
            item_id=item_id,
            price_paid=item.price,
        )
        s.add(purchase)
        # زيادة عداد التحميلات
        item_db = await s.get(StoreItem, item_id)
        if item_db:
            item_db.downloads = (item_db.downloads or 0) + 1
        await s.commit()

    logger.info("purchase: user=%s item=%s price=%s new_points=%s",
                user_id, item_id, item.price, new_points)
    return {
        "success": True,
        "message": f"تم الشراء بنجاح! رصيدك المتبقي: {new_points} نقطة",
        "item": item,
        "new_points": new_points,
    }


async def has_user_purchased(user_id: int, item_id: int) -> bool:
    """هل اشترى المستخدم هذا العنصر من قبل؟"""
    async with get_session_factory()() as s:
        stmt = select(StorePurchase).where(
            StorePurchase.user_id == user_id,
            StorePurchase.item_id == item_id,
        )
        result = await s.execute(stmt)
        return result.scalars().first() is not None


# ---------- الهدايا اليومية ---------- #

async def claim_daily_gift(user_id: int) -> dict:
    """استلام الهدية اليومية.

    Returns:
        dict with success, message, points_earned, streak
    """
    today = dt.datetime.utcnow().strftime("%Y-%m-%d")
    yesterday = (dt.datetime.utcnow() - dt.timedelta(days=1)).strftime("%Y-%m-%d")

    async with get_session_factory()() as s:
        # التحقق من استلام الهدية اليوم
        stmt_today = select(DailyGift).where(
            DailyGift.user_id == user_id,
            DailyGift.gift_date == today,
        )
        existing = (await s.execute(stmt_today)).scalars().first()
        if existing:
            return {
                "success": False,
                "message": "لقد استلمت هديتك اليومية بالفعل! عُد غداً.",
            }

        # قراءة عدد النقاط من الإعدادات
        from .repo import get_setting
        base_points = int(await get_setting("daily_gift_points", "10"))
        bonus_streak = int(await get_setting("daily_gift_streak_bonus", "5"))
        max_streak = int(await get_setting("daily_gift_max_streak", "7"))

        # التحقق من Streak (الأيام المتتالية)
        stmt_yesterday = select(DailyGift).where(
            DailyGift.user_id == user_id,
            DailyGift.gift_date == yesterday,
        )
        yesterday_gift = (await s.execute(stmt_yesterday)).scalars().first()

        if yesterday_gift:
            new_streak = min(yesterday_gift.streak + 1, max_streak)
        else:
            new_streak = 1

        # حساب النقاط (base + bonus * streak)
        bonus = bonus_streak * (new_streak - 1)
        total_points = base_points + bonus

        # حفظ الهدية
        gift = DailyGift(
            user_id=user_id,
            gift_date=today,
            points_earned=total_points,
            streak=new_streak,
        )
        s.add(gift)
        await s.commit()

    # إضافة النقاط للمستخدم
    new_total = await add_points(user_id, total_points)
    logger.info("daily gift claimed: user=%s points=%s streak=%s total=%s",
                user_id, total_points, new_streak, new_total)

    return {
        "success": True,
        "message": f"🎉 حصلت على {total_points} نقطة!",
        "points_earned": total_points,
        "streak": new_streak,
        "new_total": new_total,
    }


async def get_user_streak(user_id: int) -> int:
    """الحصول على streak المستخدم الحالي."""
    today = dt.datetime.utcnow().strftime("%Y-%m-%d")
    yesterday = (dt.datetime.utcnow() - dt.timedelta(days=1)).strftime("%Y-%m-%d")
    async with get_session_factory()() as s:
        # لو استلم اليوم، نرجع streak اليوم
        stmt = select(DailyGift).where(
            DailyGift.user_id == user_id,
            DailyGift.gift_date.in_([today, yesterday]),
        ).order_by(DailyGift.gift_date.desc())
        result = await s.execute(stmt.limit(1))
        gift = result.scalars().first()
        if gift:
            if gift.gift_date == today:
                return gift.streak
            elif gift.gift_date == yesterday:
                # لو آخر مرة كانت امبارح، الـ streak متاح للاستمرار
                return gift.streak
        return 0


async def can_claim_daily(user_id: int) -> bool:
    """هل يمكن للمستخدم استلام الهدية اليومية؟"""
    today = dt.datetime.utcnow().strftime("%Y-%m-%d")
    async with get_session_factory()() as s:
        stmt = select(DailyGift).where(
            DailyGift.user_id == user_id,
            DailyGift.gift_date == today,
        )
        result = await s.execute(stmt)
        return result.scalars().first() is None


# ---------- طابور الموافقات ---------- #

async def create_approval_request(*, user_id: int, file_name: str, file_path: str,
                                    file_id: str, language: str,
                                    security_risks: list, ai_report: str,
                                    ai_safe: bool, ai_confidence: int) -> int:
    """إنشاء طلب موافقة جديد."""
    import json
    async with get_session_factory()() as s:
        req = ApprovalRequest(
            user_id=user_id,
            file_name=file_name,
            file_path=file_path,
            file_id=file_id,
            language=language,
            security_risks=json.dumps(security_risks, ensure_ascii=False),
            ai_report=ai_report,
            ai_safe=ai_safe,
            ai_confidence=ai_confidence,
            status="pending",
        )
        s.add(req)
        await s.commit()
        await s.refresh(req)
        logger.info("approval request created: id=%s user=%s file=%s", req.id, user_id, file_name)
        return req.id


async def list_pending_approvals(limit: int = 20) -> list[ApprovalRequest]:
    """عرض الطلبات المعلقة."""
    async with get_session_factory()() as s:
        stmt = select(ApprovalRequest).where(
            ApprovalRequest.status == "pending"
        ).order_by(ApprovalRequest.created_at.desc()).limit(limit)
        result = await s.execute(stmt)
        return list(result.scalars().all())


async def get_approval_request(req_id: int) -> ApprovalRequest | None:
    async with get_session_factory()() as s:
        return await s.get(ApprovalRequest, req_id)


async def review_approval_request(req_id: int, *, approved: bool, reviewer_id: int) -> ApprovalRequest | None:
    """موافقة أو رفض طلب."""
    async with get_session_factory()() as s:
        req = await s.get(ApprovalRequest, req_id)
        if not req or req.status != "pending":
            return None
        req.status = "approved" if approved else "rejected"
        req.reviewed_by = reviewer_id
        req.reviewed_at = dt.datetime.utcnow()
        await s.commit()
        await s.refresh(req)
        return req
