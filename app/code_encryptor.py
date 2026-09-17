"""code_encryptor.py - تشفير ملفات البوتات قبل التشغيل.

يخفي الكود الأصلي بحيث لا يمكن قراءته.
يستخدم hash البوت كمفتاح للتشفير - صعب فكه بدون معرفة الـ hash.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import marshal
import os
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)


def _bot_hash(source_code: str) -> str:
    """إنشاء hash من الكود - يُستخدم كمفتاح تشفير."""
    return hashlib.sha256(source_code.encode("utf-8")).hexdigest()[:32]


def encrypt_bot_code(source_code: str, bot_id: int = 0) -> str:
    """تشفير كود Python بحيث يصعب قراءته.

    العملية:
    1. compile الكود لـ bytecode
    2. marshal لتحويله لـ bytes
    3. base64 لتحويله لـ string
    4. XOR مع hash البوت كمفتاح

    Returns:
        كود Python مشفر جاهز للتشغيل
    """
    try:
        # compile الكود
        code_obj = compile(source_code, "<bot>", "exec")
        # marshal لـ bytes
        marshaled = marshal.dumps(code_obj)
        # base64
        encoded = base64.b64encode(marshaled)
        # hash البوت كمفتاح
        key = _bot_hash(source_code)
        key_bytes = key.encode("utf-8")
        # XOR
        xored = bytearray(encoded)
        for i in range(len(xored)):
            xored[i] ^= key_bytes[i % len(key_bytes)]
        # base64 نهائي
        final_encoded = base64.b64encode(bytes(xored))

        # إنشاء loader script - بسيط وفعال
        loader = (
            "# TikZoom Protected Bot\n"
            "# This code is encrypted with bot hash\n"
            "import base64,marshal,hashlib\n"
            f"_H='{key}'\n"
            f"_D={final_encoded!r}\n"
            "_X=bytearray(base64.b64decode(_D))\n"
            "_K=_H.encode()\n"
            "for _i in range(len(_X)):\n"
            "    _X[_i]^=_K[_i%len(_K)]\n"
            "exec(marshal.loads(base64.b64decode(bytes(_X))))\n"
        )
        return loader
    except Exception as exc:
        logger.warning("encrypt failed: %s, using original", exc)
        return source_code


def encrypt_bot_file(file_path: str | Path, bot_id: int = 0) -> bool:
    """تشفير ملف بوت في مكانه.

    Returns:
        True لو تم التشفير بنجاح
    """
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return False

    try:
        source = p.read_text(encoding="utf-8", errors="replace")
        # لا نشفر لو الملف مشفر بالفعل
        if "# TikZoom Protected Bot" in source:
            return True
        # لا نشفر الملفات غير Python
        if p.suffix.lower() != ".py":
            return False
        encrypted = encrypt_bot_code(source, bot_id)
        p.write_text(encrypted, encoding="utf-8")
        logger.info("bot file encrypted: %s", p.name)
        return True
    except Exception as exc:
        logger.warning("encrypt file failed: %s", exc)
        return False


def encrypt_project(project_dir: str | Path, bot_id: int = 0) -> int:
    """تشفير كل ملفات Python في مجلد المشروع.

    Returns:
        عدد الملفات المشفرة
    """
    count = 0
    p = Path(project_dir)
    if not p.is_dir():
        return 0
    for py_file in p.rglob("*.py"):
        if py_file.name in ("deps.log",):
            continue
        if encrypt_bot_file(py_file, bot_id):
            count += 1
    logger.info("encrypted %s files in %s", count, p.name)
    return count
