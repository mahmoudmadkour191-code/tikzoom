"""security_scan.py — نظام الحماية الذكي بطبقتين لمنصة TikZoom.

[الطبقة 1] فحص أمان أساسي (ثابت، بدون تنفيذ الملف):
  - ضرر للسيرفر: os.system / subprocess / rm -rf / shutdown / mkfs
  - سرقة ملفات: .env / platform.db / مفاتيح SSH / /etc/passwd / firebase keys
  - path traversal: ../ أو مسارات مطلقة خارج صندوق الرمل
  - سحب بيانات: POST بملفات/بيانات إلى مواقع مشبوهة (webhook.site وغيرها)

[الطبقة 2] فحص AI يفهم وظيفة البوت:
  - AI يقرأ الكود ويفهم وظيفته الفعلية
  - يحكم: هل يضر السيرفر؟ هل يسحب ملفات المنصة؟
  - غير قانوني لكن لا يضر السيرفر → يعدّيه (allow)
  - يضر السيرفر → يرفضه (reject)
  - غير متأكد → يرفعه للأدمن (review)

النتيجة النهائية (SmartVerdict):
  - run      → آمن، يشغّل فوراً
  - reject   → ضرر واضح، رفض + إبلاغ الأدمن
  - review   → مشبوه، يُرسل للأدمن مع تقرير AI

التوافق الخلفي: الدوال القديمة scan_file / scan_text / ScanResult /
ai_review ما زالت تعمل بنفس التوقيعات حتى لا تنكسر بقية المنصة.
"""
from __future__ import annotations

import ast
import base64
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# ==================================================================== #
# [الطبقة 1] — أنماط الفحص الثابت المصنفة حسب نوع التهديد              #
# ==================================================================== #

# --- 1) ضرر مباشر للسيرفر (block) --- #
_SERVER_HARM_PATTERNS = [
    re.compile(r"(?i)\bos\.system\s*\("),
    re.compile(r"(?i)\bos\.popen\s*\("),
    re.compile(r"(?i)\bsubprocess\.(?:run|Popen|call|check_output|check_call|getoutput|getstatusoutput)\s*\("),
    re.compile(r"(?i)\bcommands\.get(?:output|statusoutput)\s*\("),
    re.compile(r"(?i)\bos\.exec[lv]\w*\s*\("),          # os.execv / os.execl ...
    re.compile(r"(?i)\bos\.spawn[lv]\w*\s*\("),          # os.spawnv ...
    re.compile(r"(?i)\bos\.fork(?:pty)?\s*\("),
    re.compile(r"(?i)\basyncio\.create_subprocess_(?:exec|shell)\s*\("),
    # أوامر تخريبية داخل نصوص
    re.compile(r"(?i)['\"]\s*rm\s+(-[a-z]+\s+)*-[a-z]*r[a-z]*[f v]*\s"),
    re.compile(r"(?i)rm\s+-rf\s+/(?:\s|$|home|etc|var|usr|root|boot)"),
    re.compile(r"(?i)\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b"),
    re.compile(r"(?i)\bmkfs\.\w+\b"),
    re.compile(r"(?i)\bdd\s+if="),
    re.compile(r"(?i):\(\)\s*\{\s*:\|:&\s*\};:"),        # fork bomb
    re.compile(r"(?i)\bcrontab\s+[-lre]"),
    re.compile(r"(?i)/etc/(?:systemd|cron|sudoers|passwd|shadow)"),
    re.compile(r"(?i)\bchmod\s+[0-7]{3,4}\s+/"),
    re.compile(r"(?i)\bchown\s+\w+\s+/"),
    re.compile(r"(?i)\bshutil\.rmtree\s*\(\s*['\"]/(?:home|etc|var|usr|root)"),
    re.compile(r"(?i)\bos\.kill(?:pg)?\s*\(\s*(?:1\b|os\.getppid)"),
    re.compile(r"(?i)\bresource\.setrlimit\s*\("),
    re.compile(r"(?i)\bsignal\.(?:SIGKILL|SIGSTOP)\b"),
    re.compile(r"(?i)\bmultiprocessing\.\w*Process\s*\("),
    re.compile(r"(?i)\bpty\.spawn\s*\("),
]

# --- 2) سرقة ملفات وأسرار المنصة (block) --- #
_SECRET_THEFT_PATTERNS = [
    re.compile(r"(?i)platform\.db"),
    re.compile(r"(?i)(?<![a-z])\.env(?![a-z])"),          # .env وليس .envoy
    re.compile(r"(?i)\.ssh[\\/]"),
    re.compile(r"(?i)\bid_rsa(?:\.pub)?\b"),
    re.compile(r"(?i)\bid_ed25519(?:\.pub)?\b"),
    re.compile(r"(?i)\bid_ecdsa(?:\.pub)?\b"),
    re.compile(r"(?i)/etc/(?:passwd|shadow|hosts|sudoers)"),
    re.compile(r"(?i)/proc/(?:self|\d+)/environ"),
    re.compile(r"(?i)/proc/\d+/cmdline"),
    re.compile(r"(?i)firebase[_-]?service[_-]?account"),
    re.compile(r"(?i)\bservice[_-]?account\.json\b"),
    re.compile(r"(?i)credentials\.json"),
    re.compile(r"(?i)\.aws[\\/]"),
    re.compile(r"(?i)\.google[_-]?credentials"),
    re.compile(r"(?i)token_hash|token_encrypted|fernet[_-]?key|webhook[_-]?secret"),
    re.compile(r"(?i)bots[_-]?storage"),
    re.compile(r"(?i)tikzoom[-_]?bot[-_]?host"),
    re.compile(r"(?i)c:[\\/]+tikzoom"),
    re.compile(r"(?i)windows[\\/]+system32[\\/]+config"),
    re.compile(r"(?i)appdata[\\/]+(?:roaming|local)"),
    re.compile(r"(?i)\bkeychain\b|\bkeytar\b"),
    re.compile(r"(?i)\bssh[_-]?agent\b"),
    re.compile(r"(?i)\bgnome[_-]?keyring\b"),
    re.compile(r"(?i)\bnetrc\b"),
    re.compile(r"(?i)\.npmrc|\.pypirc"),                  # مفاتيح سجل الحزم
    re.compile(r"(?i)\bAWS_ACCESS_KEY_ID\b|\bAWS_SECRET_ACCESS_KEY\b"),
    re.compile(r"(?i)\bGITHUB_TOKEN\b|\bGITLAB_TOKEN\b|\bOPENAI_API_KEY\b|\bANTHROPIC_API_KEY\b"),
]

# --- 3) تجاوز مسارات الصندوق (block) --- #
_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"(?i)['\"]/home/\w+"),
    re.compile(r"(?i)['\"]/root[\\/]"),
    re.compile(r"(?i)['\"]/etc/"),
    re.compile(r"(?i)['\"]/var/(?:log|lib|spool)"),
    re.compile(r"(?i)['\"]/opt/"),
    re.compile(r"(?i)['\"]/srv/"),
    re.compile(r"(?i)['\"]/boot/"),
    re.compile(r"(?i)['\"]/dev/(?:sd|nvme|disk)"),
    re.compile(r"(?i)['\"]C:[\\/]+Users[\\/]"),
    re.compile(r"(?i)Path\.cwd\(\)\.parent"),
    re.compile(r"(?i)Path\(['\"]\.\./"),
    re.compile(r"(?i)\bopen\s*\(\s*['\"]\.\./"),
]

# --- 4) سحب بيانات للخارج (block عند نقاط نهاية معروفة، warn للبقية) --- #
_EXFIL_URL_PATTERN = re.compile(
    r"(?i)https?://"
    r"(?:[a-z0-9-]+\.)*"
    r"(?:webhook\.site|requestbin(?:\.com)?|pipedream\.net|ngrok(?:\.io|\.pro|\.dev)?[\"'/\s]|"
    r"discord(?:app)?\.com/api/webhooks|transfer\.sh|filebin\.net|file\.io|0x0\.st|"
    r"paste\.ee|pastebin\.com|dpaste\.(?:com|org)|hastebin|termbin\.com|"
    r"jsonbin\.org|api\.npoint\.io|pastes?\.io|ghostbin\.com|walkox\.com)"
)

_EXFIL_ENDPOINT_HOSTS = re.compile(
    r"(?i)(webhook\.site|requestbin|pipedream|ngrok|discord(?:app)?\.com/api/webhooks|"
    r"transfer\.sh|filebin|file\.io|0x0\.st|paste\.ee|pastebin\.com|dpaste|hastebin|jsonbin|npoint)"
)

# POST بحِمل بيانات/ملفات إلى وجهة خارجية (warn — الـ AI يفحص الوجهة)
_EXFIL_POST_PATTERNS = [
    re.compile(r"(?i)requests\.post\s*\([^)]*(?:files\s*=|data\s*=|json\s*=)"),
    re.compile(r"(?i)httpx\.post\s*\([^)]*(?:files\s*=|data\s*=|json\s*=)"),
    re.compile(r"(?i)aiohttp[^)]*\.post\s*\([^)]*(?:files\s*=|data\s*=)"),
    re.compile(r"(?i)\bsession\.post\s*\([^)]*(?:files\s*=|data\s*=)"),
    re.compile(r"(?i)urllib\.request\.urlopen\s*\([^)]*Request\s*\("),
    re.compile(r"(?i)\bcurl\s+[^;'\"]*-d\b"),
    re.compile(r"(?i)\bwget\s+[^;'\"]*--post"),
]

# --- 5) تشويش/إخفاء كود (warn — يتصاعد block إذا اقترن بـ exec) --- #
_OBFUSCATION_PATTERNS = [
    re.compile(r"(?i)\bbase64\.b64decode\s*\("),
    re.compile(r"(?i)\bbase64\.urlsafe_b64decode\s*\("),
    re.compile(r"(?i)\bbase64\.decodebytes\s*\("),
    re.compile(r"(?i)\bbinascii\.unhexlify\s*\("),
    re.compile(r"(?i)\bbytes\.fromhex\s*\("),
    re.compile(r"(?i)\bbytearray\.fromhex\s*\("),
    re.compile(r"(?i)\bzlib\.decompress\s*\("),
    re.compile(r"(?i)\bgzip\.decompress\s*\("),
    re.compile(r"(?i)\blzma\.decompress\s*\("),
    re.compile(r"(?i)\bbz2\.decompress\s*\("),
    re.compile(r"(?i)\bcodecs\.decode\s*\("),
    re.compile(r"(?i)\brozlipt?\.decompress\s*\("),
    re.compile(r"(?i)\bmarshal\.loads?\s*\("),
    re.compile(r"(?i)\bpickle\.loads?\s*\("),
    re.compile(r"(?i)\bdill\.loads?\s*\("),
    re.compile(r"(?i)\bshelve\.open\s*\("),
    re.compile(r"(?i)\bexec\s*\("),
    re.compile(r"(?i)\beval\s*\("),
    re.compile(r"(?i)\bcompile\s*\("),
    re.compile(r"(?i)\b__import__\s*\("),
    re.compile(r"(?i)\bimportlib\.import_module\s*\("),
    re.compile(r"(?i)\bgetattr\s*\(\s*(?:__builtins__|builtins)\s*,"),
    re.compile(r"(?i)\bglobals\s*\(\s*\)\s*\["),
    re.compile(r"(?i)\bxor_(?:decrypt|cipher)\b"),
    re.compile(r"(?i)\brot13\b"),
    re.compile(r"(?i)\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){8,}"),  # سلاسل hex طويلة
    re.compile(r"(?i)['\"][A-Za-z0-9+/=]{200,}['\"]"),        # base64 عملاق
]

# --- 6) استكشاف النظام (warn — غير ضار داخل الصندوق لكنه للمراقبة) --- #
_RECON_PATTERNS = [
    re.compile(r"(?i)\bpsutil\.\w+"),
    re.compile(r"(?i)\bos\.getuid\s*\(|\bos\.getgid\s*\(|\bos\.geteuid\s*\("),
    re.compile(r"(?i)\bgetpass\.getuser\s*\(|\bos\.getlogin\s*\("),
    re.compile(r"(?i)\bpwd\.getpwuid\s*\(|\bpwd\.getpwnam\s*\(|\bgrp\.getgrnam\s*\("),
    re.compile(r"(?i)\bplatform\.node\s*\(|\bplatform\.platform\s*\(|\bplatform\.system\s*\("),
    re.compile(r"(?i)\bsocket\.gethostname\s*\(|\bsocket\.gethostbyname(?:_ex)?\s*\(|\bsocket\.getfqdn\s*\("),
    re.compile(r"(?i)\bos\.uname\s*\(|\bos\.cpu_count\s*\(|\bos\.getloadavg\s*\("),
    re.compile(r"(?i)\bnetifaces\.\w+|\bifcfg\.\w+|\bdns\.resolver\b|\bdnspython\b"),
    re.compile(r"(?i)\bos\.listdir\s*\(|\bos\.walk\s*\(|\bos\.scandir\s*\(|\bglob\.glob\s*\("),
    re.compile(r"(?i)\bos\.getcwd\s*\(|\bos\.getpid\s*\(|\bos\.getppid\s*\("),
    re.compile(r"(?i)\bos\.name\b|\bsys\.platform\b"),
    re.compile(r"(?i)\bmmap\s*\(|\bctypes\.memmove\b"),
    re.compile(r"(?i)\bssl\.create_default_context\b|\bssl\.wrap_socket\b"),
]

# --- 7) وحدات بايثون محظورة تماماً (block) --- #
_BLOCKING_PYTHON_MODULES = {
    "ctypes", "cffi",
    "winreg", "_winreg", "win32api", "win32con", "win32security",
    "win32process", "pywintypes", "pythoncom",
    "paramiko", "fabric", "smbprotocol", "telnetlib", "pexpect",
    "pyautogui", "pyHook", "pynput",          # مراقبة إدخال
    "keyring", "keyrings",
    "pythoncom", "SystemRegistry",
}

# وحدات مشروعة لكن تستدعي مراجعة بشرية (warn)
_REVIEW_PYTHON_MODULES = {"socket", "ftplib", "psutil", "netifaces", "serial", "usb"}

# استدعاءات مدمجة ممنوعة (AST)
_FORBIDDEN_PYTHON_BUILTINS = {"eval", "exec", "compile", "__import__", "execfile", "breakpoint"}

# سلاسل وصول تشير لتشويش
_OBFUSCATION_ATTR_CHAINS = {
    ("importlib", "import_module"),
    ("importlib", "__import__"),
    ("marshal", "loads"),
    ("pickle", "loads"),
    ("dill", "loads"),
    ("base64", "b64decode"),
    ("zlib", "decompress"),
    ("codecs", "decode"),
}

# --- 8) أنماط Node.js --- #
_NODE_PATTERNS = [
    (re.compile(r"\brequire\s*\(\s*['\"]child_process['\"]\s*\)"), "تشغيل عمليات نظام Node (child_process)"),
    (re.compile(r"\brequire\s*\(\s*['\"](?:fs|os|net|tls|dgram|dns)['\"]\s*\)"), "وحدة Node حساسة"),
    (re.compile(r"\bprocess\.env\.(?!BOT_TOKEN|PORT|WEBHOOK_URL|WEBHOOK_PATH|PLATFORM)[A-Z_][A-Z0-9_]*"), "قراءة متغير بيئة غير مخصص للبوت"),
    (re.compile(r"\beval\s*\("), "استدعاء eval()"),
    (re.compile(r"\bnew\s+Function\s*\("), "استخدام new Function()"),
    (re.compile(r"\bBuffer\.from\s*\([^)]*['\"],\s*['\"]base64['\"]\s*\)"), "فك تشفير base64"),
    (re.compile(r"\bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\("), "تنفيذ أوامر شل"),
    (re.compile(r"\brequire\s*\(\s*['\"]https?['\"]\s*\)\.request"), "اتصال HTTP خام"),
]

# --- 9) أنماط PHP --- #
_PHP_PATTERNS = [
    (re.compile(r"\b(?:eval|assert|create_function)\s*\("), "استدعاء eval-equivalent في PHP"),
    (re.compile(r"\b(?:system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\("), "تنفيذ أوامر شل PHP"),
    (re.compile(r"\b(?:file_get_contents|fopen|readfile|file)\s*\(\s*['\"][^'\"]*(?:\.\.|/etc/|c:\\|tikzoom)", re.I), "قراءة خارج صندوق الرمل"),
    (re.compile(r"\bgetenv\s*\(\s*['\"](?!BOT_TOKEN|PORT|WEBHOOK_URL|WEBHOOK_PATH|PLATFORM)"), "قراءة متغير بيئة غير مخصص"),
    (re.compile(r"\$_(?:SERVER|ENV)\b"), "الوصول لمتغيرات السيرفر العامة"),
    (re.compile(r"\bbase64_decode\s*\("), "فك تشفير base64"),
    (re.compile(r"\bpassthru\s*\(|\bpopen\s*\("), "تنفيذ أوامر شل"),
    (re.compile(r"\bopcache_invalidate|\bauto_prepend_file"), "تلاعب بمحرك PHP"),
]


def _count_patterns() -> int:
    n = 0
    for lst in (_SERVER_HARM_PATTERNS, _SECRET_THEFT_PATTERNS, _PATH_TRAVERSAL_PATTERNS,
                _EXFIL_POST_PATTERNS, _OBFUSCATION_PATTERNS, _RECON_PATTERNS,
                _NODE_PATTERNS, _PHP_PATTERNS):
        n += len(lst)
    n += len(_BLOCKING_PYTHON_MODULES) + len(_REVIEW_PYTHON_MODULES) + len(_FORBIDDEN_PYTHON_BUILTINS)
    return n


PATTERN_COUNT = _count_patterns()


# ==================================================================== #
# نتائج الفحص                                                          #
# ==================================================================== #

@dataclass
class ScanResult:
    """Summary of a single static-analysis pass over an uploaded bot file."""

    safe: bool = True
    risks: list[str] = field(default_factory=list)
    severity: str = "ok"  # ok | warn | block

    def add(self, risk: str, *, severity: str = "block") -> None:
        self.risks.append(risk)
        # Severity ratchets up but never down.
        order = {"ok": 0, "warn": 1, "block": 2}
        if order[severity] > order[self.severity]:
            self.severity = severity
        if severity == "block":
            self.safe = False

    def merge(self, other: "ScanResult") -> None:
        for r in other.risks:
            self.risks.append(r)
        order = {"ok": 0, "warn": 1, "block": 2}
        if order[other.severity] > order[self.severity]:
            self.severity = other.severity
        if not other.safe:
            self.safe = False

    def summary(self) -> str:
        if self.safe and not self.risks:
            return "ملف نظيف."
        lines = ["تم اكتشاف المخاطر الآتية في الملف:"]
        for r in self.risks[:20]:
            lines.append(f"  • {r}")
        if len(self.risks) > 20:
            lines.append(f"  • ... و{len(self.risks) - 20} نتيجة أخرى")
        return "\n".join(lines)


# إجراءات القرار النهائي
ACTION_RUN = "run"          # آمن → تشغيل فوراً
ACTION_REJECT = "reject"    # ضرر واضح → رفض + إبلاغ الأدمن
ACTION_REVIEW = "review"    # مشبوه → عرض على الأدمن مع تقرير AI

_SEVERITY_ACTION = {"ok": ACTION_RUN, "warn": ACTION_REVIEW, "block": ACTION_REJECT}


@dataclass
class SmartVerdict:
    """قرار الحماية الذكي النهائي بعد الطبقتين."""

    action: str = ACTION_RUN            # run | reject | review
    layer1: ScanResult = field(default_factory=ScanResult)
    ai_used: bool = False
    ai_action: str | None = None        # allow | reject | review (قرار الـ AI)
    ai_confidence: int = 0              # 0..100
    ai_report: str = ""                 # تقرير AI نصي
    bot_function: str = ""              # وظيفة البوت كما فهمها الـ AI

    @property
    def severity(self) -> str:
        return self.layer1.severity

    @property
    def risks(self) -> list[str]:
        return self.layer1.risks

    @property
    def safe(self) -> bool:
        return self.action == ACTION_RUN

    def summary(self) -> str:
        icon = {ACTION_RUN: "✅", ACTION_REJECT: "❌", ACTION_REVIEW: "📋"}
        lines = [f"{icon.get(self.action, '•')} القرار: {self.action}"]
        if self.layer1.risks:
            lines.append("🛡️ الطبقة 1 (فحص ثابت):")
            lines += [f"  • {r}" for r in self.layer1.risks[:10]]
        if self.ai_used:
            lines.append(f"🤖 الطبقة 2 (AI): {self.ai_action} (ثقة {self.ai_confidence}%)")
            if self.bot_function:
                lines.append(f"  وظيفة البوت: {self.bot_function}")
            if self.ai_report:
                lines.append(f"  {self.ai_report[:400]}")
        return "\n".join(lines)


# ==================================================================== #
# محرك الفحص الثابت — الطبقة 1                                         #
# ==================================================================== #

def _scan_lists(text: str, result: ScanResult) -> None:
    for pat in _SERVER_HARM_PATTERNS:
        m = pat.search(text)
        if m:
            result.add(f"ضرر للسيرفر: نمط خطير «{_short(m.group(0))}»", severity="block")
    for pat in _SECRET_THEFT_PATTERNS:
        m = pat.search(text)
        if m:
            result.add(f"سرقة أسرار/ملفات: «{_short(m.group(0))}»", severity="block")
    for pat in _PATH_TRAVERSAL_PATTERNS:
        m = pat.search(text)
        if m:
            result.add(f"تجاوز مسار: «{_short(m.group(0))}»", severity="block")
    for pat in _EXFIL_POST_PATTERNS:
        m = pat.search(text)
        if m:
            result.add(f"إرسال بيانات للخارج: «{_short(m.group(0))}»", severity="warn")
    for pat in _OBFUSCATION_PATTERNS:
        m = pat.search(text)
        if m:
            result.add(f"تشويش كود: «{_short(m.group(0))}»", severity="warn")
    for pat in _RECON_PATTERNS:
        m = pat.search(text)
        if m:
            result.add(f"استكشاف نظام: «{_short(m.group(0))}»", severity="warn")
    m = _EXFIL_URL_PATTERN.search(text)
    if m:
        result.add(f"نقطة نهاية مشبوهة لسحب البيانات: «{_short(m.group(0))}»", severity="block")


def scan_text(text: str, language: str) -> ScanResult:
    """فحص ثابت لنص الكود (الطبقة 1 فقط — بدون AI)."""
    result = ScanResult()
    if not text:
        return result
    _scan_lists(text, result)
    # إسكات التشويش إذا لم يقترن بتنفيذ أو استخراج — يبقى warn على أي حال.
    if language == "python":
        _scan_python(text, result)
    elif language == "node":
        for pat, msg in _NODE_PATTERNS:
            if pat.search(text):
                sev = "block" if ("child_process" in msg or "شل" in msg) else "warn"
                result.add(f"Node: {msg}", severity=sev)
    elif language == "php":
        for pat, msg in _PHP_PATTERNS:
            if pat.search(text):
                sev = "block" if ("شل" in msg or "خارج" in msg) else "warn"
                result.add(f"PHP: {msg}", severity=sev)
    return result


def scan_file(path: str | Path, language: str) -> ScanResult:
    """فحص ثابت لملف مرفوع (الطبقة 1 فقط — بدون AI)."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result = ScanResult()
        result.add(f"تعذر قراءة الملف للفحص: {exc}", severity="warn")
        return result
    result = scan_text(text, language)
    # فحص طبقات إضافية: base64 عملاق داخل الكود أو ترويسات تنفيذية مخفية
    result.merge(_scan_encoded_chunks(text))
    return result


def _scan_encoded_chunks(text: str) -> ScanResult:
    """فكّ سلاسل base64 الطويلة والبحث فيها عن أنماط خطيرة."""
    result = ScanResult()
    for m in re.finditer(r"['\"]([A-Za-z0-9+/=]{60,})['\"]", text):
        chunk = m.group(1)
        try:
            decoded = base64.b64decode(chunk + "=" * (-len(chunk) % 4),
                                       validate=False).decode("utf-8", "ignore")
        except Exception:
            continue
        if not decoded:
            continue
        for pat in _SERVER_HARM_PATTERNS:
            if pat.search(decoded):
                result.add("محتوى مشفر يحتوي أوامر ضرر للسيرفر", severity="block")
                return result
        for pat in _SECRET_THEFT_PATTERNS:
            if pat.search(decoded):
                result.add("محتوى مشفر يحاول قراءة أسرار المنصة", severity="block")
                return result
        if _EXFIL_URL_PATTERN.search(decoded):
            result.add("محتوى مشفر يرسل بيانات لنقطة نهاية مشبوهة", severity="block")
            return result
    return result


# -------------------- AST scanner for Python -------------------- #

def _flat_name(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return parts[-1] if parts else ""


def _lit_str(node: ast.AST) -> str:
    """أول نص حرفي داخل التعبير (إن وجد)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                return v.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _lit_str(node.left)
    return ""


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, result: ScanResult) -> None:
        self.result = result

    # --- imports --- #
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in _BLOCKING_PYTHON_MODULES:
                self.result.add(f"استيراد وحدة محظورة: {alias.name}", severity="block")
            elif root in _REVIEW_PYTHON_MODULES:
                self.result.add(f"استيراد وحدة للمراجعة: {alias.name}", severity="warn")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        root = (node.module or "").split(".")[0]
        if root in _BLOCKING_PYTHON_MODULES:
            self.result.add(f"استيراد وحدة محظورة: from {node.module}", severity="block")
        elif root in _REVIEW_PYTHON_MODULES:
            self.result.add(f"استيراد وحدة للمراجعة: from {node.module}", severity="warn")
        self.generic_visit(node)

    # --- calls --- #
    def visit_Call(self, node: ast.Call) -> None:
        name = _flat_name(node.func)
        root = name.split(".")[0]

        # ضرر مباشر
        if root == "os" and name.split(".")[-1].startswith(("system", "popen", "exec", "spawn", "fork")):
            self.result.add(f"تنفيذ أوامر نظام: {name}()", severity="block")
        if root == "subprocess":
            self.result.add(f"استدعاء subprocess: {name}()", severity="block")
        if root == "asyncio" and "subprocess" in name:
            self.result.add(f"تشغيل عملية فرعية: {name}()", severity="block")

        # مدمجات ممنوعة
        if name in _FORBIDDEN_PYTHON_BUILTINS:
            self.result.add(f"استدعاء مدمجة خطيرة: {name}()", severity="warn")
            # eval/exec مع سلاسل مشفرة → block
            for arg in node.args:
                src = ast.dump(arg) if not isinstance(arg, ast.Constant) else ""
                if src and ("base64" in src or "decode" in src or "BinOp" in src):
                    self.result.add("تشويش مغلف بـ eval/exec", severity="block")

        # سحب كل متغيرات البيئة
        if name in {"os.environ.items", "os.environ.values", "os.environ.keys"}:
            self.result.add("سحب جميع متغيرات البيئة", severity="block")
        if name == "os.getenv" or name == "os.environ.get":
            arg0 = _lit_str(node.args[0]) if node.args else ""
            allowed = {"BOT_TOKEN", "PORT", "WEBHOOK_URL", "WEBHOOK_PATH", "PLATFORM",
                       "ADMIN_ID", "TMPDIR", "HOME", "PYTHONUNBUFFERED"}
            if arg0 and arg0 not in allowed and not arg0.startswith(("TIKZOOM_", "BOT_", "ADMIN_")):
                self.result.add(f"قراءة متغير بيئة غير مخصص: {arg0}", severity="warn")

        # POST بحِمل للخارج
        if name.endswith(("post", ".post")):
            kw_names = {k.arg for k in node.keywords}
            if kw_names & {"files", "data"}:
                self.result.add(f"إرسال بيانات/ملفات عبر POST: {name}()", severity="warn")

        # فتح ملفات خارج الصندوق
        if name == "open" and node.args:
            target = _lit_str(node.args[0])
            if target:
                for pat in _PATH_TRAVERSAL_PATTERNS + _SECRET_THEFT_PATTERNS[:20]:
                    try:
                        if pat.search(target):
                            self.result.add(f"فتح مسار محظور: {_short(target)}", severity="block")
                            break
                    except re.error:
                        continue

        self.generic_visit(node)


def _scan_python(text: str, result: ScanResult) -> None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return  # الكود غير صالح — فشل التشغيل لاحقاً يكفي
    _PyVisitor(result).visit(tree)


# -------------------- helpers -------------------- #

def _short(s: str, *, n: int = 60) -> str:
    s = s.replace("\n", " ").replace("\r", " ").strip()
    return s if len(s) <= n else s[:n] + "…"


# ==================================================================== #
# [الطبقة 2] فحص AI — يفهم وظيفة البوت ويحكم على نيته                  #
# ==================================================================== #

_AI_SECURITY_SYSTEM_PROMPT = (
    "أنت خبير أمني في منصة TikZoom لاستضافة بوتات تيليجرام داخل حاويات معزولة. "
    "مهمتك قراءة كود البوت وفهم وظيفته الفعلية ثم الحكم على نيته فقط من ناحية "
    "ضرره للسيرفر أو المنصة — وليس من ناحية قانونية استخدامه.\n\n"
    "قواعد الحكم:\n"
    "1. لو الكود يضر السيرفر أو المنصة (تنفيذ أوامر نظام، حذف ملفات، قراءة أسرار "
    "المنصة مثل platform.db أو .ssh، سحب ملفات المستخدمين، فيروسات، تعدين عملات، "
    "هجمات شبكات) → القرار: reject.\n"
    "2. لو الكود غير قانوني أو غير لائق (سبام، احتيال، محتوى مشبوه) لكنه لا يضر "
    "السيرفر ولا يسحب ملفات → القرار: allow مع ذكر الملاحظة في reasons.\n"
    "3. لو مش متأكد أو فيه مؤشرات تحتاج عين بشرية → القرار: review.\n\n"
    "ردّك JSON فقط بدون أي شرح إضافي:\n"
    '{"action": "allow|reject|review", "confidence": 0-100, '
    '"bot_function": "وصف وظيفة البوت في سطر واحد", '
    '"reasons": ["سبب 1", "سبب 2"]}'
)


async def ai_review(text: str, language: str,
                    layer1_risks: list[str] | None = None) -> ScanResult | None:
    """طبقة 2 — مراجعة AI. للتوافق الخلفي ترجع ScanResult.

    الاستخدام الجديد الموصى به: `ai_verdict()` لأنه يرجع تفاصيل أدق.
    """
    v = await ai_verdict(text, language, layer1_risks)
    if v is None:
        return None
    r = ScanResult(severity="ok" if v["action"] == "allow" else
                   ("block" if v["action"] == "reject" else "warn"))
    r.safe = v["action"] != "reject"
    for reason in v["reasons"]:
        r.add(f"AI: {reason}", severity=r.severity if r.severity != "ok" else "warn")
    return r


async def ai_verdict(text: str, language: str,
                     layer1_risks: list[str] | None = None) -> dict | None:
    """طبقة 2 — يرجع {"action", "confidence", "bot_function", "reasons"} أو None.

    المسار: Gemini API (gemini_guard.py) أولاً — إن فشل تماماً يُجرَّب
    بروكسي الـ AI القديم كاحتياطي أخير.
    """
    if not text:
        return None
    # 1) Gemini — النظام الأساسي المُعتمد
    try:
        from .gemini_guard import gemini_scan_text
        v = await gemini_scan_text(text, language, layer1_risks)
        if v is not None:
            return v
    except Exception as exc:  # noqa: BLE001
        logger.info("Gemini guard unavailable: %s", exc)

    # 2) احتياطي: بروكسي الـ AI القديم
    try:
        from .ai_assistant import chat
    except Exception as exc:  # noqa: BLE001
        logger.info("AI layer unavailable: %s", exc)
        return None

    risks_txt = "\n".join(f"- {r}" for r in (layer1_risks or [])) or "- لا مؤشرات ثابتة"
    instr = (
        f"افحص كود البوت التالي ({language}).\n\n"
        f"مؤشرات الفحص الثابت (الطبقة 1):\n{risks_txt}\n\n"
        "مهمتك: افهم وظيفة الكود وقرر إن كان يضر السيرفر أو يسحب ملفات أم لا.\n"
        "لاحظ: البوت يعمل داخل حاوية معزولة بمجلد /workspace فقط، و BOT_TOKEN "
        "متاح له شرعياً، وقراءة ملفاته هو يحتاجها (قاعدة بيانات، إعدادات) طبيعية.\n"
        "فك التشفير العادي للصور أو النصوص غير ضار. الأوامر التلقائية لتنزيل "
        "محتوى (يوتيوب مثلاً) داخل الحاوية مقبولة ما لم تنفذ أوامر نظام.\n\n"
        f"```{language}\n{text[:18000]}\n```"
    )
    try:
        reply = await chat(instr, timeout=90.0,
                           system=_AI_SECURITY_SYSTEM_PROMPT)
    except Exception as exc:  # noqa: BLE001
        logger.info("AI review skipped: %s", exc)
        return None

    obj = _extract_json(reply)
    if not isinstance(obj, dict) or "action" not in obj:
        return None
    action = str(obj.get("action", "review")).lower()
    if action not in {"allow", "reject", "review"}:
        action = "review"
    try:
        conf = int(obj.get("confidence") or 0)
    except (TypeError, ValueError):
        conf = 0
    conf = max(0, min(100, conf))
    return {
        "action": action,
        "confidence": conf,
        "bot_function": str(obj.get("bot_function") or "")[:200],
        "reasons": [str(x) for x in (obj.get("reasons") or [])][:8],
    }


def _extract_json(reply: str) -> object:
    """استخراج أول كائن JSON من رد الـ AI."""
    import json
    reply = reply.strip()
    # كتلة ```json ... ```
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", reply, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # أول { ... } متوازن
    start = reply.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(reply)):
        if reply[i] == "{":
            depth += 1
        elif reply[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(reply[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


# ==================================================================== #
# القرار الذكي الكامل — الطبقتان معاً                                  #
# ==================================================================== #

# ثقة الـ AI المطلوبة لتجاوز أو تأكيد الطبقة 1
_AI_CONFIDENCE_THRESHOLD = 70


async def smart_scan_file(path: str | Path, language: str) -> SmartVerdict:
    """فحص ذكي كامل لملف: طبقة 1 ثابتة + طبقة 2 AI عند الحاجة."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        layer1 = ScanResult()
        layer1.add(f"تعذر قراءة الملف: {exc}", severity="warn")
        return SmartVerdict(action=ACTION_REVIEW, layer1=layer1)
    return await smart_scan_text(text, language)


async def smart_scan_text(text: str, language: str) -> SmartVerdict:
    """فحص ذكي كامل لنص كود: طبقة 1 ثابتة + طبقة 2 AI عند الحاجة.

    المنطق:
      - طبقة 1 نظيفة            → run فوراً (بدون استدعاء AI — سريع)
      - طبقة 1 block (ضرر واضح) → AI للتأكيد:
            * AI allow بثقة ≥ 70  → run مع ملاحظة (غير قانوني لكن غير ضار)
            * AI reject بثقة ≥ 70 → reject
            * غير ذلك            → review
      - طبقة 1 warn (مشبوه)     → AI:
            * AI allow بثقة ≥ 70  → run
            * AI reject بثقة ≥ 70 → reject
            * غير ذلك            → review مع تقرير AI
    """
    layer1 = scan_text(text, language)

    # مسار سريع: نظيف تماماً → تشغيل فوري بدون AI
    if layer1.severity == "ok":
        return SmartVerdict(action=ACTION_RUN, layer1=layer1)

    # الطبقة 2: AI يفهم وظيفة البوت
    ai = await ai_verdict(text, language, layer1.risks)
    verdict = SmartVerdict(layer1=layer1, ai_used=ai is not None)
    if ai:
        verdict.ai_action = ai["action"]
        verdict.ai_confidence = ai["confidence"]
        verdict.bot_function = ai["bot_function"]
        verdict.ai_report = "؛ ".join(ai["reasons"])

        confident = ai["confidence"] >= _AI_CONFIDENCE_THRESHOLD
        if ai["action"] == "allow" and confident:
            verdict.action = ACTION_RUN
            if layer1.severity == "block":
                verdict.ai_report = ("AI أعاد الكود: لا ضرر فعلي للسيرفر. " +
                                     verdict.ai_report)
        elif ai["action"] == "reject" and confident:
            verdict.action = ACTION_REJECT
        else:
            verdict.action = ACTION_REVIEW
    else:
        # AI غير متاح → نلتزم بحكم الطبقة 1
        verdict.action = _SEVERITY_ACTION.get(layer1.severity, ACTION_REVIEW)

    return verdict

