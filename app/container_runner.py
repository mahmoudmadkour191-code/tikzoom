"""Rootless Podman runner for untrusted user projects.

This runner intentionally exposes only a small interface compatible with the
existing BotRunner. User code never runs as a host process: it runs in a
rootless container with a project-only writable mount, dropped capabilities,
no-new-privileges, a read-only image filesystem, resource limits, and no host
loopback access.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import get_settings
from .deps import sandbox_python_pip_targets

log = logging.getLogger(__name__)

# مفاتيح متغيرات البيئة المسموح تمريرها للبوت
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_IMAGES = {
    "python": os.environ.get("TIKZOOM_PYTHON_IMAGE", "localhost/tikzoom-python:3.12-common"),
    "node": "docker.io/library/node:22-slim",
    "php": "docker.io/library/php:8.3-cli",
}

# Packages already baked into the TikZoom Python image. They must not be
# downloaded again for every upload; project-specific packages remain covered
# by the automatic fallback installer below.
_BASE_PYTHON_PACKAGES = frozenset({
    "aiohttp", "aiosqlite", "aiogram", "python-dotenv", "requests",
    "pyTelegramBotAPI", "telethon", "kvsqlite", "flask", "beautifulsoup4",
    "PyYAML", "Pillow",
})

@dataclass
class RunResult:
    pid: int | None
    error: str | None

class ContainerRunner:
    def __init__(self) -> None:
        self._containers: dict[int, str] = {}
        self._log_tasks: dict[int, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    def is_running(self, bot_id: int) -> bool:
        name = self._containers.get(bot_id)
        if not name:
            return False
        # This is an in-process view; the service reconciles after restart.
        return True

    async def _podman(self, *args: str, timeout: float = 30.0,
                      detached: bool = False) -> tuple[int, str, str]:
        env = dict(os.environ)
        env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        p = await asyncio.create_subprocess_exec(
            "podman", *args, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=env,
        )
        try:
            if detached:
                # `podman run -d` exits before the container process. Waiting
                # for communicate() can hang because conmon may inherit the
                # pipe. Wait for Podman itself, then read the container id line.
                await asyncio.wait_for(p.wait(), timeout)
                out = await asyncio.wait_for(p.stdout.readline(), 2.0)
                try:
                    err = await asyncio.wait_for(p.stderr.read(), 2.0)
                except asyncio.TimeoutError:
                    err = b""
            else:
                out, err = await asyncio.wait_for(p.communicate(), timeout)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                p.kill()
            with contextlib.suppress(ProcessLookupError, asyncio.TimeoutError):
                await asyncio.wait_for(p.wait(), 5.0)
            return 124, "", "podman command timed out"
        return p.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    async def _follow_logs(self, bot_id: int, name: str, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("ab", buffering=0) as fp:
            env = dict(os.environ)
            env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
            p = await asyncio.create_subprocess_exec(
                "podman", "logs", "-f", name,
                stdout=fp, stderr=fp, env=env,
            )
            try:
                await p.wait()
            except asyncio.CancelledError:
                with contextlib.suppress(ProcessLookupError):
                    p.terminate()
                raise

    async def start(self, *, bot_id: int, language: str, file_path: str,
                    token: str, port: int | None, webhook_url: str | None,
                    cwd: str | None = None,
                    extra_env: dict[str, str] | None = None) -> RunResult:
        async with self._lock:
            await self.stop(bot_id)
            image = _IMAGES.get(language)
            if not image:
                return RunResult(None, f"runtime for '{language}' is not supported")
            project = Path(cwd or Path(file_path).parent).resolve()
            if not project.is_dir():
                return RunResult(None, "project directory does not exist")
            entry = Path(file_path).resolve()
            if not entry.is_file():
                # A file can be renamed or removed by a project-side file
                # operation. Recover only when there is exactly one plausible
                # source file; never guess among multiple entry points.
                allowed = {
                    "python": {".py"},
                    "node": {".js", ".mjs", ".cjs"},
                    "php": {".php"},
                }.get(language, set())
                candidates = sorted(
                    p for p in project.rglob("*")
                    if p.is_file()
                    and p.suffix.lower() in allowed
                    and not any(part in {".git", "backups", "logs", "database"} for part in p.parts)
                )
                if len(candidates) == 1:
                    entry = candidates[0].resolve()
                    log.info("entry path recovered for project %s: %s", bot_id, entry)
                else:
                    listed = ", ".join(str(p.relative_to(project)) for p in candidates[:5])
                    detail = f"; candidates: {listed}" if listed else ""
                    return RunResult(None, f"entry file not found: {file_path}{detail}")
            try:
                rel = entry.relative_to(project)
            except ValueError:
                return RunResult(None, "entry file must be inside project directory")
            name = f"tikzoom-project-{bot_id}"
            log_path = Path(get_settings().data_path) / "logs" / f"bot_{bot_id}.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            # ضمان إن مجلد البوت قابل للكتابة من user 1000 داخل الحاوية
            try:
                import os, subprocess
                # chown للمجلد وكل محتوياته
                os.chown(project, 1000, 1000)
                for item in project.rglob("*"):
                    try:
                        os.chown(item, 1000, 1000)
                    except Exception:
                        pass
                # chmod 777 لضمان الكتابة
                subprocess.run(["chmod", "-R", "777", str(project)], timeout=10,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            cmd = [
                "run", "-d", "--replace", "--name", name,
                "--user", "1000:1000",
                # شبكة معزولة
                "--network", "slirp4netns:allow_host_loopback=false",
                # إسقاط كل الصلاحيات
                "--cap-drop=all", "--security-opt=no-new-privileges",
                # موارد محدودة - خفيفة عشان تشتغل كل البوتات
                "--pids-limit=32",
                "--memory=256m",
                "--memory-swap=256m",
                "--cpus=0.25",
                "--ulimit", "nofile=64:64",
                "--ulimit", "fsize=50000000",
                # tmpfs للملفات المؤقتة
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                "--tmpfs", "/run:rw,nosuid,nodev,size=8m",
                # volumes - /workspace قابل للكتابة
                "-v", f"tikzoom-deps-{bot_id}:/opt/tikzoom-deps:rw",
                "-v", f"{project}:/workspace:rw",
                "-w", "/workspace",
                "-e", f"BOT_TOKEN={token}",
                "-e", "PLATFORM=tikzoom",
                "-e", "HOME=/workspace",
                "-e", "TMPDIR=/tmp",
                "-e", "PYTHONUNBUFFERED=1",
            ]
            # متغيرات بيئة إضافية (ADMIN_ID ومفاتيح اختيارية) — قيم مُنقّاة فقط
            for ek, ev in (extra_env or {}).items():
                if not _ENV_KEY_RE.match(str(ek)):
                    continue
                sv = str(ev)
                if len(sv) > 2000 or "\n" in sv or "\r" in sv:
                    continue
                cmd += ["-e", f"{ek}={sv}"]
            # أسماء بديلة شائعة للتوكن والأدمن — كثير من بوتات GitHub تقرأها مباشرة
            admin_val = str((extra_env or {}).get("ADMIN_ID", ""))
            for alias in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_TOKEN", "API_TOKEN", "TOKEN"):
                cmd += ["-e", f"{alias}={token}"]
            if admin_val:
                for alias in ("ADMINS", "ADMIN"):
                    cmd += ["-e", f"{alias}={admin_val}"]
            if port:
                cmd += ["-p", f"127.0.0.1:{port}:{port}", "-e", f"PORT={port}"]
            if webhook_url:
                cmd += ["-e", f"WEBHOOK_URL={webhook_url}"]
            if language == "python":
                # Discover imports without assuming the host's installed packages.
                # The actual installation happens inside the isolated container.
                auto_packages = ""
                try:
                    source = entry.read_text(encoding="utf-8", errors="replace")
                    auto_packages = " ".join(
                        pkg for pkg in sandbox_python_pip_targets(source)
                        if pkg not in _BASE_PYTHON_PACKAGES
                    )
                except OSError:
                    auto_packages = ""
                # /workspace is a project mount and may be owned by root. Keep
                # pip's user base on the writable tmpfs so scripts can install
                # aiosqlite, telebot, aiohttp, etc. without PermissionError.
                cmd += [
                    "-e", "HOME=/tmp/tikzoom-home",
                    "-e", "PYTHONUSERBASE=/opt/tikzoom-deps",
                    "-e", "PIP_CACHE_DIR=/tmp/tikzoom-pip-cache",
                    "-e", "PYTHONPATH=/opt/tikzoom-deps/lib/python3.12/site-packages:/tmp/tikzoom-home/.local/lib/python3.12/site-packages",
                    "-e", "PATH=/opt/tikzoom-deps/bin:/usr/local/bin:/usr/bin:/bin",
                    "-e", f"TIKZOOM_AUTO_PACKAGES={auto_packages}",
                ]
                script = (
                    "mkdir -p /tmp/tikzoom-home/.local/lib/python3.12/site-packages "
                    "/opt/tikzoom-deps/lib/python3.12/site-packages /tmp/tikzoom-pip-cache; "
                    "if [ -f requirements.txt ]; then "
                    # تثبيت سطراً-سطراً: سطر فاسد واحد لا يُسقط الباقي
                    "while IFS= read -r line; do "
                    "  [ -z \"$line\" ] && continue; "
                    "  python -m pip install --user --no-cache-dir --disable-pip-version-check \"$line\" "
                    "    >/dev/null 2>&1 || true; "
                    "done < requirements.txt; "
                    "elif [ -n \"$TIKZOOM_AUTO_PACKAGES\" ]; then "
                    "python -m pip install --user --no-cache-dir --disable-pip-version-check "
                    "$TIKZOOM_AUTO_PACKAGES || echo 'TikZoom: auto dependency install failed; continuing'; "
                    "fi; exec python -u \"$1\""
                )
                cmd += [image, "sh", "-lc", script, "--", f"/workspace/{rel}"]
            elif language == "node":
                # npm must place node_modules in the writable project mount.
                script = "if [ -f package.json ]; then npm install --omit=dev --no-audit --no-fund || echo 'TikZoom: npm install failed; continuing'; fi; exec node \"$1\""
                cmd += [image, "sh", "-lc", script, "--", f"/workspace/{rel}"]
            else:
                cmd += [image, "php", f"/workspace/{rel}"]
            # إعادة المحاولة عند فشل بدء الحاوية
            last_err = None
            for attempt in range(2):
                rc, out, err = await self._podman(*cmd, timeout=120, detached=True)
                if rc == 0 and out.strip():
                    break
                last_err = (err or out or "container start failed")[-1200:]
                log.warning("bot_id=%s start attempt %s failed: %s", bot_id, attempt + 1, last_err[:200])
                if attempt == 0:
                    await asyncio.sleep(2)
            else:
                return RunResult(None, last_err)
            self._containers[bot_id] = name
            # `podman run -d` can succeed even when the entry process exits
            # immediately. Catch that case so the API reports the real launch
            # error instead of persisting a false `running` status.
            for _ in range(8):
                await asyncio.sleep(0.5)
                state_rc, state_out, state_err = await self._podman(
                    "inspect", "--format", "{{.State.Status}}", name, timeout=10,
                )
                state = state_out.strip().lower()
                if state in {"exited", "dead"}:
                    log_rc, log_out, log_err = await self._podman(
                        "logs", "--tail", "120", name, timeout=10,
                    )
                    self._containers.pop(bot_id, None)
                    return RunResult(None, (log_out + log_err or state_err or "project exited during startup")[-1200:])
                if state == "running":
                    break
            task = asyncio.create_task(self._follow_logs(bot_id, name, log_path))
            self._log_tasks[bot_id] = task
            # جدولة فحص دوري للتحقق من استمرار البوت في العمل
            self._schedule_health_check(bot_id, name)
            return RunResult(None, None)

    async def start_supervised(self, **kwargs: Any) -> RunResult:
        return await self.start(**kwargs)

    def _schedule_health_check(self, bot_id: int, name: str) -> None:
        """جدولة فحص صحي دوري - يعيد تشغيل البوت إذا تعطل."""
        async def _check_loop():
            # انتظر دقيقتين قبل أول فحص
            await asyncio.sleep(120)
            restart_count = 0
            max_restarts = 3
            while restart_count < max_restarts:
                try:
                    if bot_id not in self._containers:
                        # البوت تم إيقافه يدوياً
                        return
                    state_rc, state_out, _ = await self._podman(
                        "inspect", "--format", "{{.State.Status}}", name, timeout=10,
                    )
                    state = state_out.strip().lower()
                    if state in {"exited", "dead"}:
                        log.warning("bot_id=%s exited (state=%s), attempting restart #%s",
                                    bot_id, state, restart_count + 1)
                        # فحص سبب الإنهاء
                        exit_rc, exit_out, _ = await self._podman(
                            "inspect", "--format", "{{.State.ExitCode}}", name, timeout=10,
                        )
                        exit_code = exit_out.strip()
                        log.warning("bot_id=%s exit_code=%s", bot_id, exit_code)
                        # Exit code 137 = OOM Kill - نحاول إعادة التشغيل
                        # Exit code 1 = خطأ في الكود - لا نعيد التشغيل
                        # Exit code 0 = إنهاء طبيعي - لا نعيد
                        if exit_code in {"0", "1", "2"}:
                            log.info("bot_id=%s exit_code=%s - لا إعادة تشغيل", bot_id, exit_code)
                            return
                        # إعادة التشغيل
                        restart_count += 1
                        # إزالة الحاوية القديمة
                        await self._podman("rm", "-f", name, timeout=20)
                        # إعادة تشغيل الحاوية بنفس المواصفات
                        await asyncio.sleep(5)
                        # نعتمد على الخدمة الرئيسية لإعادة التشغيل
                        log.info("bot_id=%s restart scheduled", bot_id)
                        return
                    # البوت يعمل - انتظر دقيقة قبل الفحص القادم
                    await asyncio.sleep(60)
                except asyncio.CancelledError:
                    return
                except Exception as exc:
                    log.warning("health check bot_id=%s failed: %s", bot_id, exc)
                    await asyncio.sleep(60)
        task = asyncio.create_task(_check_loop())
        self._log_tasks.setdefault(f"health_{bot_id}", task)

    async def stop(self, bot_id: int) -> bool:
        name = self._containers.pop(bot_id, None) or f"tikzoom-project-{bot_id}"
        task = self._log_tasks.pop(bot_id, None)
        if task:
            task.cancel()
        rc, _out, _err = await self._podman("rm", "-f", name, timeout=20)
        return rc == 0 or rc == 125

    async def stop_all(self) -> None:
        for bid in list(self._containers):
            await self.stop(bid)

    async def exec(self, bot_id: int, command: str, timeout: float = 20.0) -> tuple[int, str]:
        name = self._containers.get(bot_id) or f"tikzoom-project-{bot_id}"
        if not command or len(command) > 2000:
            return 400, "invalid command"
        # Terminal commands are executed as the non-root project user in the
        # container, never through a host shell.
        rc, out, err = await self._podman(
            "exec", "--user", "1000:1000", "--workdir", "/workspace", name,
            "sh", "-lc", "umask 077; " + command,
            timeout=timeout,
        )
        return rc, (out + err)[-12000:]

_runner: ContainerRunner | None = None

def get_container_runner() -> ContainerRunner:
    global _runner
    if _runner is None:
        _runner = ContainerRunner()
    return _runner
