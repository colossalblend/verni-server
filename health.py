# SPDX-License-Identifier: GPL-3.0-only
"""FairPlay-цепочка (worker + iTunes) — здоровье и автореcovery.

Статусы: UNKNOWN, HEALTHY, DEGRADED, RECOVERING, FAILED.

Что реально восстанавливается автоматически:
  * мёртвый процесс iOSAuthSingle -> respawn с exponential backoff + jitter,
    single-flight (один recovery одновременно, результат кэшируется 10с);
  * подтверждение восстановления = порт снова слушает (транспорт).

Что восстановить нельзя автоматически (и мы НЕ пытаемся — без обхода
CAPTCHA/2FA/блокировок Apple): проблемы iTunes-стороны — SC Info, авторизация
компьютера, отсутствующие DLL. Это DEGRADED/FAILED + уведомление админу
(manual_action_required=true). REAUTH_REQUIRED представлен этими же статусами
с соответствующим error_class в payload.

Уведомления: лог-событие всегда; webhook (VERNI_WEBHOOK_URL) при настроенном
канале. Дедуп: одинаковые события не чаще раза в 15 минут; при повторном
уведомлении об активном инциденте интервал 30 минут; recovery-сообщение
шлётся один раз после инцидента. Секретов в уведомлениях нет.

Метрики (in-process, счётчики) — для /v1/health.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import socket
import time
import urllib.request
from collections import deque
from pathlib import Path

log = logging.getLogger("verni.health")

UNKNOWN = "UNKNOWN"
HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
RECOVERING = "RECOVERING"
FAILED = "FAILED"

metrics: dict[str, int] = {}


def inc(name: str, n: int = 1) -> None:
    metrics[name] = metrics.get(name, 0) + n


class WorkerHealth:
    """Отслеживание FairPlay-интеграции + автореcovery respawn'ом воркера."""

    NOTIFY_MIN_GAP = 15 * 60      # дедуп одинаковых событий
    INCIDENT_RE_NOTIFY = 30 * 60  # повтор по активному инциденту
    SPAWN_WINDOW = 10 * 60        # окно подсчёта неудачных respawn
    MAX_SPAWN_FAILS = 5           # после этого FAILED (ручное вмешательство)

    def __init__(self, exe: str | None, host: str, ports: list[int], notify_url: str = ""):
        self.exe = exe
        self.host = host
        self.ports = ports
        self.notify_url = notify_url
        self.state = UNKNOWN
        self.last_error = ""
        self.last_transition = time.time()
        self._lock = asyncio.Lock()            # single-flight recovery
        self._recover_result: tuple[bool, float] = (False, 0.0)
        self._fail_streak = 0
        self._spawn_fails: deque[float] = deque()
        self._last_notify: dict[str, float] = {}
        self._incident_open = False
        self._process: subprocess.Popen | None = None  # type: ignore[name-defined]

    # ---------- запись исходов ----------

    def record_success(self) -> None:
        self._fail_streak = 0
        self._spawn_fails.clear()
        if self.state != HEALTHY:
            self._transition(HEALTHY, "traffic ok")
            if self._incident_open:
                self._incident_open = False
                self.notify("recovery", {
                    "integration": "fairplay-worker",
                    "result": "recovered",
                }, min_gap=0)

    async def record_failure(self, kind: str, detail: str) -> None:
        """kind: connect | timeout | reset | protocol."""
        self._fail_streak += 1
        self.last_error = f"{kind}: {detail}"[:300]
        inc(f"worker_fail_{kind}")
        if kind == "connect":
            # транспорт умер — можно и нужно пробовать восстановить
            await self.try_recover()
        else:
            # порт жив, но нативная часть не отвечает — iTunes-сторона
            self._transition(DEGRADED, self.last_error)
            self.notify("integration_degraded", {
                "integration": "fairplay-worker",
                "error_class": kind,
                "error": self.last_error,
                "failures": self._fail_streak,
                "manual_action_required": True,
                "hint": "check iTunes authorization / SC Info.sidb+sidd / Apple Application Support",
            }, min_gap=self.NOTIFY_MIN_GAP)

    def _transition(self, new: str, reason: str) -> None:
        old = self.state
        if old == new:
            return
        self.state = new
        self.last_transition = time.time()
        log.warning("health transition", extra={"event": "health_transition",
                   "detail": f"{old} -> {new} ({reason})", "status": new})

    # ---------- автореcovery ----------

    async def try_recover(self) -> bool:
        """Single-flight: параллельные вызовы ждут и переиспользуют результат."""
        async with self._lock:
            ok, ts = self._recover_result
            if time.time() - ts < 10:
                return ok
            ok = await self._do_recover()
            self._recover_result = (ok, time.time())
            return ok

    async def _port_open(self, port: int, timeout: float = 2.0) -> bool:
        try:
            w = await asyncio.wait_for(asyncio.open_connection(self.host, port), timeout)
            w[1].close()
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    def _spawn_backoff_ok(self) -> bool:
        """Exponential backoff + jitter; >= MAX_SPAWN_FAILS за окно -> не спамим."""
        now = time.time()
        while self._spawn_fails and now - self._spawn_fails[0] > self.SPAWN_WINDOW:
            self._spawn_fails.popleft()
        if len(self._spawn_fails) >= self.MAX_SPAWN_FAILS:
            return False
        n = len(self._spawn_fails)
        if n == 0:
            return True
        delay = min(60.0, 2.0 ** n) * (0.5 + random.random())
        return now - self._spawn_fails[-1] >= delay

    async def _do_recover(self) -> bool:
        self._transition(RECOVERING, "connect failure")
        for port in self.ports:
            if await self._port_open(port):
                inc("recovery_port_up")
                return True  # транспорт жив, ошибка была другой природы
        if not self.exe or not Path(self.exe).is_file():
            inc("recovery_no_exe")
            return False
        if not self._spawn_backoff_ok():
            fails = len(self._spawn_fails)
            self._transition(FAILED, f"respawn exhausted ({fails} fails/{self.SPAWN_WINDOW}s)")
            self._incident_open = True
            self.notify("integration_failed", {
                "integration": "fairplay-worker",
                "error_class": "respawn_exhausted",
                "spawn_failures": fails,
                "manual_action_required": True,
                "hint": "worker process will not start; check iTunes DLLs and event log",
            }, min_gap=self.INCIDENT_RE_NOTIFY)
            return False
        import subprocess
        try:
            creation = 0
            if os.name == "nt":
                creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            self._process = subprocess.Popen(
                [self.exe], cwd=str(Path(self.exe).parent), creationflags=creation,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except OSError as e:
            self._spawn_fails.append(time.time())
            self.last_error = f"spawn: {e}"[:300]
            inc("recovery_spawn_fail")
            return False
        # даём воркеру время подняться (bind 27987)
        deadline = time.time() + 8
        while time.time() < deadline:
            for port in self.ports:
                if await self._port_open(port, 1.0):
                    inc("recovery_respawn_ok")
                    log.warning("worker respawned", extra={"event": "worker_respawn",
                               "detail": f"pid={self._process.pid} port={port}", "status": "ok"})
                    return True
            await asyncio.sleep(0.5)
        self._spawn_fails.append(time.time())
        self.last_error = "spawn: port never opened"
        inc("recovery_spawn_fail")
        return False

    # ---------- уведомления ----------

    def notify(self, event: str, payload: dict, min_gap: float = 15 * 60) -> None:
        now = time.time()
        if min_gap > 0 and now - self._last_notify.get(event, 0) < min_gap:
            return
        self._last_notify[event] = now
        log.error("admin notify", extra={"event": "admin_notify", "detail": json.dumps(payload, ensure_ascii=False)})
        if self.notify_url:
            asyncio.get_running_loop().create_task(self._post(event, dict(payload)))

    async def _post(self, event: str, payload: dict) -> None:
        try:
            body = json.dumps({"event": event, **payload, "ts": time.time()}).encode()
            req = urllib.request.Request(self.notify_url, data=body,
                                         headers={"Content-Type": "application/json"}, method="POST")
            await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=10).read()), 15)
        except Exception as e:  # уведомление не должно ронять сервер
            log.warning("webhook failed", extra={"event": "webhook_fail", "detail": repr(e)[:200]})

    # ---------- снапшот для /v1/health ----------

    def snapshot(self) -> dict:
        return {
            "state": self.state,
            "last_error": self.last_error,
            "ports": list(self.ports),
            "fail_streak": self._fail_streak,
            "last_transition_s_ago": round(time.time() - self.last_transition, 1),
        }
