# SPDX-License-Identifier: GPL-3.0-only
r"""Серверная часть заменяет verniapp.ru:18766.

HTTP-контракт строго повторяет клиент remote_provider.py:
- POST application/json, Bearer-токен (43-128 символов [A-Za-z0-9_-]);
  токенов может быть несколько: VERNI_TOKENS="tok1,tok2" (по токену на
  телефон; сессии и привязка UDID изолированы по токену)
- /v1/ready    -> {'status':'listener_ready'} / catalog/account варианты
- /v1/begin    -> {'status':'grappa_ready','session_id':<64hex>,'Grappa':<b64>}
- /v1/complete -> {'status':'response_generated','device_acceptance_verified':True,
                   'response':<b64>,'sig':<b64>}
- /v1/abort    -> {'status':'aborted'}
- /v1/health   -> GET, служебный (токен): состояние FairPlay-интеграции, метрики
- ошибки: {'error_code': <одно из известных клиенту значений>} + не-200 статус

Безопасность: постоянная времени-безопасная проверка токена, rate limiting
по IP ( sliding window ), блокировка IP после серии неудачных авторизаций,
лимит размера тела, лимит сессий, проверка владельца сессии на complete/abort,
привязка ключ->UDID, идемпотентность (begin 409, complete 404 после потребления).

FairPlay делегируется воркеру iOSAuthRuntime через bridge.py; процесс воркера
поднимается автоматически (autostart / health.try_recover).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import logging.handlers
import os
import re
import secrets
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import bridge
import health

TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43,128}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
UDID_RE = re.compile(r"[0-9a-fA-F\-]{20,64}")
MAX_BODY = 2 * 1024 * 1024

OWNER_TOKENS = {t.strip() for t in os.environ.get(
    "VERNI_TOKENS", os.environ.get("VERNI_TOKEN", "")).split(",") if t.strip()}
WORKER_HOST = os.environ.get("VERNI_WORKER_HOST", "127.0.0.1")
WORKER_PORT = int(os.environ.get("VERNI_WORKER_PORT", "27987"))
WORKER_PORTS_RAW = os.environ.get("VERNI_WORKER_PORTS", "")
WORKER_PORTS = [int(p) for p in WORKER_PORTS_RAW.replace(";", ",").split(",") if p.strip()] or [WORKER_PORT]
ACCOUNTS_PATH = Path(os.environ.get("VERNI_ACCOUNTS", os.path.join(os.path.dirname(__file__), "accounts.json")))
CATALOG_PATH = Path(os.environ.get("VERNI_CATALOG", os.path.join(os.path.dirname(__file__), "ipa-catalog.json")))
SESSION_TTL = float(os.environ.get("VERNI_SESSION_TTL", "900"))
MAX_SESSIONS = int(os.environ.get("VERNI_MAX_SESSIONS", "64"))
RATE_LIMIT = int(os.environ.get("VERNI_RATE_LIMIT", "120"))       # req/IP/окно
RATE_WINDOW = float(os.environ.get("VERNI_RATE_WINDOW", "60"))
AUTH_FAIL_LIMIT = int(os.environ.get("VERNI_AUTH_FAIL_LIMIT", "10"))
AUTH_FAIL_WINDOW = float(os.environ.get("VERNI_AUTH_FAIL_WINDOW", "600"))

# ---------------- logging (структурированный, JSON) ----------------

class _JsonFormatter(logging.Formatter):
    FIELDS = ("event", "rid", "ip", "path", "status", "ms", "detail", "error")

    def format(self, record: logging.LogRecord) -> str:
        out = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "level": record.levelname, "comp": record.name, "msg": record.getMessage()}
        for f in self.FIELDS:
            v = getattr(record, f, None)
            if v is not None:
                out[f] = v
        return json.dumps(out, ensure_ascii=False)


def _setup_logging() -> logging.Logger:
    root = logging.getLogger("verni")
    root.setLevel(logging.INFO)
    root.propagate = False
    if root.handlers:
        return root
    fmt = _JsonFormatter()
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)
    try:
        file_h = logging.handlers.RotatingFileHandler(
            os.path.join(os.path.dirname(__file__), "srvlog.txt"),
            maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
        file_h.setFormatter(fmt)
        root.addHandler(file_h)
    except OSError:
        pass
    return root


log = _setup_logging()

bridge.configure_worker(WORKER_HOST, WORKER_PORTS)

# ---------------- FairPlay health/recovery ----------------

def _find_worker_exe() -> str | None:
    wdir = Path(__file__).resolve().parent / "worker"
    if wdir.exists():
        hits = list(wdir.rglob("iOSAuthSingle.exe"))
        if hits:
            return str(hits[0])
    return None


worker_health = health.WorkerHealth(
    exe=_find_worker_exe(), host=WORKER_HOST, ports=WORKER_PORTS,
    notify_url=os.environ.get("VERNI_WEBHOOK_URL", ""),
)

app = FastAPI(title="verni-server", docs_url=None, redoc_url=None, openapi_url=None)

# ---------------- состояние ----------------

key_udid_path = Path(os.environ.get("VERNI_KEY_UDID", os.path.join(os.path.dirname(__file__), "key_udids.json")))
sessions: dict[str, bridge.WorkerSession] = {}
owner_session: dict[str, str] = {}      # owner-hash -> session_id
begin_locks: dict[str, asyncio.Lock] = {}

key_udid: dict[str, str] = {}
if key_udid_path.exists():
    try:
        key_udid = json.loads(key_udid_path.read_text(encoding="utf-8"))
    except Exception:
        key_udid = {}


def save_key_udid() -> None:
    save_json_atomic(key_udid_path, key_udid)


def save_json_atomic(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)  # атомарная замена: переживает crash mid-write


def load_json(path: Path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def err(code: str, status: int) -> JSONResponse:
    return JSONResponse({"error_code": code}, status_code=status)


# ---------------- rate limiting (in-process sliding window) ----------------

class SlidingWindow:
    """Окно на ключ. Память ограничена: >MAX_BUCKETS ключей — чистим протухшие."""

    MAX_BUCKETS = 8192

    def __init__(self, limit: int, window: float):
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque] = {}

    def _prune(self, now: float) -> None:
        if len(self._hits) <= self.MAX_BUCKETS:
            return
        stale = [k for k, dq in self._hits.items() if not dq or now - dq[-1] > self.window]
        for k in stale:
            self._hits.pop(k, None)

    def hit(self, key: str) -> bool:
        """True = разрешено. False = лимит исчерпан."""
        now = time.monotonic()
        self._prune(now)
        dq = self._hits.get(key)
        if dq is None:
            dq = self._hits[key] = deque()
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.limit:
            return False
        dq.append(now)
        return True

    def count(self, key: str) -> int:
        now = time.monotonic()
        dq = self._hits.get(key)
        if not dq:
            return 0
        while dq and now - dq[0] > self.window:
            dq.popleft()
        return len(dq)


req_window = SlidingWindow(RATE_LIMIT, RATE_WINDOW)
auth_fail_window = SlidingWindow(AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ---------------- middleware: rid + rate limit + журнал ----------------

@app.middleware("http")
async def guard(request: Request, call_next):
    rid = uuid.uuid4().hex[:12]
    request.state.rid = rid
    ip = client_ip(request)
    start = time.perf_counter()
    response: JSONResponse | None = None
    if request.url.path.startswith("/v1/"):
        if auth_fail_window.count(ip) >= AUTH_FAIL_LIMIT:
            health.inc("rate_limited")
            log.warning("ip locked out", extra={"event": "ip_locked", "rid": rid, "ip": ip, "path": request.url.path})
            response = err("owner_generator_busy", 429)
        elif not req_window.hit(f"ip:{ip}"):
            health.inc("rate_limited")
            log.warning("rate limited", extra={"event": "rate_limited", "rid": rid, "ip": ip, "path": request.url.path})
            response = err("owner_generator_busy", 429)
    if response is None:
        try:
            response = await call_next(request)
        except Exception:
            health.inc("http_500")
            log.exception("unhandled error", extra={"event": "unhandled", "rid": rid, "ip": ip, "path": request.url.path})
            response = JSONResponse({"error_code": "owner_generator_busy"}, status_code=500)
    ms = round((time.perf_counter() - start) * 1000, 1)
    response.headers["x-request-id"] = rid
    response.headers["x-content-type-options"] = "nosniff"
    status = response.status_code
    if status >= 400:
        health.inc(f"http_{status // 100}xx")
    log.info("request", extra={"event": "http_request", "rid": rid, "ip": ip,
                               "path": request.url.path, "status": status, "ms": ms})
    return response


# ---------------- auth ----------------

def bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    if TOKEN_RE.fullmatch(token):
        for t in OWNER_TOKENS:
            if secrets.compare_digest(token, t):
                return token
    ip = client_ip(request)
    auth_fail_window.hit(ip)  # учитываем неудачу; блокировка считается в middleware
    health.inc("auth_failures")
    rid = getattr(request.state, "rid", "-")
    log.warning("auth failed", extra={"event": "auth_fail", "rid": rid, "ip": ip,
                                      "path": request.url.path})
    return None


def owner(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


async def read_json(request: Request) -> dict | None:
    body = await request.body()
    if not body or len(body) > MAX_BODY:
        return None
    try:
        value = json.loads(body)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def select_kind(payload: dict) -> tuple[str, str] | None:
    account_id = payload.get("account_id")
    ipa = payload.get("ipa_sha256")
    if (ipa is None) == (account_id is None):
        return None
    if account_id is not None:
        if not isinstance(account_id, str) or not HEX64_RE.fullmatch(account_id):
            return ("invalid", "account_id")
        return ("account", account_id)
    if not isinstance(ipa, str) or not HEX64_RE.fullmatch(ipa):
        return ("invalid", "ipa_sha256")
    return ("ipa", ipa)


def find_account(account_id: str) -> tuple[str, dict] | tuple[None, None]:
    accounts = load_json(ACCOUNTS_PATH)
    for email, info in accounts.items():
        if hashlib.sha256(email.encode("utf-8")).hexdigest() == account_id:
            return email, info if isinstance(info, dict) else {}
    return None, None


def account_dsid(info: dict) -> int:
    raw = info.get("dsid", 0)
    if isinstance(raw, bool):
        return 0
    if isinstance(raw, int) and 0 < raw <= 9223372036854775807:
        return raw
    if isinstance(raw, str) and raw.strip().isdigit() and 0 < int(raw) <= 9223372036854775807:
        return int(raw)
    return 0


def _plain_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


async def bridge_drop(session_id: str) -> None:
    session = sessions.pop(session_id, None)
    if session is not None:
        await session.close()
    for oref, sid in list(owner_session.items()):
        if sid == session_id:
            owner_session.pop(oref, None)


def _b64(value) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return None


# ---------------- endpoints ----------------

@app.post("/v1/ready")
async def ready(request: Request):
    token = bearer(request)
    if token is None:
        return err("unauthorized", 401)
    payload = await read_json(request)
    if payload is None:
        # пустой health-запрос (клиент шлёт и такое)
        return JSONResponse({"status": "listener_ready"})
    selection = select_kind(payload)
    if selection is None:
        return JSONResponse({"status": "listener_ready"})
    kind, value = selection
    if kind == "invalid":
        return err("invalid_account_id" if value == "account_id" else "invalid_ipa_hash", 400)
    if kind == "account":
        matched, info = find_account(value)
        if matched is None:
            return err("account_not_in_catalog", 404)
        display_name = info.get("display_name") or info.get("account_display") or matched.split("@")[0]
        return JSONResponse({"status": "account_ready", "account_display_name": display_name})
    return JSONResponse({"status": "catalog_ready", "ipa_sha256": value})


@app.post("/v1/begin")
async def begin(request: Request):
    token = bearer(request)
    if token is None:
        return err("unauthorized", 401)
    payload = await read_json(request)
    if payload is None:
        return err("invalid_request", 400)
    selection = select_kind(payload)
    if selection is None:
        return err("invalid_request", 400)
    kind, value = selection
    if kind == "invalid":
        return err("invalid_account_id" if value == "account_id" else "invalid_ipa_hash", 400)
    dsid = 0
    if kind == "account":
        matched, info = find_account(value)
        if matched is None:
            return err("account_not_in_catalog", 404)
        dsid = account_dsid(info)

    device_udid = payload.get("deviceUDID")
    fpc_b64 = payload.get("FairPlayCertificate")
    device_type = payload.get("deviceType")
    key_version = payload.get("keyTypeSupportVersion")
    if not isinstance(device_udid, str) or not UDID_RE.fullmatch(device_udid):
        return err("invalid_request", 400)
    fpc = _b64(fpc_b64)
    if fpc is None or not 0 < len(fpc) <= 512 * 1024:
        return err("invalid_request", 400)
    if not _plain_int(device_type) or not _plain_int(key_version):
        return err("invalid_request", 400)
    if len(key_udid) > 0 and owner(token) in key_udid and key_udid[owner(token)] != device_udid:
        return err("wrong_device", 403)

    oref = owner(token)
    lock = begin_locks.setdefault(oref, asyncio.Lock())
    async with lock:
        if oref in owner_session:
            return err("begin_already_used", 409)
        if len(sessions) >= MAX_SESSIONS:
            return err("owner_generator_busy", 503)

        # Резервируем слот ДО обращения к воркеру: гонка begin'ов того же
        # токена получает мгновенный 409, а не двойную сессию.
        session_id = secrets.token_hex(32)
        session = bridge.WorkerSession(session_id)
        owner_session[oref] = session_id
        sessions[session_id] = session
        try:
            grappa = await asyncio.wait_for(
                session.begin(
                    device_udid=device_udid,
                    fairplay_cert=fpc,
                    device_type=device_type,
                    key_type_support_version=key_version,
                    dsid=dsid,
                    grappa_support_info=None,
                ),
                timeout=30,
            )
        except asyncio.TimeoutError:
            await bridge_drop(session_id)
            await worker_health.record_failure("timeout", "begin: no worker response in 30s")
            return err("owner_generator_busy", 503)
        except (OSError, ValueError):
            await bridge_drop(session_id)
            await worker_health.record_failure("connect", "begin: worker unreachable")
            ok = await worker_health.try_recover()
            if ok:
                # один ретрай свежей сессией после успешного respawn
                session2 = bridge.WorkerSession(secrets.token_hex(32))
                owner_session[oref] = session2.session_id
                sessions[session2.session_id] = session2
                try:
                    grappa = await asyncio.wait_for(
                        session2.begin(
                            device_udid=device_udid, fairplay_cert=fpc,
                            device_type=device_type, key_type_support_version=key_version,
                            dsid=dsid, grappa_support_info=None,
                        ),
                        timeout=30,
                    )
                    session = session2
                except (asyncio.TimeoutError, OSError, ValueError):
                    await bridge_drop(session2.session_id)
                    return err("worker_reported_error", 503)
            else:
                return err("worker_reported_error", 503)
        key_udid[oref] = device_udid
        save_key_udid()
        worker_health.record_success()
        health.inc("begin_success")
        return JSONResponse({
            "status": "grappa_ready",
            "session_id": session.session_id,
            "Grappa": base64.b64encode(grappa).decode("ascii"),
        })


@app.post("/v1/complete")
async def complete(request: Request):
    token = bearer(request)
    if token is None:
        return err("unauthorized", 401)
    payload = await read_json(request)
    if payload is None:
        return err("unknown_session", 404)
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not HEX64_RE.fullmatch(session_id):
        return err("unknown_session", 404)
    oref = owner(token)
    if owner_session.get(oref) != session_id:
        health.inc("foreign_session_attempts")
        rid = getattr(request.state, "rid", "-")
        log.warning("foreign session attempt", extra={"event": "idor_blocked", "rid": rid,
                   "ip": client_ip(request), "path": request.url.path})
        return err("unknown_session", 404)
    session = sessions.get(session_id)
    if session is None:
        return err("unknown_session", 404)

    request_blob = _b64(payload.get("request"))
    rq_sig = _b64(payload.get("rq_sig"))
    device_grappa = _b64(payload.get("deviceGrappa"))
    if request_blob is None or rq_sig is None or device_grappa is None:
        await bridge_drop(session_id)
        return err("invalid_request", 400)
    if not (0 < len(request_blob) <= 512 * 1024):
        await bridge_drop(session_id)
        return err("invalid_request", 400)
    if len(rq_sig) != bridge.LEN_RQSIG or len(device_grappa) != bridge.LEN_GRAPPA:
        await bridge_drop(session_id)
        return err("invalid_request", 400)

    try:
        response, sig = await asyncio.wait_for(
            session.complete(device_grappa=device_grappa, rq_sig=rq_sig, request=request_blob),
            timeout=60,
        )
    except (asyncio.TimeoutError, OSError, ValueError, ConnectionError):
        await bridge_drop(session_id)
        await worker_health.record_failure("protocol", "complete: worker session failed")
        return err("worker_reported_error", 503)
    await bridge_drop(session_id)
    worker_health.record_success()
    health.inc("complete_success")
    return JSONResponse({
        "status": "response_generated",
        "device_acceptance_verified": True,
        "response": base64.b64encode(response).decode("ascii"),
        "sig": base64.b64encode(sig).decode("ascii"),
    })


@app.post("/v1/abort")
async def abort(request: Request):
    token = bearer(request)
    if token is None:
        return err("unauthorized", 401)
    payload = await read_json(request)
    session_id = (payload or {}).get("session_id")
    if isinstance(session_id, str) and HEX64_RE.fullmatch(session_id):
        # BOLA-фикс: дропаем ТОЛЬКО свою сессию. Чужую/неизвестную молча
        # игнорируем (не раскрываем существование), отвечаем стандартно.
        if owner_session.get(owner(token)) == session_id:
            await bridge_drop(session_id)
    return JSONResponse({"status": "aborted"})


@app.get("/v1/health")
async def health_endpoint(request: Request):
    token = bearer(request)
    if token is None:
        return err("unauthorized", 401)
    return JSONResponse({
        "status": "listener_ready",
        "uptime_s": round(time.time() - START_TS, 1),
        "sessions_active": len(sessions),
        "owner_tokens": len(OWNER_TOKENS),
        "worker": worker_health.snapshot(),
        "metrics": dict(health.metrics),
    })


START_TS = time.time()


# ---------------- startup / shutdown ----------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.worker_proc = None
    if os.environ.get("VERNI_WORKER_AUTOSTART", "1") == "1":
        async def _port_open(port: int) -> bool:
            try:
                w = await asyncio.open_connection(WORKER_HOST, port)
                w[1].close()
                return True
            except OSError:
                return False
        exe = _find_worker_exe()
        if exe is None:
            log.warning("worker exe not found", extra={"event": "worker_autostart", "detail": "worker/verni-worker-Win32/iOSAuthSingle.exe"})
        else:
            first_port = WORKER_PORTS[0]
            if not await _port_open(first_port):
                exe_dir = Path(exe).resolve().parent
                dsid_file = exe_dir / "dsid.txt"
                if not dsid_file.exists():
                    accounts = load_json(ACCOUNTS_PATH)
                    for info in accounts.values():
                        dsid = account_dsid(info if isinstance(info, dict) else {})
                        if dsid:
                            dsid_file.write_text(str(dsid), encoding="ascii")
                            log.info("fallback dsid written", extra={"event": "dsid_fallback", "detail": str(dsid_file)})
                            break
                import subprocess
                creation = 0
                if os.name == "nt":
                    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                app.state.worker_proc = subprocess.Popen(
                    [exe], cwd=str(exe_dir), creationflags=creation,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                log.info("worker spawned", extra={"event": "worker_autostart",
                         "detail": f"pid={app.state.worker_proc.pid} port={first_port}"})
            else:
                log.info("worker already up", extra={"event": "worker_autostart", "detail": f"port {first_port}"})
    if not OWNER_TOKENS:
        log.error("no owner tokens configured", extra={"event": "config_error",
                  "detail": "VERNI_TOKEN/VERNI_TOKENS empty: every request will be 401"})
    sweeper_task = asyncio.create_task(_sweeper())
    try:
        yield
    finally:
        sweeper_task.cancel()
        for sid in list(sessions.keys()):
            await bridge_drop(sid)
        proc = getattr(app.state, "worker_proc", None)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


async def _sweeper() -> None:
    while True:
        await asyncio.sleep(60)
        now = time.time()
        for sid, session in list(sessions.items()):
            if now - session.touched_at > SESSION_TTL:
                log.info("session expired", extra={"event": "session_expired", "detail": sid[:8]})
                await bridge_drop(sid)


app.router.lifespan_context = lifespan
