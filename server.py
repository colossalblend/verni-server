# SPDX-License-Identifier: GPL-3.0-only
r"""Серверная часть заменяет verniapp.ru:18766.

HTTP-контракт строго повторяет клиент C:\Windows\Temp\opencode\Verni_extract\payload\app\remote_provider.py:
- POST application/json, Bearer-токен (43-128 символов [A-Za-z0-9_-])
- /v1/ready    -> {'status':'listener_ready'} / catalog/account варианты
- /v1/begin    -> {'status':'grappa_ready','session_id':<64hex>,'Grappa':<b64>}
- /v1/complete -> {'status':'response_generated','device_acceptance_verified':True,
                   'response':<b64>,'sig':<b64>}
- /v1/abort    -> {'status':'aborted'}
- ошибки: {'error_code': <одно из известных клиенту значений>} + не-200 статус

FairPlay работы не выполняет сам: делегирует воркеру iOSAuthRuntime через bridge.py
(worker = iOSAuthSingle.exe со сборкой iOSAuthRuntime, рядом iTunes.dll под
C:\ProgramData\Apple Computer\iTunes\SC Info и свой DSID).

Запуск:
  set VERNI_TOKEN=...43+ символа [A-Za-z0-9_-]...
  uvicorn server:app --host 0.0.0.0 --port 18766 --ssl-certfile cert.pem --ssl-keyfile key.pem
":WORKER_PORT по умолчанию 27987 (порт кода iOSAuthSingle из main.cpp).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import secrets
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import bridge

TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43,128}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
UDID_RE = re.compile(r"[0-9a-fA-F\-]{20,64}")
MAX_BODY = 2 * 1024 * 1024

OWNER_TOKEN = os.environ.get("VERNI_TOKEN", "")
WORKER_HOST = os.environ.get("VERNI_WORKER_HOST", "127.0.0.1")
WORKER_PORT = int(os.environ.get("VERNI_WORKER_PORT", "27987"))
ACCOUNTS_PATH = Path(os.environ.get("VERNI_ACCOUNTS", os.path.join(os.path.dirname(__file__), "accounts.json")))
CATALOG_PATH = Path(os.environ.get("VERNI_CATALOG", os.path.join(os.path.dirname(__file__), "ipa-catalog.json")))
IPA_PATH = Path(os.environ.get("VERNI_PA_PATH", os.path.join(os.path.dirname(__file__), "ipa")))
SESSION_TTL = float(os.environ.get("VERNI_SESSION_TTL", "900"))

bridge.configure_worker(WORKER_HOST, WORKER_PORT)

app = FastAPI(title="verni-server")

# Привязка ключ -> UDID (persist-хранилище).
key_udid_path = Path(os.environ.get("VERNI_KEY_UDID", os.path.join(os.path.dirname(__file__), "key_udids.json")))

# Активные воркер-сессии: session_id -> WorkerSession
sessions: dict[str, bridge.WorkerSession] = {}
# Владелец-токен -> session_id активной сессии (одна на ключ)
owner_session: dict[str, str] = {}

# Загруженная привязка token ->UDID
key_udid: dict[str, str] = {}
if key_udid_path.exists():
    key_udid = json.loads(key_udid_path.read_text(encoding="utf-8"))


def save_key_udid() -> None:
    key_udid_path.write_text(json.dumps(key_udid, indent=2), encoding="utf-8")


def load_json(path: Path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def err(code: str, status: int) -> JSONResponse:
    return JSONResponse({"error_code": code}, status_code=status)


def bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:]
    if not TOKEN_RE.fullmatch(token) or not secrets.compare_digest(token, OWNER_TOKEN):
        return None
    return token


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


def owner(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def owner_token_by_session(session_id: str) -> str | None:
    for token, sid in owner_session.items():
        if sid == session_id:
            return token
    return None


@app.post("/v1/ready")
async def ready(request: Request):
    token = bearer(request)
    if token is None:
        return err("unauthorized", 401)
    payload = await read_json(request)
    if payload is None:
        return err("unauthorized", 401)
    selection = select_kind(payload)
    if selection is None:
        # пустой health-запрос
        return JSONResponse({"status": "listener_ready"})
    kind, value = selection
    if kind == "invalid":
        return err("invalid_account_id" if value == "account_id" else "invalid_ipa_hash", 400)
    if kind == "account":
        accounts = load_json(ACCOUNTS_PATH)
        matched = None
        for email in accounts:
            if hashlib.sha256(email.encode("utf-8")).hexdigest() == value:
                matched = email
                break
        if matched is None:
            return err("account_not_in_catalog", 404)
        info = accounts[matched]
        display_name = info.get("display_name") or info.get("account_display") or matched.split("@")[0]
        return JSONResponse({"status": "account_ready", "account_display_name": display_name})
    catalog = load_json(CATALOG_PATH)
    if isinstance(catalog, dict) and value in catalog:
        return JSONResponse({"status": "catalog_ready", "ipa_sha256": value})
    return JSONResponse({"status": "catalog_ready", "ipa_sha256": value})


@app.post("/v1/begin")
async def begin(request: Request):
    token = bearer(request)
    if token is None:
        return err("unauthorized", 401)
    payload = await read_json(request)
    if payload is None:
        return err("unauthorized", 401)
    selection = select_kind(payload)
    if selection is None:
        return err("invalid_request", 400)
    kind, value = selection
    if kind == "invalid":
        return err("invalid_account_id" if value == "account_id" else "invalid_ipa_hash", 400)
    if kind == "account":
        accounts = load_json(ACCOUNTS_PATH)
        matched = None
        for email in accounts:
            if hashlib.sha256(email.encode("utf-8")).hexdigest() == value:
                matched = email
                break
        if matched is None:
            return err("account_not_in_catalog", 404)
    # ipa-режим допустим

    device_udid = payload.get("deviceUDID")
    fpc_b64 = payload.get("FairPlayCertificate")
    device_type = payload.get("deviceType")
    key_version = payload.get("keyTypeSupportVersion")
    if not isinstance(device_udid, str) or not UDID_RE.fullmatch(device_udid):
        return err("invalid_request", 400)
    if not isinstance(fpc_b64, str) or not fpc_b64:
        return err("invalid_request", 400)
    if not isinstance(device_type, int) or not isinstance(key_version, int):
        return err("invalid_request", 400)
    if len(key_udid) > 0 and owner(token) in key_udid and key_udid[owner(token)] != device_udid:
        return err("wrong_device", 403)

    oref = owner(token)
    if oref in owner_session:
        return err("begin_already_used", 409)

    try:
        import base64
        fpc = base64.b64decode(fpc_b64, validate=True)
    except Exception:
        return err("invalid_request", 400)
    if not 0 < len(fpc) <= 512 * 1024:
        return err("invalid_request", 400)

    session_id = secrets.token_hex(32)
    session = bridge.WorkerSession(session_id)
    try:
        grappa = await asyncio.wait_for(
            session.begin(
                device_udid=device_udid,
                fairplay_cert=fpc,
                device_type=device_type,
                key_type_support_version=key_version,
                grappa_support_info=None,
            ),
            timeout=30,
        )
    except asyncio.TimeoutError:
        return err("owner_generator_busy", 503)
    except (OSError, ValueError):
        return err("worker_reported_error", 503)

    key_udid[oref] = device_udid
    save_key_udid()
    sessions[session_id] = session
    owner_session[oref] = session_id
    import base64 as _b64
    return JSONResponse({
        "status": "grappa_ready",
        "session_id": session_id,
        "Grappa": _b64.b64encode(grappa).decode("ascii"),
    })


@app.post("/v1/complete")
async def complete(request: Request):
    token = bearer(request)
    if token is None:
        return err("unauthorized", 401)
    payload = await read_json(request)
    if payload is None:
        return err("unauthorized", 401)
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not HEX64_RE.fullmatch(session_id):
        return err("unknown_session", 404)
    session = sessions.get(session_id)
    if session is None:
        return err("unknown_session", 404)
    oref = owner(token)
    if owner_session.get(oref) != session_id:
        return err("unknown_session", 404)

    import base64
    try:
        request_blob = base64.b64decode(payload.get("request") or "", validate=True)
        rq_sig = base64.b64decode(payload.get("rq_sig") or "", validate=True)
        device_grappa = base64.b64decode(payload.get("deviceGrappa") or "", validate=True)
    except Exception:
        await bridge_drop(session_id)
        return err("unknown_session", 404)
    if not (0 < len(request_blob) <= 512 * 1024):
        await bridge_drop(session_id)
        return err("unknown_session", 404)

    try:
        response, sig = await asyncio.wait_for(
            session.complete(device_grappa=device_grappa, rq_sig=rq_sig, request=request_blob),
            timeout=60,
        )
    except (asyncio.TimeoutError, OSError, ValueError, ConnectionError):
        await bridge_drop(session_id)
        return err("worker_reported_error", 503)
    await bridge_drop(session_id)
    return JSONResponse({
        "status": "response_generated",
        "device_acceptance_verified": True,
        "response": base64.b64encode(response).decode("ascii"),
        "sig": base64.b64encode(sig).decode("ascii"),
    })


async def bridge_drop(session_id: str) -> None:
    session = sessions.pop(session_id, None)
    if session is not None:
        await session.close()
    for oref, sid in list(owner_session.items()):
        if sid == session_id:
            owner_session.pop(oref, None)


@app.post("/v1/abort")
async def abort(request: Request):
    token = bearer(request)
    if token is None:
        return err("unauthorized", 401)
    payload = await read_json(request)
    if payload is None:
        return err("unauthorized", 401)
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not HEX64_RE.fullmatch(session_id):
        return JSONResponse({"status": "aborted"})
    await bridge_drop(session_id)
    return JSONResponse({"status": "aborted"})


@app.on_event("startup")
async def startup() -> None:
    async def sweeper():
        while True:
            await asyncio.sleep(60)
            for sid, session in list(sessions.items()):
                if time.time() - session.touched_at > SESSION_TTL:
                    await bridge_drop(sid)
    app.state.sweeper = asyncio.create_task(sweeper())


@app.on_event("shutdown")
async def shutdown() -> None:
    task = getattr(app.state, "sweeper", None)
    if task is not None:
        task.cancel()
    for sid in list(sessions.keys()):
        await bridge_drop(sid)
