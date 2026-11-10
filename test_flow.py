# SPDX-License-Identifier: GPL-3.0-only
"""Сквозной тест против живого server.py и fake_worker.py (как в CI, так и локально).

Требования: сервер уже запущен (см. README шаг 5 / GitHub workflow tests.yml).

  python test_flow.py https://127.0.0.1:18766 <VERNI_TOKEN>
"""
from __future__ import annotations

import base64
import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.request

FAKE_UDID = "00008101-000A112233445581"
FAKE_CERT_PLAIN = b"000081019999FAKECERT" * 6
ACCOUNT_EMAIL = "your-apple-id@example.com"


def post(url, token, payload, ca):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    data = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:18766"
    token = sys.argv[2] if len(sys.argv) > 2 else "A" * 64
    import pathlib
    cert = str(pathlib.Path(__file__).resolve().parent / "cert.pem")

    account_id = hashlib.sha256(ACCOUNT_EMAIL.encode()).hexdigest()

    status, j = post(f"{base}/v1/begin", token, {
        "account_id": account_id,
        "deviceUDID": FAKE_UDID,
        "FairPlayCertificate": base64.b64encode(FAKE_CERT_PLAIN).decode(),
        "deviceType": 16,
        "keyTypeSupportVersion": 99,
    }, cert)
    print("begin:", status, {k: (v[:24] + "..." if isinstance(v, str) and len(v) > 27 else v) for k, v in j.items()})
    if status != 200 or j.get("status") != "grappa_ready":
        return 1
    grappa = base64.b64decode(j["Grappa"])
    print("grappa bytes:", len(grappa))
    session = j["session_id"]

    status, j = post(f"{base}/v1/complete", token, {
        "session_id": session,
        "request": base64.b64encode(b"AFSYNC-RQ-PAYLOAD" * 8).decode(),
        "rq_sig": base64.b64encode(bytes(21)).decode(),
        "deviceGrappa": base64.b64encode(bytes(83)).decode(),
    }, cert)
    print("complete:", status, {k: (v[:24] + "..." if isinstance(v, str) and len(v) > 27 else v) for k, v in j.items()})
    if status != 200 or j.get("status") != "response_generated":
        return 1
    response = base64.b64decode(j["response"])
    sig = base64.b64decode(j["sig"])
    print("response:", len(response), response[:24])
    print("sig:", len(sig), sig)
    ok = len(sig) == 21 and len(response) > 0

    status, j = post(f"{base}/v1/abort", token, {"session_id": session}, cert)
    print("abort:", status, j)
    return 0 if (ok and status == 200 and j.get("status") == "aborted") else 1


if __name__ == "__main__":
    raise SystemExit(main())
