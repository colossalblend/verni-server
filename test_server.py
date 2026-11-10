# SPDX-License-Identifier: GPL-3.0-only
"""Проверка HTTP-сервера (server.py) без телефона и без воркера.

  python test_server.py [base_url] [bearer_token]

Примеры:
  python test_server.py https://127.0.0.1:18766 "<VERNI_TOKEN>"
"""
from __future__ import annotations

import base64
import json
import ssl
import sys
import urllib.error
import urllib.request


def post(url: str, token: str, payload: dict, ca: str | None = None):
    ctx = ssl.create_default_context()
    if ca:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
        ctx.check_hostname = False
    data = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main() -> int:
    cert = str(__import__("pathlib").Path(__file__).resolve().parent / "cert.pem")
    base = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:18766"
    token = sys.argv[2] if len(sys.argv) > 2 else "A" * 64

    good = 0
    status, j = post(base + "/v1/ready", token, {}, cert)
    print(f"ready/no-sel   -> {status} {j}")
    good += status == 200 and j.get("status") == "listener_ready"

    status, j = post(base + "/v1/ready", "B" * 64, {}, cert)
    print(f"ready/bad-key  -> {status} {j}")
    good += status == 401 and j.get("error_code") == "unauthorized"

    bad_hex = "z" * 64
    status, j = post(base + "/v1/ready", token, {"account_id": bad_hex}, cert)
    print(f"ready/bad-sel  -> {status} {j}")
    good += status == 400 and j.get("error_code") in ("invalid_account_id", "unauthorized")

    status, j = post(base + "/v1/complete", token, {"session_id": "0" * 64, "request": "A", "rq_sig": "B", "deviceGrappa": "C"}, cert)
    print(f"complete/ghost -> {status} {j}")
    good += status == 404 and j.get("error_code") == "unknown_session"

    status, j = post(base + "/v1/abort", token, {"session_id": "0" * 64}, cert)
    print(f"abort/ghost    -> {status} {j}")
    good += status == 200 and j.get("status") == "aborted"

    print(f"\n{'ok' if good == 5 else 'проблемы'}: {good}/5")
    return 0 if good == 5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
