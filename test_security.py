# SPDX-License-Identifier: GPL-3.0-only
"""Секьюрити-батарея против живого server.py (как в CI, так и локально).

  python test_security.py https://127.0.0.1:18766 <tokenA> [tokenB]

tokenB (второй ключ) нужен для IDOR-сценариев; если равен tokenA,
IDOR-тесты помечаются как skipped. Запускается ПОСЛЕ test_server/test_flow:
в конце батарея заполняет rate-окно и блокирует IP (auth lockout) —
это намеренно последнее действие против этого адреса на ~10 минут.
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

FAKE_UDID = "00008101-000A112233445581"
FAKE_CERT = base64.b64encode(b"000081019999FAKECERT" * 6).decode()
RQ = base64.b64encode(b"AFSYNC-RQ-PAYLOAD" * 8).decode()
RQSIG = base64.b64encode(bytes(21)).decode()
DGRAPPA = base64.b64encode(bytes(83)).decode()

results: list[tuple[str, str]] = []  # (name, PASS/FAIL/SKIP)


def check(name: str, cond: bool, note: str = "") -> None:
    results.append((name, "PASS" if cond else "FAIL"))
    print(f"[{'ok' if cond else 'FAIL'}] {name} {note}")


def post(url, token, payload, ca=None, method="POST"):
    ctx = ssl.create_default_context(cafile=ca)
    if ca:
        ctx.check_hostname = False
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:18766"
    tok_a = sys.argv[2] if len(sys.argv) > 2 else "A" * 64
    tok_b = sys.argv[3] if len(sys.argv) > 3 else tok_a
    cert = str(Path(__file__).resolve().parent / "cert.pem")
    n_fail_before = len(results)

    def acc_hash(email: str) -> str:
        return hashlib.sha256(email.encode()).hexdigest()

    def begin_payload(extra=None):
        p = {"account_id": acc_hash("your-apple-id@example.com"),
             "deviceUDID": FAKE_UDID, "FairPlayCertificate": FAKE_CERT,
             "deviceType": 16, "keyTypeSupportVersion": 99}
        p.update(extra or {})
        return p

    # ---- 1. auth required ----
    for path in ("/v1/ready", "/v1/begin", "/v1/complete", "/v1/abort"):
        st, _ = post(f"{base}{path}", None, {}, cert)
        check(f"noauth {path} -> 401", st == 401, str(st))
    st, _ = post(f"{base}/v1/health", None, None, cert, method="GET")
    check("noauth /v1/health -> 401", st == 401, str(st))

    # ---- 2. bad token ----
    st, _ = post(f"{base}/v1/ready", "B" * 64, {}, cert)
    check("bad token -> 401", st == 401, str(st))
    st, _ = post(f"{base}/v1/ready", tok_a[:-1] + ("0" if tok_a[-1] != "0" else "1"), {}, cert)
    check("near-miss token -> 401", st == 401, str(st))

    # ---- 3. malformed headers ----
    st, _ = post(f"{base}/v1/ready", "short", {}, cert)
    check("short token -> 401", st == 401, str(st))

    # ---- 4. health endpoint ----
    st, j = post(f"{base}/v1/health", tok_a, None, cert, method="GET")
    check("health w/ token -> 200", st == 200 and "worker" in j, str(st))

    # ---- 5. input validation fuzz ----
    st, _ = post(f"{base}/v1/begin", tok_a, begin_payload({"deviceType": True}), cert)
    check("bool deviceType -> 400", st == 400, str(st))
    st, _ = post(f"{base}/v1/begin", tok_a, begin_payload({"keyTypeSupportVersion": "99"}), cert)
    check("string keyVersion -> 400", st == 400, str(st))
    st, _ = post(f"{base}/v1/begin", tok_a, begin_payload({"FairPlayCertificate": "!!!notb64"}), cert)
    check("bad b64 cert -> 400", st == 400, str(st))
    st, _ = post(f"{base}/v1/begin", tok_a, begin_payload({"FairPlayCertificate": ""}), cert)
    check("empty cert -> 400", st == 400, str(st))
    st, _ = post(f"{base}/v1/begin", tok_a,
                 begin_payload({"FairPlayCertificate": base64.b64encode(b"Z" * (512 * 1024 + 1)).decode()}), cert)
    check("oversize cert -> 400", st == 400, str(st))
    st, _ = post(f"{base}/v1/begin", tok_a, begin_payload({"deviceUDID": "zz"}), cert)
    check("bad udid -> 400", st == 400, str(st))
    st, _ = post(f"{base}/v1/begin", tok_a,
                 begin_payload({"account_id": acc_hash("your-apple-id@example.com"),
                                "ipa_sha256": "a" * 64}), cert)
    check("double selection -> 400", st == 400, str(st))
    st, _ = post(f"{base}/v1/begin", tok_a,
                 begin_payload({"account_id": acc_hash("no-such@example.com")}), cert)
    check("unknown account -> 404", st == 404, str(st))
    st, _ = post(f"{base}/v1/complete", tok_a,
                 {"session_id": "0" * 64, "request": RQ, "rq_sig": base64.b64encode(bytes(5)).decode(),
                  "deviceGrappa": DGRAPPA}, cert)
    check("short rq_sig -> 400/404", st in (400, 404), str(st))
    st, _ = post(f"{base}/v1/complete", tok_a,
                 {"session_id": "0" * 64, "request": RQ, "rq_sig": RQSIG,
                  "deviceGrappa": base64.b64encode(bytes(3)).decode()}, cert)
    check("short deviceGrappa -> 400/404", st in (400, 404), str(st))
    st, j = post(f"{base}/v1/begin", tok_a, begin_payload({"FairPlayCertificate": FAKE_CERT} | {"deviceUDID": FAKE_UDID} | {"deviceType": 16} | {"keyTypeSupportVersion": 99} | {"junk": "x" * 300000}), cert)
    check("mass-assignment junk tolerated safely", st in (200, 409, 400), str(st))
    if st == 200:
        st2, _ = post(f"{base}/v1/abort", tok_a, {"session_id": j["session_id"]}, cert)
        check("cleanup junk session (slot freed)", st2 == 200, str(st2))

    # ---- 6. IDOR / BOLA ----
    if tok_a == tok_b:
        results.append(("idor suite", "SKIP"))
        print("[skip] idor suite (needs two different tokens)")
    else:
        st, j = post(f"{base}/v1/begin", tok_a, begin_payload(), cert)
        ok = st == 200 and j.get("status") == "grappa_ready"
        check("A begin ok", ok, str(st))
        if ok:
            sid_a = j["session_id"]
            # B пытается работать с сессией A
            st, _ = post(f"{base}/v1/complete", tok_b,
                         {"session_id": sid_a, "request": RQ, "rq_sig": RQSIG, "deviceGrappa": DGRAPPA}, cert)
            check("B complete(A session) -> 404", st == 404, str(st))
            st, _ = post(f"{base}/v1/abort", tok_b, {"session_id": sid_a}, cert)
            check("B abort(A session) -> 200 (no-op)", st == 200, str(st))
            # сессия A должна выжить и отработать до конца
            st, j2 = post(f"{base}/v1/complete", tok_a,
                          {"session_id": sid_a, "request": RQ, "rq_sig": RQSIG, "deviceGrappa": DGRAPPA}, cert)
            check("A complete survives B abort -> 200", st == 200 and j2.get("status") == "response_generated", str(st))
            if st != 200:
                st, _ = post(f"{base}/v1/abort", tok_a, {"session_id": sid_a}, cert)
            # изоляция слотов: B может начать свою параллельную сессию
            st, j3 = post(f"{base}/v1/begin", tok_b, begin_payload(), cert)
            check("B begin ok (per-token slot)", st == 200, str(st))
            if st == 200:
                sid_b = j3["session_id"]
                check("B session != A session", sid_b != sid_a)
                st, _ = post(f"{base}/v1/abort", tok_b, {"session_id": sid_b}, cert)
            st, _ = post(f"{base}/v1/complete", tok_b, {"session_id": sid_a, "request": RQ, "rq_sig": RQSIG, "deviceGrappa": DGRAPPA}, cert)
            check("B complete consumed A session -> 404", st == 404, str(st))

    # ---- 7. replay: complete второй раз ----
    st, j = post(f"{base}/v1/begin", tok_a, begin_payload(), cert)
    if st == 200:
        sid = j["session_id"]
        st1, _ = post(f"{base}/v1/complete", tok_a, {"session_id": sid, "request": RQ, "rq_sig": RQSIG, "deviceGrappa": DGRAPPA}, cert)
        st2, _ = post(f"{base}/v1/complete", tok_a, {"session_id": sid, "request": RQ, "rq_sig": RQSIG, "deviceGrappa": DGRAPPA}, cert)
        check("replay complete -> second 404", st1 == 200 and st2 == 404, f"{st1},{st2}")
    else:
        check("replay setup begin", False, str(st))

    # ---- 8. race: параллельные begin одного токена ----
    def race_begin(_i):
        return post(f"{base}/v1/begin", tok_a, begin_payload(), cert)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        codes = list(ex.map(race_begin, range(6)))
    wins = codes.count(200)
    conflicts = codes.count(409)
    check("race begin: 1 win + 5x409", wins == 1 and conflicts == 5, str(codes))

    # ---- 9. big body ----
    st, _ = post(f"{base}/v1/begin", tok_a, begin_payload({"FairPlayCertificate": FAKE_CERT}) | {"_pad": "x" * (2 * 1024 * 1024 + 1)}, cert)
    check("big body -> 400", st == 400, str(st))

    # ---- 10. rate limit (заполняет окно) ----
    codes = []
    for _ in range(130):
        st, _ = post(f"{base}/v1/ready", tok_a, {}, cert)
        codes.append(st)
        if st == 429:
            break
    check("rate limit -> 429", 429 in codes, f"codes tail {codes[-3:]}")

    # ---- 11. auth lockout (САМОЕ ПОСЛЕДНЕЕ: блокирует IP) ----
    for _ in range(12):
        post(f"{base}/v1/ready", "C" * 64, {}, cert)
    st, _ = post(f"{base}/v1/ready", tok_a, {}, cert)
    check("auth lockout valid token -> 429", st == 429, str(st))

    # ---- 12. секреты не утекают ----
    leak = False
    log_path = Path(__file__).resolve().parent / "srvlog.txt"
    if log_path.exists():
        tail = log_path.read_bytes()[-200000:]
        for tok in {tok_a, tok_b}:
            if tok.encode() in tail:
                leak = True
    check("no token in srvlog.txt", not leak)

    fails = [n for n, s in results if s == "FAIL"]
    print(f"\nsecurity battery: {len(results) - len(fails)} ok, {len(fails)} fail"
          + (f", skipped: {sum(1 for _, s in results if s == 'SKIP')}" if any(s == 'SKIP' for _, s in results) else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
