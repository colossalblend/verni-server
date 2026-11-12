# SPDX-License-Identifier: GPL-3.0-only
r"""Демон прогрева Apple-сессии: держит dsid живым, при смерти — перевыпуск.

Цикл (по умолчанию каждые 6 часов, --interval):
1. Открывает Edge с персистентным профилем аккаунта (profiles/<email>/) на
   icloud.com — сам факт визита освежает cookies; сессия не умирает.
2. Проверяет, что dsid извлекается из cookies.
3. Жива и совпадает с accounts.json -> статус session_ok (обновление файлов
   не требуется). Жива, но dsid другой -> обновляет dsid.txt/accounts.json.
4. Мертва -> авто-вход по паролю из secrets.dat (DPAPI, кладёт туда
   setup_account.py). Если вход требует 2FA — в авто-режиме не обходится:
   уведомление reauth_required (лог + webhook) и повтор в следующем цикле.
   Пароль в secrets.dat отсутствует -> reauth_required_no_creds.

Уведомления: консоль (с меткой времени) + POST json на VERNI_WEBHOOK_URL
(без секретов — только event/detail/email/ts). Статус каждого цикла
пишется в session_state.json.

Запуск:
  python session_keepalive.py --email you@example.com
  python session_keepalive.py --email you@example.com --once   # один цикл
  python session_keepalive.py --interval 4h --email ...
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request
from pathlib import Path

import apple_session
import store

HERE = Path(__file__).resolve().parent
STATE_PATH = HERE / "session_state.json"
SECRETS_PATH = HERE / "secrets.dat"


def log(msg: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def notify(webhook: str | None, event: str, detail: str = "", email: str = "") -> None:
    log(f"event={event}" + (f" ({detail})" if detail else ""))
    if not webhook:
        return
    body = json.dumps({"event": event, "detail": detail,
                       "email": email, "ts": int(time.time())}).encode()
    req = urllib.request.Request(webhook, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception:
        pass  # уведомление не должно валить демон


def write_state(status: str, dsid: str | None, email: str) -> None:
    apple_session.save_json_atomic(STATE_PATH, {
        "ts": int(time.time()),
        "email": email,
        "status": status,
        "dsid": dsid or None,
    })


def check_dsid_agrees(email: str, dsid: str, webhook) -> str:
    acc = apple_session.load_accounts(HERE / "accounts.json")
    known = str(acc.get(email, {}).get("dsid", "")) if email else ""
    if known and known != dsid:
        apple_session.write_dsid(dsid, email, log=log)
        notify(webhook, "dsid_changed", f"{known} -> {dsid}", email)
        return "dsid_changed"
    return "session_ok"


def cycle(email: str, timeout: float, webhook: str | None) -> str:
    profile = apple_session.PROFILES_DIR / apple_session.safe_name(email) if email \
        else apple_session.PROFILES_DIR / "default"
    if not (profile / "Default").exists() and not (profile / "Preferences").exists():
        log("[!] профиль аккаунта не найден — сначала setup_account.py")
        write_state("no_profile", None, email)
        return "no_profile"

    port = apple_session.free_port()
    proc = apple_session.launch_edge(port, profile)
    driver = None
    try:
        driver = apple_session.attach(port)
        time.sleep(apple_session.rand(5.0, 8.0))
        dsid = apple_session.poll_dsid(driver, time.time() + 20)
        if dsid:
            status = check_dsid_agrees(email, dsid, webhook)
            write_state(status, dsid, email)
            return status
        log("[i] сессия мертва — пробую перевыпуск по сохранённому паролю ...")
        creds = store.load_secret(SECRETS_PATH)
        if not creds or creds.get("email") != email or not creds.get("password"):
            notify(webhook, "reauth_required_no_creds",
                   "пароля в secrets.dat нет — запусти setup_account.py", email)
            write_state("reauth_required_no_creds", None, email)
            return "reauth_required_no_creds"
        dsid = apple_session.run_login(email, creds["password"], timeout=timeout,
                                       log=log, ask_2fa=False, profile_dir=profile,
                                       do_warmup=False)
        if dsid:
            apple_session.write_dsid(dsid, email, log=log)
            notify(webhook, "session_reissued", f"dsid {dsid}", email)
            write_state("session_reissued", dsid, email)
            return "session_reissued"
        notify(webhook, "reauth_required",
               "авто-вход не завершён (вероятна 2FA) — нужен ручной вход", email)
        write_state("reauth_required", None, email)
        return "reauth_required"
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        try:
            proc.terminate()
        except Exception:
            pass


def parse_interval(s: str) -> int:
    s = s.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return int(float(s[:-1] if s[-1:] in units else s) * units.get(s[-1:], 1))


def main() -> int:
    acc = apple_session.load_accounts(HERE / "accounts.json")
    first = next(iter(acc), "") if acc else ""
    ap = argparse.ArgumentParser(description="Прогрев/перевыпуск Apple-сессии (демон)")
    ap.add_argument("--email", default=first, help="по умолчанию первый аккаунт из accounts.json")
    ap.add_argument("--interval", default="6h", help="пауза между циклами: 6h, 30m, 900s ...")
    ap.add_argument("--once", action="store_true", help="один цикл и выход")
    ap.add_argument("--timeout", type=int, default=240, help="лимит попытки перевыпуска, с")
    args = ap.parse_args()
    if not args.email:
        print("[!] нет аккаунта: передай --email или заполни accounts.json")
        return 1
    webhook = os.environ.get("VERNI_WEBHOOK_URL", "")
    interval = parse_interval(args.interval)
    log(f"демон стартовал: email={args.email}, интервал={interval}s")
    while True:
        try:
            cycle(args.email, args.timeout, webhook)
        except KeyboardInterrupt:
            log("стоп по Ctrl+C")
            return 0
        except Exception as e:
            log(f"[!] цикл упал: {e!r}")
            notify(webhook, "cycle_error", repr(e)[:200], args.email)
        if args.once:
            return 0
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            log("стоп по Ctrl+C")
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
