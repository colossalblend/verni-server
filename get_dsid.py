# SPDX-License-Identifier: GPL-3.0-only
"""Get DSID: opens music.apple.com, waits for your manual login, and reads
the dsid cookie as soon as it appears.

  python get_dsid.py            # Edge (default), stay open up to 15 min
  python get_dsid.py chrome     # if chromium-based, another choice

Writes dsid.txt with the numeric dsid when found.

Note: do not close the window manually until it prints [ok] "dsid found".
You can stop any moment with Ctrl+C (browser will close automatically).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

DSID_URL = "https://www.icloud.com/"
HERE = Path(__file__).resolve().parent
DSID_FILE = HERE / "dsid.txt"
POLL_S = 1.5
DEFAULT_DEADS = 15 * 60  # 15 min


def extract_dsid(cookies) -> str | None:
    for c in cookies:
        name = c.get("name", "")
        value = str(c.get("value", "")).strip()
        if name.lower() in ("dsid", "x_dsid", "x-dsid"):
            if value.isdigit():
                return value
        # iCloud's current web session exposes the DSID as X-APPLE-WEBAUTH-USER:
        # "v=1:s=0:d=17230907310".
        if name.lower() == "x-apple-webauth-user":
            match = re.search(r"(?:^|:)d=([0-9]{6,20})(?:$|:)", value.strip('"'))
            if match:
                return match.group(1)
    # Fallback: any cookie ending/containing 'dsid' with numeric value
    for c in cookies:
        name = c.get("name", "").lower()
        value = str(c.get("value", "")).strip()
        if "dsid" in name and re.fullmatch(r"[0-9]{6,16}", value):
            return value
    return None


def browser_cookies(driver):
    try:
        # Chromium can return cookies across Apple domains, not just the current host.
        return driver.execute_cdp_cmd("Network.getAllCookies", {}).get("cookies", [])
    except Exception:
        return driver.get_cookies()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def edge_path() -> str:
    candidates = [
        shutil.which("msedge.exe"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    raise SystemExit("Microsoft Edge was not found")


def wait_for_debugger(port: int, timeout: float = 15) -> None:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/json/version"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise SystemExit("Edge remote debugging endpoint did not start")


def main() -> int:
    ap = argparse.ArgumentParser(description="Open iCloud and read the authenticated DSID.")
    ap.add_argument("browser", nargs="?", default="edge", choices=["edge"])
    ap.add_argument("--timeout", type=int, default=DEFAULT_DEADS)
    ap.add_argument("--account", default="", help="email to upsert into accounts.json (multi-account)")
    ap.add_argument("--headless-smoke", action="store_true", help="hidden probe only (debug)")
    args = ap.parse_args()

    try:
        from selenium import webdriver
    except ImportError:
        raise SystemExit("pip install selenium") from None

    if args.headless_smoke:
        raise SystemExit("headless-smoke is disabled: use a visible normal Edge window for Apple login")

    port = free_port()
    profile_dir = Path(tempfile.mkdtemp(prefix="verni-edge-"))
    browser = subprocess.Popen([
        edge_path(),
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--start-maximized",
        DSID_URL,
    ])
    wait_for_debugger(port)

    opts = webdriver.EdgeOptions()
    opts.add_experimental_option("debuggerAddress", f"127.0.0.1:{port}")
    driver = webdriver.Edge(options=opts)

    try:
        driver.get(DSID_URL)
        print("[*] opened iCloud, log in via the visible browser")
        print("[*] polling X-APPLE-WEBAUTH-USER and dsid cookies ...")
        dsid = None
        cookie_dump = set()
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            try:
                cookies = browser_cookies(driver)
            except Exception as e:
                print(f"[!] {e!r} - browser closed? Try retry")
                break
            dsid = extract_dsid(cookies)
            if dsid:
                break
            cookie_dump = {c["name"] for c in cookies}
            time.sleep(POLL_S)
        if dsid:
            DSID_FILE.write_text(dsid, encoding="ascii")
            print(f"[ok] dsid found: {dsid}")
            print(f"[ok] saved to {DSID_FILE}")
            worker_candidates = list((HERE / "worker").rglob("iOSAuthSingle.exe")) if (HERE / "worker").exists() else []
            if worker_candidates:
                worker_dir = worker_candidates[0].parent
                (worker_dir / "dsid.txt").write_text(dsid, encoding="ascii")
                print(f"[ok] copied to {worker_dir / 'dsid.txt'} (worker reads it on next connection)")
            print("[ok] for multiple accounts, put the dsid into accounts.json:")
            print(json.dumps({
                "you@example.com": {"display_name": "You", "dsid": int(dsid)},
            }, indent=2))
            if args.account:
                acc_path = HERE / "accounts.json"
                try:
                    acc = json.loads(acc_path.read_text(encoding="utf-8")) if acc_path.exists() else {}
                except Exception:
                    acc = {}
                acc[args.account] = {"display_name": args.account.split("@")[0], "dsid": int(dsid)}
                acc_path.write_text(json.dumps(acc, indent=2), encoding="utf-8")
                print(f"[ok] accounts.json updated: {args.account} -> dsid {dsid}")
        else:
            print(f"[!] dsid not found in {args.timeout}s. All cookies seen: {cookie_dump or '<empty>'}")
            return 1
        return 0
    finally:
        try:
            driver.quit()
        except Exception:
            pass
        try:
            browser.terminate()
            browser.wait(timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        sys.exit(130)
