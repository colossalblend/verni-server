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
import re
import sys
import time
from pathlib import Path

DSID_URL = "https://music.apple.com/us/account"
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


def main() -> int:
    ap = argparse.ArgumentParser(description="Open music.apple.com and steal dsid cookie.")
    ap.add_argument("browser", nargs="?", default="edge", choices=["edge", "chrome"])
    ap.add_argument("--timeout", type=int, default=DEFAULT_DEADS)
    ap.add_argument("--headless-smoke", action="store_true", help="hidden probe only (debug)")
    args = ap.parse_args()

    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service as ChromeSVC
        from selenium.webdriver.edge.service import Service as EdgeSVC
    except ImportError:
        raise SystemExit("pip install selenium") from None

    if args.browser == "edge":
        opts = webdriver.EdgeOptions()
        opts.add_argument("start-maximized")
        if args.headless_smoke:
            opts.add_argument("--headless=new")
        driver = webdriver.Edge(service=EdgeSVC(), options=opts)
    else:
        opts = webdriver.ChromeOptions()
        opts.add_argument("start-maximized")
        if args.headless_smoke:
            opts.add_argument("--headless=new")
        driver = webdriver.Chrome(service=ChromeSVC(), options=opts)

    try:
        driver.get(DSID_URL)
        print("[*] opened music.apple.com/us/account, log in via the visible browser")
        print("[*] polling cookies for dsid ...")
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
        else:
            print(f"[!] dsid not found in {args.timeout}s. All cookies seen: {cookie_dump or '<empty>'}")
            return 1
        return 0
    finally:
        try:
            driver.quit()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        sys.exit(130)
