# SPDX-License-Identifier: GPL-3.0-only
r"""Полная настройка аккаунта из логина+пароля — минимум рук.

Этап 1 — браузер (Edge + CDP): автологин на icloud.com. Пароль вводится
скриптом; 2FA/CAPTCHA/подтверждение доверенного устройства НЕ обходятся —
скрипт либо ждёт, пока ты завершишь шаг в видимом окне, либо принимает код
в консоли и подставляет его. DSID берётся из cookie X-APPLE-WEBAUTH-USER и
прописывается в accounts.json (по --email) + dsid.txt (корень и каталог
воркера). Если автозаполнение DOM ломается — автоматом включается
резервный режим "дологинься руками в окне", дальше всё равно автоматически.

Этап 2 — iTunes: установка (install_itunes.ps1), первый запуск (создаёт
SC Info), ожидание появления SC Info.sidb/sidd. Если после первого запуска
файлов нет — одна инструкция (войти в аккаунт + Store -> Authorize) и
поллинг до появления. Пароли Apple в консоль/логи не печатаются.

Запуск (в RDP-сессии сервера, окно должно быть видно):
  python setup_account.py --email you@example.com
  python setup_account.py --email you@example.com --password-stdin < pw.txt
  python setup_account.py --email you@example.com --skip-itunes
  python setup_account.py --email you@example.com --skip-browser   # только iTunes
"""
from __future__ import annotations

import argparse
import getpass
import json
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import winreg

DSID_URL = "https://www.icloud.com/"
HERE = Path(__file__).resolve().parent
ACCOUNTS_PATH = HERE / "accounts.json"
DSID_FILE = HERE / "dsid.txt"
SC_DIR = Path(r"C:\ProgramData\Apple Computer\iTunes\SC Info")


# ---------------- утилиты ----------------

def extract_dsid(cookies) -> str | None:
    for c in cookies:
        name = c.get("name", "").lower()
        value = str(c.get("value", "")).strip().strip('"')
        if name in ("dsid", "x_dsid", "x-dsid") and value.isdigit():
            return value
        if name == "x-apple-webauth-user":
            m = re.search(r"(?:^|:)d=([0-9]{6,20})(?:$|:)", value)
            if m:
                return m.group(1)
    for c in cookies:
        name = c.get("name", "").lower()
        value = str(c.get("value", "")).strip()
        if "dsid" in name and re.fullmatch(r"[0-9]{6,16}", value):
            return value
    return None


def browser_cookies(driver):
    try:
        return driver.execute_cdp_cmd("Network.getAllCookies", {}).get("cookies", [])
    except Exception:
        return driver.get_cookies()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def edge_path() -> str:
    for cand in (
        shutil.which("msedge.exe"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ):
        if cand and Path(cand).exists():
            return cand
    raise SystemExit("Edge не найден")


def wait_for_debugger(port: int, timeout: float = 20) -> None:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/json/version"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise SystemExit("Edge remote debugging не поднялся")


def write_dsid(dsid: str, email: str | None) -> None:
    DSID_FILE.write_text(dsid, encoding="ascii")
    print(f"[ok] dsid {dsid} -> {DSID_FILE}")
    hits = list((HERE / "worker").rglob("iOSAuthSingle.exe")) if (HERE / "worker").exists() else []
    for h in hits:
        (h.parent / "dsid.txt").write_text(dsid, encoding="ascii")
        print(f"[ok] dsid -> {h.parent / 'dsid.txt'}")
    if email:
        acc = {}
        if ACCOUNTS_PATH.exists():
            try:
                acc = json.loads(ACCOUNTS_PATH.read_text(encoding="utf-8"))
            except Exception:
                acc = {}
        acc[email] = {"display_name": email.split("@")[0], "dsid": int(dsid)}
        save_json_atomic(ACCOUNTS_PATH, acc)
        print(f"[ok] accounts.json: {email} -> dsid {dsid}")


def save_json_atomic(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    import os
    os.replace(tmp, path)


# ---------------- этап 1: браузер ----------------

def first_text(driver, selectors, timeout=8):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    end = time.time() + timeout
    while time.time() < end:
        for sel in selectors:
            try:
                el = driver.find_element(By.CSS_SELECTOR, sel)
                if el.is_displayed():
                    return el
            except Exception:
                pass
        time.sleep(0.4)
    return None


def enter_idmsa_frame(driver, timeout=25) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        for f in driver.find_elements("tag name", "iframe"):
            src = (f.get_attribute("src") or "") + (f.get_attribute("id") or "")
            if "idmsa" in src or "idms" in src:
                driver.switch_to.frame(f)
                return True
        time.sleep(0.5)
    return False


def login_phase(args) -> str | None:
    from selenium import webdriver

    port = free_port()
    profile_dir = Path(tempfile.mkdtemp(prefix="verni-login-"))
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
    dsid = None
    try:
        time.sleep(3)
        driver.get(DSID_URL)
        print("[*] icloud.com открыт; пробую автологин...")
        # кнопка входа на лендинге (если есть)
        for text in ("Sign In", "Войти"):
            try:
                btns = [b for b in driver.find_elements("tag name", "a") + driver.find_elements("tag name", "button")
                        if text.lower() in (b.text or "").lower()]
                if btns:
                    btns[0].click()
                    print(f"[*] нажал '{text}'")
                    break
            except Exception:
                pass
        time.sleep(3)
        in_frame = enter_idmsa_frame(driver)
        filled = False
        if in_frame:
            email_el = first_text(driver, [
                "#account_name_text_field", "input[type=email]", "input[name=accountName]"])
            if email_el is not None:
                email_el.clear()
                email_el.send_keys(args.email)
                btn = first_text(driver, ["#sign-in", "button[type=submit]", "button[aria-label*=Continue]"])
                if btn is not None:
                    btn.click()
                    print("[*] email отправлен")
                    time.sleep(2)
                    pw_el = first_text(driver, ["input[type=password]"], timeout=12)
                    if pw_el is not None:
                        pw_el.clear()
                        pw_el.send_keys(args.password)
                        btn = first_text(driver, ["#sign-in", "button[type=submit]"])
                        if btn is not None:
                            btn.click()
                            filled = True
                            print("[*] пароль отправлен")
        if not filled:
            print("[!] автозаполнение не удалось — дологинься руками в открытом окне")
        # 2FA: не обходим; ждём либо ручного завершения, либо кода в консоли
        deadline = time.time() + args.timeout
        prompted_2fa = False
        while time.time() < deadline:
            cookies = browser_cookies(driver)
            dsid = extract_dsid(cookies)
            if dsid:
                break
            try:
                page = (driver.page_source or "").lower()
            except Exception:
                page = ""
            if not prompted_2fa and ("verif" in page or "verification" in page or "enter the code" in page
                                     or "код" in page or "input[type=tel]" in page):
                prompted_2fa = True
                print("[!] нужна 2FA: возьми код с доверенного устройства.")
                print("    Введи его в окне браузера ИЛИ вставь сюда и нажми Enter (пусто = ждём окно):")
                try:
                    code = input().strip()
                except EOFError:
                    code = ""
                if code and code.isdigit():
                    try:
                        inputs = driver.find_elements("css selector", "input[id*=code], input[type=tel]")
                        for i, ch in enumerate(code[:6]):
                            inputs[i].send_keys(ch)
                        print("[*] код подставлен")
                    except Exception as e:
                        print(f"[!] код не подставился ({e!r}) — введи в окне руками")
            time.sleep(1.5)
        if dsid:
            print("[ok] вход выполнен")
            write_dsid(dsid, args.email)
        else:
            print(f"[!] DSID не получен за {args.timeout}s — проверь вход вручную и перезапусти")
        return dsid
    finally:
        try:
            driver.quit()
        except Exception:
            pass
        try:
            browser.terminate()
        except Exception:
            pass


# ---------------- этап 2: iTunes ----------------

def itunes_installed() -> str | None:
    for hive in (winreg.HKEY_LOCAL_MACHINE,):
        for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
            try:
                k = winreg.OpenKey(hive, r"SOFTWARE\Apple Computer, Inc.\iTunes", 0, winreg.KEY_READ | view)
                val, _ = winreg.QueryValueEx(k, "InstallDir")
                exe = Path(val) / "iTunes.exe"
                if exe.exists():
                    return str(exe)
            except OSError:
                continue
    return None


def itunes_phase(args) -> bool:
    exe = itunes_installed()
    if exe is None:
        print("[*] iTunes не найден — тихая установка 12.10.11 (32-bit)...")
        ps = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", str(HERE / "install_itunes.ps1")],
            cwd=str(HERE))
        if ps.returncode != 0:
            print(f"[!] установщик вернул {ps.returncode} — смотри вывод выше")
        exe = itunes_installed()
    if exe is None:
        print("[!] iTunes так и не установлен — установка вручную и перезапуск")
        return False

    sc_sidb = SC_DIR / "SC Info.sidb"
    sc_sidd = SC_DIR / "SC Info.sidd"
    if sc_sidb.exists() and sc_sidd.exists():
        print(f"[ok] SC Info уже на месте: {SC_DIR}")
        return True

    print(f"[*] запускаю iTunes: {exe} (первый запуск создаёт SC Info)")
    subprocess.Popen([exe])
    print("[*] жду SC Info.sidb/sidd ...")
    print("    Если iTunes покажет приветствие/соглашение — прими его в окне.")
    print("    Если файлов долго нет: войди в аккаунт в iTunes и сделай")
    print("    Store -> Authorize This Computer (это единственный шаг,")
    print("    который Apple не даёт автоматизировать).")
    deadline = time.time() + args.itunes_wait
    while time.time() < deadline:
        if sc_sidb.exists() and sc_sidd.exists():
            print(f"[ok] SC Info на месте: {SC_DIR}")
            return True
        time.sleep(3)
    print(f"[!] SC Info не появились за {args.itunes_wait}s — заверши авторизацию в iTunes")
    return False


# ---------------- main ----------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Автонастройка аккаунта: браузер -> DSID -> iTunes -> SC Info")
    ap.add_argument("--email", required="--skip-browser" not in sys.argv, default="")
    ap.add_argument("--password-stdin", action="store_true", help="пароль первой строкой stdin")
    ap.add_argument("--env", action="store_true", help="пароль из VERNI_APPLE_PASSWORD")
    ap.add_argument("--timeout", type=int, default=15 * 60, help="лимит этапа браузера, с")
    ap.add_argument("--itunes-wait", type=int, default=15 * 60, help="сколько ждать SC Info, с")
    ap.add_argument("--skip-itunes", action="store_true")
    ap.add_argument("--skip-browser", action="store_true")
    args = ap.parse_args()

    password = ""
    if not args.skip_browser:
        if args.password_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
        elif args.env:
            password = __import__("os").environ.get("VERNI_APPLE_PASSWORD", "")
        else:
            password = getpass.getpass(f"пароль Apple ID для {args.email}: ")
        if not password:
            print("[!] пароль не получен")
            return 1

    ok = True
    if not args.skip_browser:
        dsid = login_phase(args)
        ok = dsid is not None
    if ok and not args.skip_itunes:
        ok = itunes_phase(args)

    print()
    print("Готово." if ok else "Есть незакрытые шаги — смотри сообщения выше.")
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] прервано")
        sys.exit(130)
