# SPDX-License-Identifier: GPL-3.0-only
"""Реалистичный Edge для Apple-входа: прогрев, живой ввод, живой профиль.

- Edge запускается как обычный процесс (без webdriver-флагов), selenium
  подключается по CDP (debuggerAddress) -> navigator.webdriver = false,
  для Apple это неотличимо от обычного браузера.
- Профиль персистентный (profiles/<email>/): cookies и история живут между
  запусками, сессия не обнуляется при перезапусках и переиспользуется.
- Прогрев: apple.com с dwell и скроллом -> icloud.com, человеческий ритм,
  случайные паузы. Это снижает срабатывание риск-движка Apple при входе.
- Ввод посимвольный с джиттером и случайными "задумчивыми" паузами.
- 2FA НЕ обходится: отдельный запрос в консоли (введи код) либо довершение
  руками в окне; скрипт в обоих случаях ждёт cookie X-APPLE-WEBAUTH-USER.
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import winreg

DSID_URL = "https://www.icloud.com/"
PROFILES_DIR = Path(__file__).resolve().parent / "profiles"


# ---------------- dsid / cookies ----------------

def extract_dsid(cookies) -> str | None:
    for c in cookies:
        name = str(c.get("name", "")).lower()
        value = str(c.get("value", "")).strip().strip('"')
        if name in ("dsid", "x_dsid", "x-dsid") and value.isdigit():
            return value
        if name == "x-apple-webauth-user":
            m = re.search(r"(?:^|:)d=([0-9]{6,20})(?:$|:)", value)
            if m:
                return m.group(1)
    for c in cookies:
        name = str(c.get("name", "")).lower()
        value = str(c.get("value", "")).strip()
        if "dsid" in name and re.fullmatch(r"[0-9]{6,16}", value):
            return value
    return None


def browser_cookies(driver):
    try:
        return driver.execute_cdp_cmd("Network.getAllCookies", {}).get("cookies", [])
    except Exception:
        try:
            return driver.get_cookies()
        except Exception:
            return []


def poll_dsid(driver, deadline, log=print) -> str | None:
    while time.time() < deadline:
        dsid = extract_dsid(browser_cookies(driver))
        if dsid:
            return dsid
        try:
            time.sleep(1.5)
        except KeyboardInterrupt:
            return None
    return None


# ---------------- accounts.json ----------------

def load_accounts(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_json_atomic(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def write_dsid(dsid: str, email: str | None, log=print) -> None:
    here = Path(__file__).resolve().parent
    (here / "dsid.txt").write_text(dsid, encoding="ascii")
    log(f"[ok] dsid {dsid} -> dsid.txt")
    worker_dir = here / "worker"
    if worker_dir.exists():
        for h in worker_dir.rglob("iOSAuthSingle.exe"):
            (h.parent / "dsid.txt").write_text(dsid, encoding="ascii")
            log(f"[ok] dsid -> {h.parent / 'dsid.txt'}")
    if email:
        acc = load_accounts(here / "accounts.json")
        entry = acc.get(email, {})
        entry.update({"display_name": entry.get("display_name") or email.split("@")[0],
                      "dsid": int(dsid)})
        acc[email] = entry
        save_json_atomic(here / "accounts.json", acc)
        log(f"[ok] accounts.json: {email} -> dsid {dsid}")


# ---------------- браузер ----------------

def rand(lo: float, hi: float) -> float:
    return random.uniform(lo, hi)


def safe_name(email: str) -> str:
    return re.sub(r"[^a-z0-9_.@-]", "_", email.lower())


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


def launch_edge(port: int, profile_dir: Path, url: str = DSID_URL):
    """Обычный Edge-процесс с персистентным профилем, без automation-флагов."""
    profile_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen([
        edge_path(),
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile_dir}",
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--no-default-browser-check",
        "--start-maximized",
        url,
    ])
    wait_for_debugger(port)
    return proc


def attach(port: int):
    from selenium import webdriver
    opts = webdriver.EdgeOptions()
    opts.add_experimental_option("debuggerAddress", f"127.0.0.1:{port}")
    return webdriver.Edge(options=opts)


def human_type(el, text: str) -> None:
    el.click()
    time.sleep(rand(0.4, 0.9))
    for ch in text:
        el.send_keys(ch)
        time.sleep(rand(0.05, 0.16))
        if random.random() < 0.03:
            time.sleep(rand(0.3, 0.7))
    time.sleep(rand(0.4, 1.0))


def human_pause(lo: float = 0.6, hi: float = 1.8) -> None:
    time.sleep(rand(lo, hi))


def visible(driver, selectors, timeout: float = 8):
    end = time.time() + timeout
    while time.time() < end:
        for sel in selectors:
            try:
                el = driver.find_element("css selector", sel)
                if el.is_displayed():
                    return el
            except Exception:
                pass
        time.sleep(0.4)
    return None


def click_text(driver, texts, tags=("a", "button"), timeout: float = 6) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        for tag in tags:
            try:
                for el in driver.find_elements("tag name", tag):
                    t = (el.text or "").strip().lower()
                    if t and any(x in t for x in texts) and el.is_displayed():
                        el.click()
                        return True
            except Exception:
                pass
        time.sleep(0.5)
    return False


def enter_idmsa_frame(driver, timeout: float = 25) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            for f in driver.find_elements("tag name", "iframe"):
                src = (f.get_attribute("src") or "") + (f.get_attribute("id") or "")
                if "idmsa" in src or "idms" in src:
                    driver.switch_to.frame(f)
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def back_to_top(driver) -> None:
    try:
        driver.switch_to.default_content()
    except Exception:
        pass


# ---------------- прогрев ----------------

def warmup(driver, log=print) -> None:
    log("[*] прогрев сессии: apple.com ...")
    try:
        driver.get("https://www.apple.com/")
    except Exception as e:
        log(f"[i] apple.com не открылся ({e!r}) — не критично")
    time.sleep(rand(3.0, 5.0))
    try:
        for _ in range(random.randint(2, 4)):
            driver.execute_script("window.scrollBy(0, 500)")
            time.sleep(rand(0.8, 1.6))
        driver.execute_script("window.scrollTo(0, 0)")
    except Exception:
        pass
    human_pause(1.0, 2.5)
    log("[*] прогрев: icloud.com ...")
    try:
        driver.get(DSID_URL)
    except Exception:
        pass
    time.sleep(rand(4.0, 7.0))


# ---------------- 2FA ----------------

def detect_2fa(driver) -> bool:
    try:
        page = (driver.page_source or "").lower()
    except Exception:
        return False
    markers = ("verification", "verify your identity", "enter the code",
               "проверк", "введите код", "двухфакторн")
    return any(m in page for m in markers)


def fill_2fa(driver, code: str) -> bool:
    try:
        inputs = [i for i in driver.find_elements("css selector",
                  "input[id*=code], input[type=tel], input[autocomplete*=one-time]")
                  if i.is_displayed()]
        if not inputs:
            return False
        if len(inputs) >= len(code):
            for i, ch in enumerate(code):
                inputs[i].send_keys(ch)
        else:
            inputs[0].send_keys(code)
        time.sleep(rand(0.6, 1.2))
        try:
            for b in driver.find_elements("css selector", "button"):
                if (b.text or "").strip().lower() in ("continue", "продолжить", "submit") \
                        and b.is_displayed():
                    b.click()
                    break
        except Exception:
            pass
        return True
    except Exception:
        return False


# ---------------- вход ----------------

def run_login(email: str, password: str, timeout: float = 15 * 60,
              log=print, ask_2fa: bool = True,
              profile_dir: Path | None = None,
              do_warmup: bool = True) -> str | None:
    """Полный вход. Возвращает dsid или None. 2FA — отдельным запросом.

    ask_2fa=True: при появлении экрана проверки скрипт просит код в консоли
    и сам его подставляет; Enter без кода -> завершай руками в окне.
    ask_2fa=False (демо-режим): просто ждём, пока вход завершится в окне.
    """
    profile = profile_dir or (PROFILES_DIR / safe_name(email))
    port = free_port()
    proc = launch_edge(port, profile)
    driver = attach(port)
    dsid = None
    try:
        if do_warmup:
            warmup(driver, log)
        log("[*] автологин: ищу форму входа ...")
        if not click_text(driver, ("sign in", "войти")):
            log("[i] кнопка входа не найдена — возможно, уже залогинены")
        human_pause(1.5, 3.0)
        filled = False
        if enter_idmsa_frame(driver):
            email_el = visible(driver, ["#account_name_text_field",
                                        "input[type=email]", "input[name=accountName]"])
            if email_el is not None:
                email_el.clear()
                human_type(email_el, email)
                btn = visible(driver, ["#sign-in", "button[type=submit]"])
                if btn is not None:
                    btn.click()
                    log("[*] email отправлен, жду поле пароля ...")
                    time.sleep(rand(2.0, 3.5))
                    pw_el = visible(driver, ["input[type=password]",
                                             "#password_text_field"], timeout=12)
                    if pw_el is not None:
                        pw_el.clear()
                        human_type(pw_el, password)
                        btn = visible(driver, ["#sign-in", "button[type=submit]"])
                        if btn is not None:
                            btn.click()
                            filled = True
                            log("[*] пароль отправлен")
                            human_pause(2.0, 4.0)
        if not filled:
            log("[!] автозаполнение не удалось — дологинься руками в открытом окне")
            log("    скрипт ждёт cookie входа, не закрывай окно")

        deadline = time.time() + timeout
        prompted = False
        while time.time() < deadline:
            dsid = extract_dsid(browser_cookies(driver))
            if dsid:
                break
            if ask_2fa and not prompted and detect_2fa(driver):
                prompted = True
                log("")
                log("[2FA] нужна двухфакторка — ОТДЕЛЬНЫЙ ЗАПРОС:")
                log("      возьми код с доверенного устройства")
                try:
                    code = input("      код (Enter = завершу в окне сам): ").strip()
                except EOFError:
                    code = ""
                if code.isdigit() and len(code) >= 6:
                    back_to_top(driver)
                    if enter_idmsa_frame(driver, timeout=8) or True:
                        ok = fill_2fa(driver, code)
                        log("[*] код подставлен" if ok
                            else "[!] не подставил — введи код в окне руками")
                else:
                    log("[i] жду завершения входа в окне ...")
            time.sleep(1.5)
        if dsid:
            log("[ok] вход выполнен, dsid получен")
        else:
            log(f"[!] dsid не получен за {int(timeout)}s")
        return dsid
    finally:
        try:
            driver.quit()
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass
