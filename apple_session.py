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
            for sel in ("button[type=submit]", "button"):
                for b in driver.find_elements("css selector", sel):
                    t = (b.text or "").strip().lower()
                    if b.is_displayed() and (t in ("continue", "продолжить", "submit", "отправить")
                                             or sel.endswith("type=submit]")):
                        _js_click(b)
                        return True
        except Exception:
            pass
        try:
            inputs[-1].send_keys("\n")  # Enter как fallback
        except Exception:
            pass
        return True
    except Exception:
        return False


# ---------------- вход ----------------

AUTH_COOKIE_NAMES = (
    "X-APPLE-WEBAUTH-USER", "X-APPLE-WEBAUTH-TOKEN", "X-APPLE-WEBAUTH-VARIANT",
    "X-APPLE-DS-WEB-SESSION-TOKEN", "X-APPLE-DS-WEB-SESSION-HTTP",
    "X-APPLE-DS-WEB-STAT", "X-APPLE-DS-ID", "myacinfo",
)


def _log(msg: str) -> None:
    print(msg, flush=True)


def clear_auth_cookies(driver, log=_log) -> None:
    """Убивает старые auth-cookies: любые dsid после этого — только свежий вход."""
    n = 0
    for name in AUTH_COOKIE_NAMES:
        for domain in (".icloud.com", "icloud.com", ".apple.com", "apple.com",
                       "idmsa.apple.com", "idmsa.apple.com.".rstrip(".")):
            try:
                driver.execute_cdp_cmd("Network.deleteCookies",
                                       {"name": name, "domain": domain})
                n += 1
            except Exception:
                pass
    log(f"[*] старые auth-cookies почищены ({n})")


def _safe_page(driver) -> str:
    try:
        return (driver.page_source or "").lower()
    except Exception:
        return ""


def _frame_scan(driver, pred, timeout: float, depth: int = 0):
    """Ищет первый фрейм (или top), где pred(driver) истинно; остаётся
    переключенным туда. Возвращает дескриптор ('top'/'self'/element) или None.
    depth ограничивает вложенность iframe."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            driver.switch_to.default_content()
        except Exception:
            pass
        if _safe_pred(driver, pred):
            return "top"
        try:
            frames = driver.find_elements("tag name", "iframe")
        except Exception:
            frames = []
        for f in frames:
            try:
                driver.switch_to.frame(f)
                if _safe_pred(driver, pred):
                    return f
                if depth < 2:
                    try:
                        inner = driver.find_elements("tag name", "iframe")
                    except Exception:
                        inner = []
                    for g in inner:
                        try:
                            driver.switch_to.frame(g)
                            if _safe_pred(driver, pred):
                                return g
                            driver.switch_to.parent_frame()
                        except Exception:
                            driver.switch_to.parent_frame()
                driver.switch_to.default_content()
            except Exception:
                driver.switch_to.default_content()
        time.sleep(0.6)
    return None


def _safe_pred(driver, pred) -> bool:
    try:
        return bool(pred(driver))
    except Exception:
        return False


def _email_visible(driver) -> bool:
    for sel in ("#account_name_text_field", "input[type=email]", "input[name=accountName]"):
        try:
            for el in driver.find_elements("css selector", sel):
                if el.is_displayed():
                    return True
        except Exception:
            pass
    return False


def _pw_visible(driver) -> bool:
    try:
        for el in driver.find_elements("css selector", "input[type=password]"):
            if el.is_displayed():
                return True
    except Exception:
        pass
    return False


def _code_visible(driver) -> bool:
    try:
        for el in driver.find_elements("css selector",
                                       "input[id*=code], input[type=tel], input[autocomplete*=one-time]"):
            if el.is_displayed():
                return True
    except Exception:
        pass
    return False


def _js_click(el) -> None:
    try:
        el.click()
    except Exception:
        try:
            el.parent.execute_script("arguments[0].click()", el)
        except Exception:
            pass


def sign_in_click(driver, log=_log) -> bool:
    """Клик по кнопке входа: a/button/div/span по тексту (shadow DOM часто
    прячет кнопку от обычных селекторов), затем проверка новых вкладок."""
    xpaths = [
        "//*[self::a or self::button or @role='button'][contains(translate(., 'SINGVOЙР', 'singvoйр'),'sign in')]",
        "//*[self::a or self::button or @role='button'][contains(translate(., 'АВОЙР', 'авойр'),'войти')]",
        "//*[contains(@class,'sign-in') or contains(@id,'sign-in')][self::div or self::span or self::a or self::button]",
    ]
    end = time.time() + 10
    while time.time() < end:
        for xp in xpaths:
            try:
                for el in driver.find_elements("xpath", xp):
                    t = (el.text or "").strip().lower()
                    if t and ("sign" in t or "войти" in t or "вход" in t) and el.is_displayed():
                        _js_click(el)
                        log(f"[*] нажал кнопку входа ('{t[:40]}')")
                        human_pause(1.5, 3.0)
                        try:
                            handles = driver.window_handles
                            if len(handles) > 1:
                                driver.switch_to.window(handles[-1])
                                log("[*] форма открылась в новой вкладке")
                        except Exception:
                            pass
                        return True
            except Exception:
                pass
        time.sleep(0.7)
    return False


def _trust_visible(driver) -> bool:
    try:
        for b in driver.find_elements("xpath",
                "//button[contains(translate(., 'TRUSTДОВЕРЯ', 'trustдоверя'),'trust') or "
                "contains(translate(., 'TRUSTДОВЕРЯ', 'trustдоверя'),'доверя')]"):
            if b.is_displayed():
                return True
    except Exception:
        pass
    return False


def _click_trust(driver) -> bool:
    try:
        for b in driver.find_elements("xpath",
                "//button[contains(translate(., 'TRUSTДОВЕРЯ', 'trustдоверя'),'trust') or "
                "contains(translate(., 'TRUSTДОВЕРЯ', 'trustдоверя'),'доверя')]"):
            if b.is_displayed() and "not" not in (b.text or "").lower() \
                    and "не" not in (b.text or "").lower():
                _js_click(b)
                return True
    except Exception:
        pass
    return False


def _has_session(driver) -> bool:
    """Настоящий вход = dsid + сессионный токен (появляется после 2FA)."""
    for c in browser_cookies(driver):
        if str(c.get("name", "")).lower() == "x-apple-ds-web-session-token" \
                and str(c.get("value", "")).strip():
            return True
    return False


def _url_auth(driver) -> bool:
    try:
        u = (driver.current_url or "").lower()
    except Exception:
        return False
    return "idmsa" in u or "idmswebauth" in u


def _auth_form_visible(driver) -> bool:
    """Экран входа/2FA ещё висит (в любом фрейме, включая top-level редирект)."""
    def _forms() -> bool:
        return _email_visible(driver) or _pw_visible(driver) or _code_visible(driver)
    try:
        driver.switch_to.default_content()
        if _forms():
            return True
        for f in driver.find_elements("tag name", "iframe"):
            try:
                driver.switch_to.frame(f)
                if _forms():
                    return True
                for g in driver.find_elements("tag name", "iframe"):
                    try:
                        driver.switch_to.frame(g)
                        if _forms():
                            return True
                        driver.switch_to.parent_frame()
                    except Exception:
                        driver.switch_to.parent_frame()
                driver.switch_to.default_content()
            except Exception:
                driver.switch_to.default_content()
    except Exception:
        pass
    return _url_auth(driver)


def _two_fa_screen(driver) -> bool:
    if _code_visible(driver):
        return True
    page = _safe_page(driver)
    markers = ("verification", "verify your identity", "enter the code",
               "trusted device", "проверк", "введите код", "доверенного устройства")
    return any(m in page for m in markers)


def _choose_code_option(driver) -> bool:
    """Экран выбора способа 2FA: жмём 'ввести код' / 'enter code'."""
    try:
        for tag in ("a", "button", "div", "span"):
            for el in driver.find_elements("tag name", tag):
                t = (el.text or "").strip().lower()
                if t and ("код" in t or "code" in t) \
                        and ("введи" in t or "ввести" in t or "enter" in t) \
                        and el.is_displayed():
                    _js_click(el)
                    return True
    except Exception:
        pass
    return False


def poll_code_file(code_file: str | None, timeout: float = 300,
                   log=_log) -> str | None:
    """Ждёт код 2FA в файле (канал для фонового запуска) или из консоли."""
    if not code_file:
        try:
            return input().strip() or None
        except EOFError:
            return None
    cf = Path(code_file)
    if cf.exists():
        cf.unlink()
    end = time.time() + timeout
    log(f"      жду код в {cf} ({int(timeout)}s) ...")
    while time.time() < end:
        try:
            if cf.exists():
                code = cf.read_text(encoding="ascii", errors="ignore").strip()
                if code.isdigit() and len(code) >= 6:
                    try:
                        cf.unlink()
                    except Exception:
                        pass
                    return code
        except Exception:
            pass
        time.sleep(1.0)
    return None


def run_login(email: str, password: str, timeout: float = 15 * 60,
              log=_log, ask_2fa: bool = True,
              profile_dir: Path | None = None,
              do_warmup: bool = True,
              code_file: str | None = None) -> str | None:
    """Полный вход. Возвращает dsid или None.

    ask_2fa=True: при экране проверки скрипт берёт код (code_file — канал
    для фонового запуска, иначе консоль) и сам его подставляет по-живому.
    ask_2fa=False (демо-режим): просто ждём завершения входа в окне.
    """
    profile = profile_dir or (PROFILES_DIR / safe_name(email))
    port = free_port()
    proc = launch_edge(port, profile)
    driver = attach(port)
    dsid = None
    try:
        if do_warmup:
            warmup(driver, log)
        clear_auth_cookies(driver, log)
        log("[*] автологин: ищу кнопку входа ...")
        if not sign_in_click(driver, log):
            log("[i] кнопка входа не найдена — возможно, уже залогинены")
        # форма email: в любом фрейме (idmsa-iframe или прямо в DOM)
        log("[*] ищу форму ввода email ...")
        if _frame_scan(driver, _email_visible, timeout=40) is None:
            log("[!] форма email не найдена — пробую ещё раз кнопку входа")
            sign_in_click(driver, log)
            if _frame_scan(driver, _email_visible, timeout=25) is None:
                log("[!] форма email не найдена — введи данные руками в окне")
        email_el = visible(driver, ["#account_name_text_field",
                                    "input[type=email]", "input[name=accountName]"], timeout=6)
        if email_el is not None:
            email_el.clear()
            human_type(email_el, email)
            btn = visible(driver, ["#sign-in", "button[type=submit]"])
            if btn is not None:
                _js_click(btn)
            log("[*] email введён, жду поле пароля ...")
        else:
            log("[!] поле email не нашёл — введи его в окне, дальше скрипт подхватит")
        # поле пароля: может появиться в этом же или другом фрейме
        if _frame_scan(driver, _pw_visible, timeout=35) is None:
            log("[!] поле пароля не появилось")
        pw_el = visible(driver, ["input[type=password]", "#password_text_field"], timeout=6)
        if pw_el is not None:
            pw_el.clear()
            human_type(pw_el, password)
            btn = visible(driver, ["#sign-in", "button[type=submit]"])
            if btn is not None:
                _js_click(btn)
            log("[*] пароль введён, отправлен")
            human_pause(2.0, 4.0)
        else:
            log("[!] поле пароля не нашёл — введи его в окне, дальше скрипт подхватит")

        deadline = time.time() + timeout
        announced = False
        filled = False
        filled_at = 0.0
        trusted_once = False
        while time.time() < deadline:
            dsid = extract_dsid(browser_cookies(driver))
            if dsid and _has_session(driver) and not _auth_form_visible(driver):
                break
            # ошибка входа?
            page = _safe_page(driver)
            if page and any(m in page for m in ("incorrect password", "неверный пароль",
                                                "password you entered", "invalid user")):
                log("[!] Apple отклонил данные (пароль/логин?) — проверь и перезапусти")
                break
            # доверять этому браузеру?
            if not trusted_once and _trust_visible(driver):
                trusted_once = True
                if _click_trust(driver):
                    log("[*] нажал 'доверять браузеру' — сессия проживёт дольше")
                    human_pause(2.0, 3.5)
            # 2FA: экран может быть в любом фрейме; сначала анонс, потом ввод
            if ask_2fa and not filled:
                if not announced and _two_fa_screen(driver):
                    announced = True
                    try:
                        names = ",".join(sorted({str(c.get("name"))
                                                 for c in browser_cookies(driver)}))
                        log(f"[*] cookies на экране 2FA: {names[:400]}")
                    except Exception:
                        pass
                    log("")
                    log("[2FA] экран проверки — ОТДЕЛЬНЫЙ ЗАПРОС:")
                    log("      скажи код (я подставлю и отправлю сам)")
                    if not _code_visible(driver):
                        _choose_code_option(driver)
                    human_pause(1.0, 2.0)
                if announced:
                    if not _code_visible(driver):
                        _choose_code_option(driver)
                        _frame_scan(driver, _code_visible, timeout=3)
                    if _code_visible(driver):
                        remaining = max(30, deadline - time.time())
                        code = poll_code_file(code_file,
                                              timeout=min(300, remaining), log=log)
                        if code:
                            ok = fill_2fa(driver, code)
                            log("[*] код подставлен, отправляю" if ok
                                else "[!] не подставил — введи код в окне руками")
                            if ok:
                                filled = True
                                filled_at = time.time()
                                human_pause(2.5, 4.5)
                        else:
                            log("[i] код не получен — введи его в окне руками")
            if filled and _code_visible(driver) and time.time() - filled_at > 25:
                log("[i] поле кода всё ещё видно — код не принят, жду новый")
                filled = False
            time.sleep(1.5)
        if dsid:
            # подтверждение: перезагружаем icloud, cookies и форма входа должны исчезнуть
            try:
                driver.switch_to.default_content()
                driver.get(DSID_URL)
                time.sleep(rand(5.0, 8.0))
                dsid2 = extract_dsid(browser_cookies(driver))
                confirmed = bool(dsid2) and _has_session(driver) \
                    and not _auth_form_visible(driver)
            except Exception:
                confirmed = False
            if confirmed:
                dsid = dsid2
                log(f"[ok] вход выполнен и подтверждён, dsid {dsid}")
            else:
                log("[!] сессия не подтверждена после перезагрузки (2FA не пройдена?)")
                dsid = None
        else:
            log(f"[!] dsid не получен за {int(timeout)}s")
        # окно не рвём мгновенно — дай себе осмотреться
        hold = 10 if dsid else 20
        log(f"[*] окно браузера закрою через {hold}s")
        time.sleep(hold)
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
