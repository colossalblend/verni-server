# SPDX-License-Identifier: GPL-3.0-only
r"""Автонастройка аккаунта: реалистичный вход -> DSID -> iTunes -> SC Info.

Браузерная механика — в apple_session.py: обычный Edge с персистентным
профилем (profiles/<email>/), прогрев сессии перед входом, посимвольный
живой ввод, 2FA отдельным запросом в консоли (или довершение в окне).
Обход Apple-защит исключён — то, что делает человек, делает и скрипт.

Пароль Apple ID: нигде не печатается и не логируется; после успешного входа
сохраняется в secrets.dat (DPAPI-шифрование, store.py) чтобы демон
session_keepalive.py мог сам перевыпускать сессию при умирании cookie.
Отказаться: --no-remember.

Запуск (в RDP-сессии сервера, окно видно):
  python setup_account.py --email you@example.com
  python setup_account.py --email you@example.com --password-stdin < pw.txt
  python setup_account.py --email you@example.com --skip-itunes
  python setup_account.py --email you@example.com --skip-browser
"""
from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys
import time
import winreg
from pathlib import Path

import apple_session
import store

HERE = Path(__file__).resolve().parent
SECRETS_PATH = HERE / "secrets.dat"
SC_DIR = Path(r"C:\ProgramData\Apple Computer\iTunes\SC Info")


# ---------------- этап 2: iTunes ----------------

def itunes_installed() -> str | None:
    for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Apple Computer, Inc.\iTunes",
                               0, winreg.KEY_READ | view)
            val, _ = winreg.QueryValueEx(k, "InstallDir")
            exe = Path(val) / "iTunes.exe"
            if exe.exists():
                return str(exe)
        except OSError:
            continue
    return None


def itunes_phase(itunes_wait: int) -> bool:
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
    deadline = time.time() + itunes_wait
    while time.time() < deadline:
        if sc_sidb.exists() and sc_sidd.exists():
            print(f"[ok] SC Info на месте: {SC_DIR}")
            return True
        time.sleep(3)
    print(f"[!] SC Info не появились за {itunes_wait}s — заверши авторизацию в iTunes")
    return False


# ---------------- main ----------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Автонастройка аккаунта: вход -> DSID -> iTunes -> SC Info")
    ap.add_argument("--email", required="--skip-browser" not in sys.argv, default="")
    ap.add_argument("--password-stdin", action="store_true", help="пароль первой строкой stdin")
    ap.add_argument("--env", action="store_true", help="пароль из VERNI_APPLE_PASSWORD")
    ap.add_argument("--timeout", type=int, default=15 * 60, help="лимит этапа браузера, с")
    ap.add_argument("--itunes-wait", type=int, default=15 * 60, help="сколько ждать SC Info, с")
    ap.add_argument("--skip-itunes", action="store_true")
    ap.add_argument("--skip-browser", action="store_true")
    ap.add_argument("--code-file", default=None,
                    help="файл-канал для кода 2FA при фоновом запуске")
    ap.add_argument("--no-remember", action="store_true",
                    help="не сохранять пароль в secrets.dat (перевыпуск будет ручной)")
    args = ap.parse_args()

    password = ""
    if not args.skip_browser:
        if args.password_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
        elif args.env:
            password = os.environ.get("VERNI_APPLE_PASSWORD", "")
        else:
            password = getpass.getpass(f"пароль Apple ID для {args.email}: ")
        if not password:
            print("[!] пароль не получен")
            return 1

    ok = True
    if not args.skip_browser:
        dsid = apple_session.run_login(args.email, password, timeout=args.timeout,
                                       code_file=args.code_file)
        ok = dsid is not None
        if dsid:
            apple_session.write_dsid(dsid, args.email)
            if not args.no_remember:
                try:
                    store.save_secret(SECRETS_PATH, {"email": args.email, "password": password})
                    print("[ok] пароль сохранён в secrets.dat (DPAPI) — перевыпуск сессии автоматом")
                except Exception as e:
                    print(f"[!] пароль не сохранён ({e!r}) — перевыпуск будет ручной")
    if ok and not args.skip_itunes:
        ok = itunes_phase(args.itunes_wait)

    print()
    print("Готово." if ok else "Есть незакрытые шаги — смотри сообщения выше.")
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] прервано")
        sys.exit(130)
