# SPDX-License-Identifier: GPL-3.0-only
"""Локальное хранилище секретов для авто-перевыпуска сессии.

Пароль Apple ID шифруется DPAPI (CryptProtectData) — расшифровать может
только тот же Windows-юзер на той же машине, под которым шифровали.
В открытом виде пароль не хранится и не логируется. Файл: secrets.dat
(gitignored). Ничего не передаётся по сети.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import json
import os
from pathlib import Path

MAGIC = b"DPAPI1\n"


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _in_blob(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def protect(data: bytes) -> bytes:
    out = _DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(_in_blob(data)), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("CryptProtectData failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def unprotect(blob: bytes) -> bytes:
    out = _DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(_in_blob(blob)), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def save_secret(path: Path, data: dict) -> None:
    blob = MAGIC + protect(json.dumps(data, ensure_ascii=True).encode("utf-8"))
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(blob)
    os.replace(tmp, path)


def load_secret(path: Path) -> dict | None:
    if not path.exists():
        return None
    raw = path.read_bytes()
    if not raw.startswith(MAGIC):
        return None
    try:
        return json.loads(unprotect(raw[len(MAGIC):]).decode("utf-8"))
    except Exception:
        return None


if __name__ == "__main__":
    # smoke: python store.py
    p = Path("C:\\Windows\\Temp\\opencode\\dpapi-test.dat")
    save_secret(p, {"email": "a@b.c", "password": "s3cret"})
    got = load_secret(p)
    assert got == {"email": "a@b.c", "password": "s3cret"}, got
    assert b"s3cret" not in p.read_bytes()
    p.unlink()
    print("[ok] dpapi roundtrip + no plaintext on disk")
