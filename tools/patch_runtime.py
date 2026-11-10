# SPDX-License-Identifier: GPL-3.0-only
"""Patch iOS-Auth/iOSAuthRuntime Exec.cpp so the DSID is read at RUNTIME
from dsid.txt (next to the worker .exe) instead of being baked in.

The value is re-read on every new worker connection, so changing dsid.txt
never requires a rebuild. Falls back to 99999999999 when dsid.txt is
missing or empty (transport smoke only).

Usage: python tools/patch_runtime.py path/to/Exec.cpp
"""
from __future__ import annotations

import sys
from pathlib import Path

ORIG = b"_Context->auth_dsid.QuadPart = 99999999999ull;"

NEW_RAW = (
    b"\t// DSID is read at runtime from dsid.txt next to the worker .exe.\n"
    b"\t// Re-read on every connection; missing file falls back to placeholder.\n"
    b"\t{\n"
    b"\t\twchar_t vExePath[MAX_PATH] = { 0 };\n"
    b"\t\tGetModuleFileNameW(nullptr, vExePath, MAX_PATH);\n"
    b"\t\tstd::wstring vExeDir(vExePath);\n"
    b"\t\tauto vPos = vExeDir.find_last_of(L\"\\\\/\");\n"
    b"\t\tstd::wstring vDsidFile = (vPos == std::wstring::npos)\n"
    b"\t\t\t? std::wstring(L\"dsid.txt\")\n"
    b"\t\t\t: vExeDir.substr(0, vPos + 1) + L\"dsid.txt\";\n"
    b"\t\tunsigned long long vDsidValue = 99999999999ull;\n"
    b"\t\tFILE* vDsidHandle = nullptr;\n"
    b"\t\tif (_wfopen_s(&vDsidHandle, vDsidFile.data(), L\"rb\") == 0 && vDsidHandle != nullptr)\n"
    b"\t\t{\n"
    b"\t\t\tunsigned long long vParsed = 0;\n"
    b"\t\t\tchar vTrailing = 0;\n"
    b"\t\t\tif (std::fscanf(vDsidHandle, \"%llu %c\", &vParsed, &vTrailing) == 1 && vParsed != 0 && vParsed <= 9223372036854775807ull)\n"
    b"\t\t\t\tvDsidValue = vParsed;\n"
    b"\t\t\tstd::fclose(vDsidHandle);\n"
    b"\t\t}\n"
    b"\t\t_Context->auth_dsid.QuadPart = vDsidValue;\n"
    b"\t}\n"
)

INCLUDE_REPLACEMENT = b'#include "Exec.h"\n#include <cstdio>\n'


def patch(path: Path) -> int:
    if not path.exists():
        print(f"[!] file not found: {path}")
        return 1
    data = path.read_bytes()
    if b"dsid.txt" in data and ORIG not in data:
        print("[ok] already patched, skipping")
        return 0
    if ORIG not in data:
        print("[!] anchor not found (upstream Exec.cpp changed?) - do not touch")
        return 1
    data = data.replace(b'#include "Exec.h"', INCLUDE_REPLACEMENT, 1)
    data = data.replace(ORIG, NEW_RAW, 1)
    path.write_bytes(data)
    verify = path.read_bytes()
    ok = (b"dsid.txt" in verify) and (ORIG not in verify)
    print(f"[{'ok' if ok else 'FAIL'}] patched {path}")
    return 0 if ok else 1


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("iOSAuthRuntime/Exec.cpp")
    raise SystemExit(patch(target))
