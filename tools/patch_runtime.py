# SPDX-License-Identifier: GPL-3.0-only
"""Patch iOS-Auth/iOSAuthRuntime Exec.cpp for multi-account operation.

Two patches, both verified against pristine upstream anchors:

1. dsid.txt fallback (native_init): legacy single-account deployments keep
   working - the DSID is read from dsid.txt next to the worker .exe. The value
   is re-read on every new connection, so changing dsid.txt never needs a
   rebuild.

2. Per-request DSID override (recv_package_1): the first little-endian uint64
   of the 20-byte GrappaSupportInfo field carries the DSID chosen by the
   server for this session. Nonzero overrides the fallback; zero keeps it.
   This is what makes several accounts work against one worker, because
   auth_dsid lives in the per-connection AUTH_CONTEXT.

Usage: python tools/patch_runtime.py path/to/Exec.cpp
"""
from __future__ import annotations

import sys
from pathlib import Path

INCLUDE_ANCHOR = b'#include "Exec.h"'
INCLUDE_NEW = b'#include "Exec.h"\n#include <cstdio>\n'

# Patch A: dsid.txt fallback inside auth_exec_native_init.
DSID_ANCHOR = b"\t\t_Context->auth_dsid.QuadPart = 99999999999ull;"
DSID_NEW = (
    b"\t\t// DSID is read at runtime from dsid.txt next to the worker .exe.\n"
    b"\t\t// Re-read on every connection; missing file falls back to placeholder.\n"
    b"\t\t{\n"
    b"\t\t\twchar_t vExePath[MAX_PATH] = { 0 };\n"
    b"\t\t\tGetModuleFileNameW(nullptr, vExePath, MAX_PATH);\n"
    b"\t\t\tstd::wstring vExeDir(vExePath);\n"
    b"\t\t\tauto vPos = vExeDir.find_last_of(L\"\\\\/\");\n"
    b"\t\t\tstd::wstring vDsidFile = (vPos == std::wstring::npos)\n"
    b"\t\t\t\t? std::wstring(L\"dsid.txt\")\n"
    b"\t\t\t\t: vExeDir.substr(0, vPos + 1) + L\"dsid.txt\";\n"
    b"\t\t\tunsigned long long vDsidValue = 99999999999ull;\n"
    b"\t\t\tFILE* vDsidHandle = nullptr;\n"
    b"\t\t\tif (_wfopen_s(&vDsidHandle, vDsidFile.data(), L\"rb\") == 0 && vDsidHandle != nullptr)\n"
    b"\t\t\t{\n"
    b"\t\t\t\tunsigned long long vParsed = 0;\n"
    b"\t\t\t\tif (std::fscanf(vDsidHandle, \"%llu\", &vParsed) == 1 && vParsed != 0)\n"
    b"\t\t\t\t\tvDsidValue = vParsed;\n"
    b"\t\t\t\tstd::fclose(vDsidHandle);\n"
    b"\t\t\t}\n"
    b"\t\t\t_Context->auth_dsid.QuadPart = vDsidValue;\n"
    b"\t\t}\n"
)

# Patch B: per-request DSID override inside auth_exec_recv_package_1.
# Runs after native_init in auth_exec_context_run, so the override wins.
GSI_ANCHOR = b"\tstd::memcpy(GrappaSupportInfo, data_address + offset_gsi, length_gsi);"
GSI_NEW = (
    GSI_ANCHOR
    + b"\n"
    + b"\t// Per-request DSID override: first little-endian uint64 of\n"
    + b"\t// GrappaSupportInfo. Zero keeps the native_init fallback (dsid.txt).\n"
    + b"\t{\n"
    + b"\t\tunsigned long long vDsidOverride = 0;\n"
    + b"\t\tstd::memcpy(&vDsidOverride, GrappaSupportInfo, sizeof(vDsidOverride));\n"
    + b"\t\tif (vDsidOverride != 0 && vDsidOverride <= 9223372036854775807ull)\n"
    + b"\t\t{\n"
    + b"\t\t\t_Context->auth_dsid.QuadPart = static_cast<LONGLONG>(vDsidOverride);\n"
    + b"\t\t}\n"
    + b"\t}\n"
)

MARKER = b"vDsidOverride"


def patch(path: Path) -> int:
    if not path.is_file():
        print(f"[!] file not found: {path}")
        return 1
    data = path.read_bytes()
    if MARKER in data:
        print("[ok] already patched")
        return 0

    have_include = INCLUDE_ANCHOR in data
    can_a = DSID_ANCHOR in data
    can_b = GSI_ANCHOR in data
    if not (have_include and (can_a or can_b)):
        print("[!] upstream Exec.cpp anchors changed; refusing to patch")
        return 1

    if have_include and b"<cstdio>" not in data:
        data = data.replace(INCLUDE_ANCHOR, INCLUDE_NEW, 1)
    if can_a:
        data = data.replace(DSID_ANCHOR, DSID_NEW, 1)
    if can_b:
        data = data.replace(GSI_ANCHOR, GSI_NEW, 1)
    path.write_bytes(data)

    verify = path.read_bytes()
    ok = MARKER in verify and DSID_ANCHOR not in verify
    print(f"[{'ok' if ok else 'FAIL'}] patched {path}")
    return 0 if ok else 1


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("iOSAuthRuntime/Exec.cpp")
    raise SystemExit(patch(target))
