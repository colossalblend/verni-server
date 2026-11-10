# SPDX-License-Identifier: GPL-3.0-only
"""Проверка воркера iOSAuthSingle (iOS-Auth/iOSAuthRuntime).

Посылает пакет 1 (fake UDID/cert) и ждёт кадр с Grappa -> если пришёл, воркер
жив и прогоняет нативный путь до GrappaCreate. Fake-сертификат обычно рушит
AirFairSyncSessionCreate: тогда тест хотя бы подтверждает, что порт открыт,
TLS/кадр синхронизирован, фазу 1 воркер принял.

  python test_worker.py [host] [port]
"""
from __future__ import annotations

import asyncio
import struct
import sys

LEN_GSI = 0x14
LEN_FPA = 0x10


def pkg1(udid: str, cert: bytes, device_type: int, keyver: int, gsi: bytes = bytes(LEN_GSI)) -> bytes:
    assert len(gsi) == LEN_GSI
    fpa = struct.pack("<IIII", device_type, keyver, 0, 0)
    b = udid.encode()
    return struct.pack("<II", len(b), len(cert)) + gsi + fpa + b + cert


def fake_cert(n: int = 128) -> bytes:
    return bytes((i * 7 + 3) % 251 for i in range(n))


async def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 27987
    udid = "00008101-000A112233445581"  # fake
    payload = pkg1(udid, fake_cert(), 0x00000010, 0x00000063)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
    except OSError as e:
        print(f"[fire] connect {host}:{port}: {e!r}")
        return 1
    writer.write(struct.pack("<I", len(payload)) + payload)
    await writer.drain()
    header = await reader.read(4)
    if len(header) < 4:
        data = await reader.read(1024)
        print(f"[warn] воркер ответил на пакет 1 коротким концом: {header!r} {data!r}")
        print("       (fake-сертификат, обычно так и надо: порт живой)")
        writer.close()
        return 2
    (length,) = struct.unpack("<I", header)
    grappa = await reader.readexactly(length) if length else b""
    print(f"[ok] Grappa frame: len={length} hex={grappa.hex()}")
    writer.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
