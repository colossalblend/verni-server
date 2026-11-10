# Фейковый воркер для сквозного теста server.py + bridge.py
# Говорит протоколом iOSAuthRuntime (Exec.cpp): [4B LE len][payload]
import asyncio
import struct
import sys

FAKE_GRAPPA = bytes(range(84))            # 0x54
FAKE_SIG = (("S" * 21).encode())          # 0x15 длиной
FAKE_RESPONSE = ("RESPONSE" * 100).encode()

async def one_conn(reader, writer):
    while True:
        header = await reader.readexactly(4)
        (length,) = struct.unpack("<I", header)
        payload = await reader.readexactly(length)

        # пакет 1: [4B lu][4B lf][0x14 gsi][0x10 fpa][udid][fpc]
        lu, lf = struct.unpack("<II", payload[:8])
        gsi = payload[8:8 + 0x14]
        fpa = payload[8 + 0x14:8 + 0x14 + 0x10]
        udid = payload[8 + 0x14 + 0x10:8 + 0x14 + 0x10 + lu]
        fpc = payload[8 + 0x14 + 0x10 + lu:]
        print(f"[pkg1] udid={udid!r} fpc={len(fpc)}B gsi0x14={gsi.hex()[:12]}... fpa={fpa.hex()}")
        assert len(gsi) == 0x14 and len(fpa) == 0x10
        dt, ktsv, _, _ = struct.unpack("<IIII", fpa)
        print(f"[pkg1] deviceType={dt:#x} keyTypeSupportVersion={ktsv:#x}")
        writer.write(struct.pack("<I", len(FAKE_GRAPPA)) + FAKE_GRAPPA)
        await writer.drain()

        # пакет 2: [0x53 grappa][0x15 rq_sig][rq]
        header = await reader.readexactly(4)
        (length,) = struct.unpack("<I", header)
        payload = await reader.readexactly(length)
        grappa = payload[:0x53]
        rqsig = payload[0x53:0x53 + 0x15]
        rq = payload[0x53 + 0x15:]
        print(f"[pkg2] grappa={len(grappa)}B rq_sig={len(rqsig)}B rq={len(rq)}B")
        writer.write(struct.pack("<I", len(FAKE_SIG) + len(FAKE_RESPONSE)) + FAKE_SIG + FAKE_RESPONSE)
        await writer.drain()
        writer.close()

async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5555
    server = await asyncio.start_server(one_conn, "127.0.0.1", port)
    print(f"fake worker on {port}")
    async with server:
        await server.serve_forever()

asyncio.run(main())
