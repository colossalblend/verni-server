"""Мост между HTTP-сервером VerniDesktop и воркером iOSAuthRuntime.

Протокол воркера (из Exec.cpp/Network.cpp iOS-Auth/iOSAuthRuntime):
- кадрирование: [4B little-endian длина][полезные данные], в обе стороны
- пакет 1 (мы -> воркер):
    4B len(udid) | 4B len(fpc) | 0x14B GrappaSupportInfo | 0x10B FairPlayArg
    | UDID | FairPlayCertificate
    FairPlayArg = [FairPlayDeviceType u32][KeyTypeSupportVersion u32][0][0]
- ответ 1 (воркер -> мы): Grappa (обычно 0x54 = 84 байта)
- пакет 2 (мы -> воркер): 0x53B deviceGrappa | 0x15B afsync.rq.sig | afsync.rq
- ответ 2 (воркер -> мы): [sig][response] (sig-часть отсекается по SIG_LEN)

Воркер проделывает нативный путь:
  AirFairSyncSessionCreate -> AirFairSyncGrappaCreate -> send
  AirFairSyncSetRequest -> AirFairSyncAccountAuthorize(DSID)
  -> AirFairSyncGrappaUpdate -> AirFairSyncGetResponse -> AirFairSyncCalcSig -> send
"""

import asyncio
import socket
import struct
import time

LEN_GSI = 0x14
LEN_FPA = 0x10
LEN_GRAPPA = 0x53
LEN_RQSIG = 0x15
SIG_LEN = 0x15  # размер ответной sig от AirFairSyncCalcSig (симметрично rq.sig; правь, если иначе)

_worker_host = "127.0.0.1"
_worker_port = 27987  # фактический порт iOSAuthSolution из main.cpp (auth_socket_bind(27987))


def configure_worker(host: str, port: int) -> None:
    global _worker_host, _worker_port
    _worker_host = host
    _worker_port = port


def _framed(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


async def _recv_exact(reader: asyncio.StreamReader, size: int) -> bytes:
    data = await reader.readexactly(size)
    return data


async def _recv_framed(reader: asyncio.StreamReader) -> bytes:
    raw_len = await _recv_exact(reader, 4)
    (length,) = struct.unpack("<I", raw_len)
    if length == 0 or length > (1 << 24):
        raise ValueError(f"worker bad frame length {length}")
    return await _recv_exact(reader, length)


class WorkerSession:
    """Один TCP-коннект к воркеру = один полный цикл авторизации устройства."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.created_at = time.time()
        self.touched_at = time.time()
        self.grappa: bytes | None = None

    @property
    def age(self) -> float:
        return time.time() - self.created_at

    def touch(self) -> None:
        self.touched_at = time.time()

    async def _connect(self) -> None:
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(_worker_host, _worker_port), timeout=5
        )

    async def _send(self, payload: bytes) -> None:
        assert self.writer is not None
        self.writer.write(_framed(payload))
        await self.writer.drain()

    async def begin(
        self,
        device_udid: str,
        fairplay_cert: bytes,
        device_type: int,
        key_type_support_version: int,
        grappa_support_info: bytes | None,
    ) -> bytes:
        gsi = grappa_support_info if grappa_support_info is not None else bytes(LEN_GSI)
        if len(gsi) != LEN_GSI:
            raise ValueError("GrappaSupportInfo must be 0x14 bytes")
        fpa = struct.pack("<IIII", device_type & 0xFFFFFFFF, key_type_support_version & 0xFFFFFFFF, 0, 0)
        udid = device_udid.encode("utf-8")
        payload = (
            struct.pack("<II", len(udid), len(fairplay_cert))
            + gsi
            + fpa
            + udid
            + fairplay_cert
        )
        await self._connect()
        await self._send(payload)
        self.grappa = await _recv_framed(self.reader)
        return self.grappa

    async def complete(self, device_grappa: bytes, rq_sig: bytes, request: bytes) -> tuple[bytes, bytes]:
        assert self.writer is not None and self.reader is not None
        if len(device_grappa) != LEN_GRAPPA:
            raise ValueError(f"deviceGrappa must be 0x{LEN_GRAPPA:X} bytes")
        if len(rq_sig) != LEN_RQSIG:
            raise ValueError(f"request signature must be 0x{LEN_RQSIG:X} bytes")
        payload = device_grappa + rq_sig + request
        await self._send(payload)
        data = await _recv_framed(self.reader)
        if len(data) <= SIG_LEN:
            raise ValueError(f"worker response too small: {len(data)}")
        sig = data[:SIG_LEN]
        response = data[SIG_LEN:]
        return response, sig

    async def close(self) -> None:
        if self.writer is not None:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
        self.reader = None
        self.writer = None

    async def abort(self) -> None:
        await self.close()


class Bridge:
    """Хранилище активных сессий по session_id."""

    TTL = 900  # 15 минут

    def __init__(self):
        self._sessions: dict[str, WorkerSession] = {}
        self._lock = asyncio.Lock()

    async def get(self, session_id: str) -> WorkerSession:
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError(session_id)
            return session

    async def put(self, session: WorkerSession) -> None:
        async with self._lock:
            self._sessions[session.session_id] = session

    async def drop(self, session_id: str) -> None:
        session = None
        async with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is not None:
            await session.close()

    async def sweep(self) -> None:
        stale = []
        async with self._lock:
            for sid, session in self._sessions.items():
                if time.time() - session.touched_at > self.TTL:
                    stale.append(sid)
        for sid in stale:
            await self.drop(sid)
