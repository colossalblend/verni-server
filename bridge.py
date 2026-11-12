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
_worker_ports: list[int] = [27987]  # iOSAuthSingle: auth_socket_bind(27987) в main.cpp
_port_locks: list[asyncio.Lock] = []
_rr_counter = 0


def configure_worker(host: str, ports: int | list[int]) -> None:
    """Порты воркеров. Несколько портов = несколько экземпляров iOSAuthSingle
    (каждый со своим процессом), ими обрабатываются параллельные сессии.
    Обращения к нативным iTunes DLL сериализуются замком на порт, т.к.
    потокобезопасность iTunes.dll не гарантирована."""
    global _worker_host, _worker_ports, _port_locks
    _worker_host = host
    if isinstance(ports, int):
        ports = [ports]
    _worker_ports = [int(p) for p in ports if p] or [27987]
    _port_locks = [asyncio.Lock() for _ in _worker_ports]


def _ports_snapshot() -> tuple[list[int], list[asyncio.Lock]]:
    return _worker_ports, _port_locks


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
        self._slot_lock: asyncio.Lock | None = None

    @property
    def age(self) -> float:
        return time.time() - self.created_at

    def touch(self) -> None:
        self.touched_at = time.time()

    async def _acquire_slot(self) -> int:
        """Выбирает порт воркера: сначала свободный, иначе ближайший по
        round-robin (ждём его замок). Замок держится до close()."""
        global _rr_counter
        ports, locks = _ports_snapshot()
        n = len(ports)
        if n == 0:
            raise OSError("no worker ports configured")
        if n == 1:
            await locks[0].acquire()
            self._slot_lock = locks[0]
            return ports[0]
        for _ in range(n):
            _rr_counter = (_rr_counter + 1) % n
            idx = _rr_counter
            lock = locks[idx]
            if lock.locked():
                continue
            await lock.acquire()
            self._slot_lock = lock
            return ports[idx]
        _rr_counter = (_rr_counter + 1) % n
        await locks[_rr_counter].acquire()
        self._slot_lock = locks[_rr_counter]
        return ports[_rr_counter]

    async def _connect(self) -> None:
        port = await self._acquire_slot()
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(_worker_host, port), timeout=5
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
        dsid: int = 0,
        grappa_support_info: bytes | None = None,
    ) -> bytes:
        if grappa_support_info is None:
            if not 0 <= dsid <= 0x7FFFFFFFFFFFFFFF:
                raise ValueError("DSID must be a positive signed 64-bit integer")
            # Первый QWORD GrappaSupportInfo = DSID этой сессии, остальные 12 байт нули.
            gsi = struct.pack("<Q", dsid) + bytes(LEN_GSI - 8)
        else:
            gsi = grappa_support_info
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
        # Exec.cpp пишет DSID из первого QWORD GrappaSupportInfo (патч
        # tools/patch_runtime.py); нули = fallback dsid.txt рядом с .exe.
        try:
            await self._connect()
            await self._send(payload)
            self.grappa = await _recv_framed(self.reader)
        except BaseException:
            await self.close()  # отпускаем слот порта при любой ошибке
            raise
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
        if self._slot_lock is not None:
            self._slot_lock.release()
            self._slot_lock = None

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
