from __future__ import annotations

import ctypes
import functools
import socket
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

DEFAULT_CAPTURE_PROCESSES = "VRChat.exe"
MAX_ANCESTOR_DEPTH = 16

_AF_INET = 2
_TCP_TABLE_OWNER_PID_ALL = 5
_ERROR_INSUFFICIENT_BUFFER = 122
_TCP4_ROW = struct.Struct("<I4s4s4s4sI")
_TH32CS_SNAPPROCESS = 0x2
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_MAX_CACHED_DECISIONS = 4096

Address = tuple[str, int]


@dataclass(frozen=True)
class ProcessEntry:
    pid: int
    parent_pid: int
    name: str


def parse_process_names(value: str) -> frozenset[str]:
    return frozenset(name.strip().lower() for name in (value or "").split(",") if name.strip())


def socket_address(value: Any) -> Address | None:
    if not isinstance(value, (tuple, list)) or len(value) < 2:
        return None
    host, port = value[0], value[1]
    if not isinstance(host, str) or not isinstance(port, int):
        return None
    if host.startswith("::ffff:"):
        host = host[7:]
    return host, port


def find_owner_pid(table: bytes, client: Address, proxy: Address) -> int | None:
    local_addr = socket.inet_aton(client[0])
    local_port = client[1].to_bytes(2, "big")
    remote_addr = socket.inet_aton(proxy[0])
    remote_port = proxy[1].to_bytes(2, "big")
    (count,) = struct.unpack_from("<I", table, 0)
    for index in range(min(count, (len(table) - 4) // _TCP4_ROW.size)):
        _, row_local, row_local_port, row_remote, row_remote_port, pid = _TCP4_ROW.unpack_from(
            table, 4 + index * _TCP4_ROW.size
        )
        if (
            row_local == local_addr
            and row_local_port[:2] == local_port
            and row_remote == remote_addr
            and row_remote_port[:2] == remote_port
        ):
            return pid
    return None


def is_capture_process(
    pid: int,
    processes: Mapping[int, ProcessEntry],
    created: Callable[[int], int | None],
    names: frozenset[str],
) -> bool:
    entry = processes.get(pid)
    if entry is None:
        return False
    if entry.name.lower() in names:
        return True
    child_created = created(pid)
    seen = {pid}
    for _ in range(MAX_ANCESTOR_DEPTH):
        parent = processes.get(entry.parent_pid)
        if parent is None or parent.pid in seen or child_created is None:
            return False
        parent_created = created(parent.pid)
        if parent_created is None or parent_created > child_created:
            return False
        if parent.name.lower() in names:
            return True
        seen.add(parent.pid)
        entry, child_created = parent, parent_created
    return False


class CaptureProcessFilter:
    def __init__(
        self,
        names: frozenset[str],
        table: Callable[[], bytes | None] | None = None,
        processes: Callable[[], dict[int, ProcessEntry] | None] | None = None,
        created: Callable[[int], int | None] | None = None,
    ) -> None:
        self.names = names
        self._table = table or tcp4_table
        self._processes = processes or process_snapshot
        self._created = created or process_created
        self._decisions: dict[tuple[int, int], bool] = {}

    def allows(self, client: Address | None, proxy: Address | None) -> bool:
        if client is None or proxy is None or not self.names:
            return False
        try:
            table = self._table()
            if table is None:
                return False
            pid = find_owner_pid(table, client, proxy)
            if pid is None:
                return False
            started = self._created(pid)
            if started is not None and (pid, started) in self._decisions:
                return self._decisions[(pid, started)]
            snapshot = self._processes()
            if snapshot is None:
                return False
            decision = is_capture_process(pid, snapshot, self._created, self.names)
            if started is not None:
                if len(self._decisions) >= _MAX_CACHED_DECISIONS:
                    self._decisions.clear()
                self._decisions[(pid, started)] = decision
            return decision
        except Exception:
            return False


def tcp4_table() -> bytes | None:
    iphlpapi = _windll("iphlpapi")
    if iphlpapi is None:
        return None
    get_table = iphlpapi.GetExtendedTcpTable
    get_table.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    get_table.restype = ctypes.c_ulong
    size = ctypes.c_ulong(0)
    for _ in range(8):
        buffer = ctypes.create_string_buffer(max(size.value, 4))
        result = get_table(buffer, ctypes.byref(size), 0, _AF_INET, _TCP_TABLE_OWNER_PID_ALL, 0)
        if result == 0:
            return buffer.raw
        if result != _ERROR_INSUFFICIENT_BUFFER:
            return None
    return None


class _ProcessEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def process_snapshot() -> dict[int, ProcessEntry] | None:
    kernel32 = _kernel32()
    if kernel32 is None:
        return None
    handle = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not handle or handle == ctypes.c_void_p(-1).value:
        return None
    try:
        entry = _ProcessEntry32()
        entry.dwSize = ctypes.sizeof(_ProcessEntry32)
        processes: dict[int, ProcessEntry] = {}
        more = kernel32.Process32FirstW(handle, ctypes.byref(entry))
        while more:
            pid = int(entry.th32ProcessID)
            processes[pid] = ProcessEntry(pid, int(entry.th32ParentProcessID), entry.szExeFile)
            more = kernel32.Process32NextW(handle, ctypes.byref(entry))
        return processes
    finally:
        kernel32.CloseHandle(handle)


def process_created(pid: int) -> int | None:
    kernel32 = _kernel32()
    if kernel32 is None:
        return None
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        times = [ctypes.c_ulonglong() for _ in range(4)]
        ok = kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times))
        return int(times[0].value) if ok else None
    finally:
        kernel32.CloseHandle(handle)


@functools.cache
def _windll(name: str) -> Any | None:
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        return None
    try:
        return loader(name, use_last_error=True)
    except OSError:
        return None


@functools.cache
def _kernel32() -> Any | None:
    kernel32 = _windll("kernel32")
    if kernel32 is None:
        return None
    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ProcessEntry32)]
    kernel32.Process32FirstW.restype = ctypes.c_int
    kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ProcessEntry32)]
    kernel32.Process32NextW.restype = ctypes.c_int
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_ulonglong)] * 4
    kernel32.GetProcessTimes.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    return kernel32
