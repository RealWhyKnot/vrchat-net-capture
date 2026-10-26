from __future__ import annotations

import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from capture_process import (
    CaptureProcessFilter,
    ProcessEntry,
    find_owner_pid,
    is_capture_process,
    parse_process_names,
    process_snapshot,
    socket_address,
)

VRCHAT = frozenset({"vrchat.exe"})


def tcp4_table(rows: list[tuple[tuple[str, int], tuple[str, int], int]], port_padding: bytes = b"\0\0") -> bytes:
    data = struct.pack("<I", len(rows))
    for local, remote, pid in rows:
        data += struct.pack(
            "<I4s4s4s4sI",
            5,
            socket.inet_aton(local[0]),
            local[1].to_bytes(2, "big") + port_padding,
            socket.inet_aton(remote[0]),
            remote[1].to_bytes(2, "big") + port_padding,
            pid,
        )
    return data


PROCESSES = {
    4: ProcessEntry(4, 0, "System"),
    100: ProcessEntry(100, 4, "explorer.exe"),
    200: ProcessEntry(200, 100, "start_protected_game.exe"),
    300: ProcessEntry(300, 200, "VRChat.exe"),
    400: ProcessEntry(400, 300, "yt-dlp.exe"),
    500: ProcessEntry(500, 400, "ffmpeg.exe"),
    600: ProcessEntry(600, 100, "chrome.exe"),
    700: ProcessEntry(700, 300, "Discord.exe"),
    800: ProcessEntry(800, 800, "loop.exe"),
}
CREATED = {4: 1, 100: 10, 200: 20, 300: 30, 400: 40, 500: 50, 600: 60, 700: 5, 800: 80}


class OwnerLookupTests(unittest.TestCase):
    def test_finds_the_client_side_row_not_the_proxy_side(self) -> None:
        table = tcp4_table(
            [
                (("127.0.0.1", 8080), ("127.0.0.1", 50001), 9000),
                (("127.0.0.1", 50001), ("127.0.0.1", 8080), 300),
                (("127.0.0.1", 50002), ("127.0.0.1", 8080), 600),
            ]
        )
        self.assertEqual(find_owner_pid(table, ("127.0.0.1", 50001), ("127.0.0.1", 8080)), 300)
        self.assertEqual(find_owner_pid(table, ("127.0.0.1", 50002), ("127.0.0.1", 8080)), 600)
        self.assertIsNone(find_owner_pid(table, ("127.0.0.1", 50003), ("127.0.0.1", 8080)))

    def test_ignores_junk_in_the_upper_port_bytes(self) -> None:
        table = tcp4_table([(("127.0.0.1", 50001), ("127.0.0.1", 8080), 300)], port_padding=b"\xab\xcd")
        self.assertEqual(find_owner_pid(table, ("127.0.0.1", 50001), ("127.0.0.1", 8080)), 300)

    def test_truncated_table_does_not_read_past_the_end(self) -> None:
        table = tcp4_table([(("127.0.0.1", 50001), ("127.0.0.1", 8080), 300)])
        self.assertIsNone(find_owner_pid(struct.pack("<I", 50) + table[4:], ("127.0.0.1", 1), ("127.0.0.1", 2)))

    def test_socket_address_normalizes_mitmproxy_peernames(self) -> None:
        self.assertEqual(socket_address(("127.0.0.1", 50001)), ("127.0.0.1", 50001))
        self.assertEqual(socket_address(("::ffff:127.0.0.1", 50001, 0, 0)), ("127.0.0.1", 50001))
        self.assertIsNone(socket_address(None))
        self.assertIsNone(socket_address(("ignore-conn", None)))

    def test_parse_process_names(self) -> None:
        self.assertEqual(parse_process_names(" VRChat.exe, ,Other.EXE"), frozenset({"vrchat.exe", "other.exe"}))
        self.assertEqual(parse_process_names(""), frozenset())


class ProcessTreeTests(unittest.TestCase):
    def check(self, pid: int) -> bool:
        return is_capture_process(pid, PROCESSES, CREATED.get, VRCHAT)

    def test_vrchat_and_its_children_are_captured(self) -> None:
        self.assertTrue(self.check(300))
        self.assertTrue(self.check(400))
        self.assertTrue(self.check(500))

    def test_other_programs_are_not_captured(self) -> None:
        self.assertFalse(self.check(600))
        self.assertFalse(self.check(100))
        self.assertFalse(self.check(200))
        self.assertFalse(self.check(4))
        self.assertFalse(self.check(12345))

    def test_reused_parent_pid_does_not_count(self) -> None:
        self.assertFalse(self.check(700))

    def test_parent_loops_and_missing_times_fail_closed(self) -> None:
        self.assertFalse(self.check(800))
        self.assertFalse(is_capture_process(400, PROCESSES, lambda pid: None, VRCHAT))
        self.assertTrue(is_capture_process(300, PROCESSES, lambda pid: None, VRCHAT))


class CaptureProcessFilterTests(unittest.TestCase):
    CLIENT = ("127.0.0.1", 50001)
    PROXY = ("127.0.0.1", 8080)

    def make(self, pid: int, **overrides) -> CaptureProcessFilter:
        table = tcp4_table([(self.CLIENT, self.PROXY, pid)])
        options = {"table": lambda: table, "processes": lambda: PROCESSES, "created": CREATED.get}
        options.update(overrides)
        return CaptureProcessFilter(VRCHAT, **options)

    def test_allows_only_vrchat_connections(self) -> None:
        self.assertTrue(self.make(300).allows(self.CLIENT, self.PROXY))
        self.assertTrue(self.make(400).allows(self.CLIENT, self.PROXY))
        self.assertFalse(self.make(600).allows(self.CLIENT, self.PROXY))

    def test_lookup_failures_fail_closed(self) -> None:
        def boom():
            raise OSError("no table")

        self.assertFalse(self.make(300, table=lambda: None).allows(self.CLIENT, self.PROXY))
        self.assertFalse(self.make(300, table=boom).allows(self.CLIENT, self.PROXY))
        self.assertFalse(self.make(300, processes=lambda: None).allows(self.CLIENT, self.PROXY))
        self.assertFalse(self.make(300).allows(("127.0.0.1", 50009), self.PROXY))
        self.assertFalse(self.make(300).allows(None, self.PROXY))
        self.assertFalse(self.make(300).allows(("::1", 50001), self.PROXY))
        self.assertFalse(CaptureProcessFilter(frozenset(), table=lambda: b"").allows(self.CLIENT, self.PROXY))

    def test_decisions_are_cached_per_process_start(self) -> None:
        snapshots = []

        def processes():
            snapshots.append(1)
            return PROCESSES

        created = dict(CREATED)
        process_filter = self.make(600, processes=processes, created=created.get)
        self.assertFalse(process_filter.allows(self.CLIENT, self.PROXY))
        self.assertFalse(process_filter.allows(self.CLIENT, self.PROXY))
        self.assertEqual(len(snapshots), 1)
        created[600] = 61
        process_filter.allows(self.CLIENT, self.PROXY)
        self.assertEqual(len(snapshots), 2)


@unittest.skipUnless(os.name == "nt", "uses the Windows TCP table")
class WindowsLookupTests(unittest.TestCase):
    def test_finds_this_process_as_the_owner_of_a_loopback_connection(self) -> None:
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            with socket.socket() as client:
                client.connect(server.getsockname())
                accepted, _ = server.accept()
                with accepted:
                    peer, local = accepted.getpeername(), accepted.getsockname()
                    snapshot = process_snapshot()
                    self.assertIsNotNone(snapshot)
                    own_name = frozenset({snapshot[os.getpid()].name.lower()})
                    self.assertTrue(CaptureProcessFilter(own_name).allows(peer, local))
                    self.assertFalse(CaptureProcessFilter(VRCHAT).allows(peer, local))


def load_addon_module():
    try:
        import mitmproxy  # noqa: F401
    except ImportError:
        import sys

        stub = SimpleNamespace(
            ctx=SimpleNamespace(log=SimpleNamespace(error=lambda *a: None, info=lambda *a: None)),
            http=SimpleNamespace(HTTPFlow=object),
        )
        sys.modules.setdefault("mitmproxy", stub)
    import capture_addon

    return capture_addon


class FakeFilter:
    names = VRCHAT

    def __init__(self, allowed_ports: set[int]) -> None:
        self.allowed_ports = allowed_ports
        self.calls = 0

    def allows(self, client, proxy) -> bool:
        self.calls += 1
        return client is not None and client[1] in self.allowed_ports


def client(port: int) -> SimpleNamespace:
    return SimpleNamespace(id=f"client-{port}", peername=("127.0.0.1", port), sockname=("127.0.0.1", 8080))


class AddonProcessFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        module = load_addon_module()
        self.module = module
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.addon = module.CaptureAddon()
        self.addon.capture_dir = root
        self.addon.bodies_dir = root / "bodies"
        self.addon.decoded_dir = root / "decoded"
        self.addon.by_host_dir = root / "by-host"
        self.addon.streams_dir = root / "streams"
        self.addon.websockets_dir = root / "websockets"
        self.addon.flows_jsonl = root / "flows.jsonl"
        self.addon.events_jsonl = root / "events.jsonl"
        self.filter = FakeFilter({50001})
        self.addon.process_filter = self.filter
        self.vrchat = client(50001)
        self.other = client(50002)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def hello(self, conn) -> SimpleNamespace:
        return SimpleNamespace(
            context=SimpleNamespace(client=conn, server=None),
            client_hello=SimpleNamespace(sni="example.com", alpn_protocols=[]),
            ignore_connection=False,
        )

    def flow(self, conn) -> SimpleNamespace:
        return SimpleNamespace(
            id="flow",
            client_conn=conn,
            server_conn=None,
            request=SimpleNamespace(pretty_host="example.com", pretty_url="https://example.com/", path="/"),
            response=None,
            error=None,
            messages=[SimpleNamespace(content=b"secret", from_client=True, timestamp=1.0)],
        )

    def test_other_programs_tls_is_passed_through_undecrypted(self) -> None:
        data = self.hello(self.other)
        self.addon.tls_clienthello(data)
        self.assertTrue(data.ignore_connection)
        self.assertEqual(self.addon._events, [])

    def test_vrchat_tls_is_still_intercepted(self) -> None:
        data = self.hello(self.vrchat)
        self.addon.tls_clienthello(data)
        self.assertFalse(data.ignore_connection)
        self.assertEqual([e["kind"] for e in self.addon._events], ["tls_clienthello"])

    def test_capture_all_processes_intercepts_everything(self) -> None:
        self.addon.capture_all_processes = True
        data = self.hello(self.other)
        self.addon.tls_clienthello(data)
        self.assertFalse(data.ignore_connection)
        self.assertEqual(self.filter.calls, 0)

    def test_process_options_apply_before_the_proxy_starts(self) -> None:
        original = self.module.ctx
        self.module.ctx = SimpleNamespace(
            options=SimpleNamespace(capture_all_processes=True, capture_processes="Curl.exe"), log=None
        )
        try:
            self.addon.configure({"capture_all_processes", "capture_processes"})
        finally:
            self.module.ctx = original
        self.assertTrue(self.addon.capture_all_processes)
        self.assertEqual(self.addon.process_filter.names, frozenset({"curl.exe"}))
        data = self.hello(self.other)
        self.addon.tls_clienthello(data)
        self.assertFalse(data.ignore_connection)

    def test_other_programs_are_not_recorded(self) -> None:
        recorded = []
        original = self.module.build_http_record
        self.module.build_http_record = lambda *a, **k: recorded.append(a) or {}
        try:
            self.addon.client_connected(self.other)
            self.addon.http_connect(self.flow(self.other))
            self.addon.requestheaders(self.flow(self.other))
            self.addon.response(self.flow(self.other))
            self.addon.error(self.flow(self.other))
            self.addon.tcp_message(self.flow(self.other))
            self.addon.tcp_end(self.flow(self.other))
            self.addon.server_connect(SimpleNamespace(client=self.other, server=None))
            self.addon.tls_failed_client(SimpleNamespace(context=SimpleNamespace(client=self.other), conn=None))
            self.addon.client_disconnected(self.other)
        finally:
            self.module.build_http_record = original
        self.assertEqual(recorded, [])
        self.assertEqual(self.addon._events, [])
        self.assertFalse(self.addon.events_jsonl.exists())
        self.assertFalse(self.addon.streams_dir.exists())

    def test_vrchat_events_are_recorded_and_lookups_cached_per_connection(self) -> None:
        self.addon.client_connected(self.vrchat)
        self.addon.server_connect(SimpleNamespace(client=self.vrchat, server=None))
        self.addon.tls_clienthello(self.hello(self.vrchat))
        self.addon.client_disconnected(self.vrchat)
        kinds = [e["kind"] for e in self.addon._events]
        self.assertEqual(kinds, ["client_connected", "server_connect", "tls_clienthello", "client_disconnected"])
        self.assertEqual(self.filter.calls, 1)
        self.assertEqual(self.addon._clients, {})


if __name__ == "__main__":
    unittest.main()
