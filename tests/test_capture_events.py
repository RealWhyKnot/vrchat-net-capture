from __future__ import annotations

import unittest

from capture_events import build_summary, stream_event, websocket_event


class Dummy:
    pass


def make_flow(message: bytes = b"hello", from_client: bool = True, is_text: bool = True):
    flow = Dummy()
    flow.id = "flow-1"
    flow.client_conn = None
    flow.server_conn = None

    req = Dummy()
    req.pretty_host = "pipeline.vrchat.cloud"
    req.pretty_url = "wss://pipeline.vrchat.cloud/socket"
    req.method = "GET"
    req.path = "/socket"
    flow.request = req

    ws = Dummy()
    msg = Dummy()
    msg.content = message
    msg.from_client = from_client
    msg.is_text = is_text
    msg.type = "TEXT" if is_text else "BINARY"
    msg.timestamp = 1.0
    msg.dropped = False
    msg.injected = False
    ws.messages = [msg]
    flow.websocket = ws
    flow.messages = [msg]
    return flow


class CaptureEventsTests(unittest.TestCase):
    def test_websocket_event_summarizes_latest_message(self) -> None:
        event, payload = websocket_event("websocket_message", make_flow())

        self.assertEqual(payload, b"hello")
        self.assertEqual(event["kind"], "websocket_message")
        self.assertEqual(event["host"], "pipeline.vrchat.cloud")
        self.assertEqual(event["direction"], "client_to_server")
        self.assertEqual(event["text_preview"], "hello")
        self.assertEqual(event["size"], 5)

    def test_stream_event_uses_base64_for_binary_preview(self) -> None:
        event, payload = stream_event("tcp_message", make_flow(b"\x00\x01\x02", is_text=False))

        self.assertEqual(payload, b"\x00\x01\x02")
        self.assertEqual(event["preview"]["encoding"], "base64")
        self.assertEqual(event["capture_semantics"], "proxy_observed")

    def test_build_summary_counts_flows_and_events(self) -> None:
        summary = build_summary(
            [
                {"host": "api.vrchat.cloud", "method": "GET", "status": 200, "errored": False},
                {"host": "api.vrchat.cloud", "method": "POST", "status": None, "errored": True},
            ],
            [
                {"kind": "websocket_message"},
                {"kind": "tls_failed_client", "error": "bad cert"},
            ],
        )

        self.assertEqual(summary["flow_count"], 2)
        self.assertEqual(summary["event_count"], 2)
        self.assertEqual(summary["hosts"]["api.vrchat.cloud"], 2)
        self.assertEqual(summary["statuses"]["ERR"], 1)
        self.assertEqual(summary["errors"]["http_flow"], 1)
        self.assertEqual(summary["errors"]["tls_failed_client"], 1)
        self.assertEqual(summary["tls_failure_targets"], {})

    def test_build_summary_counts_tls_failure_targets(self) -> None:
        summary = build_summary(
            [],
            [
                {
                    "kind": "tls_failed_server",
                    "connection": {"sni": "example.test", "address": "203.0.113.1:443"},
                    "error": "certificate verify failed",
                }
            ],
        )

        self.assertEqual(summary["tls_failure_targets"]["example.test"], 1)


if __name__ == "__main__":
    unittest.main()
