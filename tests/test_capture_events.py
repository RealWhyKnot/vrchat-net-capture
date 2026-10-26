from __future__ import annotations

import unittest

from capture_events import (
    build_summary,
    request_headers_event,
    response_headers_event,
    stream_event,
    websocket_event,
)
from capture_records import REDACTED


class Dummy:
    pass


class Headers:
    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = items

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)


def make_http_flow():
    flow = Dummy()
    flow.id = "flow-2"
    flow.client_conn = None
    flow.server_conn = None

    req = Dummy()
    req.pretty_host = "worlds.example.test"
    req.pretty_url = "https://worlds.example.test/do_auth?authToken=secret-token&lang=en"
    req.method = "GET"
    req.path = "/do_auth?authToken=secret-token&lang=en"
    req.scheme = "https"
    req.http_version = "HTTP/1.1"
    req.headers = Headers(
        [
            ("Authorization", "Bearer secret"),
            ("Cookie", "auth=secret"),
            ("X-Auth-Token", "secret"),
            ("Accept", "application/json"),
        ]
    )
    flow.request = req

    resp = Dummy()
    resp.status_code = 200
    resp.http_version = "HTTP/1.1"
    resp.headers = Headers([("Set-Cookie", "auth=secret; Path=/"), ("Content-Type", "application/json")])
    flow.response = resp
    return flow


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

    def test_request_headers_event_redacts_credentials(self) -> None:
        event = request_headers_event(make_http_flow())

        self.assertEqual(event["headers"]["Authorization"], REDACTED)
        self.assertEqual(event["headers"]["Cookie"], REDACTED)
        self.assertEqual(event["headers"]["X-Auth-Token"], REDACTED)
        self.assertEqual(event["headers"]["Accept"], "application/json")
        self.assertNotIn("secret", str(event))

    def test_response_headers_event_redacts_set_cookie(self) -> None:
        event = response_headers_event(make_http_flow())

        self.assertEqual(event["headers"]["Set-Cookie"], REDACTED)
        self.assertEqual(event["headers"]["Content-Type"], "application/json")
        self.assertNotIn("secret", str(event))

    def test_flow_events_redact_token_query_params(self) -> None:
        event = request_headers_event(make_http_flow())

        self.assertEqual(event["url"], f"https://worlds.example.test/do_auth?authToken={REDACTED}&lang=en")
        self.assertEqual(event["path"], f"/do_auth?authToken={REDACTED}&lang=en")

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
