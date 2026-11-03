from __future__ import annotations

import unittest
from unittest.mock import patch

from typing_extensions import override

from tests.flow_fixtures import client, make_flow, make_http_flow, stream_flow
from vrchat_net_capture.capture_events import (
    build_summary,
    request_headers_event,
    response_headers_event,
    stream_event,
    websocket_event,
)
from vrchat_net_capture.capture_records import REDACTED


class CaptureEventsTests(unittest.TestCase):
    @override
    def setUp(self) -> None:
        clock = patch("vrchat_net_capture.capture_events.time.time", return_value=1.0)
        clock.start()
        self.addCleanup(clock.stop)

    def test_websocket_event_summarizes_latest_message(self) -> None:
        result = websocket_event("websocket_message", make_flow())
        event, payload = result.event, result.content

        self.assertEqual(payload, b"hello")
        self.assertEqual(event["kind"], "websocket_message")
        self.assertEqual(event.get("host"), "pipeline.vrchat.cloud")
        self.assertEqual(event.get("direction"), "client_to_server")
        self.assertEqual(event.get("text_preview"), "hello")
        self.assertEqual(event.get("size"), 5)

    def test_stream_event_uses_base64_for_binary_preview(self) -> None:
        result = stream_event("tcp_message", stream_flow(client(50001), b"\x00\x01\x02"))
        event, payload = result.event, result.content

        self.assertEqual(payload, b"\x00\x01\x02")
        preview = event.get("preview")
        if preview is None:
            self.fail("Expected a payload preview")
        self.assertEqual(preview["encoding"], "base64")
        self.assertEqual(event.get("capture_semantics"), "proxy_observed")

    def test_request_headers_event_redacts_credentials(self) -> None:
        event = request_headers_event(make_http_flow())
        headers = event.get("headers")
        if headers is None:
            self.fail("Expected headers")

        self.assertEqual(headers["Authorization"], REDACTED)
        self.assertEqual(headers["Cookie"], REDACTED)
        self.assertEqual(headers["X-Auth-Token"], REDACTED)
        self.assertEqual(headers["Accept"], "application/json")
        self.assertNotIn("secret", str(event))

    def test_response_headers_event_redacts_set_cookie(self) -> None:
        event = response_headers_event(make_http_flow())
        headers = event.get("headers")
        if headers is None:
            self.fail("Expected headers")

        self.assertEqual(headers["Set-Cookie"], REDACTED)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertNotIn("secret", str(event))

    def test_flow_events_redact_token_query_params(self) -> None:
        event = request_headers_event(make_http_flow())
        headers = event.get("headers")
        if headers is None:
            self.fail("Expected headers")

        self.assertEqual(event.get("url"), f"https://worlds.example.test/do_auth?authToken={REDACTED}&lang=en")
        self.assertEqual(event.get("path"), f"/do_auth?authToken={REDACTED}&lang=en")

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
