from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.flow_fixtures import make_http_flow, request
from vrchat_net_capture.capture_records import REDACTED, RecordingOptions, build_http_record, redact_headers, redact_url


class CaptureRecordsTests(unittest.TestCase):
    def test_redacts_sensitive_headers(self) -> None:
        headers = [
            ("Authorization", "Bearer secret"),
            ("Cookie", "session=secret"),
            ("Set-Cookie", "session=secret"),
            ("X-Access-Token", "secret"),
            ("Content-Type", "application/json"),
        ]

        redacted = redact_headers(headers)

        self.assertEqual(redacted["Authorization"], REDACTED)
        self.assertEqual(redacted["Cookie"], REDACTED)
        self.assertEqual(redacted["Set-Cookie"], REDACTED)
        self.assertEqual(redacted["X-Access-Token"], REDACTED)
        self.assertEqual(redacted["Content-Type"], "application/json")

    def test_redact_url_hides_token_like_query_params(self) -> None:
        url = (
            "https://api.example.test/api/1/auth?apiKey=k1&authToken=t1&access_token=t2&X-Amz-Security-Token=t3"
            "&client_secret=s1&password=p1&page=2&q=a%20b"
        )

        self.assertEqual(
            redact_url(url),
            (
                f"https://api.example.test/api/1/auth?apiKey={REDACTED}&authToken={REDACTED}&access_token={REDACTED}"
                f"&X-Amz-Security-Token={REDACTED}&client_secret={REDACTED}&password={REDACTED}&page=2&q=a%20b"
            ),
        )

    def test_redact_url_leaves_harmless_urls_alone(self) -> None:
        self.assertIsNone(redact_url(None))
        self.assertEqual(redact_url(""), "")
        self.assertEqual(redact_url("https://example.test/a/b"), "https://example.test/a/b")
        self.assertEqual(redact_url("/list?page=1&flag&token="), "/list?page=1&flag&token=")
        self.assertEqual(redact_url("/p?token=abc#frag"), f"/p?token={REDACTED}#frag")

    def test_http_record_redacts_url_and_path(self) -> None:
        flow = make_http_flow()
        flow.id = "flow-3"
        flow.request = request(
            "worlds.example.test", "/do_auth?token=secret-token", [("Authorization", "Bearer secret-token")]
        )
        flow.response = None

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = RecordingOptions(
                root, root, root, analyze_unity=False, unitypy_loader=None, warn=lambda _: None, clock=lambda: 1.0
            )
            record = build_http_record(flow, options)

        self.assertEqual(record["url"], f"https://worlds.example.test/do_auth?token={REDACTED}")
        self.assertEqual(record["path"], f"/do_auth?token={REDACTED}")
        self.assertNotIn("secret-token", str(record))


if __name__ == "__main__":
    unittest.main()
