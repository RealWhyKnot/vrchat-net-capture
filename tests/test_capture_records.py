from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from capture_records import REDACTED, build_http_record, redact_headers, redact_url


class Dummy:
    pass


class Headers:
    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = items

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def get(self, key: str, default: str | None = None) -> str | None:
        for name, value in self._items:
            if name.lower() == key.lower():
                return value
        return default


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
            f"https://api.example.test/api/1/auth?apiKey={REDACTED}&authToken={REDACTED}&access_token={REDACTED}"
            f"&X-Amz-Security-Token={REDACTED}&client_secret={REDACTED}&password={REDACTED}&page=2&q=a%20b",
        )

    def test_redact_url_leaves_harmless_urls_alone(self) -> None:
        self.assertIsNone(redact_url(None))
        self.assertEqual(redact_url(""), "")
        self.assertEqual(redact_url("https://example.test/a/b"), "https://example.test/a/b")
        self.assertEqual(redact_url("/list?page=1&flag&token="), "/list?page=1&flag&token=")
        self.assertEqual(redact_url("/p?token=abc#frag"), f"/p?token={REDACTED}#frag")

    def test_http_record_redacts_url_and_path(self) -> None:
        flow = Dummy()
        flow.id = "flow-3"
        flow.client_conn = None
        flow.server_conn = None
        req = Dummy()
        req.pretty_host = "worlds.example.test"
        req.pretty_url = "https://worlds.example.test/do_auth?token=secret-token"
        req.path = "/do_auth?token=secret-token"
        req.method = "GET"
        req.scheme = "https"
        req.timestamp_start = 1.0
        req.timestamp_end = 2.0
        req.raw_content = b""
        req.headers = Headers([("Authorization", "Bearer secret-token")])
        flow.request = req
        flow.response = None

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = build_http_record(flow, root, root, root, False, False, None, lambda _: None)

        self.assertEqual(record["url"], f"https://worlds.example.test/do_auth?token={REDACTED}")
        self.assertEqual(record["path"], f"/do_auth?token={REDACTED}")
        self.assertNotIn("secret-token", str(record))


if __name__ == "__main__":
    unittest.main()
