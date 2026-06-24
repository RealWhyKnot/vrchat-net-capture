from __future__ import annotations

import unittest

from capture_records import REDACTED, redact_headers


class CaptureRecordsTests(unittest.TestCase):
    def test_redacts_sensitive_headers(self) -> None:
        headers = [
            ("Authorization", "Bearer secret"),
            ("Cookie", "session=secret"),
            ("Set-Cookie", "session=secret"),
            ("Content-Type", "application/json"),
        ]

        redacted = redact_headers(headers)

        self.assertEqual(redacted["Authorization"], REDACTED)
        self.assertEqual(redacted["Cookie"], REDACTED)
        self.assertEqual(redacted["Set-Cookie"], REDACTED)
        self.assertEqual(redacted["Content-Type"], "application/json")


if __name__ == "__main__":
    unittest.main()
