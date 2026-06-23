from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from capture_vrchat_logs import mark_unmatched_log_urls, newest_output_log, parse_vrchat_log


class VrchatLogTests(unittest.TestCase):
    def test_parse_url_bearing_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "output_log_2026-06-23_12-00-00.txt"
            path.write_text(
                "\n".join(
                    [
                        "[String Download] Attempting to load String from URL 'https://example.test/catalog.json'",
                        "[Video Playback] URL 'https://video.test/master.m3u8' resolved",
                        "ordinary log line",
                    ]
                ),
                encoding="utf-8",
            )

            events = parse_vrchat_log(path)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["category"], "string_download")
        self.assertEqual(events[0]["url"], "https://example.test/catalog.json")
        self.assertEqual(events[1]["category"], "video_playback")

    def test_mark_unmatched_urls(self) -> None:
        events = [
            {"url": "https://matched.test/a"},
            {"url": "https://missing.test/b"},
        ]
        unmatched = mark_unmatched_log_urls(events, [{"url": "https://matched.test/a"}])

        self.assertEqual(len(unmatched), 1)
        self.assertTrue(events[0]["captured_by_proxy"])
        self.assertFalse(events[1]["captured_by_proxy"])

    def test_newest_output_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            older = root / "output_log_2026-06-23_10-00-00.txt"
            newer = root / "output_log_2026-06-23_11-00-00.txt"
            older.write_text("old", encoding="utf-8")
            newer.write_text("new", encoding="utf-8")

            self.assertEqual(newest_output_log(root), newer)


if __name__ == "__main__":
    unittest.main()
