from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from capture_utils import (
    append_jsonl,
    decode_response,
    hex_preview,
    is_text_content_type,
    looks_like_json,
    looks_like_text,
    safe_slug,
    write_per_host,
)


class CaptureUtilsTests(unittest.TestCase):
    def test_body_shape_detection(self) -> None:
        self.assertTrue(looks_like_json(b'  {"ok": true}'))
        self.assertFalse(looks_like_json(b'not json'))
        self.assertTrue(looks_like_text('hello world'.encode('utf-8')))
        self.assertFalse(looks_like_text(b'abc\x00def'))
        self.assertTrue(is_text_content_type('text/plain; charset=utf-8'))
        self.assertTrue(is_text_content_type('application/javascript'))
        self.assertFalse(is_text_content_type('application/octet-stream'))

    def test_safe_slug_keeps_filename_chars(self) -> None:
        self.assertEqual(safe_slug('/avatars/foo bar?x=1'), 'avatars_foo_bar_x_1')
        self.assertEqual(safe_slug(''), '_')

    def test_hex_preview_includes_offset_ascii_and_truncation(self) -> None:
        preview = hex_preview(bytes(i % 256 for i in range(300)))
        self.assertIn('00000000', preview)
        self.assertIn('... (300 bytes total)', preview)

    def test_decode_response_writes_human_readable_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            decoded = root / 'decoded'
            decoded.mkdir()

            json_path, json_hint, is_bundle = decode_response(
                root, decoded, 'jsonhash', b'{"name":"Example"}', 'application/json',
            )
            self.assertEqual(json_path, 'decoded/jsonhash.json')
            self.assertEqual(json_hint, 'json')
            self.assertFalse(is_bundle)
            self.assertEqual(json.loads((root / json_path).read_text(encoding='utf-8'))['name'], 'Example')

            m3u8_path, m3u8_hint, _ = decode_response(
                root, decoded, 'm3u8hash', b'#EXTM3U\n#EXT-X-ENDLIST\n', 'application/vnd.apple.mpegurl',
            )
            self.assertEqual(m3u8_path, 'decoded/m3u8hash.m3u8')
            self.assertEqual(m3u8_hint, 'EXTM3U')

    def test_index_writers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            by_host = root / 'by-host'
            record = {
                'flow_id': 'abcdef123456',
                'host': 'api.vrchat.cloud',
                'ts_start': 1_700_000_000.123,
                'method': 'GET',
                'status': 200,
                'path': '/api/1/users?x=1',
            }

            append_jsonl(root / 'flows.jsonl', record)
            self.assertEqual(len((root / 'flows.jsonl').read_text(encoding='utf-8').splitlines()), 1)

            write_per_host(by_host, record)
            written = list((by_host / 'api.vrchat.cloud').glob('*.json'))
            self.assertEqual(len(written), 1)
            self.assertEqual(json.loads(written[0].read_text(encoding='utf-8'))['flow_id'], 'abcdef123456')


if __name__ == '__main__':
    unittest.main()
