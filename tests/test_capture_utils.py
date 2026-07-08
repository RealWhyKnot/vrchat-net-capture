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

# Real vr-m.net /1/l/6 (movie lock) response body, transport gzip already stripped. Catalog
# metadata only (Ratatouille -> lockId 4697); used to check the packed-body dispatch routing.
_VRM_LOCK_6_PACKED = bytes.fromhex(
    "01c3ac02201d007901c380065008c2803a00c38002c38008c2806c01c2bc06301ac3804901c29010600d003600c3a403"
    "7042407401c2a407401b010500c3a8022014c2806101c39011c3b01bc3807501c2a406c38046c280220424072019411a"
    "01c2840730194044047c11c2b008c2803200c38003000dc3802d00c38003600b403200c3a0127008c2806901c2b40610"
    "19c38065015407201b010600c28806c2801d007401c38007300ec2802f00c2bc077019406200c2b807601cc2802d01c2"
    "b402c3a01bc2806501c39002c3b018407001c2a402c3b01b406501c29006c29018402f01c39006c2801d406d01c28806"
    "c3a018412400c2bc03100dc2803001c29403c29019003900c38002c3900d006200c39006105e403701c28803100b4061"
    "00c398035018c2802d01c29006400d003700c3a003500e006401c29818c3a018402e01c38006c3a019c3802201c3b7c3"
    "bfc3b000"
)


class CaptureUtilsTests(unittest.TestCase):
    def test_body_shape_detection(self) -> None:
        self.assertTrue(looks_like_json(b'  {"ok": true}'))
        self.assertFalse(looks_like_json(b"not json"))
        self.assertTrue(looks_like_text(b"hello world"))
        self.assertFalse(looks_like_text(b"abc\x00def"))
        self.assertTrue(is_text_content_type("text/plain; charset=utf-8"))
        self.assertTrue(is_text_content_type("application/javascript"))
        self.assertFalse(is_text_content_type("application/octet-stream"))

    def test_safe_slug_keeps_filename_chars(self) -> None:
        self.assertEqual(safe_slug("/avatars/foo bar?x=1"), "avatars_foo_bar_x_1")
        self.assertEqual(safe_slug(""), "_")

    def test_hex_preview_includes_offset_ascii_and_truncation(self) -> None:
        preview = hex_preview(bytes(i % 256 for i in range(300)))
        self.assertIn("00000000", preview)
        self.assertIn("... (300 bytes total)", preview)

    def test_decode_response_writes_human_readable_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            decoded = root / "decoded"
            decoded.mkdir()

            json_path, json_hint, is_bundle = decode_response(
                root,
                decoded,
                "jsonhash",
                b'{"name":"Example"}',
                "application/json",
            )
            self.assertEqual(json_path, "decoded/jsonhash.json")
            self.assertEqual(json_hint, "json")
            self.assertFalse(is_bundle)
            self.assertEqual(json.loads((root / json_path).read_text(encoding="utf-8"))["name"], "Example")

            m3u8_path, m3u8_hint, _ = decode_response(
                root,
                decoded,
                "m3u8hash",
                b"#EXTM3U\n#EXT-X-ENDLIST\n",
                "application/vnd.apple.mpegurl",
            )
            self.assertEqual(m3u8_path, "decoded/m3u8hash.m3u8")
            self.assertEqual(m3u8_hint, "EXTM3U")

    def test_decode_response_routes_vrm_packed_body(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            decoded = root / "decoded"
            decoded.mkdir()

            # Packed vr-m body from a vr-m host decodes to JSON.
            vrm_path, vrm_hint, _ = decode_response(
                root, decoded, "vrmhash", _VRM_LOCK_6_PACKED, "application/json", host="vr-m.net"
            )
            self.assertEqual(vrm_path, "decoded/vrmhash.json")
            self.assertEqual(vrm_hint, "vrm")
            self.assertEqual(json.loads((root / vrm_path).read_text(encoding="utf-8"))["lockId"], 4697)

            # Same bytes from a non-vr-m host are never treated as a packed body.
            _, other_hint, _ = decode_response(
                root, decoded, "otherhash", _VRM_LOCK_6_PACKED, "application/json", host="example.com"
            )
            self.assertNotEqual(other_hint, "vrm")

            # Plain JSON from a vr-m host falls through to the normal JSON branch.
            plain_path, plain_hint, _ = decode_response(
                root, decoded, "plainhash", b'{"availableLanguages":["en"]}', "application/json", host="vr-m.net"
            )
            self.assertEqual(plain_path, "decoded/plainhash.json")
            self.assertEqual(plain_hint, "json")

    def test_index_writers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            by_host = root / "by-host"
            record = {
                "flow_id": "abcdef123456",
                "host": "api.vrchat.cloud",
                "ts_start": 1_700_000_000.123,
                "method": "GET",
                "status": 200,
                "path": "/api/1/users?x=1",
            }

            append_jsonl(root / "flows.jsonl", record)
            self.assertEqual(len((root / "flows.jsonl").read_text(encoding="utf-8").splitlines()), 1)

            write_per_host(by_host, record)
            written = list((by_host / "api.vrchat.cloud").glob("*.json"))
            self.assertEqual(len(written), 1)
            self.assertEqual(json.loads(written[0].read_text(encoding="utf-8"))["flow_id"], "abcdef123456")


if __name__ == "__main__":
    unittest.main()
