from __future__ import annotations

import json
import unittest

from vrm_codec import try_decode

# Real vr-m.net /1/l/6 (movie lock) response body, transport gzip already stripped, as captured.
# Catalog metadata only (Ratatouille -> lockId 4697); no token or user data.
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


def _lzw_compress(data: bytes) -> bytes:
    """Inverse of vrm_codec's LZW: MSB-first, 14-bit codes, dict preloaded 0..255, frozen at 2**14."""
    table = {bytes((i,)): i for i in range(256)}
    nxt = 256
    codes: list[int] = []
    w = b""
    for byte in data:
        wc = w + bytes((byte,))
        if wc in table:
            w = wc
        else:
            codes.append(table[w])
            if nxt < (1 << 14):
                table[wc] = nxt
                nxt += 1
            w = bytes((byte,))
    if w:
        codes.append(table[w])

    bits: list[int] = []
    for code in codes:
        for k in range(13, -1, -1):
            bits.append((code >> k) & 1)
    while len(bits) % 8:
        bits.append(0)
    out = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for j in range(8):
            value = (value << 1) | bits[i + j]
        out.append(value)
    return bytes(out)


def _pack(obj: object, trailing: bytes = b"") -> bytes:
    """Encode obj the way vr-m.net does: LZW, then the Latin-1 -> UTF-8 transport mojibake."""
    packed = _lzw_compress(json.dumps(obj).encode("utf-8")) + trailing
    return packed.decode("latin-1").encode("utf-8")


class VrmCodecTests(unittest.TestCase):
    def test_round_trips_a_json_object(self) -> None:
        obj = {"title": "Ratatouille", "lockId": 4697, "genres": ["Animation", "Family"]}
        self.assertEqual(json.loads(try_decode(_pack(obj))), obj)

    def test_handles_kwkwk_repeated_run(self) -> None:
        # A long single-character run drives the code == dict.Count (KwKwK) branch.
        obj = {"x": "a" * 64}
        self.assertEqual(json.loads(try_decode(_pack(obj))), obj)

    def test_trims_trailing_bit_padding(self) -> None:
        # Real bodies emit a spurious code from bit-padding after the closing brace.
        obj = {"ok": True, "n": 12345}
        self.assertEqual(json.loads(try_decode(_pack(obj, trailing=b"\x00\x01\xff"))), obj)

    def test_returns_none_for_plain_json(self) -> None:
        self.assertIsNone(try_decode(b'{"already":"json"}'))
        self.assertIsNone(try_decode(b'  ["a","b"]'))

    def test_returns_none_for_empty_or_binary(self) -> None:
        self.assertIsNone(try_decode(b""))
        self.assertIsNone(try_decode(b"\x89PNG\r\n\x1a\n"))

    def test_decodes_real_captured_lock_body(self) -> None:
        decoded = json.loads(try_decode(_VRM_LOCK_6_PACKED))
        self.assertEqual(decoded["title"], "Ratatouille")
        self.assertEqual(decoded["lockId"], 4697)


if __name__ == "__main__":
    unittest.main()
