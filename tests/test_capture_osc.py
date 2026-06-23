from __future__ import annotations

import struct
import unittest

from capture_osc import OscParseError, decode_osc_packet, looks_like_osc_packet


def osc_string(value: str) -> bytes:
    raw = value.encode("utf-8") + b"\x00"
    return raw + (b"\x00" * ((4 - len(raw) % 4) % 4))


class CaptureOscTests(unittest.TestCase):
    def test_decodes_message_with_redacted_values(self) -> None:
        packet = osc_string("/avatar/parameters/Muted") + osc_string(",T")

        decoded = decode_osc_packet(packet)

        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["message_count"], 1)
        message = decoded["messages"][0]
        self.assertEqual(message["address"], "/avatar/parameters/Muted")
        self.assertEqual(message["type_tags"], ",T")
        self.assertTrue(message["arguments"][0]["redacted"])

    def test_decodes_values_when_enabled(self) -> None:
        packet = osc_string("/input/LookHorizontal") + osc_string(",f") + struct.pack(">f", 0.5)

        decoded = decode_osc_packet(packet, include_values=True)

        assert decoded is not None
        self.assertAlmostEqual(decoded["messages"][0]["arguments"][0]["value"], 0.5)

    def test_rejects_malformed_message(self) -> None:
        self.assertTrue(looks_like_osc_packet(b"/bad"))
        with self.assertRaises(OscParseError):
            decode_osc_packet(b"/bad")


if __name__ == "__main__":
    unittest.main()
