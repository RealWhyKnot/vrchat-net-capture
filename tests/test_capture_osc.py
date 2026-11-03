from __future__ import annotations

import struct
import unittest
from dataclasses import dataclass

from vrchat_net_capture.capture_osc import OscParseError, OscValue, decode_osc_packet, looks_like_osc_packet


@dataclass(frozen=True)
class OscCase:
    tag: str
    payload: bytes
    value: OscValue


def osc_string(value: str) -> bytes:
    raw = value.encode("utf-8") + b"\x00"
    return raw + (b"\x00" * ((4 - len(raw) % 4) % 4))


class CaptureOscTests(unittest.TestCase):
    def test_decodes_message_with_redacted_values(self) -> None:
        packet = osc_string("/avatar/parameters/Muted") + osc_string(",T")

        decoded = decode_osc_packet(packet)

        self.assertIsNotNone(decoded)
        if decoded is None:
            self.fail("Expected an OSC packet")
        self.assertEqual(decoded["message_count"], 1)
        message = decoded["messages"][0]
        self.assertEqual(message["address"], "/avatar/parameters/Muted")
        self.assertEqual(message["type_tags"], ",T")
        self.assertTrue(message["arguments"][0].get("redacted"))

    def test_decodes_values_when_enabled(self) -> None:
        packet = osc_string("/input/LookHorizontal") + osc_string(",f") + struct.pack(">f", 0.5)

        decoded = decode_osc_packet(packet, include_values=True)

        if decoded is None:
            self.fail("Expected an OSC packet")
        self.assertEqual(decoded["messages"][0]["arguments"][0].get("value"), 0.5)

    def test_preserves_values_and_redaction_for_every_supported_tag(self) -> None:
        cases = (
            OscCase("i", struct.pack(">i", -42), -42),
            OscCase("h", struct.pack(">q", -(2**60)), -(2**60)),
            OscCase("f", struct.pack(">f", 0.5), 0.5),
            OscCase("d", struct.pack(">d", 1.25), 1.25),
            OscCase("s", osc_string("hello"), "hello"),
            OscCase("b", struct.pack(">i", 3) + b"abc\x00", "YWJj"),
            OscCase("t", struct.pack(">Q", 2**64 - 1), 2**64 - 1),
            OscCase("T", b"", value=True),
            OscCase("F", b"", value=False),
            OscCase("N", b"", None),
            OscCase("I", b"", "impulse"),
        )
        for case in cases:
            for include_values in (False, True):
                with self.subTest(tag=case.tag, include_values=include_values):
                    payload = osc_string("/test") + osc_string(f",{case.tag}") + case.payload
                    decoded = decode_osc_packet(payload, include_values=include_values)
                    if decoded is None:
                        self.fail("Expected an OSC packet")
                    argument = decoded["messages"][0]["arguments"][0]
                    if include_values:
                        self.assertEqual(argument.get("value"), case.value)
                        self.assertNotIn("redacted", argument)
                    else:
                        self.assertTrue(argument.get("redacted"))
                        self.assertNotIn("value", argument)

    def test_nested_bundle_keeps_message_and_bundle_counts(self) -> None:
        message = osc_string("/test") + osc_string(",T")
        inner = b"#bundle\x00" + bytes(8) + struct.pack(">i", len(message)) + message
        outer = b"#bundle\x00" + bytes(8) + struct.pack(">i", len(inner)) + inner
        decoded = decode_osc_packet(outer)
        if decoded is None:
            self.fail("Expected an OSC packet")
        self.assertEqual(decoded["bundle_count"], 2)
        self.assertEqual(decoded["message_count"], 1)
        self.assertEqual(decoded["messages"][0]["address"], "/test")

    def test_truncated_numeric_values_keep_the_error_text(self) -> None:
        formats = {"i": "int32", "h": "int64", "f": "float32", "d": "float64", "t": "uint64"}
        for tag, name in formats.items():
            with self.subTest(tag=tag), self.assertRaisesRegex(OscParseError, f"^truncated {name}$"):
                decode_osc_packet(osc_string("/test") + osc_string(f",{tag}"))

    def test_rejects_malformed_message(self) -> None:
        self.assertTrue(looks_like_osc_packet(b"/bad"))
        with self.assertRaises(OscParseError):
            decode_osc_packet(b"/bad")


if __name__ == "__main__":
    unittest.main()
