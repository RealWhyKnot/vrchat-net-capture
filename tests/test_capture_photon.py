from __future__ import annotations

import struct
import unittest

from capture_photon import build_photon_summary, classify_photon_packet


class CapturePhotonTests(unittest.TestCase):
    def test_classifies_known_port_with_metadata_only_note(self) -> None:
        event = {
            "direction": "client_to_server",
            "client": {"sockname": "127.0.0.1:53000"},
            "server": {"address": "203.0.113.10:5055"},
        }
        payload = struct.pack(">HBBII", 1, 0, 1, 123, 456) + (b"\x00" * 12)

        photon = classify_photon_packet(event, payload)

        self.assertIsNotNone(photon)
        assert photon is not None
        self.assertEqual(photon["confidence"], "medium")
        self.assertEqual(photon["ports"], [5055])
        self.assertEqual(photon["capture_semantics"], "proxy_observed")
        self.assertEqual(photon["payload_semantics"], "not decoded")
        self.assertEqual(photon["header_guess"]["command_count"], 1)

    def test_classifies_realtime_27002_port(self) -> None:
        event = {
            "direction": "outbound",
            "source_port": 50507,
            "destination_port": 27002,
            "capture_semantics": "wire_copy",
        }
        payload = b"\x00" * 32

        photon = classify_photon_packet(event, payload)

        self.assertIsNotNone(photon)
        assert photon is not None
        self.assertEqual(photon["ports"], [27002])
        self.assertEqual(photon["capture_semantics"], "wire_copy")

    def test_summary_counts_candidates(self) -> None:
        summary = build_photon_summary(
            [
                {"direction": "client_to_server", "photon": {"confidence": "low", "ports": [5058]}},
                {"direction": "server_to_client"},
            ]
        )

        self.assertEqual(summary["candidate_packet_count"], 1)
        self.assertEqual(summary["ports"]["5058"], 1)
        self.assertEqual(summary["capture_semantics"], "proxy_observed")
        self.assertEqual(summary["payload_semantics"], "not decoded")


if __name__ == "__main__":
    unittest.main()
