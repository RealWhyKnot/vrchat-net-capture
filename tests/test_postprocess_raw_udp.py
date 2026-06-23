from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from postprocess_raw_udp import main


def osc_string(value: str) -> bytes:
    raw = value.encode("utf-8") + b"\x00"
    return raw + (b"\x00" * ((4 - len(raw) % 4) % 4))


class PostprocessRawUdpTests(unittest.TestCase):
    def test_postprocess_decodes_raw_osc_and_photon_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            network = root / "network"
            payloads = network / "payloads"
            payloads.mkdir(parents=True)

            osc_payload = osc_string("/avatar/parameters/Muted") + osc_string(",T")
            photon_payload = b"photon-port-only"
            (payloads / "osc.udp.bin").write_bytes(osc_payload)
            (payloads / "photon.udp.bin").write_bytes(photon_payload)

            records = [
                {
                    "packet_number": 1,
                    "ts_utc": "2026-06-23T00:00:00Z",
                    "capture_semantics": "wire_copy",
                    "backend": "WinDivert",
                    "direction": "outbound",
                    "loopback": True,
                    "source_address": "127.0.0.1",
                    "source_port": 50000,
                    "destination_address": "127.0.0.1",
                    "destination_port": 9000,
                    "payload_sha256": "osc",
                    "payload_path": "network/payloads/osc.udp.bin",
                    "payload_length": len(osc_payload),
                    "pid_confidence": "none",
                },
                {
                    "packet_number": 2,
                    "ts_utc": "2026-06-23T00:00:01Z",
                    "capture_semantics": "wire_copy",
                    "backend": "WinDivert",
                    "direction": "outbound",
                    "loopback": False,
                    "source_address": "192.0.2.5",
                    "source_port": 50001,
                    "destination_address": "203.0.113.10",
                    "destination_port": 5055,
                    "payload_sha256": "photon",
                    "payload_path": "network/payloads/photon.udp.bin",
                    "payload_length": len(photon_payload),
                    "pid_confidence": "none",
                },
            ]
            (network / "udp-datagrams.jsonl").write_text(
                "\n".join(json.dumps(r) for r in records) + "\n",
                encoding="utf-8",
            )

            code = main_with_args(["--capture-dir", str(root), "--decode-osc", "--photon-metadata"])

            self.assertEqual(code, 0)
            osc_events = (root / "osc" / "osc-events.jsonl").read_text(encoding="utf-8")
            photon_packets = [
                json.loads(line)
                for line in (root / "photon" / "photon-packets.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            photon_summary = json.loads((root / "photon" / "photon-summary.json").read_text(encoding="utf-8"))
            self.assertIn("/avatar/parameters/Muted", osc_events)
            self.assertEqual(len(photon_packets), 1)
            self.assertEqual(photon_packets[0]["photon"]["capture_semantics"], "wire_copy")
            self.assertEqual(photon_packets[0]["photon"]["confidence"], "low")
            self.assertEqual(photon_packets[0]["photon"]["ports"], [5055])
            self.assertEqual(photon_summary["capture_semantics"], "wire_copy")
            self.assertEqual(photon_summary["capture_semantics_counts"], {"wire_copy": 1})


def main_with_args(args: list[str]) -> int:
    import sys

    old_argv = sys.argv
    try:
        sys.argv = ["postprocess_raw_udp.py", *args]
        return main()
    finally:
        sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()
