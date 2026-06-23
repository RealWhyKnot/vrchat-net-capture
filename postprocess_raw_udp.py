from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from capture_osc import OscParseError, build_osc_summary, decode_osc_packet
from capture_photon import build_photon_summary, classify_photon_packet
from capture_utils import append_jsonl


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-dir", required=True)
    parser.add_argument("--decode-osc", action="store_true")
    parser.add_argument("--store-osc-values", action="store_true")
    parser.add_argument("--photon-metadata", action="store_true")
    args = parser.parse_args()

    capture_dir = Path(args.capture_dir)
    datagrams_path = capture_dir / "network" / "udp-datagrams.jsonl"
    if not datagrams_path.exists():
        return 0

    osc_dir = capture_dir / "osc"
    photon_dir = capture_dir / "photon"
    osc_records: list[dict[str, Any]] = []
    photon_records: list[dict[str, Any]] = []

    if args.decode_osc:
        osc_dir.mkdir(parents=True, exist_ok=True)
    if args.photon_metadata:
        photon_dir.mkdir(parents=True, exist_ok=True)

    for datagram in read_jsonl(datagrams_path):
        payload_path = capture_dir / str(datagram.get("payload_path") or "")
        if not payload_path.exists():
            continue
        payload = payload_path.read_bytes()

        if args.decode_osc:
            record = osc_record(datagram, payload, args.store_osc_values)
            if record is not None:
                osc_records.append(record)
                append_jsonl(osc_dir / "osc-events.jsonl", record)

        if args.photon_metadata:
            photon = classify_photon_packet(datagram, payload)
            if photon is not None:
                record = base_record("photon_packet", datagram)
                record["photon"] = photon
                photon_records.append(record)
                append_jsonl(photon_dir / "photon-packets.jsonl", record)

    if args.decode_osc:
        (osc_dir / "osc-summary.json").write_text(
            json.dumps(build_osc_summary(osc_records), indent=2), encoding="utf-8"
        )
    if args.photon_metadata:
        (photon_dir / "photon-summary.json").write_text(
            json.dumps(build_photon_summary(photon_records), indent=2),
            encoding="utf-8",
        )
    return 0


def osc_record(datagram: dict[str, Any], payload: bytes, store_values: bool) -> dict[str, Any] | None:
    try:
        osc = decode_osc_packet(payload, include_values=store_values)
        if osc is None:
            return None
    except OscParseError as exc:
        osc = {"status": "error", "error": str(exc)}
    record = base_record("osc_packet", datagram)
    record["osc"] = osc
    return record


def base_record(kind: str, datagram: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": kind,
        "schema_version": 1,
        "packet_number": datagram.get("packet_number"),
        "ts_utc": datagram.get("ts_utc"),
        "capture_semantics": datagram.get("capture_semantics"),
        "backend": datagram.get("backend"),
        "direction": datagram.get("direction"),
        "loopback": datagram.get("loopback"),
        "source": {
            "address": datagram.get("source_address"),
            "port": datagram.get("source_port"),
        },
        "destination": {
            "address": datagram.get("destination_address"),
            "port": datagram.get("destination_port"),
        },
        "payload_sha256": datagram.get("payload_sha256"),
        "payload_path": datagram.get("payload_path"),
        "payload_length": datagram.get("payload_length"),
        "pid_confidence": datagram.get("pid_confidence"),
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


if __name__ == "__main__":
    raise SystemExit(main())
