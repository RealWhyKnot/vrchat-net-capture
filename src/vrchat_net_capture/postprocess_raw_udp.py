from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from vrchat_net_capture.capture_errors import configure_errors
from vrchat_net_capture.capture_osc import OscPacket, OscParseError, build_osc_summary, decode_osc_packet
from vrchat_net_capture.capture_photon import build_photon_summary, classify_photon_packet

if TYPE_CHECKING:
    from vrchat_net_capture.capture_schema import AnalysisRecord, OscFailure, RawDatagram
from vrchat_net_capture.capture_utils import append_jsonl


@dataclass
class PostprocessOptions:
    capture_dir: str = ""
    decode_osc: bool = False
    store_osc_values: bool = False
    photon_metadata: bool = False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-dir", required=True)
    parser.add_argument("--decode-osc", action="store_true")
    parser.add_argument("--store-osc-values", action="store_true")
    parser.add_argument("--photon-metadata", action="store_true")
    args = parser.parse_args(namespace=PostprocessOptions())
    configure_errors(Path(args.capture_dir))
    return process_capture(args)


def process_capture(args: PostprocessOptions) -> int:

    capture_dir = Path(args.capture_dir)
    datagrams_path = capture_dir / "network" / "udp-datagrams.jsonl"
    if not datagrams_path.exists():
        return 0

    osc_dir = capture_dir / "osc"
    photon_dir = capture_dir / "photon"
    osc_records: list[AnalysisRecord] = []
    photon_records: list[AnalysisRecord] = []

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
            record = osc_record(datagram, payload, store_values=args.store_osc_values)
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

    write_summaries(args, osc_dir, photon_dir, osc_records, photon_records)
    return 0


def write_summaries(
    args: PostprocessOptions,
    osc_dir: Path,
    photon_dir: Path,
    osc_records: list[AnalysisRecord],
    photon_records: list[AnalysisRecord],
) -> None:
    if args.decode_osc:
        (osc_dir / "osc-summary.json").write_text(
            json.dumps(build_osc_summary(osc_records), indent=2), encoding="utf-8"
        )
    if args.photon_metadata:
        (photon_dir / "photon-summary.json").write_text(
            json.dumps(build_photon_summary(photon_records), indent=2),
            encoding="utf-8",
        )


def osc_record(datagram: RawDatagram, payload: bytes, *, store_values: bool) -> AnalysisRecord | None:
    osc: OscPacket | OscFailure | None
    try:
        osc = decode_osc_packet(payload, include_values=store_values)
        if osc is None:
            return None
    except OscParseError as exc:
        osc = {"status": "error", "error": str(exc)}
    record = base_record("osc_packet", datagram)
    record["osc"] = osc
    return record


def base_record(kind: str, datagram: RawDatagram) -> AnalysisRecord:
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


def read_jsonl(path: Path) -> list[RawDatagram]:
    records: list[RawDatagram] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                records.append(cast("RawDatagram", json.loads(line)))
            except json.JSONDecodeError:
                return read_json_stream(path)
    return records


def read_json_stream(path: Path) -> list[RawDatagram]:
    text = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    records: list[RawDatagram] = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        record, index = decoder.raw_decode(text, index)
        if isinstance(record, dict):
            records.append(cast("RawDatagram", record))
    return records


if __name__ == "__main__":
    raise SystemExit(main())
