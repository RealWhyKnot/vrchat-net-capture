from __future__ import annotations

import struct
from collections import Counter
from typing import TYPE_CHECKING, Literal, TypedDict, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

PHOTON_PORTS = {27000, 27001, 27002}
ENET_HEADER_BYTES = 12
ENET_COMMAND_BYTES = 12
MAX_ENET_COMMANDS = 32


class PhotonHeader(TypedDict):
    peer_id: int
    flags: int
    command_count: int
    timestamp: int
    challenge: int


class PhotonPacket(TypedDict):
    candidate: bool
    confidence: Literal["medium", "low"]
    reasons: list[str]
    ports: list[int]
    size: int
    capture_semantics: str
    header_guess: PhotonHeader | None
    payload_semantics: Literal["not decoded"]
    note: str


class PhotonSummary(TypedDict):
    candidate_packet_count: int
    directions: dict[str, int]
    ports: dict[str, int]
    confidences: dict[str, int]
    capture_semantics: str
    capture_semantics_counts: dict[str, int]
    decoder: Literal["metadata-only"]
    payload_semantics: Literal["not decoded"]


def classify_photon_packet(event: Mapping[str, object], payload: bytes) -> PhotonPacket | None:
    ports = sorted(p for p in _event_ports(event) if p in PHOTON_PORTS)
    header = _photon_enet_header_guess(payload)
    if not ports and header is None:
        return None

    reasons: list[str] = []
    if ports:
        reasons.append("known_photon_port")
    if header is not None:
        reasons.append("enet_header_shape")

    confidence = "medium" if ports and header is not None else "low"
    return {
        "candidate": True,
        "confidence": confidence,
        "reasons": reasons,
        "ports": ports,
        "size": len(payload),
        "capture_semantics": _capture_semantics(event),
        "header_guess": header,
        "payload_semantics": "not decoded",
        "note": "metadata only; payload semantics are not decoded",
    }


def build_photon_summary(records: Sequence[Mapping[str, object]]) -> PhotonSummary:
    candidates = [r for r in records if isinstance(r.get("photon"), dict)]
    ports: Counter[str] = Counter()
    confidences: Counter[str] = Counter()
    directions: Counter[str] = Counter()
    semantics: Counter[str] = Counter()

    for record in candidates:
        directions[str(record.get("direction") or "_unknown")] += 1
        photon = cast("Mapping[str, object]", record["photon"])
        confidences[str(photon.get("confidence") or "_unknown")] += 1
        semantics[_capture_semantics(record, photon)] += 1
        for port in cast("Sequence[object]", photon.get("ports") or []):
            ports[str(port)] += 1

    capture_semantics = "proxy_observed"
    if semantics:
        capture_semantics = next(iter(semantics)) if len(semantics) == 1 else "mixed"

    return {
        "candidate_packet_count": len(candidates),
        "directions": dict(sorted(directions.items())),
        "ports": dict(sorted(ports.items())),
        "confidences": dict(sorted(confidences.items())),
        "capture_semantics": capture_semantics,
        "capture_semantics_counts": dict(sorted(semantics.items())),
        "decoder": "metadata-only",
        "payload_semantics": "not decoded",
    }


def _photon_enet_header_guess(payload: bytes) -> PhotonHeader | None:
    if len(payload) < ENET_HEADER_BYTES:
        return None
    peer_id, flags, command_count, timestamp, challenge = struct.unpack(">HBBII", payload[:ENET_HEADER_BYTES])
    if command_count < 1 or command_count > MAX_ENET_COMMANDS:
        return None
    if len(payload) < ENET_HEADER_BYTES + command_count * ENET_COMMAND_BYTES:
        return None
    return {
        "peer_id": peer_id,
        "flags": flags,
        "command_count": command_count,
        "timestamp": timestamp,
        "challenge": challenge,
    }


def _event_ports(event: Mapping[str, object]) -> set[int]:
    ports: set[int] = set()
    for key in ("source_port", "destination_port", "client_port", "server_port"):
        port = _parse_port(event.get(key))
        if port is not None:
            ports.add(port)
    for key in ("client", "server"):
        value = event.get(key)
        if isinstance(value, dict):
            for address_key in ("address", "peername", "sockname"):
                port = _parse_port(cast("Mapping[str, object]", value).get(address_key))
                if port is not None:
                    ports.add(port)
    for key in ("source", "destination"):
        value = event.get(key)
        if isinstance(value, dict):
            port = _parse_port(cast("Mapping[str, object]", value).get("port"))
            if port is not None:
                ports.add(port)
    return ports


def _parse_port(value: object) -> int | None:
    if value is None or (isinstance(value, str) and not value):
        return None
    if isinstance(value, int):
        return value
    text = str(value)
    try:
        port = int(text)
    except ValueError:
        try:
            port = int(text.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            return None
    return port


def _capture_semantics(*records: Mapping[str, object]) -> str:
    for record in records:
        value = record.get("capture_semantics")
        if value:
            return str(value)
    return "proxy_observed"
