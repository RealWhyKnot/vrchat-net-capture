from __future__ import annotations

import struct
from collections import Counter
from typing import Any

PHOTON_PORTS = {5055, 5056, 5058}


def classify_photon_packet(event: dict[str, Any], payload: bytes) -> dict[str, Any] | None:
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
        "header_guess": header,
        "payload_semantics": "not decoded",
        "note": "metadata only; payload semantics are not decoded",
    }


def build_photon_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [r for r in records if isinstance(r.get("photon"), dict)]
    ports: Counter[str] = Counter()
    confidences: Counter[str] = Counter()
    directions: Counter[str] = Counter()

    for record in candidates:
        directions[str(record.get("direction") or "_unknown")] += 1
        photon = record["photon"]
        confidences[str(photon.get("confidence") or "_unknown")] += 1
        for port in photon.get("ports") or []:
            ports[str(port)] += 1

    return {
        "candidate_packet_count": len(candidates),
        "directions": dict(sorted(directions.items())),
        "ports": dict(sorted(ports.items())),
        "confidences": dict(sorted(confidences.items())),
        "decoder": "metadata-only",
        "payload_semantics": "not decoded",
    }


def _photon_enet_header_guess(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 12:
        return None
    peer_id, flags, command_count, timestamp, challenge = struct.unpack(">HBBII", payload[:12])
    if command_count < 1 or command_count > 32:
        return None
    if len(payload) < 12 + command_count * 12:
        return None
    return {
        "peer_id": peer_id,
        "flags": flags,
        "command_count": command_count,
        "timestamp": timestamp,
        "challenge": challenge,
    }


def _event_ports(event: dict[str, Any]) -> set[int]:
    ports: set[int] = set()
    for key in ("client", "server"):
        value = event.get(key)
        if isinstance(value, dict):
            for address_key in ("address", "peername", "sockname"):
                port = _parse_port(value.get(address_key))
                if port is not None:
                    ports.add(port)
    return ports


def _parse_port(value: Any) -> int | None:
    if not value:
        return None
    text = str(value)
    try:
        return int(text.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None
