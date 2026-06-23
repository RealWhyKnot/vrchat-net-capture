from __future__ import annotations

import base64
import struct
from collections import Counter
from typing import Any


class OscParseError(ValueError):
    pass


def looks_like_osc_packet(data: bytes) -> bool:
    return data.startswith(b"/") or data.startswith(b"#bundle\x00")


def decode_osc_packet(data: bytes, include_values: bool = False) -> dict[str, Any] | None:
    if not looks_like_osc_packet(data):
        return None
    state = _ParseState(include_values=include_values)
    _parse_packet(data, 0, len(data), state, depth=0)
    return {
        "status": "ok",
        "size": len(data),
        "message_count": len(state.messages),
        "bundle_count": state.bundle_count,
        "messages": state.messages,
    }


def build_osc_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    addresses: Counter[str] = Counter()
    tags: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    directions: Counter[str] = Counter()

    for record in records:
        directions[str(record.get("direction") or "_unknown")] += 1
        osc = record.get("osc")
        if not isinstance(osc, dict):
            continue
        if osc.get("status") != "ok":
            errors[str(osc.get("error") or "decode_error")] += 1
            continue
        for message in osc.get("messages") or []:
            if not isinstance(message, dict):
                continue
            addresses[str(message.get("address") or "_unknown")] += 1
            tags[str(message.get("type_tags") or ",")] += 1

    return {
        "packet_count": len(records),
        "directions": dict(sorted(directions.items())),
        "addresses": dict(sorted(addresses.items())),
        "type_tags": dict(sorted(tags.items())),
        "errors": dict(sorted(errors.items())),
    }


class _ParseState:
    def __init__(self, include_values: bool) -> None:
        self.include_values = include_values
        self.messages: list[dict[str, Any]] = []
        self.bundle_count = 0


def _parse_packet(data: bytes, offset: int, limit: int, state: _ParseState, depth: int) -> int:
    if depth > 16:
        raise OscParseError("OSC bundle nesting too deep")
    if data[offset:limit].startswith(b"#bundle\x00"):
        return _parse_bundle(data, offset, limit, state, depth)
    return _parse_message(data, offset, limit, state)


def _parse_bundle(data: bytes, offset: int, limit: int, state: _ParseState, depth: int) -> int:
    state.bundle_count += 1
    if offset + 16 > limit:
        raise OscParseError("truncated OSC bundle")
    if data[offset : offset + 8] != b"#bundle\x00":
        raise OscParseError("invalid OSC bundle header")
    offset += 16
    while offset < limit:
        size, offset = _read_int32(data, offset, limit)
        if size < 0:
            raise OscParseError("negative OSC bundle element size")
        end = offset + size
        if end > limit:
            raise OscParseError("truncated OSC bundle element")
        _parse_packet(data, offset, end, state, depth + 1)
        offset = end
    return offset


def _parse_message(data: bytes, offset: int, limit: int, state: _ParseState) -> int:
    address, offset = _read_string(data, offset, limit)
    if not address.startswith("/"):
        raise OscParseError("OSC address does not start with /")
    tags, offset = _read_string(data, offset, limit)
    if not tags.startswith(","):
        raise OscParseError("OSC type tag string does not start with comma")

    args: list[dict[str, Any]] = []
    for tag in tags[1:]:
        arg, offset = _read_argument(tag, data, offset, limit, state.include_values)
        args.append(arg)

    if offset != limit:
        raise OscParseError("OSC message has trailing bytes")

    state.messages.append(
        {
            "address": address,
            "type_tags": tags,
            "argument_count": len(args),
            "arguments": args,
        }
    )
    return offset


def _read_argument(tag: str, data: bytes, offset: int, limit: int, include_values: bool) -> tuple[dict[str, Any], int]:
    if tag == "i":
        value, offset = _read_int32(data, offset, limit)
        return _arg(tag, "int32", value, include_values), offset
    if tag == "h":
        value, offset = _read_int64(data, offset, limit)
        return _arg(tag, "int64", value, include_values), offset
    if tag == "f":
        value, offset = _read_float32(data, offset, limit)
        return _arg(tag, "float32", value, include_values), offset
    if tag == "d":
        value, offset = _read_float64(data, offset, limit)
        return _arg(tag, "float64", value, include_values), offset
    if tag == "s":
        value, offset = _read_string(data, offset, limit)
        return _arg(tag, "string", value, include_values), offset
    if tag == "b":
        value, offset = _read_blob(data, offset, limit)
        stored = base64.b64encode(value).decode("ascii")
        return _arg(tag, "blob", stored, include_values, size=len(value)), offset
    if tag == "t":
        value, offset = _read_uint64(data, offset, limit)
        return _arg(tag, "timetag", value, include_values), offset
    if tag in ("T", "F", "N", "I"):
        names = {"T": "true", "F": "false", "N": "nil", "I": "impulse"}
        value = {"T": True, "F": False, "N": None, "I": "impulse"}[tag]
        return _arg(tag, names[tag], value, include_values), offset
    raise OscParseError(f"unsupported OSC type tag {tag!r}")


def _arg(tag: str, name: str, value: Any, include_values: bool, size: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"tag": tag, "type": name}
    if size is not None:
        result["size"] = size
    if include_values:
        result["value"] = value
    else:
        result["redacted"] = True
    return result


def _read_string(data: bytes, offset: int, limit: int) -> tuple[str, int]:
    end = data.find(b"\x00", offset, limit)
    if end < 0:
        raise OscParseError("unterminated OSC string")
    raw = data[offset:end]
    next_offset = _align4(end + 1)
    if next_offset > limit:
        raise OscParseError("truncated OSC string padding")
    return raw.decode("utf-8", errors="replace"), next_offset


def _read_blob(data: bytes, offset: int, limit: int) -> tuple[bytes, int]:
    size, offset = _read_int32(data, offset, limit)
    if size < 0:
        raise OscParseError("negative OSC blob size")
    end = offset + size
    if end > limit:
        raise OscParseError("truncated OSC blob")
    next_offset = _align4(end)
    if next_offset > limit:
        raise OscParseError("truncated OSC blob padding")
    return data[offset:end], next_offset


def _read_int32(data: bytes, offset: int, limit: int) -> tuple[int, int]:
    if offset + 4 > limit:
        raise OscParseError("truncated int32")
    return struct.unpack(">i", data[offset : offset + 4])[0], offset + 4


def _read_int64(data: bytes, offset: int, limit: int) -> tuple[int, int]:
    if offset + 8 > limit:
        raise OscParseError("truncated int64")
    return struct.unpack(">q", data[offset : offset + 8])[0], offset + 8


def _read_uint64(data: bytes, offset: int, limit: int) -> tuple[int, int]:
    if offset + 8 > limit:
        raise OscParseError("truncated uint64")
    return struct.unpack(">Q", data[offset : offset + 8])[0], offset + 8


def _read_float32(data: bytes, offset: int, limit: int) -> tuple[float, int]:
    if offset + 4 > limit:
        raise OscParseError("truncated float32")
    return struct.unpack(">f", data[offset : offset + 4])[0], offset + 4


def _read_float64(data: bytes, offset: int, limit: int) -> tuple[float, int]:
    if offset + 8 > limit:
        raise OscParseError("truncated float64")
    return struct.unpack(">d", data[offset : offset + 8])[0], offset + 8


def _align4(value: int) -> int:
    return (value + 3) & ~3
