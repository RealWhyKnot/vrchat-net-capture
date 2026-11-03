from __future__ import annotations

import base64
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, TypedDict, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

MAX_BUNDLE_DEPTH = 16
BUNDLE_HEADER_BYTES = 16
OscValue = str | int | float | bool | None


class OscParseError(ValueError):
    pass


class OscArgument(TypedDict, total=False):
    tag: str
    type: str
    size: int
    value: OscValue
    redacted: bool


class OscMessage(TypedDict):
    address: str
    type_tags: str
    argument_count: int
    arguments: list[OscArgument]


class OscPacket(TypedDict):
    status: Literal["ok"]
    size: int
    message_count: int
    bundle_count: int
    messages: list[OscMessage]


class OscSummary(TypedDict):
    packet_count: int
    directions: dict[str, int]
    addresses: dict[str, int]
    type_tags: dict[str, int]
    errors: dict[str, int]


@dataclass
class _ParseState:
    include_values: bool
    messages: list[OscMessage] = field(default_factory=list[OscMessage])
    bundle_count: int = 0


@dataclass
class _PacketReader:
    data: bytes
    offset: int
    limit: int

    def read_number(self, format_code: str, name: str) -> int | float:
        size = struct.calcsize(format_code)
        if self.offset + size > self.limit:
            message = f"truncated {name}"
            raise OscParseError(message)
        value = cast("int | float", struct.unpack_from(format_code, self.data, self.offset)[0])
        self.offset += size
        return value

    def read_int32(self) -> int:
        return int(self.read_number(">i", "int32"))

    def read_string(self) -> str:
        end = self.data.find(b"\x00", self.offset, self.limit)
        if end < 0:
            message = "unterminated OSC string"
            raise OscParseError(message)
        raw = self.data[self.offset : end]
        next_offset = _align4(end + 1)
        if next_offset > self.limit:
            message = "truncated OSC string padding"
            raise OscParseError(message)
        self.offset = next_offset
        return raw.decode("utf-8", errors="replace")

    def read_blob(self) -> bytes:
        size = self.read_int32()
        if size < 0:
            message = "negative OSC blob size"
            raise OscParseError(message)
        end = self.offset + size
        if end > self.limit:
            message = "truncated OSC blob"
            raise OscParseError(message)
        next_offset = _align4(end)
        if next_offset > self.limit:
            message = "truncated OSC blob padding"
            raise OscParseError(message)
        value = self.data[self.offset : end]
        self.offset = next_offset
        return value

    def read_argument(self, tag: str, *, include_values: bool) -> OscArgument:
        formats = {"i": ">i", "h": ">q", "f": ">f", "d": ">d", "t": ">Q"}
        names = {"i": "int32", "h": "int64", "f": "float32", "d": "float64", "t": "timetag"}
        if tag in formats:
            value = self.read_number(formats[tag], "uint64" if tag == "t" else names[tag])
            return _argument(tag, names[tag], value, include_values=include_values)
        if tag == "s":
            return _argument(tag, "string", self.read_string(), include_values=include_values)
        if tag == "b":
            blob = self.read_blob()
            stored = base64.b64encode(blob).decode("ascii")
            return _argument(tag, "blob", stored, include_values=include_values, size=len(blob))
        constants: dict[str, OscValue] = {"T": True, "F": False, "N": None, "I": "impulse"}
        constant_names = {"T": "true", "F": "false", "N": "nil", "I": "impulse"}
        if tag in constants:
            return _argument(tag, constant_names[tag], constants[tag], include_values=include_values)
        message = f"unsupported OSC type tag {tag!r}"
        raise OscParseError(message)


def looks_like_osc_packet(data: bytes) -> bool:
    return data.startswith((b"/", b"#bundle\x00"))


def decode_osc_packet(data: bytes, *, include_values: bool = False) -> OscPacket | None:
    if not looks_like_osc_packet(data):
        return None
    state = _ParseState(include_values=include_values)
    _parse_packet(_PacketReader(data, 0, len(data)), state, depth=0)
    return {
        "status": "ok",
        "size": len(data),
        "message_count": len(state.messages),
        "bundle_count": state.bundle_count,
        "messages": state.messages,
    }


def build_osc_summary(records: Sequence[Mapping[str, object]]) -> OscSummary:
    addresses: Counter[str] = Counter()
    tags: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    directions: Counter[str] = Counter()
    for record in records:
        directions[str(record.get("direction") or "_unknown")] += 1
        raw_osc = record.get("osc")
        if not isinstance(raw_osc, dict):
            continue
        osc = cast("Mapping[str, object]", raw_osc)
        if osc.get("status") != "ok":
            errors[str(osc.get("error") or "decode_error")] += 1
            continue
        for raw_message in cast("Sequence[object]", osc.get("messages") or []):
            if not isinstance(raw_message, dict):
                continue
            message = cast("Mapping[str, object]", raw_message)
            addresses[str(message.get("address") or "_unknown")] += 1
            tags[str(message.get("type_tags") or ",")] += 1
    return {
        "packet_count": len(records),
        "directions": dict(sorted(directions.items())),
        "addresses": dict(sorted(addresses.items())),
        "type_tags": dict(sorted(tags.items())),
        "errors": dict(sorted(errors.items())),
    }


def _parse_packet(reader: _PacketReader, state: _ParseState, depth: int) -> None:
    if depth > MAX_BUNDLE_DEPTH:
        message = "OSC bundle nesting too deep"
        raise OscParseError(message)
    if reader.data[reader.offset : reader.limit].startswith(b"#bundle\x00"):
        _parse_bundle(reader, state, depth)
    else:
        _parse_message(reader, state)


def _parse_bundle(reader: _PacketReader, state: _ParseState, depth: int) -> None:
    state.bundle_count += 1
    if reader.offset + BUNDLE_HEADER_BYTES > reader.limit:
        message = "truncated OSC bundle"
        raise OscParseError(message)
    if reader.data[reader.offset : reader.offset + 8] != b"#bundle\x00":
        message = "invalid OSC bundle header"
        raise OscParseError(message)
    reader.offset += BUNDLE_HEADER_BYTES
    while reader.offset < reader.limit:
        size = reader.read_int32()
        if size < 0:
            message = "negative OSC bundle element size"
            raise OscParseError(message)
        end = reader.offset + size
        if end > reader.limit:
            message = "truncated OSC bundle element"
            raise OscParseError(message)
        _parse_packet(_PacketReader(reader.data, reader.offset, end), state, depth + 1)
        reader.offset = end


def _parse_message(reader: _PacketReader, state: _ParseState) -> None:
    address = reader.read_string()
    if not address.startswith("/"):
        message = "OSC address does not start with /"
        raise OscParseError(message)
    tags = reader.read_string()
    if not tags.startswith(","):
        message = "OSC type tag string does not start with comma"
        raise OscParseError(message)
    arguments = [reader.read_argument(tag, include_values=state.include_values) for tag in tags[1:]]
    if reader.offset != reader.limit:
        message = "OSC message has trailing bytes"
        raise OscParseError(message)
    state.messages.append(
        {
            "address": address,
            "type_tags": tags,
            "argument_count": len(arguments),
            "arguments": arguments,
        }
    )


def _argument(tag: str, name: str, value: OscValue, *, include_values: bool, size: int | None = None) -> OscArgument:
    result: OscArgument = {"tag": tag, "type": name}
    if size is not None:
        result["size"] = size
    if include_values:
        result["value"] = value
    else:
        result["redacted"] = True
    return result


def _align4(value: int) -> int:
    return (value + 3) & ~3
