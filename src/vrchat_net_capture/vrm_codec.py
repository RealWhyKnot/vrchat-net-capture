"""Decoder for vr-m.net packed response bodies.

vr-m.net serves its catalog/session JSON under a custom transport codec: the payload is
LZW-compressed, and that binary stream is re-encoded UTF-8-from-Latin-1 so it survives a
"text" channel (a byte 0x00-0xFF becomes its Latin-1 code point, stored as UTF-8). This
module reverses that so a captured body can be read as plain JSON.

`try_decode` is a view-only helper over a body the capture already received; it never raises
into the pipeline and returns None for anything that is not a packed body.
"""

from __future__ import annotations

import json

_LZW_BITS = 14
_LZW_MAX = 1 << _LZW_BITS


def _lzw_decompress(data: bytes) -> bytes:
    """MSB-first, fixed 14-bit LZW: dict preloaded 0..255, no clear/stop codes, frozen at 2**14."""
    codes: list[int] = []
    buf = 0
    count = 0
    for byte in data:
        buf = (buf << 8) | byte
        count += 8
        while count >= _LZW_BITS:
            count -= _LZW_BITS
            codes.append((buf >> count) & (_LZW_MAX - 1))

    table: dict[int, bytes] = {i: bytes((i,)) for i in range(256)}
    nxt = 256
    out = bytearray()
    prev: bytes | None = None
    for code in codes:
        if code in table:
            entry = table[code]
        elif prev is not None and code == nxt:  # KwKwK: code not yet in the table
            entry = prev + prev[:1]
        else:
            break
        out += entry
        if prev is not None and nxt < _LZW_MAX:
            table[nxt] = prev + entry[:1]
            nxt += 1
        prev = entry
    return bytes(out)


def _looks_like_json(raw: bytes) -> bool:
    stripped = raw.lstrip()
    return bool(stripped) and stripped[:1] in (b"{", b"[")


def try_decode(raw_bytes: bytes) -> str | None:
    """Return the decoded UTF-8 JSON text of a packed vr-m.net body, or None if it is not one.

    `raw_bytes` is the ungzipped response body (the capture strips transport gzip already).
    Bodies that are empty or already plain JSON return None so the caller keeps its normal
    handling; any decode failure also returns None so non-packed bodies never break capture.
    """
    if not raw_bytes or _looks_like_json(raw_bytes):
        return None
    try:
        packed = raw_bytes.decode("utf-8").encode("latin-1")
        text = _lzw_decompress(packed).decode("utf-8")
        value, _ = json.JSONDecoder().raw_decode(text)  # ignore trailing bit-padding after the value
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return None
