from __future__ import annotations

import json

_LZW_BITS = 14
_LZW_MAX = 1 << _LZW_BITS


def _lzw_decompress(data: bytes) -> bytes:

    codes: list[int] = []
    bit_buffer = 0
    count = 0
    for byte in data:
        bit_buffer = (bit_buffer << 8) | byte
        count += 8
        while count >= _LZW_BITS:
            count -= _LZW_BITS
            codes.append((bit_buffer >> count) & (_LZW_MAX - 1))

    table: dict[int, bytes] = {i: bytes((i,)) for i in range(256)}
    next_code = 256
    output = bytearray()
    previous: bytes | None = None
    for code in codes:
        if code in table:
            entry = table[code]
        elif previous is not None and code == next_code:
            entry = previous + previous[:1]
        else:
            break
        output += entry
        if previous is not None and next_code < _LZW_MAX:
            table[next_code] = previous + entry[:1]
            next_code += 1
        previous = entry
    return bytes(output)


def _looks_like_json(raw: bytes) -> bool:
    stripped = raw.lstrip()
    return bool(stripped) and stripped[:1] in {b"{", b"["}


def try_decode(raw_bytes: bytes) -> str | None:

    if not raw_bytes or _looks_like_json(raw_bytes):
        return None
    try:
        packed = raw_bytes.decode("utf-8").encode("latin-1")
        text = _lzw_decompress(packed).decode("utf-8")
        value, _ = json.JSONDecoder().raw_decode(text)
        return json.dumps(value, ensure_ascii=False)
    except (UnicodeError, json.JSONDecodeError):
        return None
