from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

from vrchat_net_capture.vrm_codec import try_decode as vrm_try_decode

UNITY_MAGICS = (b"UnityFS", b"UnityRaw", b"UnityWeb")
VRM_HOSTS = {"vr-m.net", "data.vr-m.net"}
HEX_PREVIEW_BYTES = 256
ASCII_PRINTABLE_START = 32
ASCII_PRINTABLE_END = 127
SAFE_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class ResponseBody:
    digest: str
    content: bytes
    content_type: str | None
    host: str = ""


@dataclass(frozen=True)
class DecodedBody:
    path: str
    hint: str
    is_unity_bundle: bool = False


class HostRecord(TypedDict):
    host: str
    ts_start: float
    path: str | None
    flow_id: str
    method: str
    status: int | None


class UnityType(Protocol):
    @property
    def name(self) -> str: ...


class UnityObject(Protocol):
    @property
    def type(self) -> UnityType: ...

    @property
    def path_id(self) -> int: ...


class UnityEnvironment(Protocol):
    @property
    def objects(self) -> Sequence[UnityObject]: ...


def decode_response(capture_dir: Path, decoded_dir: Path, response: ResponseBody) -> DecodedBody:
    h, body, content_type, host = response.digest, response.content, response.content_type, response.host
    ctype = (content_type or "").lower()
    magic = body[:8]

    for m in UNITY_MAGICS:
        if body.startswith(m):
            hexpath = decoded_dir / f"{h}.hex"
            hexpath.write_text(hex_preview(body), encoding="utf-8")
            return DecodedBody(relative_artifact_path(capture_dir, hexpath), m.decode("ascii"), is_unity_bundle=True)

    if host in VRM_HOSTS:
        decoded = vrm_try_decode(body)
        if decoded is not None:
            p = decoded_dir / f"{h}.json"
            p.write_text(json.dumps(json.loads(decoded), indent=2, ensure_ascii=False), encoding="utf-8")
            return DecodedBody(relative_artifact_path(capture_dir, p), "vrm")

    if body.startswith(b"#EXTM3U") or "mpegurl" in ctype:
        p = decoded_dir / f"{h}.m3u8"
        p.write_bytes(body)
        return DecodedBody(relative_artifact_path(capture_dir, p), "EXTM3U")

    decoded = decode_text_response(capture_dir, decoded_dir, response)
    if decoded is not None:
        return decoded

    hexpath = decoded_dir / f"{h}.hex"
    hexpath.write_text(hex_preview(body), encoding="utf-8")
    return DecodedBody(relative_artifact_path(capture_dir, hexpath), f"bin:{magic.hex()}")


def decode_text_response(capture_dir: Path, decoded_dir: Path, response: ResponseBody) -> DecodedBody | None:
    text = None
    body = response.content
    content_type = (response.content_type or "").lower()
    if "json" in content_type or looks_like_json(body):
        try:
            text = body.decode("utf-8")
            value = json.loads(text)
            path = decoded_dir / f"{response.digest}.json"
            path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
        except (OSError, UnicodeError, json.JSONDecodeError):
            logging.getLogger(__name__).debug("Response decoding failed", exc_info=True)
        else:
            return DecodedBody(relative_artifact_path(capture_dir, path), "json")
    if is_text_content_type(content_type) or looks_like_text(body):
        try:
            text = text if text is not None else body.decode("utf-8", errors="replace")
            path = decoded_dir / f"{response.digest}.txt"
            path.write_text(text, encoding="utf-8")
        except (OSError, UnicodeError):
            logging.getLogger(__name__).debug("Response decoding failed", exc_info=True)
        else:
            return DecodedBody(relative_artifact_path(capture_dir, path), "text")
    return None


def unity_object_lines(environment: UnityEnvironment, digest: str) -> list[str]:
    lines = [f"# UnityPy peek for body hash {digest}\n", f"# total objects: {len(environment.objects)}\n"]
    for item in environment.objects[:200]:
        try:
            lines.append(f"  {item.type.name}\tpath_id={item.path_id}\n")
        except (AttributeError, TypeError, ValueError):
            lines.append("  <object failed to introspect>\n")
    return lines


def unitypy_peek(
    capture_dir: Path,
    decoded_dir: Path,
    response: ResponseBody,
    loader: Callable[[bytes], UnityEnvironment],
    warn: Callable[[str], None],
) -> str | None:
    h = response.digest
    try:
        env = loader(response.content)
        lines = unity_object_lines(env, h)
        p = decoded_dir / f"{h}.unitypy.txt"
        p.write_text("".join(lines), encoding="utf-8")
        return relative_artifact_path(capture_dir, p)
    except (OSError, ValueError, TypeError, AttributeError, EOFError) as e:
        warn(f"capture_addon: UnityPy peek failed for {h}: {e}")
        return None


def append_jsonl(path: Path, record: object) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_per_host(by_host_dir: Path, record: HostRecord) -> None:
    host = record["host"] or "_other"
    host_dir = by_host_dir / safe_slug(host)
    host_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%H%M%S", time.localtime(record["ts_start"]))
    ms = int((record["ts_start"] % 1) * 1000)
    slug = safe_slug((record["path"] or "/")[:60]) or "root"
    fid = (record["flow_id"] or "")[:8]
    fname = f"{ts}_{ms:03d}__{record['method']}__{record['status'] or 'ERR'}__{slug}__{fid}.json"
    try:
        (host_dir / fname).write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError:
        (host_dir / f"{record['flow_id']}.json").write_text(
            json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def hex_preview(body: bytes) -> str:
    head = body[:HEX_PREVIEW_BYTES]
    hex_lines: list[str] = []
    for i in range(0, len(head), 16):
        chunk = head[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if ASCII_PRINTABLE_START <= b < ASCII_PRINTABLE_END else "." for b in chunk)
        hex_lines.append(f"{i:08x}  {hex_part:<47}  {ascii_part}")
    suffix = "" if len(body) <= HEX_PREVIEW_BYTES else f"\n... ({len(body)} bytes total)"
    return "\n".join(hex_lines) + suffix + "\n"


def looks_like_json(body: bytes) -> bool:
    if not body:
        return False
    s = body.lstrip()[:1]
    return s in {b"{", b"["}


def looks_like_text(body: bytes) -> bool:
    if not body:
        return False
    sample = body[:1024]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def is_text_content_type(ctype: str) -> bool:
    if not ctype:
        return False
    return (
        ctype.startswith("text/")
        or "javascript" in ctype
        or "xml" in ctype
        or "html" in ctype
        or "x-www-form-urlencoded" in ctype
    )


def safe_slug(s: str) -> str:
    s = s.lstrip("/").rstrip("/").replace("/", "_")
    s = SAFE_SLUG_RE.sub("_", s)
    return s[:80] or "_"


def relative_artifact_path(capture_dir: Path, path: Path) -> str:
    return str(path.relative_to(capture_dir)).replace("\\", "/")
