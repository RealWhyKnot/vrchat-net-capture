from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Callable

UNITY_MAGICS = (b"UnityFS", b"UnityRaw", b"UnityWeb")
HEX_PREVIEW_BYTES = 256
SAFE_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def decode_response(
    capture_dir: Path,
    decoded_dir: Path,
    h: str,
    body: bytes,
    content_type: str,
) -> tuple[str | None, str | None, bool]:
    ctype = (content_type or "").lower()
    magic = body[:8]

    for m in UNITY_MAGICS:
        if body.startswith(m):
            hexpath = decoded_dir / f"{h}.hex"
            hexpath.write_text(hex_preview(body), encoding="utf-8")
            return (relative_artifact_path(capture_dir, hexpath), m.decode("ascii"), True)

    if body.startswith(b"#EXTM3U") or "mpegurl" in ctype:
        p = decoded_dir / f"{h}.m3u8"
        p.write_bytes(body)
        return (relative_artifact_path(capture_dir, p), "EXTM3U", False)

    text = None
    if "json" in ctype or looks_like_json(body):
        try:
            text = body.decode("utf-8")
            obj = json.loads(text)
            p = decoded_dir / f"{h}.json"
            p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
            return (relative_artifact_path(capture_dir, p), "json", False)
        except Exception:
            pass

    if is_text_content_type(ctype) or looks_like_text(body):
        try:
            if text is None:
                text = body.decode("utf-8", errors="replace")
            p = decoded_dir / f"{h}.txt"
            p.write_text(text, encoding="utf-8")
            return (relative_artifact_path(capture_dir, p), "text", False)
        except Exception:
            pass

    hexpath = decoded_dir / f"{h}.hex"
    hexpath.write_text(hex_preview(body), encoding="utf-8")
    return (relative_artifact_path(capture_dir, hexpath), f"bin:{magic.hex()}", False)


def unitypy_peek(
    capture_dir: Path,
    decoded_dir: Path,
    h: str,
    body: bytes,
    loader: Callable[[bytes], Any],
    warn: Callable[[str], None],
) -> str | None:
    try:
        env = loader(body)
        lines = [f"# UnityPy peek for body hash {h}\n", f"# total objects: {len(env.objects)}\n"]
        for obj in env.objects[:200]:
            try:
                lines.append(f"  {obj.type.name}\tpath_id={obj.path_id}\n")
            except Exception:
                lines.append("  <object failed to introspect>\n")
        p = decoded_dir / f"{h}.unitypy.txt"
        p.write_text("".join(lines), encoding="utf-8")
        return relative_artifact_path(capture_dir, p)
    except Exception as e:
        warn(f"capture_addon: UnityPy peek failed for {h}: {e}")
        return None


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_per_host(by_host_dir: Path, record: dict[str, Any]) -> None:
    host = record["host"] or "_other"
    host_dir = by_host_dir / safe_slug(host)
    host_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%H%M%S", time.localtime(record["ts_start"]))
    ms = int((record["ts_start"] % 1) * 1000)
    slug = safe_slug((record["path"] or "/")[:60]) or "root"
    fid = (record["flow_id"] or "")[:8]
    fname = f"{ts}_{ms:03d}__{record['method']}__{record['status'] or 'ERR'}__{slug}__{fid}.json"
    try:
        (host_dir / fname).write_text(
            json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except OSError:
        (host_dir / f"{record['flow_id']}.json").write_text(
            json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def hex_preview(body: bytes) -> str:
    head = body[:HEX_PREVIEW_BYTES]
    hex_lines = []
    for i in range(0, len(head), 16):
        chunk = head[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_lines.append(f"{i:08x}  {hex_part:<47}  {ascii_part}")
    suffix = "" if len(body) <= HEX_PREVIEW_BYTES else f"\n... ({len(body)} bytes total)"
    return "\n".join(hex_lines) + suffix + "\n"


def looks_like_json(body: bytes) -> bool:
    if not body:
        return False
    s = body.lstrip()[:1]
    return s in (b"{", b"[")


def looks_like_text(body: bytes) -> bool:
    if not body:
        return False
    sample = body[:1024]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


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
