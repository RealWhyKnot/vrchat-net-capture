"""mitmproxy addon — capture VRChat HTTP(S) traffic and decode for analysis.

Loaded via:  mitmdump -s capture_addon.py --set capture_dir=<path>

Per flow we write:
  bodies/<sha256>.bin                raw decompressed response body
  bodies/<sha256>.req.bin            raw request body (only if non-empty)
  decoded/<sha256>.{json,txt,m3u8,hex}   best-effort human-readable form
  by-host/<host>/<ts>__<method>__<slug>.json    per-flow record, browseable
  flows.jsonl                        append-only index (one JSON object per line)

flows.json (the array form) is written at shutdown.

The addon is intentionally defensive: a single malformed flow must not
break the rest of the capture. Every per-flow handler is wrapped in a
broad try/except that logs and moves on.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

from mitmproxy import ctx, http

# Optional UnityPy peek — best-effort, never fatal.
try:
    import UnityPy  # type: ignore
    _HAVE_UNITYPY = True
except Exception:
    _HAVE_UNITYPY = False


_UNITY_MAGICS = (b"UnityFS", b"UnityRaw", b"UnityWeb")
_HEX_PREVIEW_BYTES = 256
_SAFE_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


class CaptureAddon:
    def __init__(self) -> None:
        self.capture_dir: Path | None = None
        self.bodies_dir: Path | None = None
        self.decoded_dir: Path | None = None
        self.by_host_dir: Path | None = None
        self.flows_jsonl: Path | None = None
        self.ignore_hosts: set[str] = set()
        self._records: list[dict[str, Any]] = []
        self._started = False

    # ---- mitmproxy lifecycle ----------------------------------------------

    def load(self, loader) -> None:
        loader.add_option(
            name="capture_dir",
            typespec=str,
            default="",
            help="Directory to write capture artefacts into.",
        )
        loader.add_option(
            name="ignore_hosts_list",
            typespec=str,
            default="",
            help="Comma-separated list of hosts to skip recording.",
        )

    def running(self) -> None:
        if self._started:
            return
        cap = ctx.options.capture_dir
        if not cap:
            ctx.log.error("capture_addon: --set capture_dir=<path> is required")
            sys.exit(2)
        self.capture_dir = Path(cap).resolve()
        self.bodies_dir = self.capture_dir / "bodies"
        self.decoded_dir = self.capture_dir / "decoded"
        self.by_host_dir = self.capture_dir / "by-host"
        self.flows_jsonl = self.capture_dir / "flows.jsonl"
        for d in (self.bodies_dir, self.decoded_dir, self.by_host_dir):
            d.mkdir(parents=True, exist_ok=True)

        ignore = (ctx.options.ignore_hosts_list or "").strip()
        if ignore:
            self.ignore_hosts = {h.strip().lower() for h in ignore.split(",") if h.strip()}

        ctx.log.info(f"capture_addon ready — writing to {self.capture_dir}")
        if self.ignore_hosts:
            ctx.log.info(f"  ignoring hosts: {sorted(self.ignore_hosts)}")
        if _HAVE_UNITYPY:
            ctx.log.info("  UnityPy available — will peek at asset bundles")
        else:
            ctx.log.info("  UnityPy not installed — bundles will be archived raw only")
        self._started = True

    def done(self) -> None:
        if not self.capture_dir:
            return
        try:
            (self.capture_dir / "flows.json").write_text(
                json.dumps(self._records, indent=2), encoding="utf-8"
            )
            ctx.log.info(f"capture_addon: wrote {len(self._records)} flows to flows.json")
        except Exception as e:
            ctx.log.error(f"capture_addon: failed to write flows.json: {e}")

    # ---- per-flow ---------------------------------------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            self._record_flow(flow)
        except Exception:
            ctx.log.error(
                "capture_addon: error while recording flow:\n" + traceback.format_exc()
            )

    def error(self, flow: http.HTTPFlow) -> None:
        # Connection-level errors — log them too, with whatever request/response we have.
        try:
            self._record_flow(flow, errored=True)
        except Exception:
            ctx.log.error(
                "capture_addon: error while recording errored flow:\n" + traceback.format_exc()
            )

    # -----------------------------------------------------------------------

    def _record_flow(self, flow: http.HTTPFlow, errored: bool = False) -> None:
        assert self.bodies_dir and self.decoded_dir and self.by_host_dir and self.flows_jsonl

        req = flow.request
        resp = flow.response

        host = (req.pretty_host or "").lower()
        if host in self.ignore_hosts:
            return

        ts_start = float(getattr(req, "timestamp_start", time.time()) or time.time())
        ts_end = float(
            (getattr(resp, "timestamp_end", None) if resp else None)
            or getattr(req, "timestamp_end", None)
            or ts_start
        )

        # Bodies: mitmproxy auto-decompresses for us when we touch .content.
        req_body = req.raw_content or b""
        try:
            req_decoded = req.content if req_body else b""
        except Exception:
            req_decoded = req_body
        resp_body = b""
        resp_decoded = b""
        if resp is not None:
            try:
                resp_body = resp.raw_content or b""
            except Exception:
                resp_body = b""
            try:
                resp_decoded = resp.content if resp_body else b""
            except Exception:
                resp_decoded = resp_body

        req_hash = self._save_body(req_decoded, suffix=".req.bin") if req_decoded else None
        resp_hash = self._save_body(resp_decoded, suffix=".bin") if resp_decoded else None

        decoded_path: str | None = None
        magic_hint: str | None = None
        is_unity_bundle = False
        unitypy_summary_path: str | None = None
        if resp_hash and resp_decoded:
            decoded_path, magic_hint, is_unity_bundle = self._decode_response(
                resp_hash, resp_decoded, resp
            )
            if is_unity_bundle and _HAVE_UNITYPY:
                unitypy_summary_path = self._unitypy_peek(resp_hash, resp_decoded)

        record: dict[str, Any] = {
            "flow_id": flow.id or str(uuid.uuid4()),
            "errored": errored or (resp is None),
            "ts_start": ts_start,
            "ts_end": ts_end,
            "duration_ms": int((ts_end - ts_start) * 1000),
            "method": req.method,
            "url": req.pretty_url,
            "scheme": req.scheme,
            "host": host,
            "path": req.path,
            "status": resp.status_code if resp else None,
            "request_headers": dict(req.headers.items()),
            "response_headers": dict(resp.headers.items()) if resp else None,
            "request_body_hash": req_hash,
            "request_body_size": len(req_decoded) if req_decoded else 0,
            "response_body_hash": resp_hash,
            "response_body_path": f"bodies/{resp_hash}.bin" if resp_hash else None,
            "response_decoded_path": decoded_path,
            "response_size": len(resp_decoded) if resp_decoded else 0,
            "response_size_on_wire": len(resp_body) if resp_body else 0,
            "response_content_type": resp.headers.get("content-type") if resp else None,
            "response_compression": resp.headers.get("content-encoding") if resp else None,
            "magic_bytes_hint": magic_hint,
            "is_unity_assetbundle": is_unity_bundle,
            "unitypy_summary_path": unitypy_summary_path,
            "client_ip": flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else None,
            "server_ip": flow.server_conn.peername[0] if flow.server_conn and flow.server_conn.peername else None,
        }

        self._records.append(record)
        self._append_jsonl(record)
        self._write_per_host(record)

    # ---- helpers ----------------------------------------------------------

    def _save_body(self, data: bytes, suffix: str = ".bin") -> str:
        assert self.bodies_dir
        h = hashlib.sha256(data).hexdigest()
        path = self.bodies_dir / f"{h}{suffix}"
        if not path.exists():
            path.write_bytes(data)
        return h

    def _decode_response(
        self, h: str, body: bytes, resp: http.Response
    ) -> tuple[str | None, str | None, bool]:
        assert self.decoded_dir
        ctype = (resp.headers.get("content-type") or "").lower() if resp else ""
        magic = body[:8]

        # Unity asset bundle?
        for m in _UNITY_MAGICS:
            if body.startswith(m):
                hexpath = self.decoded_dir / f"{h}.hex"
                hexpath.write_text(_hex_preview(body), encoding="utf-8")
                return (str(hexpath.relative_to(self.capture_dir)).replace("\\", "/"),
                        m.decode("ascii"), True)

        # HLS playlist?
        if body.startswith(b"#EXTM3U") or "mpegurl" in ctype:
            p = self.decoded_dir / f"{h}.m3u8"
            p.write_bytes(body)
            return (str(p.relative_to(self.capture_dir)).replace("\\", "/"),
                    "EXTM3U", False)

        # JSON?
        text = None
        if "json" in ctype or _looks_like_json(body):
            try:
                text = body.decode("utf-8")
                obj = json.loads(text)
                p = self.decoded_dir / f"{h}.json"
                p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
                return (str(p.relative_to(self.capture_dir)).replace("\\", "/"),
                        "json", False)
            except Exception:
                pass

        # Generic text?
        if _is_text_content_type(ctype) or _looks_like_text(body):
            try:
                if text is None:
                    text = body.decode("utf-8", errors="replace")
                p = self.decoded_dir / f"{h}.txt"
                p.write_text(text, encoding="utf-8")
                return (str(p.relative_to(self.capture_dir)).replace("\\", "/"),
                        "text", False)
            except Exception:
                pass

        # Binary fallback: hex preview only.
        hexpath = self.decoded_dir / f"{h}.hex"
        hexpath.write_text(_hex_preview(body), encoding="utf-8")
        return (str(hexpath.relative_to(self.capture_dir)).replace("\\", "/"),
                f"bin:{magic.hex()}", False)

    def _unitypy_peek(self, h: str, body: bytes) -> str | None:
        assert self.decoded_dir
        try:
            env = UnityPy.load(body)  # type: ignore
            lines = []
            lines.append(f"# UnityPy peek for body hash {h}\n")
            lines.append(f"# total objects: {len(env.objects)}\n")
            for obj in env.objects[:200]:
                try:
                    lines.append(f"  {obj.type.name}\tpath_id={obj.path_id}\n")
                except Exception:
                    lines.append("  <object failed to introspect>\n")
            p = self.decoded_dir / f"{h}.unitypy.txt"
            p.write_text("".join(lines), encoding="utf-8")
            return str(p.relative_to(self.capture_dir)).replace("\\", "/")
        except Exception as e:
            ctx.log.warn(f"capture_addon: UnityPy peek failed for {h}: {e}")
            return None

    def _append_jsonl(self, record: dict[str, Any]) -> None:
        assert self.flows_jsonl
        with self.flows_jsonl.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _write_per_host(self, record: dict[str, Any]) -> None:
        assert self.by_host_dir
        host = record["host"] or "_other"
        host_dir = self.by_host_dir / _safe_slug(host)
        host_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%H%M%S", time.localtime(record["ts_start"]))
        ms = int((record["ts_start"] % 1) * 1000)
        slug = _safe_slug((record["path"] or "/")[:60]) or "root"
        # short, informative filename — flow-id suffix prevents collisions
        fid = (record["flow_id"] or "")[:8]
        fname = f"{ts}_{ms:03d}__{record['method']}__{record['status'] or 'ERR'}__{slug}__{fid}.json"
        try:
            (host_dir / fname).write_text(
                json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except OSError:
            # path too long etc. — fall back to a plain hash name.
            (host_dir / f"{record['flow_id']}.json").write_text(
                json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
            )


# ---- module-level helpers ---------------------------------------------------


def _hex_preview(body: bytes) -> str:
    head = body[:_HEX_PREVIEW_BYTES]
    hex_lines = []
    for i in range(0, len(head), 16):
        chunk = head[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_lines.append(f"{i:08x}  {hex_part:<47}  {ascii_part}")
    suffix = "" if len(body) <= _HEX_PREVIEW_BYTES else f"\n... ({len(body)} bytes total)"
    return "\n".join(hex_lines) + suffix + "\n"


def _looks_like_json(body: bytes) -> bool:
    if not body:
        return False
    s = body.lstrip()[:1]
    return s in (b"{", b"[")


def _looks_like_text(body: bytes) -> bool:
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


def _is_text_content_type(ctype: str) -> bool:
    if not ctype:
        return False
    return (
        ctype.startswith("text/")
        or "javascript" in ctype
        or "xml" in ctype
        or "html" in ctype
        or "x-www-form-urlencoded" in ctype
    )


def _safe_slug(s: str) -> str:
    s = s.lstrip("/").rstrip("/").replace("/", "_")
    s = _SAFE_SLUG_RE.sub("_", s)
    return s[:80] or "_"


# mitmproxy plugin contract
addons = [CaptureAddon()]
