from __future__ import annotations

import hashlib
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

from capture_utils import decode_response, relative_artifact_path, unitypy_peek

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-access-token",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-vrc-api-key",
    "x-xsrf-token",
}
SENSITIVE_QUERY_PARAMS = {"apikey", "auth", "password", "passwd", "sessionid"}
SENSITIVE_QUERY_MARKERS = ("token", "secret")
REDACTED = "<redacted>"


def save_body(bodies_dir: Path, data: bytes, suffix: str = ".bin") -> str:
    h = hashlib.sha256(data).hexdigest()
    path = bodies_dir / f"{h}{suffix}"
    if not path.exists():
        path.write_bytes(data)
    return h


def build_http_record(
    flow: Any,
    capture_dir: Path,
    bodies_dir: Path,
    decoded_dir: Path,
    analyze_unity: bool,
    have_unitypy: bool,
    unitypy_loader: Any,
    warn: Any,
    errored: bool = False,
) -> dict[str, Any]:
    req = flow.request
    resp = flow.response

    host = (req.pretty_host or "").lower()
    ts_start = float(getattr(req, "timestamp_start", time.time()) or time.time())
    ts_end = float(
        (getattr(resp, "timestamp_end", None) if resp else None) or getattr(req, "timestamp_end", None) or ts_start
    )

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

    req_hash = save_body(bodies_dir, req_decoded, suffix=".req.bin") if req_decoded else None
    resp_hash = save_body(bodies_dir, resp_decoded, suffix=".bin") if resp_decoded else None

    decoded_path: str | None = None
    magic_hint: str | None = None
    is_unity_bundle = False
    unitypy_summary_path: str | None = None
    if resp_hash and resp_decoded:
        decoded_path, magic_hint, is_unity_bundle = decode_response(
            capture_dir,
            decoded_dir,
            resp_hash,
            resp_decoded,
            resp.headers.get("content-type") if resp else "",
            host,
        )
        if is_unity_bundle and analyze_unity and have_unitypy:
            unitypy_summary_path = unitypy_peek(
                capture_dir,
                decoded_dir,
                resp_hash,
                resp_decoded,
                unitypy_loader,
                warn,
            )

    return {
        "kind": "http_flow",
        "flow_id": flow.id or str(uuid.uuid4()),
        "errored": errored or (resp is None),
        "ts_start": ts_start,
        "ts_end": ts_end,
        "duration_ms": int((ts_end - ts_start) * 1000),
        "method": req.method,
        "url": redact_url(req.pretty_url),
        "scheme": req.scheme,
        "host": host,
        "path": redact_url(req.path),
        "status": resp.status_code if resp else None,
        "request_headers": redact_headers(req.headers.items()),
        "response_headers": redact_headers(resp.headers.items()) if resp else None,
        "request_body_hash": req_hash,
        "request_body_path": f"bodies/{req_hash}.req.bin" if req_hash else None,
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
        "client_ip": peer_host(flow.client_conn),
        "server_ip": peer_host(flow.server_conn),
    }


def redact_headers(headers: Any) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in headers:
        if str(key).lower() in SENSITIVE_HEADERS:
            redacted[str(key)] = REDACTED
        else:
            redacted[str(key)] = str(value)
    return redacted


def redact_url(url: str | None) -> str | None:
    if not url or "?" not in url:
        return url
    base, _, rest = url.partition("?")
    query, hash_mark, fragment = rest.partition("#")
    parts = [redact_query_part(part) for part in query.split("&")]
    return f"{base}?{'&'.join(parts)}{hash_mark}{fragment}"


def redact_query_part(part: str) -> str:
    name, sep, value = part.partition("=")
    if not sep or not value or not is_sensitive_query_param(name):
        return part
    return f"{name}={REDACTED}"


def is_sensitive_query_param(name: str) -> bool:
    key = unquote_plus(name).lower().replace("_", "").replace("-", "")
    return key in SENSITIVE_QUERY_PARAMS or any(marker in key for marker in SENSITIVE_QUERY_MARKERS)


def peer_host(conn: Any) -> str | None:
    peername = getattr(conn, "peername", None) if conn else None
    if not peername:
        return None
    try:
        return peername[0]
    except Exception:
        return str(peername)


def write_websocket_payload(capture_dir: Path, payload_dir: Path, event: dict[str, Any], content: bytes) -> str | None:
    if not content:
        return None
    h = hashlib.sha256(content).hexdigest()
    path = payload_dir / f"{h}.ws.bin"
    if not path.exists():
        path.write_bytes(content)
    event["payload_hash"] = h
    event["payload_path"] = relative_artifact_path(capture_dir, path)
    return h
