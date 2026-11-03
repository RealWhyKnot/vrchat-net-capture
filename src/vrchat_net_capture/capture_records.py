from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from vrchat_net_capture.capture_utils import ResponseBody

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path

    from mitmproxy.connection import Connection
    from mitmproxy.http import HTTPFlow, Message

    from vrchat_net_capture.capture_schema import CaptureEvent, HttpRecord
    from vrchat_net_capture.capture_utils import UnityEnvironment
from urllib.parse import unquote_plus

from vrchat_net_capture.capture_utils import decode_response, relative_artifact_path, unitypy_peek


class HeadersView(Protocol):
    def items(self) -> Iterable[tuple[str, str]]: ...

    def get(self, key: str, default: str | None = None) -> str | None: ...


def http_headers(message: Message) -> HeadersView:
    return cast("HeadersView", message.headers)


@dataclass
class HttpBodies:
    request: bytes | None
    response: bytes | None
    response_on_wire: bytes


def read_http_bodies(flow: HTTPFlow) -> HttpBodies:
    request_body = flow.request.raw_content or b""
    try:
        request_decoded = flow.request.content if request_body else b""
    except (ValueError, OSError, AttributeError):
        request_decoded = request_body
    response_body = b""
    response_decoded = b""
    if flow.response is not None:
        try:
            response_body = flow.response.raw_content or b""
        except (ValueError, OSError, AttributeError):
            response_body = b""
        try:
            response_decoded = flow.response.content if response_body else b""
        except (ValueError, OSError, AttributeError):
            response_decoded = response_body
    return HttpBodies(request_decoded, response_decoded, response_body)


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


@dataclass
class RecordingOptions:
    capture_dir: Path
    bodies_dir: Path
    decoded_dir: Path
    analyze_unity: bool
    unitypy_loader: Callable[[bytes], UnityEnvironment] | None
    warn: Callable[[str], None]
    clock: Callable[[], float] = time.time


def build_http_record(flow: HTTPFlow, options: RecordingOptions, *, errored: bool = False) -> HttpRecord:
    req = flow.request
    resp = flow.response

    host = (req.pretty_host or "").lower()
    ts_start = float(req.timestamp_start or options.clock())
    ts_end = float((resp.timestamp_end if resp else None) or req.timestamp_end or ts_start)

    bodies = read_http_bodies(flow)

    req_hash = save_body(options.bodies_dir, bodies.request, suffix=".req.bin") if bodies.request else None
    resp_hash = save_body(options.bodies_dir, bodies.response, suffix=".bin") if bodies.response else None

    decoded_path: str | None = None
    magic_hint: str | None = None
    is_unity_bundle = False
    unitypy_summary_path: str | None = None
    if resp_hash and bodies.response:
        response_body = ResponseBody(
            resp_hash, bodies.response, http_headers(resp).get("content-type") if resp else "", host
        )
        decoded = decode_response(options.capture_dir, options.decoded_dir, response_body)
        decoded_path, magic_hint, is_unity_bundle = decoded.path, decoded.hint, decoded.is_unity_bundle
        if is_unity_bundle and options.analyze_unity and options.unitypy_loader is not None:
            unitypy_summary_path = unitypy_peek(
                options.capture_dir,
                options.decoded_dir,
                response_body,
                options.unitypy_loader,
                options.warn,
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
        "request_headers": redact_headers(http_headers(req).items()),
        "response_headers": redact_headers(http_headers(resp).items()) if resp else None,
        "request_body_hash": req_hash,
        "request_body_path": f"bodies/{req_hash}.req.bin" if req_hash else None,
        "request_body_size": len(bodies.request) if bodies.request else 0,
        "response_body_hash": resp_hash,
        "response_body_path": f"bodies/{resp_hash}.bin" if resp_hash else None,
        "response_decoded_path": decoded_path,
        "response_size": len(bodies.response) if bodies.response else 0,
        "response_size_on_wire": len(bodies.response_on_wire),
        "response_content_type": http_headers(resp).get("content-type") if resp else None,
        "response_compression": http_headers(resp).get("content-encoding") if resp else None,
        "magic_bytes_hint": magic_hint,
        "is_unity_assetbundle": is_unity_bundle,
        "unitypy_summary_path": unitypy_summary_path,
        "client_ip": peer_host(flow.client_conn),
        "server_ip": peer_host(flow.server_conn),
    }


def redact_headers(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
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


def peer_host(conn: Connection | None) -> str | None:
    peername = conn.peername if conn else None
    if not peername:
        return None
    try:
        return peername[0]
    except (TypeError, IndexError, KeyError):
        return str(peername)


def write_websocket_payload(capture_dir: Path, payload_dir: Path, event: CaptureEvent, content: bytes) -> str | None:
    if not content:
        return None
    h = hashlib.sha256(content).hexdigest()
    path = payload_dir / f"{h}.ws.bin"
    if not path.exists():
        path.write_bytes(content)
    event["payload_hash"] = h
    event["payload_path"] = relative_artifact_path(capture_dir, path)
    return h
