from __future__ import annotations

import base64
import time
from collections import Counter
from typing import Any


def build_event(kind: str, flow: Any | None = None, **extra: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "kind": kind,
        "ts": time.time(),
    }
    if flow is not None:
        event.update(flow_identity(flow))
    event.update(extra)
    return json_safe(event)


def flow_identity(flow: Any) -> dict[str, Any]:
    request = getattr(flow, "request", None)
    server_conn = getattr(flow, "server_conn", None)
    return {
        "flow_id": getattr(flow, "id", None),
        "host": (getattr(request, "pretty_host", None) or server_address(server_conn) or "").lower() or None,
        "url": getattr(request, "pretty_url", None),
        "method": getattr(request, "method", None),
        "path": getattr(request, "path", None),
        "client": connection_summary(getattr(flow, "client_conn", None)),
        "server": connection_summary(server_conn),
    }


def request_headers_event(flow: Any) -> dict[str, Any]:
    req = flow.request
    return build_event(
        "request_headers",
        flow,
        headers=dict(req.headers.items()),
        scheme=req.scheme,
        http_version=getattr(req, "http_version", None),
    )


def response_headers_event(flow: Any) -> dict[str, Any]:
    resp = flow.response
    return build_event(
        "response_headers",
        flow,
        status=resp.status_code if resp else None,
        headers=dict(resp.headers.items()) if resp else None,
        http_version=getattr(resp, "http_version", None) if resp else None,
    )


def http_connect_event(kind: str, flow: Any) -> dict[str, Any]:
    error = getattr(flow, "error", None)
    return build_event(kind, flow, error=str(error) if error else None)


def websocket_event(kind: str, flow: Any) -> tuple[dict[str, Any], bytes]:
    ws = getattr(flow, "websocket", None)
    messages = getattr(ws, "messages", None) or []
    msg = messages[-1] if messages else None
    content = getattr(msg, "content", b"") or b""
    is_text = bool(getattr(msg, "is_text", False)) if msg else False
    text_preview = None
    if is_text and content:
        text_preview = content[:2048].decode("utf-8", errors="replace")

    event = build_event(
        kind,
        flow,
        direction="client_to_server" if getattr(msg, "from_client", False) else "server_to_client" if msg else None,
        opcode=str(getattr(msg, "type", None)) if msg else None,
        is_text=is_text,
        size=len(content),
        text_preview=text_preview,
        timestamp=getattr(msg, "timestamp", None) if msg else None,
        dropped=getattr(msg, "dropped", None) if msg else None,
        injected=getattr(msg, "injected", None) if msg else None,
    )
    return event, content


def stream_event(kind: str, flow: Any) -> tuple[dict[str, Any], bytes]:
    messages = getattr(flow, "messages", None) or []
    msg = messages[-1] if messages else None
    content = getattr(msg, "content", b"") or b""
    event = build_event(
        kind,
        flow,
        direction="client_to_server" if getattr(msg, "from_client", False) else "server_to_client" if msg else None,
        size=len(content),
        timestamp=getattr(msg, "timestamp", None) if msg else None,
        preview=payload_preview(content),
    )
    return event, content


def dns_event(kind: str, flow: Any) -> dict[str, Any]:
    request = getattr(flow, "request", None)
    response = getattr(flow, "response", None)
    error = getattr(flow, "error", None)
    return build_event(
        kind,
        flow,
        questions=[str(q) for q in getattr(request, "questions", [])] if request else [],
        answers=[str(a) for a in getattr(response, "answers", [])] if response else [],
        error=str(error) if error else None,
    )


def tls_clienthello_event(data: Any) -> dict[str, Any]:
    client_hello = getattr(data, "client_hello", None)
    alpn = []
    for proto in getattr(client_hello, "alpn_protocols", []) or []:
        alpn.append(proto.decode("ascii", errors="replace") if isinstance(proto, bytes) else str(proto))

    return build_event(
        "tls_clienthello",
        None,
        sni=getattr(client_hello, "sni", None),
        alpn_protocols=alpn,
        client=connection_summary(getattr(getattr(data, "context", None), "client", None)),
        server=connection_summary(getattr(getattr(data, "context", None), "server", None)),
    )


def tls_event(kind: str, data: Any) -> dict[str, Any]:
    conn = getattr(data, "conn", None)
    error = getattr(conn, "error", None)
    return build_event(
        kind,
        None,
        connection=connection_summary(conn),
        error=str(error) if error else None,
        is_dtls=bool(getattr(data, "is_dtls", False)),
    )


def server_event(kind: str, data: Any) -> dict[str, Any]:
    server = getattr(data, "server", None)
    error = getattr(server, "error", None)
    return build_event(
        kind,
        None,
        server=connection_summary(server),
        error=str(error) if error else None,
    )


def build_summary(records: list[dict[str, Any]], events: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    method_counts: Counter[str] = Counter()
    event_counts: Counter[str] = Counter()
    error_counts: Counter[str] = Counter()

    for record in records:
        host_counts[str(record.get("host") or "_unknown")] += 1
        method_counts[str(record.get("method") or "_unknown")] += 1
        status_counts[str(record.get("status") or "ERR")] += 1
        if record.get("errored"):
            error_counts["http_flow"] += 1

    for event in events:
        kind = str(event.get("kind") or "_unknown")
        event_counts[kind] += 1
        if event.get("error"):
            error_counts[kind] += 1

    return {
        "flow_count": len(records),
        "event_count": len(events),
        "hosts": dict(sorted(host_counts.items())),
        "methods": dict(sorted(method_counts.items())),
        "statuses": dict(sorted(status_counts.items())),
        "events": dict(sorted(event_counts.items())),
        "errors": dict(sorted(error_counts.items())),
    }


def connection_summary(conn: Any) -> dict[str, Any] | None:
    if conn is None:
        return None
    return {
        "address": address_to_string(getattr(conn, "address", None)),
        "peername": address_to_string(getattr(conn, "peername", None)),
        "sockname": address_to_string(getattr(conn, "sockname", None)),
        "sni": getattr(conn, "sni", None),
        "alpn": alpn_to_string(getattr(conn, "alpn", None)),
        "tls_established": getattr(conn, "tls_established", None),
        "error": str(getattr(conn, "error", None)) if getattr(conn, "error", None) else None,
    }


def server_address(conn: Any) -> str | None:
    address = getattr(conn, "address", None)
    if not address:
        return None
    try:
        return address[0]
    except Exception:
        return str(address)


def address_to_string(address: Any) -> str | None:
    if not address:
        return None
    if isinstance(address, tuple):
        return ":".join(str(part) for part in address)
    return str(address)


def alpn_to_string(alpn: Any) -> str | None:
    if alpn is None:
        return None
    if isinstance(alpn, bytes):
        return alpn.decode("ascii", errors="replace")
    return str(alpn)


def payload_preview(content: bytes) -> dict[str, Any] | None:
    if not content:
        return None
    sample = content[:256]
    if b"\x00" not in sample:
        try:
            return {"encoding": "text", "value": sample.decode("utf-8")}
        except UnicodeDecodeError:
            pass
    return {"encoding": "base64", "value": base64.b64encode(sample).decode("ascii")}


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [json_safe(v) for v in value]
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return str(value)
