from __future__ import annotations

import base64
import time
from collections import Counter
from typing import TYPE_CHECKING, Protocol, cast

from mitmproxy.connection import Client, Server
from mitmproxy.http import HTTPFlow
from typing_extensions import Unpack

from vrchat_net_capture.capture_schema import (
    CaptureEvent,
    CaptureSummary,
    ConnectionSummary,
    EventDetails,
    FlowIdentity,
    PayloadEvent,
    PayloadPreview,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from mitmproxy.connection import Connection
    from mitmproxy.dns import DNSFlow
    from mitmproxy.flow import Flow
    from mitmproxy.proxy.server_hooks import ServerConnectionHookData
    from mitmproxy.tcp import TCPFlow
    from mitmproxy.tls import ClientHelloData, TlsData
    from mitmproxy.udp import UDPFlow

from vrchat_net_capture.capture_records import http_headers, redact_headers, redact_url

_wall_clock = time.time


class StreamMessage(Protocol):
    content: bytes
    from_client: bool
    timestamp: float


def build_event(kind: str, flow: Flow | None = None, **extra: Unpack[EventDetails]) -> CaptureEvent:
    event: CaptureEvent = {"kind": kind, "ts": _wall_clock()}
    if flow is not None:
        event.update(**flow_identity(flow))
    event.update(**extra)
    return event


def flow_identity(flow: Flow) -> FlowIdentity:
    request = flow.request if isinstance(flow, HTTPFlow) else None
    server_conn = flow.server_conn
    return {
        "flow_id": flow.id,
        "host": ((request.pretty_host if request is not None else None) or server_address(server_conn) or "").lower()
        or None,
        "url": redact_url(request.pretty_url if request is not None else None),
        "method": (request.method if request is not None else None),
        "path": redact_url(request.path if request is not None else None),
        "client": connection_summary(flow.client_conn),
        "server": connection_summary(server_conn),
    }


def request_headers_event(flow: HTTPFlow) -> CaptureEvent:
    req = flow.request
    return build_event(
        "request_headers",
        flow,
        headers=redact_headers(http_headers(req).items()),
        scheme=req.scheme,
        http_version=req.http_version,
    )


def response_headers_event(flow: HTTPFlow) -> CaptureEvent:
    resp = flow.response
    return build_event(
        "response_headers",
        flow,
        status=resp.status_code if resp else None,
        headers=redact_headers(http_headers(resp).items()) if resp else None,
        http_version=resp.http_version if resp else None,
    )


def http_connect_event(kind: str, flow: HTTPFlow) -> CaptureEvent:
    error = flow.error
    return build_event(kind, flow, error=str(error) if error else None)


def websocket_event(kind: str, flow: HTTPFlow) -> PayloadEvent:
    ws = flow.websocket
    messages = ws.messages if ws is not None else []
    msg = messages[-1] if messages else None
    content = (msg.content if msg is not None else b"") or b""
    is_text = bool(msg.is_text) if msg else False
    text_preview = None
    if is_text and content:
        text_preview = content[:2048].decode("utf-8", errors="replace")

    event = build_event(
        kind,
        flow,
        direction="client_to_server"
        if (msg.from_client if msg is not None else False)
        else "server_to_client"
        if msg
        else None,
        opcode=str(msg.type) if msg else None,
        is_text=is_text,
        size=len(content),
        text_preview=text_preview,
        timestamp=msg.timestamp if msg else None,
        dropped=msg.dropped if msg else None,
        injected=msg.injected if msg else None,
    )
    return PayloadEvent(event, content)


def stream_event(kind: str, flow: TCPFlow | UDPFlow) -> PayloadEvent:
    messages = flow.messages
    msg = cast("StreamMessage", messages[-1]) if messages else None
    content = (msg.content if msg is not None else b"") or b""
    event = build_event(
        kind,
        flow,
        capture_semantics="proxy_observed",
        direction="client_to_server"
        if (msg.from_client if msg is not None else False)
        else "server_to_client"
        if msg
        else None,
        size=len(content),
        timestamp=msg.timestamp if msg else None,
        preview=payload_preview(content),
    )
    return PayloadEvent(event, content)


def dns_event(kind: str, flow: DNSFlow) -> CaptureEvent:
    request = flow.request
    response = flow.response
    error = flow.error
    return build_event(
        kind,
        flow,
        questions=[str(q) for q in request.questions] if request else [],
        answers=[str(a) for a in response.answers] if response else [],
        error=str(error) if error else None,
    )


def tls_clienthello_event(data: ClientHelloData) -> CaptureEvent:
    client_hello = data.client_hello
    alpn = [proto.decode("ascii", errors="replace") for proto in client_hello.alpn_protocols or []]

    return build_event(
        "tls_clienthello",
        None,
        sni=client_hello.sni,
        alpn_protocols=alpn,
        client=connection_summary(data.context.client),
        server=connection_summary(data.context.server),
    )


def tls_event(kind: str, data: TlsData) -> CaptureEvent:
    conn = data.conn
    error = conn.error
    return build_event(
        kind,
        None,
        connection=connection_summary(conn),
        error=str(error) if error else None,
        is_dtls=bool(data.is_dtls),
    )


def server_event(kind: str, data: ServerConnectionHookData) -> CaptureEvent:
    server = data.server
    error = server.error
    return build_event(
        kind,
        None,
        server=connection_summary(server),
        error=str(error) if error else None,
    )


def build_summary(records: Sequence[Mapping[str, object]], events: Sequence[Mapping[str, object]]) -> CaptureSummary:
    status_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    method_counts: Counter[str] = Counter()
    event_counts: Counter[str] = Counter()
    error_counts: Counter[str] = Counter()
    tls_failure_targets: Counter[str] = Counter()

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
        if kind.startswith("tls_failed") or kind.endswith("_error"):
            target = failure_target(event)
            if target:
                tls_failure_targets[target] += 1

    return {
        "flow_count": len(records),
        "event_count": len(events),
        "hosts": dict(sorted(host_counts.items())),
        "methods": dict(sorted(method_counts.items())),
        "statuses": dict(sorted(status_counts.items())),
        "events": dict(sorted(event_counts.items())),
        "errors": dict(sorted(error_counts.items())),
        "tls_failure_targets": dict(sorted(tls_failure_targets.items())),
    }


def connection_summary(conn: Connection | None) -> ConnectionSummary | None:
    if conn is None:
        return None
    return {
        "address": address_to_string(
            conn.address if isinstance(conn, Server) else conn.peername if isinstance(conn, Client) else None
        ),
        "peername": address_to_string(conn.peername),
        "sockname": address_to_string(conn.sockname),
        "sni": conn.sni,
        "alpn": alpn_to_string(conn.alpn),
        "tls_established": conn.tls_established,
        "error": str(conn.error) if conn.error else None,
    }


def server_address(conn: Connection | None) -> str | None:
    address = conn.address if isinstance(conn, Server) else conn.peername if isinstance(conn, Client) else None
    if not address:
        return None
    try:
        return address[0]
    except (TypeError, IndexError, KeyError):
        return str(address)


def address_to_string(address: object) -> str | None:
    if not address:
        return None
    if isinstance(address, tuple):
        return ":".join(str(part) for part in cast("tuple[object, ...]", address))
    return str(address)


def alpn_to_string(alpn: object) -> str | None:
    if alpn is None:
        return None
    if isinstance(alpn, bytes):
        return alpn.decode("ascii", errors="replace")
    return str(alpn)


def failure_target(event: Mapping[str, object]) -> str | None:
    host = event.get("host")
    if host:
        return str(host)
    for key in ("connection", "server", "client"):
        value = event.get(key)
        if not isinstance(value, dict):
            continue
        for field in ("sni", "address", "peername", "sockname"):
            field_value = cast("Mapping[str, object]", value).get(field)
            if field_value:
                return str(field_value)
    return None


def payload_preview(content: bytes) -> PayloadPreview | None:
    if not content:
        return None
    sample = content[:256]
    if b"\x00" not in sample:
        try:
            return {"encoding": "text", "value": sample.decode("utf-8")}
        except UnicodeDecodeError:
            return binary_preview(sample)
    return binary_preview(sample)


def binary_preview(sample: bytes) -> PayloadPreview:
    return {"encoding": "base64", "value": base64.b64encode(sample).decode("ascii")}
