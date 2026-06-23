"""mitmproxy addon for VRChat HTTP(S), WebSocket, TLS, DNS, and log capture."""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any

from mitmproxy import ctx, http

from capture_events import (
    build_event,
    build_summary,
    dns_event,
    http_connect_event,
    request_headers_event,
    response_headers_event,
    server_event,
    stream_event,
    tls_clienthello_event,
    tls_event,
    websocket_event,
)
from capture_records import build_http_record, save_body, write_websocket_payload
from capture_utils import append_jsonl, relative_artifact_path, write_per_host
from capture_vrchat_logs import mark_unmatched_log_urls, newest_output_log, parse_vrchat_log

try:
    import UnityPy  # type: ignore

    _HAVE_UNITYPY = True
except Exception:
    UnityPy = None  # type: ignore
    _HAVE_UNITYPY = False


class CaptureAddon:
    def __init__(self) -> None:
        self.capture_dir: Path | None = None
        self.bodies_dir: Path | None = None
        self.decoded_dir: Path | None = None
        self.by_host_dir: Path | None = None
        self.websockets_dir: Path | None = None
        self.streams_dir: Path | None = None
        self.flows_jsonl: Path | None = None
        self.events_jsonl: Path | None = None
        self.ignore_hosts: set[str] = set()
        self._records: list[dict[str, Any]] = []
        self._events: list[dict[str, Any]] = []
        self._started = False

    def load(self, loader) -> None:
        loader.add_option(
            name="capture_dir",
            typespec=str,
            default="",
            help="Directory to write capture artifacts into.",
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
        self.websockets_dir = self.capture_dir / "websockets"
        self.streams_dir = self.capture_dir / "streams"
        self.flows_jsonl = self.capture_dir / "flows.jsonl"
        self.events_jsonl = self.capture_dir / "events.jsonl"
        for directory in (self.bodies_dir, self.decoded_dir, self.by_host_dir, self.websockets_dir, self.streams_dir):
            directory.mkdir(parents=True, exist_ok=True)

        ignore = (ctx.options.ignore_hosts_list or "").strip()
        if ignore:
            self.ignore_hosts = {h.strip().lower() for h in ignore.split(",") if h.strip()}

        ctx.log.info(f"capture_addon ready - writing to {self.capture_dir}")
        if self.ignore_hosts:
            ctx.log.info(f"  ignoring hosts: {sorted(self.ignore_hosts)}")
        if _HAVE_UNITYPY:
            ctx.log.info("  UnityPy available - will peek at asset bundles")
        else:
            ctx.log.info("  UnityPy not installed - bundles will be archived raw only")
        self._started = True

    def done(self) -> None:
        if not self.capture_dir:
            return
        try:
            self._write_vrchat_log_correlation()
            (self.capture_dir / "flows.json").write_text(json.dumps(self._records, indent=2), encoding="utf-8")
            (self.capture_dir / "events.json").write_text(json.dumps(self._events, indent=2), encoding="utf-8")
            summary = build_summary(self._records, self._events)
            (self.capture_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
            ctx.log.info(f"capture_addon: wrote {len(self._records)} flows and {len(self._events)} events")
        except Exception as exc:
            ctx.log.error(f"capture_addon: failed to write shutdown artifacts: {exc}")

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        self._record_event_for_flow(flow, request_headers_event)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        self._record_event_for_flow(flow, response_headers_event)

    def http_connect(self, flow: http.HTTPFlow) -> None:
        self._record_event_for_flow(flow, lambda f: http_connect_event("http_connect", f))

    def http_connected(self, flow: http.HTTPFlow) -> None:
        self._record_event_for_flow(flow, lambda f: http_connect_event("http_connected", f))

    def http_connect_error(self, flow: http.HTTPFlow) -> None:
        self._record_event_for_flow(flow, lambda f: http_connect_event("http_connect_error", f))

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            self._record_flow(flow)
        except Exception:
            ctx.log.error("capture_addon: error while recording flow:\n" + traceback.format_exc())

    def error(self, flow: http.HTTPFlow) -> None:
        try:
            self._record_flow(flow, errored=True)
            self._append_event(build_event("http_error", flow, error=str(flow.error) if flow.error else None))
        except Exception:
            ctx.log.error("capture_addon: error while recording errored flow:\n" + traceback.format_exc())

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if self._should_ignore_flow(flow):
            return
        try:
            assert self.capture_dir and self.websockets_dir
            event, content = websocket_event("websocket_message", flow)
            write_websocket_payload(self.capture_dir, self.websockets_dir, event, content)
            self._append_event(event)
        except Exception:
            ctx.log.error("capture_addon: error while recording WebSocket message:\n" + traceback.format_exc())

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        self._record_event_for_flow(flow, lambda f: build_event("websocket_end", f))

    def tcp_message(self, flow) -> None:
        self._record_stream_event("tcp_message", flow, ".tcp.bin")

    def tcp_end(self, flow) -> None:
        self._append_event(build_event("tcp_end", flow))

    def tcp_error(self, flow) -> None:
        self._append_event(build_event("tcp_error", flow, error=str(flow.error) if flow.error else None))

    def udp_message(self, flow) -> None:
        self._record_stream_event("udp_message", flow, ".udp.bin")

    def udp_end(self, flow) -> None:
        self._append_event(build_event("udp_end", flow))

    def udp_error(self, flow) -> None:
        self._append_event(build_event("udp_error", flow, error=str(flow.error) if flow.error else None))

    def dns_request(self, flow) -> None:
        self._append_event(dns_event("dns_request", flow))

    def dns_response(self, flow) -> None:
        self._append_event(dns_event("dns_response", flow))

    def dns_error(self, flow) -> None:
        self._append_event(dns_event("dns_error", flow))

    def tls_clienthello(self, data) -> None:
        self._append_event(tls_clienthello_event(data))

    def tls_established_client(self, data) -> None:
        self._append_event(tls_event("tls_established_client", data))

    def tls_established_server(self, data) -> None:
        self._append_event(tls_event("tls_established_server", data))

    def tls_failed_client(self, data) -> None:
        self._append_event(tls_event("tls_failed_client", data))

    def tls_failed_server(self, data) -> None:
        self._append_event(tls_event("tls_failed_server", data))

    def server_connect(self, data) -> None:
        self._append_event(server_event("server_connect", data))

    def server_connected(self, data) -> None:
        self._append_event(server_event("server_connected", data))

    def server_connect_error(self, data) -> None:
        self._append_event(server_event("server_connect_error", data))

    def client_connected(self, client) -> None:
        self._append_event(build_event("client_connected", None, client=str(client)))

    def client_disconnected(self, client) -> None:
        self._append_event(build_event("client_disconnected", None, client=str(client)))

    def _record_flow(self, flow: http.HTTPFlow, errored: bool = False) -> None:
        assert self.capture_dir and self.bodies_dir and self.decoded_dir and self.by_host_dir and self.flows_jsonl
        if self._should_ignore_flow(flow):
            return

        record = build_http_record(
            flow,
            self.capture_dir,
            self.bodies_dir,
            self.decoded_dir,
            _HAVE_UNITYPY,
            UnityPy.load if _HAVE_UNITYPY else None,  # type: ignore[union-attr]
            self._warn,
            errored=errored,
        )
        self._records.append(record)
        append_jsonl(self.flows_jsonl, record)
        write_per_host(self.by_host_dir, record)

    def _record_event_for_flow(self, flow: http.HTTPFlow, builder) -> None:
        if self._should_ignore_flow(flow):
            return
        try:
            self._append_event(builder(flow))
        except Exception:
            ctx.log.error("capture_addon: error while recording event:\n" + traceback.format_exc())

    def _record_stream_event(self, kind: str, flow, suffix: str) -> None:
        try:
            assert self.capture_dir and self.streams_dir
            event, content = stream_event(kind, flow)
            if content:
                h = save_body(self.streams_dir, content, suffix=suffix)
                event["payload_hash"] = h
                event["payload_path"] = relative_artifact_path(self.capture_dir, self.streams_dir / f"{h}{suffix}")
            self._append_event(event)
        except Exception:
            ctx.log.error(f"capture_addon: error while recording {kind}:\n" + traceback.format_exc())

    def _append_event(self, event: dict[str, Any]) -> None:
        assert self.events_jsonl
        self._events.append(event)
        append_jsonl(self.events_jsonl, event)

    def _write_vrchat_log_correlation(self) -> None:
        assert self.capture_dir
        log_path = newest_output_log()
        if not log_path:
            return
        events = parse_vrchat_log(log_path)
        unmatched = mark_unmatched_log_urls(events, self._records)
        for event in events:
            event["source_log"] = str(log_path)
        (self.capture_dir / "vrchat-log-events.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + ("\n" if events else ""),
            encoding="utf-8",
        )
        (self.capture_dir / "vrchat-log-unmatched.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=False) for e in unmatched) + ("\n" if unmatched else ""),
            encoding="utf-8",
        )
        self._append_event(
            build_event(
                "vrchat_log_summary",
                None,
                source_log=str(log_path),
                url_events=len(events),
                unmatched_url_events=len(unmatched),
            )
        )

    def _should_ignore_flow(self, flow: http.HTTPFlow) -> bool:
        host = (flow.request.pretty_host or "").lower() if getattr(flow, "request", None) else ""
        return host in self.ignore_hosts

    def _warn(self, message: str) -> None:
        if hasattr(ctx.log, "warning"):
            ctx.log.warning(message)
        else:
            ctx.log.warn(message)


addons = [CaptureAddon()]
