from __future__ import annotations

import json
import logging
import traceback
from typing import TYPE_CHECKING

from mitmproxy import http

from vrchat_net_capture.capture_records import RecordingOptions

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from mitmproxy.connection import Client
    from mitmproxy.flow import Flow
    from mitmproxy.proxy.server_hooks import ServerConnectionHookData
    from mitmproxy.tcp import TCPFlow
    from mitmproxy.tls import TlsData
    from mitmproxy.udp import UDPFlow

    from vrchat_net_capture.capture_schema import AnalysisDetails, AnalysisRecord, CaptureEvent, HttpRecord

from vrchat_net_capture.capture_config import FlowType, ProcessFilter, unity_loader
from vrchat_net_capture.capture_events import (
    build_event,
    build_summary,
    server_event,
    stream_event,
    tls_event,
    websocket_event,
)
from vrchat_net_capture.capture_osc import OscParseError, build_osc_summary, decode_osc_packet
from vrchat_net_capture.capture_photon import build_photon_summary, classify_photon_packet
from vrchat_net_capture.capture_process import (
    DEFAULT_CAPTURE_PROCESSES,
    CaptureProcessFilter,
    parse_process_names,
    socket_address,
)
from vrchat_net_capture.capture_records import build_http_record, save_body, write_websocket_payload
from vrchat_net_capture.capture_utils import append_jsonl, relative_artifact_path, write_per_host
from vrchat_net_capture.capture_vrchat_logs import mark_unmatched_log_urls, newest_output_log, parse_vrchat_log


class CaptureRecorder:
    def __init__(self) -> None:
        self.capture_dir: Path | None = None
        self.bodies_dir: Path | None = None
        self.decoded_dir: Path | None = None
        self.by_host_dir: Path | None = None
        self.websockets_dir: Path | None = None
        self.streams_dir: Path | None = None
        self.flows_jsonl: Path | None = None
        self.events_jsonl: Path | None = None
        self.osc_jsonl: Path | None = None
        self.photon_jsonl: Path | None = None
        self.ignore_hosts: set[str] = set()
        self.decode_osc = False
        self.store_osc_values = False
        self.photon_metadata = False
        self.unity_metadata = False
        self.capture_all_processes = False
        self.process_filter: ProcessFilter = CaptureProcessFilter(parse_process_names(DEFAULT_CAPTURE_PROCESSES))
        self._clients: dict[str, bool] = {}
        self._passed_through = 0
        self._records: list[HttpRecord] = []
        self._events: list[CaptureEvent] = []
        self._osc_records: list[AnalysisRecord] = []
        self._photon_records: list[AnalysisRecord] = []
        self._started = False

    def _record_flow(self, flow: http.HTTPFlow, *, errored: bool = False) -> None:
        if self.capture_dir is None:
            raise AssertionError
        if self.bodies_dir is None:
            raise AssertionError
        if self.decoded_dir is None:
            raise AssertionError
        if self.by_host_dir is None:
            raise AssertionError
        if self.flows_jsonl is None:
            raise AssertionError
        if self._should_ignore_flow(flow):
            return

        loader = unity_loader()
        options = RecordingOptions(
            self.capture_dir,
            self.bodies_dir,
            self.decoded_dir,
            self.unity_metadata,
            loader.load if loader is not None else None,
            self._warn,
        )
        record = build_http_record(flow, options, errored=errored)
        self._records.append(record)
        append_jsonl(self.flows_jsonl, record)
        write_per_host(self.by_host_dir, record)

    def _record_event_for_flow(self, flow: FlowType, builder: Callable[[FlowType], CaptureEvent]) -> None:
        if self._should_ignore_flow(flow):
            return
        try:
            self._append_event(builder(flow))
        except (OSError, ValueError, TypeError, AttributeError):
            logging.getLogger(__name__).log(
                logging.ERROR, "capture_addon: error while recording event:\n%s", traceback.format_exc(), exc_info=False
            )

    def _record_tls_event(self, kind: str, data: TlsData) -> None:
        if self._client_allowed(data.context.client):
            self._append_event(tls_event(kind, data))

    def _record_server_event(self, kind: str, data: ServerConnectionHookData) -> None:
        if self._client_allowed(data.client):
            self._append_event(server_event(kind, data))

    def _record_stream_event(self, kind: str, flow: TCPFlow | UDPFlow, suffix: str) -> None:
        if not self._client_allowed(flow.client_conn):
            return
        try:
            self._write_stream(kind, flow, suffix)
        except (OSError, ValueError, TypeError, AttributeError):
            logging.getLogger(__name__).log(
                logging.ERROR,
                "capture_addon: error while recording %s:\n%s",
                kind,
                traceback.format_exc(),
                exc_info=False,
            )

    def _record_optional_udp_analysis(self, event: CaptureEvent, content: bytes) -> None:
        if self.capture_dir is None:
            raise AssertionError
        if self.decode_osc:
            try:
                osc = decode_osc_packet(content, include_values=self.store_osc_values)
            except OscParseError as exc:
                event["osc_status"] = "error"
                record = self._analysis_record("osc_packet", event, {"osc": {"status": "error", "error": str(exc)}})
                self._osc_records.append(record)
                if self.osc_jsonl:
                    append_jsonl(self.osc_jsonl, record)
            else:
                if osc is not None:
                    event["osc_status"] = "ok"
                    event["osc_message_count"] = osc["message_count"]
                    record = self._analysis_record("osc_packet", event, {"osc": osc})
                    self._osc_records.append(record)
                    if self.osc_jsonl:
                        append_jsonl(self.osc_jsonl, record)

        if self.photon_metadata:
            self._record_photon_analysis(event, content)

    def _record_photon_analysis(self, event: CaptureEvent, content: bytes) -> None:
        photon = classify_photon_packet(event, content)
        if photon is not None:
            event["photon_candidate"] = True
            event["photon_confidence"] = photon["confidence"]
            record = self._analysis_record("photon_packet", event, {"photon": photon})
            self._photon_records.append(record)
            if self.photon_jsonl:
                append_jsonl(self.photon_jsonl, record)

    @staticmethod
    def _analysis_record(kind: str, event: CaptureEvent, extra: AnalysisDetails) -> AnalysisRecord:
        record: AnalysisRecord = {
            "kind": kind,
            "ts": event.get("ts"),
            "flow_id": event.get("flow_id"),
            "direction": event.get("direction"),
            "capture_semantics": event.get("capture_semantics"),
            "client": event.get("client"),
            "server": event.get("server"),
            "payload_hash": event.get("payload_hash"),
            "payload_path": event.get("payload_path"),
            "size": event.get("size"),
        }
        if "osc" in extra:
            record["osc"] = extra["osc"]
        if "photon" in extra:
            record["photon"] = extra["photon"]
        return record

    def _append_event(self, event: CaptureEvent) -> None:
        if self.events_jsonl is None:
            raise AssertionError
        self._events.append(event)
        append_jsonl(self.events_jsonl, event)

    def _write_vrchat_log_correlation(self) -> None:
        if self.capture_dir is None:
            raise AssertionError
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

    def _should_ignore_flow(self, flow: Flow) -> bool:
        if not self._client_allowed(flow.client_conn):
            return True
        request = flow.request if isinstance(flow, http.HTTPFlow) else None
        host = (request.pretty_host or "").lower() if request is not None else ""
        return host in self.ignore_hosts

    def _client_allowed(self, client: Client | None) -> bool:
        if self.capture_all_processes:
            return True
        if client is None:
            return False
        client_id = client.id
        allowed = self._clients.get(client_id)
        if allowed is None:
            allowed = self.process_filter.allows(
                socket_address(client.peername),
                socket_address(client.sockname),
            )
            self._clients[client_id] = allowed
            if not allowed:
                self._passed_through += 1
        return allowed

    @staticmethod
    def _warn(message: str) -> None:
        logging.getLogger(__name__).warning(message)

    def _write_artifacts(self) -> None:
        if self.capture_dir is None:
            raise AssertionError
        self._write_vrchat_log_correlation()
        (self.capture_dir / "flows.json").write_text(json.dumps(self._records, indent=2), encoding="utf-8")
        (self.capture_dir / "events.json").write_text(json.dumps(self._events, indent=2), encoding="utf-8")
        if self.decode_osc:
            (self.capture_dir / "osc-events.json").write_text(json.dumps(self._osc_records, indent=2), encoding="utf-8")
            (self.capture_dir / "osc-summary.json").write_text(
                json.dumps(build_osc_summary(self._osc_records), indent=2),
                encoding="utf-8",
            )
        if self.photon_metadata:
            (self.capture_dir / "photon-summary.json").write_text(
                json.dumps(build_photon_summary(self._photon_records), indent=2),
                encoding="utf-8",
            )
        summary = build_summary(self._records, self._events)
        (self.capture_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logging.getLogger(__name__).info(
            "capture_addon: wrote %s flows and %s events", len(self._records), len(self._events)
        )
        if self._passed_through:
            logging.getLogger(__name__).info(
                "capture_addon: skipped %s connections from other programs", self._passed_through
            )

    def _write_websocket(self, flow: http.HTTPFlow) -> None:
        if self.capture_dir is None:
            raise AssertionError
        if self.websockets_dir is None:
            raise AssertionError
        payload = websocket_event("websocket_message", flow)
        event, content = payload.event, payload.content
        write_websocket_payload(self.capture_dir, self.websockets_dir, event, content)
        self._append_event(event)

    def _write_stream(self, kind: str, flow: TCPFlow | UDPFlow, suffix: str) -> None:
        if self.capture_dir is None:
            raise AssertionError
        if self.streams_dir is None:
            raise AssertionError
        payload = stream_event(kind, flow)
        event, content = payload.event, payload.content
        if content:
            h = save_body(self.streams_dir, content, suffix=suffix)
            event["payload_hash"] = h
            event["payload_path"] = relative_artifact_path(self.capture_dir, self.streams_dir / f"{h}{suffix}")
            if kind == "udp_message":
                self._record_optional_udp_analysis(event, content)
        self._append_event(event)

    def _report_started(self) -> None:
        logging.getLogger(__name__).info("capture_addon ready - writing to %s", self.capture_dir)
        if self.ignore_hosts:
            logging.getLogger(__name__).info("  ignoring hosts: %s", sorted(self.ignore_hosts))
        if self.capture_all_processes:
            logging.getLogger(__name__).info("  capturing connections from every program that uses the proxy")
        else:
            programs = ", ".join(sorted(self.process_filter.names))
            logging.getLogger(__name__).info(
                "  capturing %s and the programs they start; other programs are not decrypted or saved", programs
            )
        if self.decode_osc:
            logging.getLogger(__name__).info("  OSC decode enabled for captured UDP datagrams")
        if self.photon_metadata:
            logging.getLogger(__name__).info("  Photon metadata summary enabled for captured UDP datagrams")
        if self.unity_metadata and (unity_loader() is not None):
            logging.getLogger(__name__).info("  UnityPy metadata peek enabled for asset bundles")
        elif self.unity_metadata:
            logging.getLogger(__name__).info("  UnityPy not installed - bundles will be archived raw only")
        else:
            logging.getLogger(__name__).info("  Unity bundle metadata analysis disabled")
