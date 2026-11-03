from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from typing_extensions import NotRequired, TypedDict

if TYPE_CHECKING:
    from vrchat_net_capture.capture_osc import OscPacket
    from vrchat_net_capture.capture_photon import PhotonPacket


class ConnectionSummary(TypedDict):
    address: str | None
    peername: str | None
    sockname: str | None
    sni: str | None
    alpn: str | None
    tls_established: bool | None
    error: str | None


class FlowIdentity(TypedDict):
    flow_id: str | None
    host: str | None
    url: str | None
    method: str | None
    path: str | None
    client: ConnectionSummary | str | None
    server: ConnectionSummary | None


class PayloadPreview(TypedDict):
    encoding: Literal["text", "base64"]
    value: str


class EventDetails(TypedDict, total=False):
    flow_id: str | None
    host: str | None
    url: str | None
    method: str | None
    path: str | None
    client: ConnectionSummary | str | None
    server: ConnectionSummary | None
    connection: ConnectionSummary | None
    headers: dict[str, str] | None
    scheme: str
    http_version: str | None
    status: int | None
    error: str | None
    direction: Literal["client_to_server", "server_to_client"] | None
    opcode: str | None
    is_text: bool
    size: int
    text_preview: str | None
    timestamp: float | None
    dropped: bool | None
    injected: bool | None
    capture_semantics: str
    preview: PayloadPreview | None
    questions: list[str]
    answers: list[str]
    sni: str | None
    alpn_protocols: list[str]
    is_dtls: bool
    source_log: str
    url_events: int
    unmatched_url_events: int
    payload_hash: str
    payload_path: str
    osc_status: Literal["ok", "error"]
    osc_message_count: int
    photon_candidate: bool
    photon_confidence: Literal["low", "medium"]


class CaptureEvent(TypedDict):
    kind: str
    ts: float
    flow_id: NotRequired[str | None]
    host: NotRequired[str | None]
    url: NotRequired[str | None]
    method: NotRequired[str | None]
    path: NotRequired[str | None]
    client: NotRequired[ConnectionSummary | str | None]
    server: NotRequired[ConnectionSummary | None]
    connection: NotRequired[ConnectionSummary | None]
    headers: NotRequired[dict[str, str] | None]
    scheme: NotRequired[str]
    http_version: NotRequired[str | None]
    status: NotRequired[int | None]
    error: NotRequired[str | None]
    direction: NotRequired[Literal["client_to_server", "server_to_client"] | None]
    opcode: NotRequired[str | None]
    is_text: NotRequired[bool]
    size: NotRequired[int]
    text_preview: NotRequired[str | None]
    timestamp: NotRequired[float | None]
    dropped: NotRequired[bool | None]
    injected: NotRequired[bool | None]
    capture_semantics: NotRequired[str]
    preview: NotRequired[PayloadPreview | None]
    questions: NotRequired[list[str]]
    answers: NotRequired[list[str]]
    sni: NotRequired[str | None]
    alpn_protocols: NotRequired[list[str]]
    is_dtls: NotRequired[bool]
    source_log: NotRequired[str]
    url_events: NotRequired[int]
    unmatched_url_events: NotRequired[int]
    payload_hash: NotRequired[str]
    payload_path: NotRequired[str]
    osc_status: NotRequired[Literal["ok", "error"]]
    osc_message_count: NotRequired[int]
    photon_candidate: NotRequired[bool]
    photon_confidence: NotRequired[Literal["low", "medium"]]


@dataclass
class PayloadEvent:
    event: CaptureEvent
    content: bytes


class CaptureSummary(TypedDict):
    flow_count: int
    event_count: int
    hosts: dict[str, int]
    methods: dict[str, int]
    statuses: dict[str, int]
    events: dict[str, int]
    errors: dict[str, int]
    tls_failure_targets: dict[str, int]


class HttpRecord(TypedDict):
    kind: Literal["http_flow"]
    flow_id: str
    errored: bool
    ts_start: float
    ts_end: float
    duration_ms: int
    method: str
    url: str | None
    scheme: str
    host: str
    path: str | None
    status: int | None
    request_headers: dict[str, str]
    response_headers: dict[str, str] | None
    request_body_hash: str | None
    request_body_path: str | None
    request_body_size: int
    response_body_hash: str | None
    response_body_path: str | None
    response_decoded_path: str | None
    response_size: int
    response_size_on_wire: int
    response_content_type: str | None
    response_compression: str | None
    magic_bytes_hint: str | None
    is_unity_assetbundle: bool
    unitypy_summary_path: str | None
    client_ip: str | None
    server_ip: str | None


class OscFailure(TypedDict):
    status: Literal["error"]
    error: str


class AnalysisDetails(TypedDict, total=False):
    osc: OscPacket | OscFailure
    photon: PhotonPacket


class PacketEndpoint(TypedDict):
    address: str | None
    port: int | None


class RawDatagram(TypedDict, total=False):
    packet_number: int
    ts_utc: str
    capture_semantics: str
    backend: str
    direction: str
    loopback: bool
    source_address: str
    source_port: int
    destination_address: str
    destination_port: int
    payload_sha256: str
    payload_path: str
    payload_length: int
    pid_confidence: str


class AnalysisRecord(TypedDict, total=False):
    kind: str
    ts: float | None
    flow_id: str | None
    direction: str | None
    capture_semantics: str | None
    client: ConnectionSummary | str | None
    server: ConnectionSummary | None
    payload_hash: str | None
    payload_path: str | None
    size: int | None
    osc: OscPacket | OscFailure
    photon: PhotonPacket
    schema_version: int
    packet_number: int | None
    ts_utc: str | None
    backend: str | None
    loopback: bool | None
    source: PacketEndpoint
    destination: PacketEndpoint
    payload_sha256: str | None
    payload_length: int | None
    pid_confidence: str | None
