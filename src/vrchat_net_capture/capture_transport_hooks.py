from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.connection import Client
    from mitmproxy.dns import DNSFlow
    from mitmproxy.proxy.server_hooks import ServerConnectionHookData
    from mitmproxy.tcp import TCPFlow
    from mitmproxy.tls import ClientHelloData, TlsData
    from mitmproxy.udp import UDPFlow

from vrchat_net_capture.capture_events import (
    build_event,
    dns_event,
    tls_clienthello_event,
)
from vrchat_net_capture.capture_http_hooks import CaptureHttpHooks


class CaptureTransportHooks(CaptureHttpHooks):
    def tcp_message(self, flow: TCPFlow) -> None:
        self._record_stream_event("tcp_message", flow, ".tcp.bin")

    def tcp_end(self, flow: TCPFlow) -> None:
        self._record_event_for_flow(flow, lambda f: build_event("tcp_end", f))

    def tcp_error(self, flow: TCPFlow) -> None:
        self._record_event_for_flow(
            flow, lambda f: build_event("tcp_error", f, error=str(f.error) if f.error else None)
        )

    def udp_message(self, flow: UDPFlow) -> None:
        self._record_stream_event("udp_message", flow, ".udp.bin")

    def udp_end(self, flow: UDPFlow) -> None:
        self._record_event_for_flow(flow, lambda f: build_event("udp_end", f))

    def udp_error(self, flow: UDPFlow) -> None:
        self._record_event_for_flow(
            flow, lambda f: build_event("udp_error", f, error=str(f.error) if f.error else None)
        )

    def dns_request(self, flow: DNSFlow) -> None:
        self._record_event_for_flow(flow, lambda f: dns_event("dns_request", f))

    def dns_response(self, flow: DNSFlow) -> None:
        self._record_event_for_flow(flow, lambda f: dns_event("dns_response", f))

    def dns_error(self, flow: DNSFlow) -> None:
        self._record_event_for_flow(flow, lambda f: dns_event("dns_error", f))

    def tls_clienthello(self, data: ClientHelloData) -> None:
        if not self._client_allowed(data.context.client):
            data.ignore_connection = True
            return
        self._append_event(tls_clienthello_event(data))

    def tls_established_client(self, data: TlsData) -> None:
        self._record_tls_event("tls_established_client", data)

    def tls_established_server(self, data: TlsData) -> None:
        self._record_tls_event("tls_established_server", data)

    def tls_failed_client(self, data: TlsData) -> None:
        self._record_tls_event("tls_failed_client", data)

    def tls_failed_server(self, data: TlsData) -> None:
        self._record_tls_event("tls_failed_server", data)

    def server_connect(self, data: ServerConnectionHookData) -> None:
        self._record_server_event("server_connect", data)

    def server_connected(self, data: ServerConnectionHookData) -> None:
        self._record_server_event("server_connected", data)

    def server_connect_error(self, data: ServerConnectionHookData) -> None:
        self._record_server_event("server_connect_error", data)

    def client_connected(self, client: Client) -> None:
        if self._client_allowed(client):
            self._append_event(build_event("client_connected", None, client=str(client)))

    def client_disconnected(self, client: Client) -> None:
        allowed = self._client_allowed(client)
        self._clients.pop(client.id, None)
        if allowed:
            self._append_event(build_event("client_disconnected", None, client=str(client)))
