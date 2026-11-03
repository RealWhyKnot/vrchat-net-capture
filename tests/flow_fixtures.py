from __future__ import annotations

from mitmproxy import connection, http, options, tcp, tls, websocket
from mitmproxy.proxy.context import Context
from wsproto.frame_protocol import Opcode


def client(port: int) -> connection.Client:
    return connection.Client(
        peername=("127.0.0.1", port),
        sockname=("127.0.0.1", 8080),
        id=f"client-{port}",
        timestamp_start=1.0,
    )


def request(host: str, path: str, headers: list[tuple[str, str]]) -> http.Request:
    return http.Request(
        host=host,
        port=443,
        method=b"GET",
        scheme=b"https",
        authority=b"",
        path=path.encode("utf-8"),
        http_version=b"HTTP/1.1",
        headers=http.Headers([(key.encode(), value.encode()) for key, value in headers]),
        content=b"",
        trailers=None,
        timestamp_start=1.0,
        timestamp_end=2.0,
    )


def make_http_flow(connection_client: connection.Client | None = None) -> http.HTTPFlow:
    peer = connection_client if connection_client is not None else client(50001)
    server = connection.Server(address=None, id="server")
    flow = http.HTTPFlow(peer, server)
    flow.id = "flow-2"
    flow.request = request(
        "worlds.example.test",
        "/do_auth?authToken=secret-token&lang=en",
        [
            ("Authorization", "Bearer secret"),
            ("Cookie", "auth=secret"),
            ("X-Auth-Token", "secret"),
            ("Accept", "application/json"),
        ],
    )
    flow.response = http.Response(
        http_version=b"HTTP/1.1",
        status_code=200,
        reason=b"OK",
        headers=http.Headers([(b"Set-Cookie", b"auth=secret; Path=/"), (b"Content-Type", b"application/json")]),
        content=b"",
        trailers=None,
        timestamp_start=1.0,
        timestamp_end=2.0,
    )
    return flow


def make_flow(message: bytes = b"hello", *, from_client: bool = True, is_text: bool = True) -> http.HTTPFlow:
    flow = make_http_flow()
    flow.id = "flow-1"
    flow.request = request("pipeline.vrchat.cloud", "/socket", [])
    flow.request.scheme = "wss"
    flow.websocket = websocket.WebSocketData()
    flow.websocket.messages = [
        websocket.WebSocketMessage(
            Opcode.TEXT if is_text else Opcode.BINARY,
            from_client=from_client,
            content=message,
            timestamp=1.0,
        )
    ]
    return flow


def stream_flow(connection_client: connection.Client, content: bytes = b"secret") -> tcp.TCPFlow:
    flow = tcp.TCPFlow(connection_client, connection.Server(address=None, id="server"))
    flow.id = "flow"
    flow.messages = [tcp.TCPMessage(from_client=True, content=content, timestamp=1.0)]
    return flow


def hello(connection_client: connection.Client) -> tls.ClientHelloData:
    context = Context(connection_client, options.Options())
    packet = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x00\x2f\x01\x00\x00\x00"
    return tls.ClientHelloData(context, tls.ClientHello(packet))
