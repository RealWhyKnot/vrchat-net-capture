from __future__ import annotations

import logging
import traceback
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy import http

from vrchat_net_capture.capture_events import (
    build_event,
    http_connect_event,
    request_headers_event,
    response_headers_event,
)
from vrchat_net_capture.capture_recorder import CaptureRecorder


class CaptureHttpHooks(CaptureRecorder):
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
        except (OSError, ValueError, TypeError, AttributeError):
            logging.getLogger(__name__).log(
                logging.ERROR, "capture_addon: error while recording flow:\n%s", traceback.format_exc(), exc_info=False
            )

    def error(self, flow: http.HTTPFlow) -> None:
        if self._should_ignore_flow(flow):
            return
        try:
            self._record_flow(flow, errored=True)
            self._append_event(build_event("http_error", flow, error=str(flow.error) if flow.error else None))
        except (OSError, ValueError, TypeError, AttributeError):
            logging.getLogger(__name__).log(
                logging.ERROR,
                "capture_addon: error while recording errored flow:\n%s",
                traceback.format_exc(),
                exc_info=False,
            )

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if self._should_ignore_flow(flow):
            return
        try:
            self._write_websocket(flow)
        except (OSError, ValueError, TypeError, AttributeError):
            logging.getLogger(__name__).log(
                logging.ERROR,
                "capture_addon: error while recording WebSocket message:\n%s",
                traceback.format_exc(),
                exc_info=False,
            )

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        self._record_event_for_flow(flow, lambda f: build_event("websocket_end", f))
