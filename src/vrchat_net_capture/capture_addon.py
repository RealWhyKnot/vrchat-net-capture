from __future__ import annotations

import functools
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Set as AbstractSet

    from mitmproxy.addonmanager import Loader

from vrchat_net_capture.capture_config import capture_settings
from vrchat_net_capture.capture_process import (
    DEFAULT_CAPTURE_PROCESSES,
    CaptureProcessFilter,
    parse_process_names,
)
from vrchat_net_capture.capture_transport_hooks import CaptureTransportHooks


class CaptureAddon(CaptureTransportHooks):
    @staticmethod
    def load(loader: Loader) -> None:
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
        loader.add_option(
            name="decode_osc",
            typespec=bool,
            default=False,
            help="Decode OSC datagrams observed in captured UDP streams.",
        )
        loader.add_option(
            name="store_osc_values",
            typespec=bool,
            default=False,
            help="Store decoded OSC argument values instead of redacting them.",
        )
        loader.add_option(
            name="photon_metadata",
            typespec=bool,
            default=False,
            help="Summarize Photon-like UDP stream metadata without decoding payload semantics.",
        )
        loader.add_option(
            name="unity_metadata",
            typespec=bool,
            default=False,
            help="Run optional UnityPy metadata peeks for detected Unity bundles.",
        )
        loader.add_option(
            name="capture_processes",
            typespec=str,
            default=DEFAULT_CAPTURE_PROCESSES,
            help="Comma-separated program names to capture, along with the programs they start.",
        )
        loader.add_option(
            name="capture_all_processes",
            typespec=bool,
            default=False,
            help="Capture connections from every program that uses the proxy.",
        )

    def configure(self, updated: AbstractSet[str]) -> None:
        if "capture_all_processes" in updated:
            self.capture_all_processes = bool(capture_settings().capture_all_processes)
        if "capture_processes" in updated:
            self.process_filter = CaptureProcessFilter(parse_process_names(capture_settings().capture_processes))
        if "capture_all_processes" in updated or "capture_processes" in updated:
            self._clients.clear()

    def running(self) -> None:
        if self._started:
            return
        cap = capture_settings().capture_dir
        if not cap:
            logging.getLogger(__name__).error("capture_addon: --set capture_dir=<path> is required")
            sys.exit(2)

        self.capture_dir = Path(cap).resolve()
        self.bodies_dir = self.capture_dir / "bodies"
        self.decoded_dir = self.capture_dir / "decoded"
        self.by_host_dir = self.capture_dir / "by-host"
        self.websockets_dir = self.capture_dir / "websockets"
        self.streams_dir = self.capture_dir / "streams"
        self.flows_jsonl = self.capture_dir / "flows.jsonl"
        self.events_jsonl = self.capture_dir / "events.jsonl"
        self.osc_jsonl = self.capture_dir / "osc-events.jsonl"
        self.photon_jsonl = self.capture_dir / "photon-packets.jsonl"
        for directory in (self.bodies_dir, self.decoded_dir, self.by_host_dir, self.websockets_dir, self.streams_dir):
            directory.mkdir(parents=True, exist_ok=True)

        ignore = (capture_settings().ignore_hosts_list or "").strip()
        if ignore:
            self.ignore_hosts = {h.strip().lower() for h in ignore.split(",") if h.strip()}
        self.decode_osc = bool(capture_settings().decode_osc)
        self.store_osc_values = bool(capture_settings().store_osc_values)
        self.photon_metadata = bool(capture_settings().photon_metadata)
        self.unity_metadata = bool(capture_settings().unity_metadata)

        self._report_started()
        self._started = True

    def done(self) -> None:
        if not self.capture_dir:
            return
        try:
            self._write_artifacts()
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            logging.getLogger(__name__).log(
                logging.ERROR, "capture_addon: failed to write shutdown artifacts: %s", exc, exc_info=False
            )


@functools.cache
def __getattr__(name: str) -> list[CaptureAddon]:
    if name == "addons":
        return [CaptureAddon()]
    raise AttributeError(name)
