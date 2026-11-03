from __future__ import annotations

import functools
import importlib
from typing import TYPE_CHECKING, Protocol, TypeVar, cast

if TYPE_CHECKING:
    from mitmproxy.flow import Flow

    from vrchat_net_capture.capture_process import Address
    from vrchat_net_capture.capture_utils import UnityEnvironment
from mitmproxy import ctx

FlowType = TypeVar("FlowType", bound="Flow")


class ProcessFilter(Protocol):
    @property
    def names(self) -> frozenset[str]: ...

    def allows(self, client: Address | None, proxy: Address | None) -> bool: ...


class CaptureSettings(Protocol):
    capture_dir: str
    ignore_hosts_list: str
    decode_osc: bool
    store_osc_values: bool
    photon_metadata: bool
    unity_metadata: bool
    capture_processes: str
    capture_all_processes: bool


class UnityLoader(Protocol):
    def load(self, content: bytes) -> UnityEnvironment: ...


def capture_settings() -> CaptureSettings:
    return cast("CaptureSettings", ctx.options)


@functools.cache
def unity_loader() -> UnityLoader | None:
    try:
        module = importlib.import_module("UnityPy")
    except ImportError:
        return None
    return cast("UnityLoader", module)
