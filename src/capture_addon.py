from __future__ import annotations

from typing import TYPE_CHECKING

from vrchat_net_capture import capture_addon

if TYPE_CHECKING:
    from vrchat_net_capture.capture_addon import CaptureAddon


def __getattr__(name: str) -> list[CaptureAddon]:
    return capture_addon.__getattr__(name)
