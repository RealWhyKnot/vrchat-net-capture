from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def default_vrchat_log_dir() -> Path:
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        return Path(user_profile) / "AppData" / "LocalLow" / "VRChat" / "VRChat"
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata).parent / "LocalLow" / "VRChat" / "VRChat"
    return Path.home() / "AppData" / "LocalLow" / "VRChat" / "VRChat"


def newest_output_log(log_dir: Path | None = None) -> Path | None:
    root = log_dir or default_vrchat_log_dir()
    if not root.exists():
        return None
    logs = sorted(root.glob("output_log_*.txt"), key=lambda p: (p.stat().st_mtime, p.name), reverse=True)
    return logs[0] if logs else None


def parse_vrchat_log(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            urls = URL_RE.findall(line)
            if not urls:
                continue
            category = classify_line(line)
            for url in urls:
                events.append(
                    {
                        "kind": "vrchat_log_url",
                        "line_number": line_number,
                        "category": category,
                        "url": trim_url(url),
                        "line": line.rstrip("\r\n"),
                    }
                )
    return events


def classify_line(line: str) -> str:
    lowered = line.lower()
    if "[string download]" in lowered:
        return "string_download"
    if "[image download]" in lowered:
        return "image_download"
    if "[video playback]" in lowered:
        return "video_playback"
    if "url" in lowered and "download" in lowered:
        return "download"
    return "url"


def mark_unmatched_log_urls(events: list[dict[str, Any]], flow_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    captured_urls = {str(record.get("url")) for record in flow_records if record.get("url")}
    unmatched: list[dict[str, Any]] = []
    for event in events:
        matched = event.get("url") in captured_urls
        event["captured_by_proxy"] = matched
        if not matched:
            unmatched.append(event)
    return unmatched


def trim_url(url: str) -> str:
    return url.rstrip(").,;]")
