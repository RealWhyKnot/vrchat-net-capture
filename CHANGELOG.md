# Changelog

All notable user-visible changes to vrchat-net-capture are tracked here.

## Unreleased

- Added `VRChatNetCapture.exe`, a compiled Windows launcher for start/stop capture sessions.
- Added `build.ps1`, win-x64 publishing, release zips, manifests, and a tag-driven release workflow.
- Default capture mode is now mitmproxy local mode targeting `VRChat.exe`; regular Windows proxy mode remains available with `--mode regular`.
- Startup now asks before updating mitmproxy dependencies.
- Startup now asks before enabling OSC decoding, Photon-like UDP metadata, and Unity bundle metadata; all default to no.
- Added optional passive WinDivert raw UDP capture for selected realtime and OSC ports, with PCAPNG, packet index, and offline OSC/Photon metadata postprocessing.
- Added OSC datagram decoding for observed UDP stream payloads, with OSC argument values redacted unless explicitly enabled.
- Added proxy-observed Photon-like UDP metadata summaries for observed stream payloads; payload semantics are not decoded.
- Stream-derived UDP/TCP analysis records now label `capture_semantics` so proxy-observed data is not confused with passive wire-copy packet capture.
- Session-installed mitmproxy CA certificates are removed on stop by exact thumbprint unless `-KeepCert` is used.
- Captures now include `events.jsonl`, `events.json`, `summary.json`, `flows.mitm`, WebSocket payloads, stream payloads, and VRChat output-log URL correlation.
- Consolidated user documentation into README and removed standalone design/recon docs.
- Changed the project license from MIT to GPL-3.0-or-later and added release notices for bundled/runtime components.
