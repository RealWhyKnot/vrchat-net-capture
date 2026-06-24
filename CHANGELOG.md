# Changelog

All notable user-visible changes to vrchat-net-capture are tracked here.

## Unreleased

- Added `VRChatNetCapture.exe`, a compiled Windows launcher for start/stop capture sessions.
- Added `build.ps1`, win-x64 publishing, release zips, manifests, and a tag-driven release workflow.
- Removed mitmproxy local mode because redirecting the VRChat process can disrupt live sessions.
- Default active HTTP capture uses regular system proxy mode; start capture before launching VRChat.
- Startup now asks before updating mitmproxy dependencies.
- Startup now asks before enabling OSC decoding, Photon-like UDP metadata, and Unity bundle metadata; all default to no.
- Added optional passive WinDivert raw UDP capture for selected realtime and OSC ports, with PCAPNG, packet index, and offline OSC/Photon metadata postprocessing.
- Added `--packet-only` for passive UDP capture without mitmproxy, CA installation, or proxy changes.
- Raw UDP capture now adds currently observed VRChat-owned UDP socket ports to the WinDivert filter.
- Capture child processes are tracked as one process group, and mitmdump/raw UDP shutdown now stops the whole capture.
- Removed unused `5055`, `5056`, and `5058` ports from the default raw UDP and Photon metadata filters.
- Python capture modules now live under `src/vrchat_net_capture`.
- Added OSC datagram decoding for observed UDP stream payloads, with OSC argument values redacted unless explicitly enabled.
- Added proxy-observed Photon-like UDP metadata summaries for observed stream payloads; payload semantics are not decoded.
- Stream-derived UDP/TCP analysis records now label `capture_semantics` so proxy-observed data is not confused with passive wire-copy packet capture.
- Redacts sensitive HTTP headers in JSON outputs and no longer writes native mitmproxy flow dumps by default.
- Session-installed mitmproxy CA certificates are removed on stop by exact thumbprint unless `-KeepCert` is used.
- Captures now include `events.jsonl`, `events.json`, `summary.json`, WebSocket payloads, stream payloads, and VRChat output-log URL correlation.
- Consolidated user documentation into README and removed standalone design/recon docs.
- Changed the project license from MIT to GPL-3.0-or-later and added release notices for bundled/runtime components.
