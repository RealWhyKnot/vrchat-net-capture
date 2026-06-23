# Changelog

All notable user-visible changes to vrchat-net-capture are tracked here.

## Unreleased

- Added `VRChatNetCapture.exe`, a compiled Windows launcher for start/stop capture sessions.
- Added `build.ps1`, win-x64 publishing, release zips, manifests, and a tag-driven release workflow.
- Default capture mode is now mitmproxy local mode targeting `VRChat.exe`; regular Windows proxy mode remains available with `--mode regular`.
- Startup now asks before updating mitmproxy dependencies.
- Session-installed mitmproxy CA certificates are removed on stop by exact thumbprint unless `-KeepCert` is used.
- Captures now include `events.jsonl`, `events.json`, `summary.json`, `flows.mitm`, WebSocket payloads, stream payloads, and VRChat output-log URL correlation.
- Consolidated user documentation into README and removed standalone design/recon docs.
