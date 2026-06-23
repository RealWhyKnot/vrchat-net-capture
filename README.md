# VRChat Net Capture

VRChat Net Capture is a Windows capture tool for inspecting the HTTP(S),
WebSocket, TLS/connect, DNS, TCP, UDP, and VRChat output-log evidence from a
local VRChat session. The released app is `VRChatNetCapture.exe`; mitmproxy
does the network interception and the bundled Python addon writes the capture
artifacts.

The tool does not upload captures anywhere. Everything is written locally under
`captures\<timestamp>\`.

## Security

VRChat Net Capture installs the mitmproxy CA into `Cert:\CurrentUser\Root` while
a capture is running. The default local capture mode targets `VRChat.exe`
without changing the Windows system proxy. If you use `--mode regular`, the app
also points Windows' system proxy at a local mitmdump instance.

On stop, the app removes only the exact CA thumbprint that the current session
installed. If that CA already existed before the session, it is left alone. Use
`--keep-cert` if you want to keep a session-installed CA between runs.

## Requirements

- Windows 10/11.
- Python 3.11 or newer from python.org. The Microsoft Store `python.exe` stub is
  skipped.
- mitmproxy 10.2 or newer. If it is missing, the app installs it with pip. On
  startup, the app asks whether to update mitmproxy dependencies.

## Usage

From the release folder:

```powershell
.\VRChatNetCapture.exe
```

Default behavior:

1. Finds Python.
2. Installs mitmproxy if missing.
3. Asks whether to update mitmproxy.
4. Installs the mitmproxy CA for the current user.
5. Starts `mitmdump --mode local:VRChat.exe`.
6. Prints `READY`. Launch VRChat after that.
7. On Ctrl+C, stops mitmdump and removes the session CA.

Useful options:

```powershell
.\VRChatNetCapture.exe --mode regular
.\VRChatNetCapture.exe --mode local --local-target VRChat.exe
.\VRChatNetCapture.exe --listen-port 8081
.\VRChatNetCapture.exe --ignore-hosts api.vrchat.cloud,assets.vrchat.com
.\VRChatNetCapture.exe --keep-cert
.\VRChatNetCapture.exe --no-update-prompt
.\VRChatNetCapture.exe stop
```

Use `stop` if a capture window was closed before cleanup ran.

## Output

```
captures/<timestamp>/
|-- .session.json
|-- .mitmproxy-cert.json
|-- .previous-proxy.json          # regular mode only
|-- flows.jsonl                   # one HTTP flow per line
|-- flows.json                    # HTTP flow array written at shutdown
|-- events.jsonl                  # CONNECT/TLS/WebSocket/DNS/TCP/UDP events
|-- events.json                   # event array written at shutdown
|-- summary.json                  # counts by host/status/event/error
|-- flows.mitm                    # native mitmproxy dump
|-- vrchat-log-events.jsonl       # URL-bearing VRChat log lines
|-- vrchat-log-unmatched.jsonl    # log URLs not matched by captured HTTP flows
|-- bodies/<sha256>.bin
|-- websockets/<sha256>.ws.bin
|-- streams/<sha256>.<tcp|udp>.bin
|-- decoded/<sha256>.json|txt|m3u8|hex
`-- by-host/<host>/<time>__<METHOD>__<status>__<slug>__<flowid>.json
```

Start with `summary.json`, then inspect `by-host/`. VRChat infrastructure hosts
such as `api.vrchat.cloud`, `assets.vrchat.com`, `files.vrchat.cloud`, and
`pipeline.vrchat.cloud` are common. World-specific backends are usually hosts
that do not look VRChat-affiliated.

`vrchat-log-unmatched.jsonl` is the missed-traffic checklist: it contains URLs
seen in VRChat's own output log that did not exactly match a captured HTTP flow.

## Capture Method

For a useful world recon run:

1. Start VRChat Net Capture first.
2. Launch VRChat after the `READY` banner.
3. Enter the world fresh, preferably a new instance.
4. Wait for the main UI/catalog to populate.
5. Trigger search, paging, play buttons, images, and any controls that should
   touch the network.
6. Let playback run briefly.
7. Quit or leave the world cleanly.
8. Stop the capture.

Common patterns:

- One large JSON catalog plus many image fetches.
- HLS playlists pointing to media segment hosts.
- Per-search or per-page API requests.
- WebSocket messages in `events.jsonl` plus payloads in `websockets/`.
- TLS/connect failures where a target cannot be intercepted.

## Limits

- Photon multiplayer traffic is not decoded.
- OSC loopback traffic is not decoded.
- Certificate pinning can prevent HTTPS interception. Look for TLS/connect
  errors and unmatched VRChat log URLs.
- Unity asset bundles are detected by magic bytes and archived; deep bundle
  extraction is out of scope.

## Development

```powershell
.\scripts\format.ps1
.\scripts\lint.ps1
.\build.ps1
.\build.ps1 -Package
```

`build.ps1` writes a local daily version to `version.txt`, publishes a win-x64
distribution into `dist/`, and can create `VRChatNetCapture-v<version>.zip`
plus a manifest.

Releases are tag-driven:

```powershell
git tag vYYYY.M.D.N
git push origin vYYYY.M.D.N
```

Release tags may also use `-beta`. Commit subjects are stamped from
`version.txt` by the repo hook and the commit-message check rejects duplicate
version stamps.

## License

[MIT](LICENSE).
