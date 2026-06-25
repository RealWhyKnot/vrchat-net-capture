# VRChat Net Capture

VRChat Net Capture is a Windows capture tool for inspecting passive UDP, OSC,
Photon-like metadata, HTTP(S), WebSocket, TLS/connect, DNS, and VRChat
output-log evidence from a local VRChat session. The released app is
`VRChatNetCapture.exe`; regular system-proxy capture is the active HTTP/bundle
mode, and packet-only capture is available for passive UDP-only sessions.

The tool does not upload captures anywhere. Everything is written locally under
`captures\<timestamp>\`.

## Security

Active HTTP capture installs the mitmproxy CA into `Cert:\CurrentUser\Root`
while a capture is running and points Windows' system proxy at a local mitmdump
instance. Packet-only mode does not install a CA, run mitmproxy, or change the
Windows system proxy.

On stop, the app removes only the exact CA thumbprint that the current session
installed. If that CA already existed before the session, it is left alone. Use
`--keep-cert` if you want to keep a session-installed CA between runs.

## Requirements

- Windows 10/11.
- Python 3.11 or newer from python.org. The Microsoft Store `python.exe` stub is
  skipped.
- mitmproxy is required for active HTTP capture.
- Administrator approval is required for the default passive raw UDP packet
  capture backend.

## Usage

From the release folder:

```powershell
.\VRChatNetCapture.exe
```

Default behavior:

1. Finds Python and mitmproxy.
2. Warns if VRChat is already running.
3. Stashes current proxy settings, then points Windows at local mitmdump.
4. Asks whether to enable optional OSC, Photon metadata, and Unity metadata
   analysis. Each defaults to no.
5. Prints `READY`. Launch VRChat after that.
6. On Ctrl+C, stops mitmdump, restores proxy settings, and removes any session-installed CA.

Useful options:

```powershell
.\VRChatNetCapture.exe --mode regular
.\VRChatNetCapture.exe --mitm-ignore-hosts "(?i)^(api\.vrchat\.cloud|pipeline\.vrchat\.cloud):443$"
.\VRChatNetCapture.exe --listen-port 8081
.\VRChatNetCapture.exe --ignore-hosts api.vrchat.cloud,assets.vrchat.com
.\VRChatNetCapture.exe --keep-cert
.\VRChatNetCapture.exe --no-update-prompt
.\VRChatNetCapture.exe --packet-only --decode-osc --photon-metadata
.\VRChatNetCapture.exe --decode-osc
.\VRChatNetCapture.exe --photon-metadata
.\VRChatNetCapture.exe --unity-metadata
.\VRChatNetCapture.exe --raw-udp-capture
.\VRChatNetCapture.exe --raw-udp-ports 27000-27002,9000,9001
.\VRChatNetCapture.exe --no-analysis-prompts
.\VRChatNetCapture.exe stop
```

When raw UDP capture is enabled, VRChat Net Capture also adds UDP ports owned by
the currently running `VRChat.exe` process to the capture filter. This helps
existing sessions where VRChat has already opened dynamic local UDP ports. Raw
UDP capture requires running VRChat Net Capture as Administrator. Long-running
capture workers are linked to the launcher; if mitmdump or the raw UDP worker
stops, the rest of the capture is stopped too.

Use `stop` if a capture window was closed before cleanup ran.

Mitmproxy local mode is intentionally not supported. It redirects the VRChat
process directly and can disrupt live sessions. Regular mode can start while
VRChat is already running, but existing traffic may keep using old proxy
settings and startup traffic is already gone. For a complete startup capture,
wait for the `READY` banner, then launch VRChat.

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
|-- osc-events.jsonl              # optional decoded OSC datagrams
|-- osc-summary.json              # optional OSC counts by address/type tag
|-- photon-packets.jsonl          # optional proxy-observed Photon-like UDP metadata
|-- photon-summary.json           # optional Photon-like UDP counts
|-- network/realtime-udp.pcapng   # optional passive raw UDP packet capture
|-- network/packet-index.jsonl    # optional passive packet index
|-- network/udp-datagrams.jsonl   # optional UDP payload index
|-- network/payloads/<sha>.udp.bin
|-- osc/osc-events.jsonl          # optional passive OSC analysis
|-- photon/photon-packets.jsonl   # optional passive Photon-like metadata
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

For a useful low-disruption world run:

1. Close VRChat if you need startup traffic.
2. Start VRChat Net Capture and wait for the `READY` banner.
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
- Optional OSC datagrams in `osc-events.jsonl` when OSC decoding is enabled.
- Optional proxy-observed Photon-like UDP metadata in `photon-packets.jsonl`
  when Photon metadata is enabled.
- Optional passive raw UDP packet evidence under `network/` when
  `--raw-udp-capture` is enabled.

Packet-only mode is the default and is the least intrusive live-session capture.
It skips mitmproxy, CA installation, and proxy changes, then runs only the
passive raw UDP backend plus offline analysis.

## Limits

- Photon payload semantics are not decoded. With `--photon-metadata`,
  observed UDP datagrams are classified only as metadata candidates with ports,
  sizes, direction, and low-confidence header shape guesses. Records under the
  capture root are `capture_semantics: "proxy_observed"`. Records under
  `network/` and `photon/` come from the optional passive WinDivert sidecar and
  use `capture_semantics: "wire_copy"` with `pid_confidence: "none"` until flow
  PID correlation is added.
- OSC decoding is opt-in with `--decode-osc` or the startup prompt. It decodes
  datagrams already observed by the capture backend and redacts argument values
  unless `--store-osc-values` is used. It does not bind or compete for VRChat's
  OSC ports. If `--raw-udp-capture` is also enabled, offline passive OSC output
  is written under `osc/`.
- Certificate pinning can prevent HTTPS interception. Look for
  `tls_failure_targets` in `summary.json`, TLS/connect errors in `events.jsonl`,
  and unmatched VRChat log URLs. Prefer packet-only mode when a live VRChat
  session must not be interrupted.
- Sensitive HTTP headers such as authorization and cookie headers are redacted
  in JSON outputs. Native mitmproxy dump files are not written by default.
- Unity asset bundles are detected by magic bytes and archived. With
  `--unity-metadata`, UnityPy can write a bounded object-type metadata peek when
  it is installed. Exporting textures, meshes, audio, video, scripts, scenes, or
  repacked bundles is out of scope.

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

[GPL-3.0-or-later](LICENSE). Release archives also include [NOTICE](NOTICE) for
bundled and runtime third-party components.
