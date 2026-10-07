# VRChat net capture

I built this to answer one question: when a VRChat world loads something, where
does it come from? Point it at a live session and it records the HTTP(S) traffic,
WebSocket frames, TLS and DNS events, UDP datagrams, and the URLs VRChat writes to
its own log. You get a folder you can read afterwards.

It doesn't upload anything. Captures are written to `captures\<timestamp>\` on
your machine.

Windows only. It drives the Windows system proxy and the Windows certificate
store.

## Read this before you run it

Active capture changes two things on your machine while it runs. It installs the
mitmproxy CA into `Cert:\CurrentUser\Root`, and it points the Windows system proxy
at a local mitmdump. A clean stop undoes both.

On stop the app removes only the exact certificate thumbprint it installed in that
session. If the CA was already on your machine, it's left alone. Pass
`--keep-cert` to keep a session-installed CA between runs.

If a capture window is closed before cleanup runs, your proxy still points at a
dead port and nothing can reach the internet. Fix it with:

```powershell
.\VRChatNetCapture.exe stop
```

Packet-only mode doesn't install a CA, start mitmproxy or change the proxy.

## What you need

- Windows 10 or 11
- Python 3.11+ from python.org. The Microsoft Store stub doesn't work for this and
  is skipped on purpose.
- mitmproxy, for active HTTP capture. The app offers to install it.
- Administrator rights, only for `--raw-udp-capture`

## Running a capture

```powershell
.\VRChatNetCapture.exe
```

It finds Python and mitmproxy and warns you if VRChat is already running. Then it
saves your proxy settings and repoints them, offers the optional OSC, Photon and
Unity analysis (all off by default) and prints `READY`.

Launch VRChat after `READY`, not before. Unity reads the system proxy once at
startup. A VRChat that was already running never goes through the capture and
you'll get an empty session. Regular mode can start alongside a running VRChat,
but you'll miss the startup traffic, and existing connections keep the old
settings.

Ctrl+C stops mitmdump, restores your proxy and removes the session CA.

### Hosts that are always passed through

VRChat's own servers (`*.vrchat.cloud`, `*.vrchat.com`) and the local video
resolver (`localhost.youtube.com`) are never intercepted. VRChat's asset bundle
downloader checks against a CA bundle that comes with the game, and the local
resolver serves a self-signed certificate. Intercepting them means you can't
travel to any world that isn't cached and videos never load.

Anything you pass to `--mitm-ignore-hosts` is added to that set. If you do want to
intercept VRChat's own API, `--no-default-ignore-hosts` turns the default off and
the app warns you that worlds will fail.

### Common options

```powershell
.\VRChatNetCapture.exe --listen-port 8081
.\VRChatNetCapture.exe --mitm-ignore-hosts "(?i)^([a-z0-9-]+\.)*example\.test:\d+$"
.\VRChatNetCapture.exe --ignore-hosts api.vrchat.cloud,assets.vrchat.com
.\VRChatNetCapture.exe --no-analysis-prompts --no-update-prompt
.\VRChatNetCapture.exe --decode-osc --store-osc-values
.\VRChatNetCapture.exe --packet-only --raw-udp-capture
```

`--ignore-hosts` takes a comma-separated host list and leaves those hosts out of
what gets written. `--mitm-ignore-hosts` takes a `host:port` regex and stops those
hosts being intercepted at all. They're easy to mix up. `--help` lists the rest.

With `--raw-udp-capture` the tool also adds the UDP ports the running
`VRChat.exe` owns to the filter. That helps when VRChat has already opened its
dynamic ports. Capture workers are tied to the launcher. If mitmdump or the UDP
worker dies, the whole capture stops.

Mitmproxy's local mode isn't supported on purpose. It redirects the VRChat process
directly, and that can disrupt a live session.

## Reading a capture

```
captures/<timestamp>/
|-- .session.json
|-- .mitmproxy-cert.json
|-- .previous-proxy.json          # regular mode only
|-- flows.jsonl                   # one HTTP flow per line
|-- flows.json                    # flow array, written at shutdown
|-- events.jsonl                  # CONNECT/TLS/WebSocket/DNS/TCP/UDP events
|-- events.json                   # event array, written at shutdown
|-- summary.json                  # counts by host/status/event/error
|-- osc-events.jsonl              # optional decoded OSC datagrams
|-- osc-summary.json              # optional OSC counts by address/type tag
|-- photon-packets.jsonl          # optional Photon-like UDP metadata
|-- photon-summary.json           # optional Photon-like UDP counts
|-- network/realtime-udp.pcapng   # optional passive raw UDP capture
|-- network/packet-index.jsonl
|-- network/udp-datagrams.jsonl
|-- network/payloads/<sha>.udp.bin
|-- osc/osc-events.jsonl          # optional passive OSC analysis
|-- photon/photon-packets.jsonl   # optional passive Photon-like metadata
|-- vrchat-log-events.jsonl       # URL-bearing lines from VRChat's log
|-- vrchat-log-unmatched.jsonl    # log URLs with no matching captured flow
|-- bodies/<sha256>.bin
|-- websockets/<sha256>.ws.bin
|-- streams/<sha256>.<tcp|udp>.bin
|-- decoded/<sha256>.json|txt|m3u8|hex
`-- by-host/<host>/<time>__<METHOD>__<status>__<slug>__<flowid>.json
```

Start with `summary.json` for the host and status counts, then go to `by-host/`.
For most purposes VRChat's own hosts are noise. The interesting ones are usually
whatever doesn't look like VRChat.

Check `vrchat-log-unmatched.jsonl` when something seems to be missing. It lists
URLs that VRChat's log says it fetched but that never showed up as a captured
flow. Those are requests where interception failed without an error.

`stop` doesn't run the postprocess step. `summary.json`, `flows.json` and the log
correlation are written when you stop with Ctrl+C. After a `stop` you only have
the raw `flows.jsonl`, `events.jsonl`, `by-host/` and `bodies/`.

## Getting a good world capture

1. Close VRChat first if you want the startup traffic.
2. Start the capture and wait for `READY`.
3. Join the world fresh, ideally in a new instance.
4. Let the main UI or catalog finish loading.
5. Use it. Search, paging, play buttons, thumbnails, anything that should hit the
   network.
6. Let something play for a bit.
7. Leave the world cleanly, then stop the capture.

A typical world capture has one big JSON catalog plus lots of image fetches, HLS
playlists that point at separate media hosts, an API call per search, and TLS
failures where a host refused to be intercepted.

## What it won't do

- Photon payloads aren't decoded. With `--photon-metadata` you get ports, sizes,
  direction and low-confidence guesses at the header layout. Records under the
  capture root are marked `capture_semantics: "proxy_observed"`. Records under
  `network/` and `photon/` come from the passive WinDivert sidecar and use
  `"wire_copy"` with `pid_confidence: "none"`.
- OSC values are redacted unless you pass `--store-osc-values`. Decoding is opt-in and
  reads datagrams the backend already saw. It never binds VRChat's OSC ports or
  competes for them.
- Get past certificate pinning. Some hosts can't be intercepted. Look for
  `tls_failure_targets` in `summary.json` and TLS errors in `events.jsonl`. If a
  live session mustn't be disturbed at all, use packet-only mode.
- Unity bundles are archived as-is and detected by magic bytes.
  `--unity-metadata` adds a bounded object-type peek if UnityPy is installed.
  Pulling out textures, meshes, audio or repacked bundles is out of scope.

Authorization and cookie headers are redacted in the JSON output, and native
mitmproxy dump files aren't written at all.

## Development

```powershell
.\scripts\format.ps1
.\scripts\lint.ps1
.\build.ps1
.\build.ps1 -Package
```

`build.ps1` stamps a daily version into `version.txt` and publishes a win-x64
build into `dist/`. With `-Package` it also makes
`VRChatNetCapture-v<version>.zip` and a manifest. Pass `-Version` if you don't
want the version bumped.

The Python capture modules under `src/vrchat_net_capture` are copied into
`dist/python/` at publish time, not embedded. A stale `dist/` runs old capture
code. If behaviour looks out of date, compare `dist/version.txt` with
`version.txt`.

Releases are tag-driven:

```powershell
git tag vYYYY.M.D.N
git push origin vYYYY.M.D.N
```

Tags can have a `-beta` suffix. The repo hook stamps commit subjects from
`version.txt`, and the commit-message check rejects duplicate version stamps.

## License

[GPL-3.0-or-later](LICENSE). Release archives also include [NOTICE](NOTICE) for
bundled and runtime third-party components.
