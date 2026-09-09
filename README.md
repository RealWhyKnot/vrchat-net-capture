# VRChat Net Capture

I built this to answer one question: when a VRChat world loads something, where
does it actually come from? Point it at a live session and it records the HTTP(S)
traffic, WebSocket frames, TLS and DNS events, UDP datagrams, and the URLs VRChat
writes to its own log, then leaves you a folder you can read.

Nothing is uploaded anywhere. Everything lands in `captures\<timestamp>\` on your
machine.

Windows only, because it drives the Windows system proxy and the Windows
certificate store.

## Read this before you run it

Active capture changes two things about your machine while it runs. It installs
the mitmproxy CA into `Cert:\CurrentUser\Root`, and it points the Windows system
proxy at a local mitmdump. Both are undone on a clean stop.

On stop the app removes only the exact certificate thumbprint it installed this
session. If that CA was already on your machine beforehand, it's left alone.
Pass `--keep-cert` if you'd rather hold onto a session-installed CA between runs.

If a capture window gets closed before cleanup runs, your proxy is still pointed
at a dead port and nothing will reach the internet. Fix it with:

```powershell
.\VRChatNetCapture.exe stop
```

Packet-only mode touches none of this. No CA, no mitmproxy, no proxy change.

## What you need

- Windows 10 or 11.
- Python 3.11+ from python.org. The Microsoft Store stub is skipped deliberately,
  it doesn't work for this.
- mitmproxy, for active HTTP capture. The app will offer to install it.
- Administrator, but only for `--raw-udp-capture`. Normal runs don't need it.

## Running a capture

```powershell
.\VRChatNetCapture.exe
```

That finds Python and mitmproxy, warns you if VRChat is already running, stashes
your proxy settings and repoints them, asks whether you want the optional OSC,
Photon and Unity analysis (all default to no), then prints `READY`.

**Launch VRChat after `READY`, not before.** Unity reads the system proxy once at
startup, so a VRChat that was already running never routes through the capture
and you'll get an empty session. Regular mode can start alongside a running
VRChat, but you'll miss startup traffic and existing connections keep using the
old settings.

Ctrl+C stops mitmdump, restores your proxy, and removes the session CA.

### Hosts that are always passed through

VRChat's own infrastructure (`*.vrchat.cloud`, `*.vrchat.com`) and the local video
resolver (`localhost.youtube.com`) bypass interception on every run. This isn't
tidiness, it's required. VRChat's asset bundle downloader validates against a CA
bundle shipped inside the game and the local resolver serves a self-signed
certificate, so intercepting either one breaks it: you can't travel to any world
that isn't already cached, and videos never load.

Anything you pass to `--mitm-ignore-hosts` is added to that set, never swapped
for it. If you genuinely want to intercept VRChat's own API, `--no-default-ignore-hosts`
turns the protection off, and the app will warn you that worlds will fail.

### Options worth knowing

```powershell
.\VRChatNetCapture.exe --listen-port 8081
.\VRChatNetCapture.exe --mitm-ignore-hosts "(?i)^([a-z0-9-]+\.)*example\.test:\d+$"
.\VRChatNetCapture.exe --ignore-hosts api.vrchat.cloud,assets.vrchat.com
.\VRChatNetCapture.exe --no-analysis-prompts --no-update-prompt
.\VRChatNetCapture.exe --decode-osc --store-osc-values
.\VRChatNetCapture.exe --packet-only --raw-udp-capture
```

`--ignore-hosts` takes a comma-separated host list and drops those from what gets
written. `--mitm-ignore-hosts` takes a `host:port` regex and stops them being
intercepted at all. They're different things and it's easy to reach for the wrong
one. `--help` lists the rest.

With `--raw-udp-capture` the tool also adds UDP ports owned by the running
`VRChat.exe` to the filter, which helps when VRChat already opened its dynamic
ports. Capture workers are linked to the launcher, so if mitmdump or the UDP
worker dies, the whole capture stops rather than half-running.

Mitmproxy's local mode is deliberately unsupported. It redirects the VRChat
process directly and that can disrupt a live session.

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

Start at `summary.json` for the shape of the session, then go to `by-host/`.
VRChat's own hosts are noise for most purposes; the interesting ones are usually
whatever doesn't look VRChat-affiliated.

`vrchat-log-unmatched.jsonl` is the one to check when something feels missing. It
lists URLs that VRChat's log says it fetched but that never showed up as a
captured flow, which is how you spot interception that silently failed.

Note that `stop` does not run the postprocess step. `summary.json`, `flows.json`
and the log correlation are written on Ctrl+C shutdown. After a `stop` you'll have
the raw `flows.jsonl`, `events.jsonl`, `by-host/` and `bodies/` and nothing else.

## Getting a good world capture

1. Close VRChat first if you want the startup traffic.
2. Start the capture and wait for `READY`.
3. Join the world fresh, ideally a new instance.
4. Let the main UI or catalog finish populating.
5. Exercise it. Search, paging, play buttons, thumbnails, anything that should hit
   the network.
6. Let something play for a bit.
7. Leave the world cleanly, then stop the capture.

What you usually find: one big JSON catalog plus a pile of image fetches, HLS
playlists pointing at separate media hosts, per-search API calls, and TLS failures
where a host refused to be intercepted.

## What it won't do

- **Photon payloads aren't decoded.** With `--photon-metadata` you get ports,
  sizes, direction and low-confidence header shape guesses, nothing more. Records
  under the capture root are marked `capture_semantics: "proxy_observed"`; records
  under `network/` and `photon/` come from the passive WinDivert sidecar and use
  `"wire_copy"` with `pid_confidence: "none"`.
- **OSC values are redacted** unless you pass `--store-osc-values`. Decoding is
  opt-in and reads datagrams the backend already saw. It never binds or competes
  for VRChat's OSC ports.
- **Certificate pinning wins.** Some hosts simply can't be intercepted. Look for
  `tls_failure_targets` in `summary.json` and TLS errors in `events.jsonl`. If a
  live session must not be disturbed at all, use packet-only mode.
- **Unity bundles are archived, not extracted.** They're detected by magic bytes.
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

`build.ps1` stamps a daily version into `version.txt`, publishes a win-x64 build
into `dist/`, and with `-Package` produces `VRChatNetCapture-v<version>.zip` and a
manifest. Pass `-Version` explicitly if you don't want the version bumped.

The Python capture modules under `src/vrchat_net_capture` are copied into
`dist/python/` at publish time rather than embedded, so a stale `dist/` runs old
capture logic. Check `dist/version.txt` against `version.txt` if behaviour looks
out of date.

Releases are tag-driven:

```powershell
git tag vYYYY.M.D.N
git push origin vYYYY.M.D.N
```

Tags may use a `-beta` suffix. Commit subjects are stamped from `version.txt` by
the repo hook, and the commit-message check rejects duplicate version stamps.

## License

[GPL-3.0-or-later](LICENSE). Release archives also ship [NOTICE](NOTICE) for
bundled and runtime third-party components.
