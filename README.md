# VRChat net capture

I built this to answer one question: when a VRChat world loads something, where
does it come from? Point it at a live session and it records the HTTP(S) traffic,
WebSocket frames, TLS and DNS events, UDP datagrams, and the URLs VRChat writes to
its own log. You get a folder you can read afterwards.

It doesn't upload anything. Captures are written to `captures\<timestamp>\` on
your machine.

Windows only. It drives the Windows system proxy and the Windows certificate
store.

[Reference](docs/reference.md) · [Changelog](CHANGELOG.md) · [Report a bug](https://github.com/RealWhyKnot/vrchat-net-capture/issues/new/choose) · [Security](.github/SECURITY.md)

## Read this before you run it

Active capture changes two things on your machine while it runs. It installs the
mitmproxy CA into `Cert:\CurrentUser\Root`, and it points the Windows system proxy
at a local mitmdump. A clean stop undoes both.

Only VRChat's traffic is decrypted. For each connection the proxy looks up which
program opened it, and anything other than `VRChat.exe` or a program VRChat
started (such as yt-dlp) goes through without being decrypted or saved. That
includes your browser, Discord and anything else that follows the system proxy
while a capture runs. If the lookup fails, the connection isn't decrypted.
`--capture-all-processes` turns this off and records every program that uses the
proxy.

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
- Python 3.10+ from python.org. The Microsoft Store stub doesn't work for this and
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

## What it won't do

- Photon payloads aren't decoded. With `--photon-metadata` you get ports, sizes,
  direction and low-confidence guesses at the header layout. Records under the
  capture root are marked `capture_semantics: "proxy_observed"`. Records under
  `network/` and `photon/` come from the passive WinDivert sidecar and use
  `"wire_copy"` with `pid_confidence: "none"`.
- OSC values are redacted unless you pass `--store-osc-values`. Decoding is opt-in and
  reads datagrams the backend already saw. It never binds VRChat's OSC ports or
  competes for them.
- It can't get past certificate pinning. Some hosts can't be intercepted. Look for
  `tls_failure_targets` in `summary.json` and TLS errors in `events.jsonl`. If a
  live session mustn't be disturbed at all, use packet-only mode.
- Unity bundles are archived as-is and detected by magic bytes.
  `--unity-metadata` adds a bounded object-type peek if UnityPy is installed.
  Pulling out textures, meshes, audio or repacked bundles is out of scope.

Authorization and cookie headers are redacted in the JSON output, and native
mitmproxy dump files aren't written at all.

## Development

Install development dependencies:

```powershell
uv sync --frozen
```

Run the full gate:

```powershell
bash .githooks/pre-push
```

Format or build:

```powershell
.\.github\lint\format.ps1
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

## Bug reports and changes

Open an [issue](https://github.com/RealWhyKnot/vrchat-net-capture/issues/new/choose) for bugs and ideas. Please don't send a pull request without talking to me first. [CONTRIBUTING.md](CONTRIBUTING.md) explains why.

## License

[GPL-3.0-or-later](LICENSE). Release archives also include [NOTICE](NOTICE) for
bundled and runtime third-party components.
