# vrchat-net-capture

A one-shot HTTPS-decrypting proxy for Windows that captures every HTTP/HTTPS
request VRChat makes during a play session, decodes responses, and sorts
them per-host. Built on top of [mitmproxy](https://mitmproxy.org/).

> **Security note:** this tool installs the mitmproxy CA into your
> CurrentUser trust store and points Windows' system proxy at a local
> mitmdump. While it is running, the local proxy can MITM every HTTPS
> connection your user account makes. That is necessary for the tool to
> work, but worth being aware of. Removal instructions are below.

This tool does not transmit captures anywhere, does not attempt DRM
circumvention, and writes everything to a local `captures/<timestamp>/`
directory.

## What it does, in one sentence

Brings up a local proxy that records every HTTP(S) request VRChat makes,
decoded into a human-browseable directory tree, then cleans up after
itself when you Ctrl+C.

## Files in this repo

| File | Role |
| --- | --- |
| `start-capture.ps1` | Orchestrator — installs cert, sets system proxy, launches mitmdump, restores everything on exit. |
| `stop-capture.ps1`  | Belt-and-suspenders cleanup if `start-capture.ps1` was killed without its `finally {}` running. |
| `capture_addon.py`  | mitmproxy addon — per-flow logging, decoding, hashing, per-host sorting. |
| `requirements.txt`  | `pip install -r requirements.txt` deps. |
| `RECON.md`          | Methodology guide — how to scope a session and interpret the output. |
| `DESIGN.md`         | Why the tool is shaped the way it is. |
| `captures/`         | Per-session output (gitignored). |

## Prerequisites

1. **Windows 10/11.** PowerShell 5.1 or 7+ both work.
2. **Python 3.11 or newer** from [python.org](https://www.python.org/downloads/windows/).
   The Microsoft Store stub at
   `%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe` is **not** real
   Python — uninstall it from `Settings → Apps → App execution aliases`
   or install real Python and let it take PATH priority.
   - The script auto-detects and skips the Store stub but still needs a
     real interpreter somewhere.
3. **mitmproxy** — installed automatically into Python's user site by
   `start-capture.ps1` if missing. To install yourself:
   ```
   python -m pip install --user mitmproxy
   ```
4. **VRChat closed** when you start the proxy. Launch it *after* you see
   the `READY` banner.

## Usage

From a PowerShell prompt in this directory:

```powershell
.\start-capture.ps1
```

Sequence:

1. Python + mitmproxy resolution.
2. CA install on first run (uses CurrentUser store — no admin needed).
3. Proxy stash + set.
4. mitmdump launch.
5. Big green `READY` banner. Launch VRChat and visit the world(s) you
   want to study.
6. When you're done, Ctrl+C. The script will:
   - kill mitmdump,
   - restore your previous proxy settings,
   - leave the capture intact at `captures\<timestamp>\`.

If the PowerShell window was closed with the X button (so the cleanup
`finally {}` never ran) and your network is now broken because the system
proxy still points at a dead local port, run:

```powershell
.\stop-capture.ps1
```

## Output

```
captures/<timestamp>/
├── flows.jsonl            # one JSON object per request, append-only
├── flows.json             # same data as an array, written at shutdown
├── bodies/<sha256>.bin    # raw decompressed response bodies
├── decoded/<sha256>.json  # pretty-printed where applicable
│       <sha256>.txt
│       <sha256>.m3u8
│       <sha256>.hex       # 256-byte hex preview for binaries
└── by-host/<host>/<ts>__<METHOD>__<status>__<slug>__<flowid>.json
```

`by-host/<host>/` is the per-server view. VRChat's own infrastructure
(`api.vrchat.cloud`, `assets.vrchat.com`, etc.) will dominate the
listing; the world-specific backends are usually one or two hosts that
don't look VRChat-affiliated. See [RECON.md](RECON.md) for a worked
methodology.

## Removing the CA when you're done

The script intentionally does not remove the CA on shutdown — installing
it triggers a once-per-run prompt that gets noisy. To remove it:

```powershell
Get-ChildItem Cert:\CurrentUser\Root |
    Where-Object Subject -match 'mitmproxy' |
    Remove-Item
```

Or via `certutil`:

```
certutil -delstore -user Root mitmproxy
```

## Caveats

- **Some apps ignore the system proxy.** VRChat's standard HTTP requests
  (`[String Download]`, `[Image Download]`, asset bundle downloads, the
  VRChat REST API) all go through .NET's HttpClient, which honours the
  WinINET proxy — those *will* be captured. If something is missing
  (e.g. a bare-socket protocol), the proxy can't see it; that's where
  you'd reach for Wireshark or a system-wide hook.
- **Photon (the multiplayer transport) is UDP**, not HTTP. It will not
  appear in this capture. That's expected.
- **TLS pinning** would defeat the proxy. Symptom: a flow record with
  `errored: true` and `response_body_hash: null` for the affected host.

## Troubleshooting

- *"mitmdump did not bind 127.0.0.1:8080 within 10s"* — port already in
  use. Re-run with `-ListenPort 8081`.
- *"CurrentUser cert install failed"* — install manually and re-run
  with `-NoCertInstall`:
  ```
  certutil -addstore -user Root "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"
  ```
- *"After running, my browser shows TLS errors"* — the proxy is still
  set. Run `.\stop-capture.ps1`.
- *VRChat refuses to launch / can't auth* — same as above; restore proxy.

## License

[MIT](LICENSE).
