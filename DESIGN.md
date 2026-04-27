# DESIGN — vrchat-net-capture

## Goal (one paragraph)

A one-script, one-shot Windows tool that brings up an HTTPS-decrypting
proxy, sets the system proxy to it, captures every HTTP(S) flow VRChat
makes during a play session, decodes/decompresses bodies, sorts them
per-host with a flat JSON index, and tears everything down on Ctrl+C —
including reverting the system proxy. Output is a self-contained
`captures/<timestamp>/` directory the user can browse and copy paste from.

## Why mitmproxy

I considered three options for the on-machine proxy:

| Option | Pro | Con |
| --- | --- | --- |
| **mitmproxy / mitmdump** with a Python addon | Pure Python addon API, well-documented, has a native CA install path, decompresses gzip/br automatically, ships an HTTP CONNECT-aware MITM | Needs Python on the machine |
| Fiddler (Classic / Everywhere) | GUI, easy cert install | GUI-only, scripting is JScript or .NET, harder to make "one-shot" |
| WinDivert + custom proxy | Catches Unity even if it ignores the system proxy | Big build effort, not worth it for a recon tool |

**Picked: mitmproxy/mitmdump.** It is the right level of abstraction for a
~500-line tool. If Unity ignores the system proxy on this machine
(see "fallback" below), we'll add WinDivert later — but in practice VRChat
on Windows does honor `WinHttpRegisterProxy`-style settings on the
.NET 4.x HttpClient it uses for `[String Download]` / `[Image Download]`
/ asset bundle fetches.

## Component diagram

```
              user                                Windows
                |                                 ┌────────────────┐
                v                                 │  IE / WinINET  │
   start-capture.ps1   ──── set system proxy ───▶ │  proxy = 127…  │
        │                                         └───────┬────────┘
        │ spawn                                           │
        ▼                                                 │
    mitmdump.exe ──────── HTTPS via local CA ◀────────────┤
        │                                                 │
        │ loads                                           │
        ▼                                          VRChat / Unity
    capture_addon.py                                     │
        │                                                │
        ├── per-flow: request + response                ◀┘
        ├── decompress, pretty-print, hex-preview
        ├── write bodies/<sha256>.bin
        ├── append to flows.jsonl
        └── per-host folder symlinks/copies for browsing

   ── Ctrl+C ──▶ start-capture.ps1 finally{}
                  │
                  ├── kill mitmdump
                  ├── restore previous proxy settings
                  └── (CA stays installed; revert is a separate command)
```

## Step-by-step user flow

1. `pwsh -File .\start-capture.ps1`
   - Verifies admin (needed for cert install on first run).
   - Verifies Python and mitmproxy are on PATH; installs mitmproxy via
     pip if missing.
   - Generates the mitmproxy CA on first run (in `~/.mitmproxy`), then
     imports it into the **CurrentUser\Root** store (no admin needed
     for that store on modern Windows; if it fails, falls back to
     LocalMachine\Root which does need admin and re-elevates).
   - Reads current Internet Settings proxy configuration from
     `HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
     and stashes it in `captures/<ts>/.previous-proxy.json`.
   - Sets `ProxyEnable=1`, `ProxyServer=127.0.0.1:8080`,
     `ProxyOverride=<local>` and notifies WinINET via
     `InternetSetOption(INTERNET_OPTION_SETTINGS_CHANGED)`.
   - Spawns `mitmdump -s capture_addon.py --listen-host 127.0.0.1
     --listen-port 8080 --set confdir=...` as a child process.
   - Prints "READY — launch VRChat now. Ctrl+C to stop." and waits.
2. Inside `try { Wait-Process mitmdump } finally {}` so any exit path —
   normal, Ctrl+C, throw — restores proxy state.
3. `stop-capture.ps1` exists for the case where the user closes the
   PowerShell window with the X button (orphaned mitmdump). It scans
   for orphan mitmdump processes spawned by us, kills them, and runs
   the same proxy-restore code path.

## Output layout

```
captures/2026-04-27_17-05-12/
├── .previous-proxy.json        # what we restore on shutdown
├── flows.jsonl                  # one line per flow, append-only
├── flows.json                   # array of all flows, written at shutdown
├── bodies/
│   ├── 5f3a...e1.bin            # raw response body, sha256 of body as name
│   └── ...
├── decoded/
│   ├── 5f3a...e1.json           # pretty-printed if JSON
│   ├── 5f3a...e1.txt            # decoded UTF-8 text
│   └── 5f3a...e1.hex            # first 256 bytes hex preview for binaries
└── by-host/
    ├── api.vrchat.cloud/        # one symlink-or-copy per flow, named by ts+url-slug
    ├── assets.vrchat.com/
    ├── <world-backend-host>/    # whatever backend(s) the world(s) you visit talked to
    └── _other/
```

`flows.jsonl` schema (one JSON object per line):
```json
{
  "flow_id": "uuid",
  "ts_start": 1714240000.123,
  "ts_end": 1714240000.456,
  "method": "GET",
  "url": "https://example-host.tld/api/catalog/abcd-1234",
  "host": "example-host.tld",
  "path": "/api/catalog/abcd-1234",
  "status": 200,
  "request_headers": {...},
  "response_headers": {...},
  "request_body_hash": null,
  "response_body_hash": "5f3a...e1",
  "response_body_path": "bodies/5f3a...e1.bin",
  "response_decoded_path": "decoded/5f3a...e1.json",
  "response_size": 12345,
  "response_content_type": "application/json",
  "response_compression": "br",
  "magic_bytes_hint": null,
  "is_unity_assetbundle": false,
  "client_ip": "127.0.0.1",
  "server_ip": "172.x.x.x"
}
```

## Decoding strategy in `capture_addon.py`

For each response:
1. Hash the **decompressed** body with sha256 → `<hash>.bin` written
   verbatim into `bodies/`.
2. Detect family by Content-Type and magic bytes:
   - `application/json` (or starts with `{`/`[` after possible BOM) →
     parse + pretty-print into `decoded/<hash>.json`.
   - text-shaped (`text/*`, `application/xml`, etc.) → write UTF-8
     decoded `decoded/<hash>.txt` (best-effort, errors='replace').
   - Unity asset bundle (magic `UnityFS` / `UnityRaw` / `UnityWeb`) →
     mark `is_unity_assetbundle: true`, write a hex preview, do **not**
     try to extract by default.
   - HLS playlist (`#EXTM3U` or content-type `application/vnd.apple.mpegurl`)
     → write as `decoded/<hash>.m3u8`.
   - Anything else → hex preview of first 256 bytes only.
3. Optional `UnityPy` peek if installed:
   - If `import UnityPy` succeeds and the body is a Unity asset bundle,
     attempt `UnityPy.load(bytes)` and dump asset names/types into
     `decoded/<hash>.unitypy.txt`. **Wrapped in try/except — failure is
     logged but does not break the addon.**

For each request body (rare for these worlds, but possible):
- If non-empty, hash + save under `bodies/`. Same Content-Type sniff.
- Reference the hash in the flow record.

## Filtering / noise reduction

Two-pronged:
1. **Capture everything** — don't drop traffic at the proxy, the user
   needs the full picture.
2. **Sort during write** — `by-host/` directory makes it trivial for
   the user to ignore api.vrchat.cloud noise and focus on the world's
   own backend.

There is also a `--ignore-host` option in mitmproxy that we expose via
an env var (`VRC_CAPTURE_IGNORE_HOSTS`, comma-separated). Default empty
— the user should see VRChat traffic the first time so they can verify
nothing world-related is being dropped.

## Cert lifecycle

- **Install:** on first start. Imported into CurrentUser\Root via
  `certutil -addstore -user Root <pem>` (no admin) **OR** PowerShell's
  `Import-Certificate -CertStoreLocation Cert:\CurrentUser\Root`. We
  do NOT install into LocalMachine unless CurrentUser fails. Reason:
  scope-of-blast-radius — only this user trusts the cert.
- **Persistence:** intentionally left in place on shutdown. Removing
  and reinstalling on every run would prompt the OS each time. The
  README documents how to remove manually if the user wants it gone.
- **Ownership notice:** the README is loud about the fact that
  installing a CA gives that key the ability to MITM all your HTTPS.
  This is acceptable for a recon tool you run on your own machine
  briefly, but not something to forget about.

## System-proxy lifecycle (the critical bit)

Implemented in PowerShell so we don't depend on a Python proxy-config
library. Both start and stop:

```powershell
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
# stash:
$prev = Get-ItemProperty -Path $key |
        Select-Object ProxyEnable, ProxyServer, ProxyOverride
# set:
Set-ItemProperty $key ProxyEnable 1
Set-ItemProperty $key ProxyServer '127.0.0.1:8080'
Set-ItemProperty $key ProxyOverride '<local>'
# notify WinINET:
[Win32.WinInet]::InternetSetOption(...)  # via Add-Type signature
```

A `try { ... } finally { restore-proxy }` wraps the `Wait-Process` call
so Ctrl+C, exception, or normal exit all restore.

`stop-capture.ps1` independently restores from the most-recent
`captures/*/.previous-proxy.json` it can find — for the orphaned-window
case.

## Failure modes & handling

| Failure | Response |
| --- | --- |
| Python missing | Print clear instructions linking to `python.org` and the Microsoft Store note. Do not auto-install. |
| `pip install mitmproxy` fails | Surface the error, exit. No silent fallback. |
| Cert install denied | Exit early with a "run again as admin" hint and *no* changes left on the system. |
| mitmdump exits unexpectedly | `finally{}` block restores proxy, prints last 50 lines of mitmdump output. |
| Unity ignores system proxy | Document this and offer the WinDivert route as a follow-up — do not silently fail. |
| User closes PowerShell with X | `stop-capture.ps1` cleanup path. |

## Out of scope

- DRM-style decryption (none observed; if seen, document and stop).
- Decoding Unity asset bundle internals (best-effort `UnityPy` only).
- Persistent capture daemon / scheduled runs.
- Any network upload — output stays local.
