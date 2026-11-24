# Reference

Details for [vrchat-net-capture](../README.md). Read "Read this before you run it" in the [README](../README.md#read-this-before-you-run-it) before you run a capture.

## Common options

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

