# RECON — using the capture to characterise a VRChat world

This is a methodology guide for using `vrchat-net-capture` to figure out
what an unfamiliar VRChat world is doing on the network: what backends
it talks to, what its catalog format looks like, where its media comes
from, and what (if anything) it pushes back upstream.

## Step 1 — pre-recon from VRChat's own logs (no proxy needed)

Before bringing the proxy up, look at what VRChat has already told you.
The output log at
`%LOCALAPPDATA%Low\VRChat\VRChat\output_log_<timestamp>.txt` is updated
live during a play session and is fairly chatty:

- `[String Download] Attempting to load String from URL '...'` — every
  plain-text catalog/config fetch the world performs.
- `[Image Download] Attempting to load image from URL '...'` — every
  image fetch (atlas tiles, banners, thumbnails).
- `[Video Playback] Attempting to resolve URL '...' / URL '...' resolved
  to '...'` — every video play attempt, including any indirection
  (e.g. yt-dlp-style YouTube resolution).
- World-specific Udon `Debug.Log` lines from the world's own scripts.
  Naming conventions vary per world; grep for the world's name or
  obvious prefixes.

A surprising amount of recon can be done from the log alone. Often the
URLs you find here are the ones you most want the proxy capture for —
the proxy then confirms response body, headers, compression, status.

## Step 2 — design the capture session

For each world you want to characterise, plan ahead:

1. **Cold-start VRChat.** Don't have it running before the proxy is
   up — it will have cached its first auth before mitmdump can see it.
2. **Enter the world fresh.** A new instance is best, so you observe
   the full join sequence.
3. **Wait for the world's main UI to populate.** That is usually when
   the catalog fetch happens.
4. **Trigger every interesting interaction** — search if there's a
   search box, browse categories, click "play" on at least one item,
   let playback run ~30 seconds. The point is to surface every endpoint
   that doesn't fire on cold entry.
5. **Leave cleanly** (back to home, then quit VRChat) so any teardown
   flow runs.
6. **Stop the capture (Ctrl+C in the PowerShell window).**

If you're recon'ing more than one world in the same session, separate
them by leaving and re-entering. That makes it easy to bound them in
`flows.jsonl` by timestamp.

## Step 3 — interpret the output

In `captures/<timestamp>/`:

```
flows.json                  # full index, browseable as a single JSON array
flows.jsonl                 # same, one record per line (append-only)
bodies/<sha256>.bin         # raw decoded response bodies
decoded/<sha256>.{json,txt,m3u8,hex}  # human-readable forms
by-host/<host>/...          # per-host folders, one JSON per request
```

### Where to look first

- **`by-host/`** is the entry point. Each subdirectory is a hostname
  VRChat or the world hit during the session.
- Hosts like `api.vrchat.cloud/`, `assets.vrchat.com/`,
  `files.vrchat.cloud/`, `pipeline.vrchat.cloud/` are VRChat's own
  infrastructure — usually noise unless you specifically want to study
  VRChat itself.
- The world-specific backend will typically be one or two hosts that
  don't look VRChat-affiliated. Open the JSON files in those host
  directories: each one is a single flow record with method, URL,
  status, headers, and a pointer to the decoded body.
- For each interesting flow, the `response_decoded_path` field points
  to the human-readable body in `decoded/`. JSON catalogs are
  pretty-printed; HLS playlists land as `.m3u8`; binary blobs get a
  256-byte hex preview.

### Common shapes you'll see

- **One catalog fetch + many image fetches.** Typical for media worlds:
  one big JSON describing items, then per-item / per-tile images. Look
  for the smallest response in the host directory — often that's the
  join handshake; the largest is usually the catalog.
- **HLS playlists pointing elsewhere.** A `.m3u8` body that lists
  segment URLs on a different host means metadata and media are served
  separately. Note the segment host.
- **Per-search / per-page API calls.** If browsing or searching produces
  new flows, the world is making per-query calls. If browsing is silent
  (no new flows), the catalog was loaded entirely up-front and the world
  filters locally.
- **Asset bundles** (`UnityFS` / `UnityRaw` / `UnityWeb` magic bytes,
  recorded as `is_unity_assetbundle: true`). These are world geometry,
  Udon scripts, and embedded assets. They're opaque without further
  tooling — install `UnityPy` (uncomment in `requirements.txt`) for a
  name/type peek, or use AssetStudio / AssetRipper for deeper inspection.

## Step 4 — what this tool can't tell you

- **Photon (multiplayer transport).** UDP, won't show up here.
- **OSC.** Loopback UDP — invisible to the proxy.
- **Anything with TLS pinning.** If a host pins certificates against a
  fixed CA, the proxy can't see inside. Symptom: the flow record has
  `errored: true` and `response_body_hash: null` for that host.
- **Inside Unity asset bundles** beyond what `UnityPy` will show.

## Step 5 — write up findings

For your own notes (or to share with a collaborator), the useful things
to record per world are:

- World ID and name.
- Hosts seen (`ls captures/<ts>/by-host/`).
- Catalog endpoint(s) and a sample of the response body.
- Media URL pattern (HLS / direct MP4 / YouTube / hosted file / etc.).
- Whether the world appears to use heartbeats, search APIs, or any
  POSTs.
- Anything that looked unusual or unexpected.

The flow record schema is documented in [DESIGN.md](DESIGN.md) if you
want to slice the data programmatically.

## Ethical reminder

This tool is for inspecting traffic *you* are legitimately receiving as
part of *your own* VRChat session, on *your own* machine. Don't use it
to inventory or harass world creators, and don't republish raw catalog
contents that you don't have a license to redistribute. The point is to
understand the architecture, not to mirror someone else's content.
