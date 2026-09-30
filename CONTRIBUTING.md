# Contributing

By contributing, you agree that your contribution may be distributed under
GPL-3.0-or-later.

1. Open an issue first if you're proposing a behaviour change. For small fixes
   (typos, refactors, missing edge cases), just send a PR.
2. Say what you tested. This tool runs against unpredictable real-world traffic,
   so "I ran a capture session and checked the output" goes a long way. If you
   can't test on Windows, say so and I'll test before merging.
3. No DRM circumvention. The tool inspects traffic and metadata the user already
   receives in their VRChat session. Anything that decrypts, bypasses, injects,
   replays or extracts protected content won't be merged.
4. Keep the scope small. This is a one-shot recon tool, not a general mitmproxy
   framework. PRs that add daemons, GUIs or remote upload are out of scope.

In issues, include your Python version, mitmproxy version and what kind of
session you were running.
