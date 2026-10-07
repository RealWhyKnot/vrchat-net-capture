# Contributing

By contributing, you agree that your contribution may be distributed under
GPL-3.0-or-later.

1. Open an issue first if you're proposing a behaviour change. For small fixes
   (typos, refactors, missing edge cases), send a PR.
2. Say what you tested. The tool runs against real-world traffic that changes all
   the time, and "I ran a capture session and checked the output" tells me a lot.
   If you can't test on Windows, say so and I'll test before merging.
3. No DRM circumvention. The tool inspects traffic and metadata the user already
   receives in their VRChat session. Anything that decrypts, bypasses, injects,
   replays or extracts protected content won't be merged.
4. It's a one-shot recon tool. PRs that turn it into a general mitmproxy
   framework, or add daemons, GUIs or remote upload, are out of scope.

In issues, include your Python version, mitmproxy version and what kind of
session you were running.
