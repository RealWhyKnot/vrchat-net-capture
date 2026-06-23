# Contributing

Contributions are welcome.

By contributing, you agree that your contribution may be distributed under
GPL-3.0-or-later.

1. **Open an issue first** if you're proposing a behaviour change. For
   small fixes (typos, refactors, missing edge cases), just send a PR.
2. **Describe what you tested.** This tool runs against unpredictable
   real-world traffic, so "I ran a capture session and verified output"
   goes a long way. If you can't test on Windows, say so -- I'll verify
   before merging.
3. **No DRM circumvention.** This tool is for inspecting traffic and metadata
   the user already legitimately receives in their VRChat session. Anything
   that decrypts, bypasses, injects, replays, or extracts protected content will
   not be merged.
4. **Keep the scope small.** This is a one-shot recon tool, not a
   generic mitmproxy framework. PRs that add daemons, GUIs, or remote
   upload are out of scope.

Be specific in issues about your Python version, mitmproxy version, and
what kind of session you were running.
