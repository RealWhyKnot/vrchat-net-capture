# Contributing

I built vrchat-net-capture for my own use first and I maintain it alone. I'm picky about how the code is structured, how it's styled and how features fit together. If you hit a bug or want a change, please open an [issue](https://github.com/RealWhyKnot/vrchat-net-capture/issues/new/choose) instead of sending a surprise pull request. A description of the problem, the steps to reproduce it or what you're trying to do is more useful to me than an unannounced PR. In issues, include your Python version, mitmproxy version and what kind of session you were running.

If you'd like to help maintain it over time, especially if I'm committing to it less often, or you have a substantial change you want to build, open an issue or reach out first. I'm happy to talk through the approach and agree on code style and commit conventions before you write any code.

By contributing, you agree that your contribution may be distributed under GPL-3.0-or-later.

## If we agree on a PR

1. Link the issue where we settled the approach in the PR description.
2. Say what you tested. The tool runs against real-world traffic that changes all the time, and "I ran a capture session and checked the output" tells me a lot. If you can't run a capture, say so and I'll test before merging.
3. No DRM circumvention. The tool inspects traffic and metadata the user already receives in their VRChat session. Anything that decrypts, bypasses, injects, replays or extracts protected content won't be merged.
4. It's a one-shot recon tool. PRs that turn it into a general mitmproxy framework, or add daemons, GUIs or remote upload, are out of scope.

### Checks

Run `pwsh -NoProfile -File .github/lint/lint.ps1` after `uv sync --frozen`. It is the same gate CI runs: style rules, PowerShell lint, `ruff format --check`, `ruff check`, `pyright`, the Python unit tests, and the .NET format check, build and tests. The README's Development section covers the WSL shell checks and the build script.
