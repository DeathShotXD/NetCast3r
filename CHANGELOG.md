# Changelog

Notable changes to NetCast3r, newest first.

## Unreleased

### Added

- Historical JavaScript from the Wayback Machine is now fetched and scanned
  during a run, not only during recon.

### Fixed

- A route that omits the model no longer fails to load.
- `--json` and `--jsonl` are written together instead of one suppressing the
  other.

## 0.1.0

### Added

- Configuration with OpenCode Zen, OpenRouter, and Ollama providers and
  per-agent model routes.
- Scope engine with one entry per line, in-scope and out-of-scope, where the
  out-of-scope list wins.
- Secret patterns and extractor with entropy filtering.
- Validation engine and recipes with verified, unverified, unknown, and
  skipped outcomes, gated by the run tier.
- Egress proxy pool with health checks and rotation.
- Provider bus across OpenAI-compatible endpoints with reasoning streaming and
  fallback on rate limits.
- Recon fabric: scope aware crawler, JavaScript inventory, JavaScript in
  JavaScript recursion, endpoint extraction, and Wayback lookups.
- Evidence store.
- Agent swarm: exegete, prospector, assayer, chainer, scribe.
- Orchestrator with fan out and a deterministic fallback path.
- Report writer with redaction.
- Live console.
- Command line interface: recon, run, providers.
- Lab with a planted target and a fake provider.
- Test suite.
