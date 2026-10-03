# Changelog

Notable changes to NetCast3r, newest first.

## Unreleased

### Added

- The pattern catalog now holds 231 credential types, built from the gitleaks
  rule set, with keyword prefilters so large catalogs stay fast.
- Read-only validation recipes for the keyhacks endpoints. 26 recipes cover
  GitHub, Slack, Stripe, SendGrid, Google, Shodan, OpenAI, Anthropic, Groq,
  Hugging Face, DigitalOcean, npm, Postman, Telegram, Discord, Firebase,
  Mapbox, Dropbox, Facebook, GitLab, Cloudflare, New Relic, Fastly, Netlify,
  and Travis CI.
- A classifier agent that names candidates the patterns did not recognise,
  rates its confidence, and re-types the candidate so the right recipe runs.
  Classifications are remembered in `~/.netcast3r/classifications.json`.
- A confidence score on every candidate, from its pattern, entropy, length, and
  surrounding code.
- Self-assessment counters in the summary: `classified`, `unvalidated`, and the
  mean `confidence` of the findings.
- Historical JavaScript from the Wayback Machine is now fetched and scanned
  during a run, not only during recon.

### Changed

- Model-generated validation checks are limited to safe public `https`
  endpoints, never loopback, private, link-local, or metadata addresses, and
  follow the run tier.

### Fixed

- A route that omits the model no longer fails to load.
- `--json` and `--jsonl` are written together instead of one suppressing the
  other.
- The generic assignment and Telegram patterns no longer match identifier
  strings and Cloudflare challenge tokens.
- The Telegram recipe treats an unauthorized response as dead.

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
