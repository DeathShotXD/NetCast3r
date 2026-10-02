# Changelog

Notable changes to NetCast3r, newest first.

## Unreleased

### Added

- Historical JavaScript from the Wayback Machine is now fetched and scanned
  during a run, not only during recon.
- Patterns and read-only recipes for OpenAI, Anthropic, Groq, Hugging Face,
  DigitalOcean, npm, Postman, Shopify, Google OAuth secrets, Telegram, Discord
  webhooks, Sentry DSN, Mapbox secret tokens, database connection strings,
  Mailgun, Mailchimp, Contentful, Twilio, NVIDIA, and Facebook.

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
