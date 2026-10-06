# Changelog

Notable changes to NetCast3r, newest first.

## Unreleased

### Added

- An HTML dashboard, written with `--html` on `run` and `recon` or with the
  `dashboard` command. One self-contained file carries the run: stage rail,
  counters, coverage, validation ladder, severity split, caught credentials,
  findings table, and the agent log.
- A shared token module, `netcast3r.theme`, holding the palette, the state and
  severity colors, and the six stage rail, so the console and the dashboard
  render the same run with the same words and the same colors.
- The pattern catalog now holds 310 credential types, built from the gitleaks
  rule set and extended with the modern tokens those rules do not cover, with
  keyword prefilters so large catalogs stay fast.
- Validation recipes for the keyhacks endpoints, 135 in all, covering 121
  providers. A recipe is read-only unless it is marked as a write check.
- Paired credentials: a recipe can name a companion type, so a value that only
  works together with a second secret (Twilio, PayPal, Razorpay, Plaid, Censys)
  is checked with both parts.
- Write-tier impact proofs: when `--tier write` is set, a `_write` recipe runs
  in place of the read check, so a token can be shown to hold live access
  rather than merely being valid.
- A classifier agent that names candidates the patterns did not recognise,
  rates its confidence, and re-types the candidate so the right recipe runs.
  Classifications are remembered in `~/.netcast3r/classifications.json`.
- A confidence score on every candidate, from its pattern, entropy, length, and
  surrounding code.
- Self-assessment counters in the summary: `classified`, `unvalidated`, and the
  mean `confidence` of the findings.
- Historical JavaScript from the Wayback Machine is now fetched and scanned
  during a run, not only during recon.
- Source maps are recovered during recon: inline `data:` maps are decoded and
  remote maps are fetched in scope, so secrets and endpoints in the original
  sources behind a minified bundle are scanned too.
- Recon probes each host for an OpenAPI document and for open GraphQL
  introspection, so API routes that are never linked from the JavaScript are
  carried into the run.
- Recon reads robots.txt and sitemaps, so the paths an operator disallows and
  the pages a sitemap lists are carried into the run.

### Changed

- The dashboard renders in a single pass, so a value that contains a
  placeholder token can no longer trigger a second round of replacement, and
  the template is read once instead of on every render.
- The local dashboard server rejects foreign `Host` headers, sends a strict
  Content Security Policy and `nosniff`, and compresses large responses.
- The local dashboard server streams server-sent events, so the page reloads
  itself when the rendered file changes on disk.
- The local dashboard server exposes the run at `/api/data` and a filtered,
  sorted, paged findings list at `/api/findings`, so a large run stays
  browsable without scrolling the whole file.
- Model-generated validation checks are limited to safe public `https`
  endpoints, never loopback, private, link-local, or metadata addresses, and
  follow the run tier.

### Fixed

- The dashboard escapes every HTML-significant character in the run data, so a
  finding value can no longer close the JSON script block or inject markup.
- The over-broad gitleaks `generic-api-key` rule is dropped in favour of the
  stricter curated generic rule, which removes JavaScript property names from
  the candidate set.
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
