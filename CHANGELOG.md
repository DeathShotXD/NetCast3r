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
- A dashboard backend, started with `netcast3r ui`. It serves a local API over
  runs, findings and triage, providers, keys, settings, and a live event
  stream, backed by a SQLite index in `~/.netcast3r`. Runs execute on worker
  threads and stream their events as they go. A pasted key is stored in the OS
  keyring when one is usable, masked on every read, and never written to the
  index or a log line. The server binds loopback by default, validates the Host
  and Origin headers, and requires a per-session token.
- The dashboard itself, served by `netcast3r ui` at `/`. One self-contained
  page carries a rail, a command bar, and screens for the overview, starting a
  scan, a live run, findings and their triage, run history, providers and keys,
  and help. A live run shows its stage rail, counters, credentials and the
  agent log as they happen, with stop and rerun on hand. Screens are deep
  linkable (`#/live/run_123`), so a refresh keeps your place, and the session
  token arrives as an `HttpOnly` cookie alongside the existing query form.
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
- Assistive provider setup on the Providers screen: pick a provider from the
  preset grid (OpenRouter, NVIDIA, opencode zen, groq, deepseek, mistral,
  cerebras, openai, anthropic, gemini, ollama, custom), paste a key, and the
  connect step saves it to the key store, creates or updates the provider,
  calls its `/models` endpoint, and hands back the reachable model list with a
  latency readout. Picked models join the pool as chips. Providers gained
  `PATCH /api/v1/providers/:id` plus models, priority, and enabled columns
  (migrated in place on existing databases).
- The provider pool is now the unit of work: every enabled provider is merged
  into a run over the config file by name, its key is resolved from the key
  store, and the bus tries them in priority order, rotating to the next model
  or provider on a rate limit, so an NVIDIA key and an OpenRouter key work
  side by side. Cards carry an on switch, move up/down ordering, live health
  from the last probe, and click-to-drop model chips.
- A model activity panel on live runs: a reasoning stream (timestamped,
  coloured per agent, following the newest line) next to a call timeline that
  shows each provider attempt with its model, agent, latency, and failure
  (`HTTP 429`, connection errors). Both are emitted as `reasoning` and `model`
  events, so a finished run replays the same panel from its stored history.

### Changed

- The served dashboard got a visual pass in the style of the project art: an
  ambient backdrop of grid, glow and drifting mesh behind every screen, a
  banner-derived monogram, a redrawn cast-net hero with floating credential
  chips, a rail status module that fills the column with live run state and
  totals, HUD corner brackets on key panels, gradient buttons with a light
  sweep, staggered screen entrances, count-up counters, a stage progress bar,
  and shared empty states. Motion follows `prefers-reduced-motion`.
- The live event stream now carries the model's work: reasoning pieces and
  provider call attempts are emitted as their own event types, and under
  backpressure the stream sheds log and reasoning lines before anything else,
  so findings and state changes survive a burst.
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
- The visual pass went further: each of the six stages draws its own icon (a
  spider for crawl, braces for read js, a lens for hunt, a shield for
  validate, stairs for escalate, a seal for report) on the stage rail and in
  the help list, and the home hero carries a full banner collage -- cast net
  with a weighted hem, live terminal block, NC3R seal, barcode, and
  credential cards tethered into the mesh -- with a left fade so the copy
  stays readable. The mark breathes while a scan runs, and the backdrop adds
  rising sparks and CRT scanlines.
- Live runs render in batches: log and reasoning events are applied in one
  animation frame instead of one update per line, reasoning pieces fuse into
  per-agent blocks with a fragment count, the log and the stream cap what
  they keep on screen, and the server coalesces reasoning pieces before
  publishing and persisting them, so a noisy run stays smooth.
- The stage explanation is one component now: a ladder of glyph nodes joined
  by a connector with a travelling pulse, each step carrying its number,
  name, detail, and (in help) the agents behind it. The new scan screen and
  the help page use it in place of the stage chips, which crushed labels
  into a cramped row, and the plain numbered list.
- The home hero is rebuilt as a full-width composition: the cast net fans
  from the top corner across the whole banner, and the seal, stamp,
  terminal, credential cards, radar, and glitch bars sit in spaced bays
  down its length instead of piling into one corner, with the copy clear
  behind a left fade.
- The home banner keeps one focal object now: the net sweeps the full
  width and a single credential card hangs in the mesh on two tethers,
  replacing the crowded collage of seal, stamp, terminal, radar, and extra
  cards. The terminal readout lives on as a stream strip under the last
  run panel, showing the run's last lines behind a live chip.
- The overview grew data-ink: each KPI tile carries a share meter that
  fills on load (triage split, hits per endpoint), recent findings pair a
  confidence bar with every row, recent runs show their finding count,
  and the rail's findings item wears a badge that turns acid while
  candidates wait.
- Findings gained a confidence column with a per-finding meter, a sticky
  header over a scroll-bounded table, and a severity accent bar on row
  hover; the detail drawer draws the same meter next to its percentage.
  Run history rows pick up the status accent and a breathing chip while a
  scan runs.
- A command palette on ctrl+K, with a keycap in the top bar, filters every
  screen and the live-run actions with arrow-key selection, and the slash
  key jumps to the findings search from anywhere.
- The home banner is recreated from the project's own banner art: a hooded
  caster throws a luminous weighted net across a moonlit city skyline, four
  credential cards fan into the mesh and tether into a live report panel
  with its validation checks, confidence chips stack at the edge, and a
  six-stage rail, the lockup, and the source block anchor the foot. The
  banner's corrections apply -- ESCALATE, Evidence, and AUTONOMOUS, no AI
  wording -- and the scene adds a breathing moon, glowing eyes, blinking
  windows, travelling rail chevrons, and ticks that draw themselves.
- The banner figure is replaced by a spider caster perched at the net hub:
  eight curved legs grip the ribs, acid eyes and stripes catch the light,
  silk tethers run from the spinnerets to the hanging credentials, and a
  dark hub clearing keeps the body readable against the mesh. The four
  credential cards spread into their own zones down the banner instead of
  stacking, each on its own elliptical drift that swaps on rotation without
  resetting, and the moon and city sit clear behind them.

### Fixed

- The drifting mesh no longer shows a seam where it loops: it advances by
  background position instead of a translate, and the scan sweep fades at
  both edges instead of ending on a hard line.
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
