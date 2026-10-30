# Changelog

Notable changes to NetCast3r, newest first.

## Unreleased

### Added

- Hypothesis ledger: `hypothesis_create`, `hypothesis_list`, `hypothesis_get`,
  `hypothesis_test`, and `hypothesis_promote` keep a lead as an assertion with
  an explicit test, a supported/refuted result, and an evidence artifact before
  it can become a finding. Open and supported hypotheses appear in
  `next_actions`.
- Training subsystem: multi-source catalogue and progress. It bundles the
  273-lab PortSwigger Web Security Academy index, the Acunetix
  testphp.vulnweb.com exercise pack, and local Juice Shop, DVWA, and WebGoat
  ranges (`training_plan`, `training_status`, `training_sources`,
  `training_record`, `training_verify`). Each entry carries its source, hosts,
  setup command, objective, and proof. `training_verify` accepts the Academy
  banner or explicit `expect` markers, and can read a managed browser profile
  for client-rendered exercises. A lab counts as solved only after a recorded
  result with evidence and a written lesson; the lesson feeds technology
  expertise. Labs are teaching targets and cannot reuse a bounty mission.
- 17 bundled advanced skill packs (`skill_packs`, seeded at startup for every
  agent): SQLi, XSS context, SSRF/cloud pivot, IDOR, JWT/OAuth/SAML,
  GraphQL, deserialization, file upload, cache/smuggling, race, cloud IMDS,
  mobile APK, binary reversing, LLM features, recon, evidence/reporting, and
  business logic.
- Self-model and human-gated self-upgrade: `selfmodel_snapshot` and
  `selfmodel_gaps` derive capability scores only from stored training, skills,
  expertise, findings, missions, and submissions. `upgrade_propose`,
  `upgrade_list`, and `upgrade_update` keep improvement proposals with
  evidence; nothing is applied automatically.
- Research technique library: 38 entries from public 2025-2026 work, each with
  signals, prerequisites, test steps, the minimum proof, tools, and source
  URLs. `technique_search`, `technique_plan`, and `research_sources` rank the
  library against a target fingerprint; `research_ingest` stores a written
  write-up digest as a sourced skill. Coverage includes CSPT and cache
  deception chains, ORM leaks (Django, Prisma, Beego, OData), error-based
  SSTI, Unicode WAF bypass, Next.js cache poisoning, redirect-loop SSRF,
  XS-Leaks, OAuth mutable claims/client confusion/scope upgrade, SCIM, MCP
  authorization, parser differentials, race, mobile OAuth scheme hijack, and
  AI tool exfiltration.
- Three further bundled skill packs summarize the modern web, client, and
  identity research corpora for agents that prefer prose playbooks.
- `hunt_plan` combines a mission target and fingerprint with the technique
  library into six phases: scope, baseline, identity, technique tests,
  validation, and evidence. It is read-only and does not authorise a target.
- The self-model now reports technique coverage per capability dimension.
- Browser actions now record and auto-dismiss `alert`, `confirm`, and `prompt`
  dialogs. A DOM XSS proof no longer wedges the managed profile; the message
  is returned in the tool result as `dialogs`.
- Training missions now plan learning instead of crawling. The mission API
  marks Academy, testphp, and explicitly training-labelled missions as
  `training`; the UI shows a training badge and a **Continue training** action,
  and the agent role `training` selects the next labs, matches public-research
  techniques, reads capability gaps, and verifies the session. It never marks
  a lab solved or creates a finding.
- `selfmodel_evolve` turns the top capability gaps into deduplicated,
  human-gated upgrade proposals. It writes a backlog; it does not edit code or
  apply a change.
- `http_upload` sends one scoped multipart upload from memory (1 MiB cap) so
  file-upload labs and real endpoints can be tested without a shell or a
  temporary file.
- `oracle_extract` extracts a value through a boolean, status, or time-based
  oracle. It renders an expression into the URL, a header, or the body and
  sends a bounded, rate-limited probe per candidate; it is the missing
  primitive for blind SQL injection and blind command injection.
- `race_run` sends a bounded concurrent burst of one scoped request and
  returns every status, body shape, and elapsed time. It is a concurrent
  burst, not a single-packet attack, and the note says so.
- Training progressed to 15 solved exercises: blind SQL injection with
  conditional responses used `oracle_extract`; remote code execution via a web
  shell used `http_upload`; stored XSS used the existing browser/HTTP path.
- The limit-overrun race lab remains blocked: `race_run` applied at most two
  coupons because it opens one connection per request. It produced a
  high-priority proposal for an HTTP/2 single-packet sender rather than a
  false solved record.
- Training targets can no longer start a cast. `POST /api/v1/runs` and
  `POST /api/v1/missions/{id}/runs` return 400 for Academy, testphp, or an
  explicitly training-labelled mission; the dashboard's global action is now
  labelled **New scan**. An explicit `allow_training_scan=true` remains for an
  intentional lab crawl.
- `ui_audit` opens the local dashboard, visits selected screens, records
  console errors, failed requests, horizontal overflow, and one screenshot
  per screen. It is the first automated SQA pass over the UI.
- `rea_analyze` wraps the local artifact analyzer with a kind-specific REA
  next-step plan and tool set for APK, binary, source, JavaScript, and smart
  contract work. The JavaScript analyzer is now reachable through `kind=js`
  and auto-detection; previously `analyze_js` was defined but unreachable.
- Live transmission text is whitespace-normalised and long tokens wrap, so a
  model that returns one character per line no longer collapses the stream
  into a vertical column.
- Scripted lab runner: `lab_recipes`, `lab_run`, `POST /api/v1/labs/run`, and a
  **Run next lab** action on a training mission. A recipe launches the lab
  through the managed browser or auth profile, performs the minimum HTTP/upload
  steps, verifies the Academy banner, and records the lesson. The run appears
  in Live Runs with real events instead of a crawler transcript.
- Initial recipes: SQL injection in a WHERE clause, SQL injection login
  bypass, unprotected admin functionality, web shell upload, and JWT
  unverified-signature bypass. A failed recipe is a real capability signal, not
  a solved record.
- Public knowledge watcher: a curated feed list for MSRC, Project Zero, Google
  Security, GitHub Advisories, PortSwigger Research, Bugcrowd, and CISA KEV.
  `knowledge_sources`, `knowledge_refresh`, `knowledge_list`, and
  `knowledge_read` store new items with source URLs and a bounded excerpt.
  Feed items are leads, not findings; `research_ingest` is still the only path
  that turns a report into a reusable skill.
- A training-agent run now refreshes the public report feeds as one of its
  tasks and records the captured items in the task evidence. The `auto` lab
  selector falls back to the first unsolved scripted lab, then to the first
  recipe for a regression check.
- More chained lab recipes: GraphQL hidden-field disclosure, PHP serialized
  admin tampering, IDOR with an account API key, a client-controlled role
  cookie, SSRF to the local admin API, path traversal, and Juice Shop login
  SQL injection. Each recipe verifies before recording.
- `single_packet_race` opens one TLS/HTTP/2 connection and writes every final
  DATA frame together. It is the packet-alignment primitive that `race_run`
  was missing.
- Chain library: 13 multi-step chains (IDOR to ATO, SSRF to IAM, XSS to CSRF
  to ATO, OAuth redirect theft, CSPT plus cache deception, SCIM takeover,
  MCP resource confusion) with `chain_search`, `chain_plan`, and
  `chain_sources`.
- `docs/research/penligent-public-comparison.md` records what Penligent's
  public repository and site actually expose. The application source is not
  public, so the note does not claim a source-code review.
- `test_case_run` executes up to 12 ordered, scope-checked requests with
  explicit status, body, and header assertions, replacing broad scanners in
  the active path.
- Disposable inboxes (`inbox_create`, `inbox_list`, `inbox_read`,
  `inbox_wait`) backed by mail.tm. Mailbox passwords and bearer tokens live in
  a 0600 state file and never appear in a tool response or audit row.
- OAST callbacks (`oast_create`, `oast_list`, `oast_poll`, `oast_delete`) for
  blind SSRF and blind injection testing, with a polling cursor.
- Named auth profiles (`auth_profile_set`, `auth_profile_list`,
  `auth_profile_delete`, `auth_profile_import`) for cookies and headers, with
  header-injection validation and masked listings.
- `http_request`, a scoped authenticated request tool that carries a profile,
  supports JSON, form, and raw bodies, caps the response, and re-checks every
  redirect hop against the mission scope. Session headers do not cross a host
  boundary.
- `write_private_json` and `read_private_json` helpers for 0600 local state.
- `findings_create` and `POST /api/v1/findings` record a finding only when an
  operator or agent explicitly writes it down. Severity, confidence, tags, and
  evidence are validated; secret values are masked at the index boundary; the
  route returns 201 and the row starts in triage status `new`.
- Reverse Lab: `reveng_analyze`, `POST /api/v1/reveng/analyze`, and
  `GET /api/v1/reveng/kinds` read a local source tree, APK, Solidity project,
  JS bundle, or PE/ELF binary and return line-addressed observations. APK
  analysis uses jadx or apktool when installed; nothing is uploaded or
  executed. The dashboard has a Reverse Lab screen with severity counts and a
  one-click save that records a finding through the explicit write path.
- `http_path_diff` compares a baseline request with percent-encoded,
  case-varied, and slash-varied paths and labels where authorization and
  routing disagree (`check_skipped`, `auth_bypass`, `route_confusion`). It
  refuses state-changing methods unless the caller opts in.
- Evidence artifacts: `POST /api/v1/findings/{id}/artifacts` and
  `finding_artifact_add` store text or base64 files (up to 8 MiB) under
  `~/.netcast3r/artifacts/<finding_id>/` with a SHA-256, size, MIME type, and
  download URL. `finding_artifact_list` and `finding_artifact_get` read them;
  files are 0600.
- `recon_passive` runs allowlisted local tools (subfinder, httpx, katana,
  whatweb, gau, waybackurls) with fixed argv, no shell, bounded output, and a
  scope check. Broad scanners are deliberately not part of the active surface.
- Burp MCP: `burp_status` lists the tools exposed by a configured Burp MCP
  server; `burp_call` invokes one. Configure with `NETCAST3R_BURP_URL` /
  `NETCAST3R_BURP_TOKEN` or `~/.netcast3r/integrations.json`. URL, host, and raw
  `Host:` values in the arguments are scope-checked before the call.
- `token_pivot` sends a captured credential to a bounded list of in-scope hosts
  and reports where the response changes. It requires a mission, checks every
  host against scope, never follows a cross-host redirect, and redacts the
  credential from the audit.
- Threat intel: `threatintel_query`, `threatintel_cve`, and
  `threatintel_repro` combine NVD, CISA KEV, GitHub repository/advisory search,
  and Sploitus. Results keep their source URLs; the reproduction plan extracts
  public PoC code blocks, flags destructive payloads, and never executes them.
  Set `GITHUB_TOKEN` to raise the GitHub search limit.
- `fetch_artifact` downloads one in-scope URL to a 0600 file for offline
  analysis, without following redirects. `http_request` and `http_path_diff`
  accept `verify_tls=false` only for an authorized self-signed target.
- Learning loop: `lessons_record`, `lessons_list`, `lessons_get`,
  `lesson_reflect`, `skills_list`, `skills_get`, `skills_upsert`, and
  `next_actions` persist operational memory in SQLite. The mission agent now
  plans a `recall` step, loads matching lessons and skills, and writes one
  deterministic lesson after a failed or blocked task. Built-in seed skills
  cover path-encoding differentials, the login-method x 2FA matrix, account
  rebind takeover, and the two-account object matrix.
- Outbound MCP registry: `mcp_servers_list`, `mcp_server_tools`, and
  `mcp_server_call` drive operator-configured HTTP/SSE or stdio MCP servers
  (Hermes Agent, Agent Zero, HexStrike, OpenCode, internal servers). Target
  arguments are scope-checked; calls are high risk and approval-gated.
- Research note: `docs/research/agentic-frameworks.md` maps Hermes Agent, Agent
  Zero, HexStrike, Strix, STIX/TAXII, MCP/A2A, and planner-executor patterns to
  a phased NetCast3r roadmap.
- Skill lifecycle: skills now carry `status`, `use_count`, `success_count`, and
  `last_used_at`; `skills_use` and `skills_status` manage them, and the agent
  recalls active skills only.
- `sandbox_run` runs one short command in a locked-down Docker container with
  no network, read-only root, dropped capabilities, non-root user, and no host
  mount. High risk and approval-gated.
- `report_quality` scores a finding's report completeness and lists missing
  evidence; `program_rank` aggregates the submission ledger by program,
  platform, and currency. No estimated payouts or currency conversion.
- STIX 2.1: `stix_export` builds a bundle with an identity, vulnerability
  objects, and a report; `taxii_collections` and `taxii_poll` read a configured
  TAXII 2.1 server.
- Broad scanners were removed from the active surface. `nuclei`, `dalfox`, and
  `nmap` are no longer in the tool catalogue; the precision path is manual
  `http_request`/`http_path_diff`/`test_case_run` plus the scoped browser.
- `test_case_run` executes up to 12 ordered requests with explicit status, body,
  and header assertions, and records the raw response per step. No scanner and
  no inferred finding.
- `surface_diff` compares two runs' subdomains, assets, JavaScript, endpoints,
  secret candidates, and findings; it reports added, removed, and
  severity-changed items from the stored run inventories.
- Self-audit and diagnostics: `self_audit` checks base/database/state-file
  permissions, remote MCP settings, and the remote-access switch; `diagnostics`
  reports SQLite integrity, table counts, modes, routes, and tools. The index
  and base directory are now created 0600/0700.
- Technology expertise: lessons with technology tags update an `expertise`
  table (exposures, successes, failures, confidence, level); `expertise_profile`
  exposes it, and `next_actions` adds WordPress, GraphQL, OAuth/SAML, PHP, and
  API checks based on this instance's real exposure.
- Security hardening from the self-audit: recon wrappers no longer follow
  redirects (`httpx`, `katana`, `whatweb` stay on the registered
  domain), request and sandbox stdin are capped at 1 MiB, and remote MCP
  argument checking now covers nested objects and more target keys.
- Research note: `docs/research/penligent-and-commercial-features.md` studies
  Penligent AI's public product pattern and lists profit-making features
  (surface diff, presets, quality gate, payout ROI, verified pipeline, CI gate,
  workspace/RBAC) without copying proprietary code.

### Fixed

- A caller-supplied `Cookie` header now replaces a profile cookie in any
  casing. The previous code removed only a capital-C header and could silently
  send the profile session instead.
- Academy lab slugs are unique: colliding final path segments (reflected vs
  stored XSS, OS command vs path traversal) are prefixed with their parent
  segment so one progress row cannot count as solved in two categories.
- Mission lessons now appear in `next_actions`; the mission surface filters
  lessons by `mission_id` instead of relying on a target-host text match.

### Security

- The Scribe prompt no longer carries the raw credential: the value is masked
  and every copy of it inside the finding text is scrubbed before the writing
  call, so model prose cannot re-expose what the report redacts.
- A scope file that was named but is missing now stops the command with the
  path and exit code 2 instead of silently running with no exclusions.
- The crawler follows redirects one hop at a time and re-checks scope on every
  hop, so a target that bounces to an internal or out-of-scope host mid-chain
  is refused before its body is read.
- The findings triage endpoint validates the status against the known set and
  returns 400 for anything else, so it can no longer store arbitrary values.
- The report's code-review section (weak points, evidence, endpoints, notes) is
  scrubbed of every confirmed and candidate secret, not just the value field.
- Five credential patterns no longer backtrack catastrophically. A hostile or
  heavily minified script that mentioned a provider name could hang the
  scanner; the nested bounded repeats are flattened and a keyword rule now
  reads only the windows around each keyword. A body larger than
  `max_scan_bytes` (1 MB) is scanned at its head and tail.
- A model-planned validation check can no longer send a credential to an
  arbitrary host by default: `allow_model_checks` now defaults to off, and a
  planned check must pass an SSRF guard that also resolves the host and
  rejects any name pointing at a private address.
- Validation requests no longer follow redirects, so a provider cannot bounce
  a request that carries the value to another origin.
- The classification cache is keyed by a hash of the value, so a raw
  credential never lands in `~/.netcast3r/classifications.json`.
- Run output can no longer be written outside the results folder: a
  client-supplied `results_dir` with `..` or an absolute path is refused, and
  the dashboard's provider test refuses cloud metadata hosts.
- A validation value carrying a carriage return or newline is refused before
  the request is sent, so a scanned page cannot inject a header.
- The report scrubs the secret out of the proof and evidence, redacts short
  values, and picks a code fence longer than any backtick run, so a provider
  echo cannot leak the value or break out of the block.
- `results.json`, `results.jsonl`, and the SARIF file now redact the secret
  too; they were written in the clear while the markdown report was masked.
- Testing a provider resolves the host and refuses link-local, reserved, and
  metadata addresses, so the stored key cannot be aimed at a cloud metadata
  endpoint through a decimal or IPv4-mapped form.

### Changed

- The default openrouter model list names models that exist again
  (`openrouter/free`, nemotron 3.5 lightning, nemotron super 120b); the old
  qwen and gemma entries had been withdrawn. The Keys preset hints mirror the
  same pool.
- The value injected into a recipe URL is percent-encoded, so a key that
  contains `/`, `&`, `=`, or `+` reaches the provider intact instead of
  corrupting the check request.
- Triage notes can be cleared: an empty notes value clears the stored note,
  while an omitted field leaves it alone.
- Live event streams resume from the standard `Last-Event-ID` header and no
  longer send a replayed event twice; replayed frames carry their id so a
  reconnect picks up where it left off.
- Scope paths are normalized before matching, a scheme-less `host/path` entry
  is treated as a path rule instead of a never-matching host, and a malformed
  seed URL is skipped rather than aborting the run.

- Public proxy lists are off by default (`egress.use_public = false`); the
  pool fetched them and then never handed one out. Set it on to opt in.
- The chainer's model-authored severity, impact, and steps are recorded as
  advisory analyst notes on the finding, not as the finding's claim. The
  severity and impact a report states stay the ones the validator produced,
  and the report labels model prose as not independently verified.
- A model reply that is not a JSON object no longer aborts a run: triage,
  escalation, and recipe planning fall back to the deterministic path.
- A credential is only called confirmed when a positive marker agrees with
  the HTTP status: a success marker seen on a 401/500 body no longer
  verifies, and a 4xx listed in `success_codes` is never treated as success.
- The engine room shows only the selected run. The live stream is filtered by
  run on the server and in the browser, and a run selector lets you switch
  between parallel scans and see that domain alone.
- The report now carries three sections: the confirmed findings with proof and
  manual steps, the high and critical candidates that were not confirmed with
  manual reproduction, and the code review of endpoints and weak points the
  JavaScript pass produced.
- The provider bus retires a model after it fails twice (a 400, 404, 5xx,
  timeout, or an empty stream), so a run stops walking a dead catalogue on
  every call. A provider whose free tier refuses external use no longer
  floods the timeline with 403s on each file.

### Added

- A bounded mission agent runtime. `agent_start` plans five deterministic steps
  (scope, probe, inventory, optional advisory analysis, verify), runs them
  against a local mission with the same typed tools an external MCP client
  uses, and keeps the task timeline, evidence, and verifier notes in SQLite.
  Pause, resume, and stop are recorded in the same rows, an orphaned run reads
  as `interrupted` instead of pretending a thread exists, and budgets cap
  tasks, wall clock, and model calls. The separate verifier never treats
  reachability as a finding and the runtime creates zero findings; it cannot
  widen scope, change triage, or spend an approval. `agent_status`,
  `agent_start`, `agent_pause`, `agent_resume`, and `agent_stop` expose it over
  MCP, and the mission Agent tab shows live state, budget meters, the task
  timeline, and model calls. Provider-reported tokens and prices are recorded;
  a provider that reports no price leaves spend as "not reported" rather than
  inventing a cost.
- A submission ledger for reports actually filed: platform, program, severity,
  status, external report id, award, and paid time, with a Reports screen,
  REST routes, MCP tools, and a summary that groups money by currency. A row
  is written only by an operator or agent; the ledger never infers a
  submission from a finding and never estimates a bounty.
- An Agent Studio screen that renders the live MCP control surface instead of a
  static diagram: the heartbeat and attached client, the active policy, all 40
  typed tools with their JSON schemas and exact risk gate, the pending approval
  queue with decisions, and a filterable, expandable tool-call audit. Idle is
  labelled as idle; only a live heartbeat is called connected.
- An MCP control plane: `netcast3r mcp` serves 40 typed tools over local stdio,
  auto-discovers a running UI (or falls back to an embedded workspace), and
  exposes missions, scoped scans, runs, events, evidence slices, findings,
  triage, submissions, approvals, providers, scope checks, and bounded HTTP probes.
  Three policies (`readonly`, `supervised`, `full`), scope enforcement, single-use
  argument-bound approvals, per-bucket rate limits, resources, prompts, and a
  complete `tool_calls` audit table are included. `--print-config` emits an
  OpenCode `mcp.servers` block. See `docs/MCP.md`. The UI publishes its
  endpoint and token in a `0600` state file, and the MCP process publishes a
  heartbeat the dashboard can read. No bounty result is claimed by this.
- A UI restart keeps connected MCP clients alive: `netcast3r ui` reuses the
  token from its `0600` control-plane state file when the previous owner is
  gone, and the API transport re-reads the file once on `401` and retries.
- A providers panel on the home screen backed by `GET /api/v1/providers/health`:
  each provider shows its model count, whether a key is set, when it was last
  checked, and a one-click reachability test.
- A report viewer: `GET /api/v1/runs/{id}/report` serves the written markdown,
  and the run history has a report button that opens it in a dialog.
- An `asyncio`-free cooperative stop: a running scan now checks the stop
  request between stages and writes a partial report instead of running to the
  end after you press stop.
- Subdomain mapping. A run against a domain now enumerates its subdomains
  from certificate transparency logs and passive DNS, brute-forces a built-in
  wordlist after checking for a wildcard DNS answer, keeps only names in
  scope, and crawls every one for JavaScript. On by default for a domain
  target; `--no-subdomains` or the map subdomains toggle turns it off.
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
- The banner composition follows the operator's notes: the AWS card is
  dropped, the API key and the rotating credential move into the empty
  bottom-left over the city, and the database key stays tethered to the
  mesh on the right. The spider grows jointed legs with raised knees,
  chitin gradients, a soft cast shadow, and subtler abdomen markings. The
  rail's net status module becomes an instrument: a scope well draws the
  cast net with scan pulses running down every rib, a sonar ring sweeps
  from the hand, a standby chip and blinking cursor frame the readout, and
  the runs and findings counts split on a hairline.
- The caster is redrawn to read hard instead of cartoon: every leg becomes
  a tapered chitin wedge, thick at the femur and fine at the tarsal point,
  with a violet rim, an acid pulse down the center, and a node at each
  knee; the abdomen carries an upright widow hourglass, the eyes gather
  into one cluster, the fang tips bead with venom, and one stray foot
  steps off the moon. The backdrop drops the drifting scan sweep, which
  read as a stray line across the empty gutters, and the vertical
  AUTHORIZED TESTING ONLY edge mark.
- The banner scene listens back now: pointer sweeps bend the moon, both
  skylines, the net and the spider on four parallax depths on a damped
  lerp, the spider's eyes follow your cursor across the page, a comet
  crosses the sky on a long loop, and a signal comet streaks. Credential
  cards lean into the cursor with a lift and glow while held -- hit-tested
  in SVG space, since the copy column stacks over the scene -- and a live
  run wakes the whole sky with a slow acid wash. An aurora curtain breathes
  behind the backdrop grid, toasts drain on a time bar and exit on their
  own, countup tiles bump when a number lands, the findings badge pops on
  change, the scope well tints acid while casting, and a spotlight follows
  the pointer across KPI and form panels.
- Everything animated parks when it leaves the viewport: a
  pause-offscreen observer stamps a class that suspends every animation in
  a scrolled-away section, the parallax engine sleeps while the banner is
  offscreen or the tab is hidden, and the reduced-motion kill-switch
  overrides all of it.
- Hovering a credential card no longer teleports it across the banner: a
  CSS transform on the positioned group replaced its SVG transform
  attribute, so the lift now lives on its own inner group with a fill-box
  origin and composes with the position instead of clobbering it. The
  graffiti word art, the sweeping beam, and the acid wash are gone -- the
  scene keeps the moon, the city, the net, the spider, and the keys, and
  nothing that could not be made premium survives.
- The dashboard runs light now: the noise layer drops its blend mode, the
  grid drops its per-frame mask, the sticky bar drops its backdrop blur,
  the aurora animates opacity only, one lattice layer drifts instead of
  two, nine embers rise instead of sixteen, and the net, the windows, the
  stars and the knots pulse on slower periods with fewer animated nodes.
  Measured on a saturated four-core box with a clean 60fps control: the
  history screen went from about four frames a second to about fourteen,
  and home from about three to about eight, with the scene's whole cost
  contained inside its own layer.
- The reasoning stream reads like a briefing instead of a token dump:
  repeated lines collapse, markdown debris and bare punctuation drop,
  continuation fragments join the sentence they belong to, blocks show the
  two newest lines with an expander for the rest, and text wraps as prose.
  The garble itself is fixed at the source: the exegete reads files in
  parallel and every file's reasoning tokens used to interleave into one
  stream, so now each file buffers its own tokens and flushes them as one
  tagged block when it finishes.
- The engine room arrives as its own screen: one lane per agent with a
  pulsing led, an activity meter that fills as the agent works, its model
  call history, the stage it owns, and a click to read its latest line;
  six stage tiles light up as the pipeline advances, deep links resolve,
  and the screen picks the running run -- or the newest -- on its own.
- The banner seats itself as a stage: a soft vignette fades the copy
  column and the scene edges so the composition reads as one lit frame
  instead of a sticker sheet.
- The dead silence during a crawl is gone: recon now reports every fetch
  as it happens -- a fetch event per URL with its status, tagged html, js
  or skip -- plus a running crawled count, so the run shows work from its
  first second instead of one summary line after seven minutes. The live
  run screen grows a crawler feed panel (every url, split html/js, status
  codes, pages and js tallies) and the engine room carries the same feed
  beside a thinking-now stream of the newest reasoning lines.
- The banner drops the levitating key cards: one credential caught in the
  mesh remains -- the reference art's catch -- with a slow beacon, and the
  bottom-left breathes again. The scene keeps its parallax depths, the
  spider, and the moon; the composition follows the reference's clean
  left column and center-weighted net.
- The new scan form gains the operator's dials: requests per second,
  delay between requests, retries, a max-page ceiling, user-agent
  rotation, and a wayback toggle, all passed through to the run. Multiple
  scans already run side by side on the worker pool. The provider pool
  gains a second OpenRouter key as backup, verified live: the bus walks
  openrouter, openrouter-backup, ollama, and opencode in order and cools
  any provider that rate limits.
- The backup key turns out to be free.ai's, not OpenRouter's: it now
  speaks as its own provider at `api.free.ai`, verified live against both
  a plain call and a stream, so the bus walks openrouter, freeai, ollama,
  and opencode.
- Every thinking lane grows a watch link: click it and the agent's mind
  opens in a large spotlight pane that streams its reasoning live, with
  its line count and last model call in the header, esc to close, and the
  veil click to dismiss.
- The banner breathes again: the validation ladder stacks down the clean
  right-edge sky instead of colliding with the net's hem weights, the
  report panel rides the moon as a HUD pane instead of sitting on the
  mesh, the six-stage rail shortens clear of the source block, and a
  pairwise-overlap audit of every HUD element now reports zero collisions.
  The net status scope well thins from nine ribs and five chords to five
  ribs and three -- at instrument size, restraint reads as precision.

### Fixed

- The HTTP stop conditions count failed attempts as well as responses, so a
  target that times out on every request aborts the run instead of grinding to
  the page cap.
- A stop request interrupts the crawler between fetches instead of only at
  stage boundaries.
- A confidence value that is not a number no longer raises during finding
  indexing; it indexes as 0.0.
- Wildcard certificate names are stripped with an exact `*.` prefix instead of
  a character-set strip, so a name is never mangled.
- `mailto:`, `javascript:`, and other non-http links are skipped by the crawler
  instead of being resolved and run through scope lookups.
- The drifting mesh no longer shows a seam where it loops: it advances by
  background position instead of a translate, and the scan sweep fades at
  both edges instead of ending on a hard line.
- A rate-limited provider cools down on a 403 or a 429 with escalating
  backoff, so the next call rotates away instead of burning the same limit
  again on every call in the run.
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
- The screen swap no longer traps fixed layers after it ends: the entrance
  animation drops its forwards fill, which used to leave an identity matrix
  and a zero blur on the wrapper, making it the containing block for the
  engine spotlight and the finding drawer -- both parked at the top of the
  document once the page was scrolled.
- The top bar stops squeezing its controls into clipped text on a narrow
  screen: buttons hold their width, the brand prefix and the go key step
  aside below the small breakpoint, and the search field narrows its floor
  so the breadcrumb keeps space.
- The engine lane row fits a 360px viewport: the agent name is the part
  that yields now, so the meter floor and the line counters can no longer
  push the WATCH trigger past the right edge where it was cut off with
  nowhere to scroll.
- Provider and key rows wrap their action buttons instead of compressing
  them until the `remove` label clipped its own letters.
- The engine room reloads when the selected run changes, and a failed load
  now shows an error instead of a blank "no run" state.
- Removing a key or a provider reports a failure instead of closing the
  dialog as if it worked.
- The command palette runs a command once, not twice, per keypress.
- The findings search cannot show stale results from an earlier keystroke,
  and a backend error is shown instead of an empty "nothing caught" state.
- The provider wizard no longer saves invented model names when an endpoint
  reports none; "keep this provider" keeps it with no models.
- A model reply shaped unexpectedly (`"items": null`, a bare array, a string
  `priority`/`confidence`, non-dict `headers` or `steps`) no longer aborts a
  run with no report; the stage is skipped and the report is still written.
- A pattern whose regular expression has a capture group now reports the
  group, not the whole match, so a value no longer carries its key prefix and
  quotes, and dedupe and redaction see the real token.
- Corrupt JSON in the run index (options, counts, tags, settings, event
  payloads) no longer turns a read into a 500.
- Under backpressure the event bus retries the triggering event after shedding
  chatter, the lag marker carries its run id, and a fully drained queue still
  emits a marker, so a subscriber is never silently starved.
- Scope entries beginning with `!` are exclusions, and a scheme/path prefix
  normalizes the path, so `/app/../../admin` no longer matches `/app`.
- `netcast3r` now reads the in-scope and out-of-scope files from `[scope]` in
  the config, and `--depth 0` and the other zero-valued flags are honored.
- The engine room cancels its pending flush timers and resets per-run state
  when the selected run changes; the live scan and findings screens surface
  load failures instead of a blank or empty state, and the number-input
  advanced options no longer throw before a scan can start.
- A JSON file is no longer read as JavaScript: the extension check matched
  `.json` because it contains the substring `.js`.
- The exegete tells the model that the file is untrusted data, so a page
  cannot smuggle instructions into the analysis prompt.
- A malformed config file, a scope path or seed that is not a URL, a wayback
  reply that is not a list of rows, a non-dict classification cache, and a
  subdomain wordlist that is a directory are all handled instead of crashing
  a run or the CLI.
- One JavaScript file that fails mid-analysis no longer discards the code
  review of every other file.
- The wayback path no longer treats a `.json` URL as JavaScript.
- On the dashboard, a failed boot shows an error instead of a blank page, the
  engine and live screens close their stream when the run changes or the
  screen unmounts, the breadcrumb names the run you selected, rejecting a
  finding asks first, and the advanced depth is clamped to a range.

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
