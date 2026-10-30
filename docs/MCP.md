# MCP Control Plane

NetCast3r exposes its real workspace to any MCP client: OpenCode, Claude Code,
Codex, or an agent runtime you write yourself. The MCP server is a local stdio
process that drives the same HTTP API the Svelte UI uses. A scan started by an
agent appears in the dashboard. A human decision in the dashboard is visible to
the agent. There is one database and one audit trail.

Status: implemented and tested · 2026-10-29 · MCP protocol `2025-06-18`

---

## 1. Run it

Start the UI/control plane first so both processes share one workspace:

```sh
netcast3r ui --no-open --port 7857
```

Then check the MCP transport from another terminal:

```sh
netcast3r mcp --print-config
```

That prints a ready-to-paste OpenCode block:

```jsonc
{
  "mcp": {
    "servers": {
      "netcast3r": {
        "type": "local",
        "command": [
          "/path/to/.venv/bin/python",
          "-m", "netcast3r.cli", "mcp",
          "--policy", "supervised",
          "--backend", "auto",
          "--out", "/path/to/NetCast3r/results"
        ],
        "cwd": "/path/to/NetCast3r",
        "environment": {
          "NETCAST3R_RESULTS": "/path/to/NetCast3r/results",
          "NETCAST3R_MCP_POLICY": "supervised"
        }
      }
    }
  }
}
```

V2 uses `disabled: true` to keep a configured server disconnected; there is no
`enabled` field. The generated block omits both.

Verify the handshake:

```sh
opencode mcp list
```

MCP tool names are namespaced by OpenCode (for example
`netcast3r_status`). The server itself exposes the unqualified names.

### Backends

| Backend | When it is used | What it means |
| --- | --- | --- |
| `api` | A running UI/control plane is discovered | One shared workspace, live SSE in the dashboard, all writes go through the UI process |
| `embedded` | No UI is running, or `--backend embedded` | The MCP process opens the same SQLite index and runs scans in-process |
| `auto` (default) | Always | Probe the discovered UI; use it if healthy, otherwise embedded |

Discovery is deliberately simple and local:

1. `--api-url` / `--token` flags;
2. `NETCAST3R_API_URL` / `NETCAST3R_API_TOKEN`;
3. `~/.netcast3r/control-plane.json`, written by `netcast3r ui` with mode `0600`
   and removed on clean shutdown.

Auto mode never trusts a stale file. It probes `/api/v1/healthz` with the
published token. If that fails, it starts embedded and says so on stderr.

A clean UI restart reuses the token from the state file, so a connected MCP
client keeps working. If a token still changes (a crash or a fresh base), the
API transport re-reads the state file once on `401` and retries the call.

**Caveat:** live SSE is per-process. A run started in embedded mode is visible
in the shared database to the UI, but its live event stream belongs to the MCP
process. Start the UI first for the full dashboard experience.

---

## 2. The risk model

Three policies, selected by `--policy` or `NETCAST3R_MCP_POLICY`:

| Policy | Low | Medium | High (delete, decide) |
| --- | --- | --- | --- |
| `readonly` | allowed | denied | denied |
| `supervised` (default) | allowed | allowed | requires an approved `approval_id` |
| `full` | allowed | allowed | requires `confirm: true` |

Critical actions are not registered. Approval decisions are operator-only in
`supervised`; the agent cannot approve its own escalation. `full` is for an
operator who explicitly trusts the client process.

### Scope is an authorization, not a suggestion

Active tools (`scan_start`, `mission_start_run`, `http_probe`) require either a
`mission_id` or an explicit `scope` list. A bare target is refused. The target
must match the scope, and exclusions (`!host`, or a mission scope entry starting
with `!`) win. Mission targets are automatically part of their own scope.

`http_probe` additionally refuses cloud metadata hosts and link-local addresses
even when a scope rule names them. It supports `GET` and `HEAD` only, sends no
custom headers, does not follow redirects, and caps the body at 256 KiB.

### Approvals are single-use capabilities

`approval_request` stores the requesting actor, risk, reason, tool name, and a
SHA-256 digest of the exact arguments (excluding `approval_id` and `confirm`).
A human approves in the UI or through the API. The high-risk tool then:

1. verifies the approval is `approved` and unused;
2. verifies the mission and tool name;
3. recomputes the argument digest;
4. spends the approval (`used_at`) before executing.

An approval granted for one run cannot delete another. A replayed approval
fails. The audit row keeps the approval id.

### Rate limits

Per MCP process, sliding windows:

| Bucket | Limit |
| --- | --- |
| default reads | 180 / minute |
| mutations | 40 / minute |
| scans | 6 / hour |
| probes | 60 / minute |
| authenticated requests | 90 / minute |
| inbox waits | 6 / minute |

Denied calls are audited with status `denied`.

---

## 3. Tools

67 tools, grouped by job. Every tool publishes a JSON schema with
`additionalProperties: false`; unknown arguments are rejected rather than
silently ignored.

### Workspace

| Tool | Risk | Purpose |
| --- | --- | --- |
| `status` | low | Version, policy, counters, active runs |
| `tool_calls_list` | low | Read the audit trail |
| `self_audit` / `diagnostics` | low | Local posture and database integrity |
| `codeaudit_scan` | low | Static audit of a source tree |
| `codeaudit_rules` | low | List the static audit rules |

### Missions

| Tool | Risk | Purpose |
| --- | --- | --- |
| `missions_list` / `missions_get` | low | Read the portfolio |
| `missions_create` | medium | Create a scoped mission |
| `missions_update` | medium | Change fields or status |
| `missions_attach_run` | medium | Link an existing run |
| `mission_start_run` | medium | Start a scoped scan and link it |
| `mission_hunt` | medium | Standalone hunt: scope, fingerprint, surface, research, hypotheses |
| `model_solve` | medium | Bounded model action loop over allow-listed tools |
| `agent_status` | low | Read the runtime plan, tasks, budget, and model calls |
| `agent_start` | medium | Plan and run the bounded mission agent |
| `agent_pause` / `agent_resume` / `agent_stop` | low | Control a live run |
| `missions_delete` | high | Delete mission, links, approvals |

A mission has three ways to move. `mission_start_run` starts the crawler.
`mission_hunt` runs a deterministic read-only pass: scope, fingerprint, safe
surface paths, path-encoding comparison, technique and chain ranking, then
explicit hypotheses. `model_solve` runs the bounded model action loop: one
JSON action per step from a small allow-list (`http_probe`, `http_request`,
`http_path_diff`, `http_upload`, `oracle_extract`, the research planners, and
`hypothesis_create`), a step and wall-clock budget, and the real result of
every call fed back. The loop cannot spend an approval, call a high-risk tool,
or create a finding; a status the model returns is a lead, not evidence. It
appears in Live Runs as Reason, Act, Observe, Decide. All three refuse a
training mission; labs use a recipe.

### Runs and scans

| Tool | Risk | Purpose |
| --- | --- | --- |
| `runs_list` / `runs_get` / `runs_events` | low | Read runs and persisted events |
| `runs_report` / `runs_inventory` | low | Read the Markdown report and evidence slices |
| `scan_start` | medium | Scoped ad-hoc scan |
| `runs_stop` | medium | Cooperative stop |
| `runs_resume` | medium | Resume from a checkpoint |
| `runs_delete` | high | Delete run, findings, events, safe output |

### Findings

| Tool | Risk | Purpose |
| --- | --- | --- |
| `findings_list` / `findings_get` / `findings_summary` | low | Read findings and counts |
| `findings_create` | medium | Record a validated finding with its evidence |
| `finding_triage` | medium | Status, notes, tags, severity override |

Values are masked at the index boundary. Tools cannot reconstruct a secret.

### Reports and submissions

| Tool | Risk | Purpose |
| --- | --- | --- |
| `submissions_list` / `submissions_get` | low | Read filed reports and outcomes |
| `submissions_summary` | low | Counts and recorded award/payout totals by currency |
| `submissions_create` | medium | Record a report that was actually filed |
| `submissions_update` | medium | Change status, evidence links, award, or notes |
| `submissions_delete` | high | Remove a ledger row, not the report file |

A submission is never inferred from a finding. The ledger only holds what an
operator or agent wrote down; summary totals are grouped by currency and are
never converted into a single invented number.

### Governance

| Tool | Risk | Purpose |
| --- | --- | --- |
| `approvals_list` | low | Pending and decided requests |
| `approval_request` | medium | Ask for a bound high-risk approval |
| `approval_decide` | high | Operator decision (denied in supervised) |

### Providers and scope

| Tool | Risk | Purpose |
| --- | --- | --- |
| `providers_list` | low | Health and model list, never keys |
| `provider_test` | medium | One real provider completion |
| `scope_check` | low | Classify a target without traffic |
| `http_probe` | medium | One scoped GET/HEAD, bounded |

### Identity and callbacks

| Tool | Risk | Purpose |
| --- | --- | --- |
| `inbox_create` | low | Disposable mail.tm or GuerrillaMail inbox; credentials stay in a 0600 file |
| `inbox_providers` | low | List the mailbox providers this workspace can use |
| `inbox_list` / `inbox_read` | low | Masked mailbox list and message contents |
| `inbox_wait` | low | Block for a verification mail, optionally matched |
| `oast_create` | medium | Unique webhook.site callback URL |
| `oast_list` / `oast_poll` | low | Read callbacks and a polling cursor |
| `oast_delete` | medium | Remove the remote endpoint and local record |
| `auth_profile_set` | medium | Store named headers and cookies |
| `auth_profile_list` | low | Names only, never values |
| `auth_profile_delete` | medium | Remove a profile |
| `auth_profile_import` | medium | Import cookies from a Playwright storage state |

Inbox passwords, bearer tokens, and callback tokens are written to
`~/.netcast3r/mailboxes.json`, `oast.json`, and `auth-profiles.json` with mode
`0600`. Tool responses mask them; audit rows redact `cookies`, `headers`,
`authorization`, and `set-cookie`.

### Authenticated testing

`http_request` is the authenticated counterpart to `http_probe`. It accepts a
method, extra headers, a named auth profile, and a raw, JSON, or form body.
Active work still needs a mission or explicit scope, and every redirect hop is
resolved and re-checked against that scope before the next request is sent. A
redirect to an out-of-scope host is returned with `blocked_redirect` instead of
being followed, and session headers are dropped when a redirect crosses to a
different host. Metadata and link-local addresses are refused at every hop.
Bodies are capped at 512 KiB and the response returns `set_cookie` separately
so cookie flags can be reviewed.

### Uploads and blind oracles

`http_upload` sends one scoped multipart upload with an optional form body and
auth profile. The file is held in memory, capped at 1 MiB, and the response is
capped like any other request. It exists so an agent can test extension, MIME,
magic-byte, and storage handling without a shell or a temporary file.

`oracle_extract` is the blind-extraction primitive. The caller puts `{{expr}}`
in the URL, a header, or the body, then supplies `expr_template` with
`{query}`, `{pos}`, and `{char}`. The tool tries each character at each
position and stops on a body marker, a status, or a time threshold. It is
capped at 2000 probes, rate-limited separately from normal requests, and every
probe goes through the same scope check. It does not decide that a bug exists;
the extracted value still has to be used to prove impact.

`race_run` sends the same scoped request up to 50 times with a bounded worker
pool and returns every response. It is a concurrent burst, not a single-packet
attack; a duplicate side effect is the proof. Campaigns that need packet-level
alignment still require a dedicated HTTP/2 sender.

### Path differentials

`http_path_diff` sends the same request to a bounded set of path variants —
literal, percent-encoded, mixed-case, doubled-slash, trailing-slash, and
semicolon forms — and labels where the response diverges from the baseline.
A `403` that becomes `400` is labelled `check_skipped`: the authorization gate
did not match the encoded route and the handler did. A `403`/`401` that
becomes `2xx` is labelled `auth_bypass`. This turns a manual finding class into
a repeatable check without deciding that a target is vulnerable; the response
body still has to be confirmed.

Non-safe methods (`POST`, `PUT`, `PATCH`, `DELETE`) are refused unless
`allow_unsafe_method=true`, because replaying a state-changing request against
variants can create state. Requests are spaced by a configurable delay and
capped at 24 variants, and every variant goes through the same scope and auth
profile checks as `http_request`.

### Reverse engineering

`reveng_analyze` reads an artifact the operator legitimately holds — a source
tree, an APK, a Solidity project, a JS bundle, or a PE/ELF binary — and returns
observations with file and line numbers. Nothing is uploaded, executed, or run
against a target. APK analysis uses `jadx` or `apktool` when installed; the
remaining checks are plain text analysis, so the tool works on a stock machine.

`rea_analyze` is the orchestration layer: it runs the same local analysis and
adds a kind-specific REA plan and tool set (APK, binary, source, JavaScript,
contract). `kind=js` and auto-detection now reach the JavaScript analyzer;
previously the analyzer existed but was unreachable.

`ui_audit` is the SQA pass for the dashboard. It opens the local control plane
in Chromium, visits the requested screens, records console errors, failed
requests, horizontal overflow, and writes one screenshot per screen under
`~/.netcast3r/artifacts/ui-audit/`. It does not judge visual taste, but it
catches the runtime and layout gaps that a screenshot review would miss.

The analyzers cover:

- **Source:** hardcoded credentials (AWS, Google, Stripe, GitHub, Slack, npm,
  PyPI, SendGrid, Shopify, JWTs, private keys, URL-embedded credentials),
  endpoints, dangerous sinks per language (`pickle`, unsafe YAML, `eval`,
  `child_process`, Java deserialization, SQL concatenation, `template.HTML`,
  PHP object injection, Ruby `YAML.load`, `BinaryFormatter`), and disabled TLS
  verification.
- **APK:** manifest flags (`debuggable`, `allowBackup`, cleartext traffic),
  exported components without a permission, intent-filter defaults, deep
  links, dangerous permissions, network-security config, certificate pinning
  markers, Firebase identifiers, native libraries, and secrets/endpoints in
  decompiled sources and resources.
- **Contracts:** `tx.origin`, `delegatecall`, `selfdestruct`, unchecked math,
  low-level calls, timestamp dependence, inline assembly, `ecrecover` without a
  zero-address check, floating pragmas, and initializer review prompts.
- **Binaries:** PE/ELF/Mach-O detection, ASCII and UTF-16 strings, kernel
  imports (`IoCreateDevice`, `MmMapIoSpace`, `ZwTerminateProcess`,
  `ObRegisterCallbacks`, IOCTL dispatch), IOCTL names and hex constants,
  embedded URLs/IPs, and ELF hardening (`PIE`, executable stack, canary,
  `checkelf` output when available).

Results are observations, not findings. The Reverse Lab screen in the dashboard
runs the same API (`POST /api/v1/reveng/analyze`), shows severity counts and
line-addressed evidence, and has a one-click "save" that records a finding
through `POST /api/v1/findings` — still an explicit write, never inferred from
the scan.

### Evidence artifacts

A finding can carry its own evidence files. `finding_artifact_add` (or
`POST /api/v1/findings/{id}/artifacts`) accepts text or base64 content up to
8 MiB, writes it 0600 under `~/.netcast3r/artifacts/<finding_id>/`, records the
SHA-256, size, and MIME type, and returns a download URL. `finding_artifact_list`
and `finding_artifact_get` read the metadata and content back. The finding row
remains the authority; the artifact is the bytes that outlive the conversation.

### Local recon tools

`recon_passive` runs subfinder, httpx, katana, whatweb, gau, or waybackurls.
Broad scanners (nuclei, dalfox, nmap) are intentionally not part of the active
surface: they consume time and produce too many false positives. The precision
path is `http_request`, `http_path_diff`, the scoped browser, and
`test_case_run`, which executes an explicit ordered test case with assertions.
`recon_passive` uses a fixed argv, never a shell, refuses private/metadata
targets, caps output at 200 KB, and requires a mission or explicit scope.

### Burp MCP

`burp_status` connects to a Burp MCP server and lists its tools. `burp_call`
invokes one, after checking any `url`, `target`, `host`, `hostname`, or
`endpoint` argument—and any `Host:` header in a raw request—against the mission
scope. Configure the endpoint with `NETCAST3R_BURP_URL` and an optional
`NETCAST3R_BURP_TOKEN`, or write:

```json
{"burp": {"url": "http://127.0.0.1:9876", "token": ""}}
```

to `~/.netcast3r/integrations.json`. The client speaks MCP's streamable-HTTP
transport, including JSON and SSE responses and the `Mcp-Session-Id` header.

### Credential pivoting

`token_pivot` takes a token, cookie, or API key and a bounded list of hosts,
sends one authenticated GET and one baseline GET to each, and reports where the
status or body changed. It requires a mission, scope-checks every host, caps the
list at 25, never follows a cross-host redirect, and redacts the credential from
the audit. A changed response is a lead, not proof; confirm the account and the
body before recording it.

### Threat intelligence

`threatintel_query` and `threatintel_cve` answer "what is this CVE, how bad is
it, and is there a PoC?" across:

- **NVD** — description, CVSS v2/v3/v4, CWE, references;
- **CISA KEV** — known exploitation and ransomware use;
- **GitHub** — public PoC repositories and advisory records;
- **Sploitus** — public exploit entries.

Results keep their source URLs and are cached for six hours. `GITHUB_TOKEN`
raises the GitHub rate limit.

`threatintel_repro` builds a cited, non-executing plan: it reads the top PoC
READMEs, extracts code blocks, flags destructive payloads, and lays out the
smallest safe proof against an authorized target. It never runs the payload and
explicitly stops at a benign marker. This is the input an agent should use
before testing a recent CVE, not a scanner that fires exploits.

### Training range

Training is separate from hunting. `training_sources` lists the bundled
catalogue: the PortSwigger Academy index, the Acunetix testphp.vulnweb.com
exercise pack, and local Juice Shop, DVWA, and WebGoat ranges. Each entry
carries its source, allowed hosts, setup command, objective, and proof.

| Tool | Risk | Purpose |
| --- | --- | --- |
| `lab_recipes` | low | List labs with a scripted end-to-end recipe |
| `lab_run` | medium | Run a recipe (or `slug=auto`) through scoped tools; it verifies before recording |
| `lab_run_all` | medium | Queue every scripted recipe with bounded concurrency |
| `lab_model_study` | medium | Store a free-model explanation of a verified chain as a skill |
| `training_plan` | low | Rotate across source and category, easiest unsolved first |
| `training_status` | low | Solved and in-progress counts by source, category, and difficulty |
| `training_sources` | low | List packs, hosts, setup, and progress |
| `training_record` | medium | Record an in-progress, solved, blocked, or skipped result |
| `training_verify` | low | Check the Academy banner, explicit `expect` markers, or a browser profile |

A solved record needs evidence and a written lesson. The lesson updates
technology expertise and appears in `next_actions`. Local ranges are loopback
only. testphp is a published public lab; its pack is catalogued but it has been
intermittently unreachable, so a record is only written after a live check.

Starting a mission agent with `role=training` (or starting a mission that the
index marks as training) selects the next labs, matches research techniques,
reads capability gaps, and verifies the session. It does not crawl the target,
mark a lab solved, or create a finding. The dashboard shows **Continue
training** instead of **Launch cast** for these missions.

### Learning loop

NetCast3r keeps operational memory in the same SQLite index as runs and
findings. A lesson is written only from a record the control plane already
stored, so experience cannot be invented:

| Tool | Risk | Purpose |
| --- | --- | --- |
| `lessons_record` | medium | Persist a technique, failure, or correction with mission/run/task links |
| `lessons_list` / `lessons_get` | low | Search and read lessons by text, tag, or outcome |
| `lesson_reflect` | low | Derive a lesson from a stored tool call or run |
| `skills_list` / `skills_get` | low | Read the markdown skill library |
| `skill_packs` | low | List the 17 bundled advanced playbooks and their install state |
| `skills_upsert` | medium | Create or version a technique/checklist/write-up digest |
| `next_actions` | low | Rank the next concrete steps from stored records |
| `selfmodel_snapshot` | low | Capability scores from stored training, skills, expertise, and findings |
| `selfmodel_gaps` | low | Rank the weakest areas with one concrete next step |
| `selfmodel_evolve` | medium | Turn the top gaps into deduplicated, human-gated proposals |
| `upgrade_propose` / `upgrade_list` / `upgrade_update` | medium | Human-gated improvement proposals with evidence |
| `technique_search` / `technique_plan` | low | Rank a 38-entry public-research technique library against a target |
| `chain_search` / `chain_plan` | low | Rank multi-step exploit chains against a target |
| `offsec_frameworks` | low | Map Metasploit, BloodHound, Impacket, etc. to real NetCast3r coverage |
| `boot2root_plan` | low | Turn an OS and service list into a phased host route |
| `host_probe` | medium | Explicit-port banner and TLS certificate grab |
| `single_packet_race` | medium | HTTP/2 last-byte-aligned burst for check-then-act bugs |
| `research_sources` | low | Coverage of the technique library by class and rarity |
| `research_ingest` | medium | Store a sourced write-up digest as an active skill |
| `knowledge_sources` | low | Curated advisory and research feeds |
| `knowledge_refresh` | medium | Fetch new public report and advisory items |
| `knowledge_list` / `knowledge_read` | low | Read one captured report before writing a lesson |
| `hunt_plan` | low | Turn a mission and its fingerprint into scope, baseline, identity, technique, validation, and evidence phases |

The mission agent now plans a `recall` task before the active probe. It loads
lessons and skills that match the target, then writes one deterministic lesson
after a failed or blocked task. Reflection classifies the cause (scope, policy,
approval, auth, routing, input, reliability, tooling) and records one concrete
next step.

Four generic procedures are seeded on first start: path-encoding scope
differentials, the login-method x 2FA matrix, account rebind takeover, and the
two-account object matrix. Seventeen advanced packs are installed beside them:
SQLi, XSS, SSRF/cloud pivot, IDOR, JWT/OAuth/SAML, GraphQL, deserialization,
upload, cache/smuggling, race, cloud IMDS, mobile APK, binary reversing, LLM
features, recon, evidence/reporting, and business logic. They are procedures,
not target notes. Add a new skill with `skills_upsert` after a test produces a
reusable method.

### Technology expertise

Every lesson whose tags name a technology (wordpress, php, graphql, oauth,
saml, api, aws, nginx, react, nuxt, and so on) increments a per-instance
`expertise` row: exposures, successes, failures, confidence, and level. This is
deliberately local. Two researchers running the same build against different
targets end up with different expertise, because the lessons are different.

`expertise_profile` returns the ranked technology profile. `next_actions`
uses it: a WordPress-heavy instance is told to enumerate plugins, themes, and
REST users; a GraphQL-heavy instance is told to test introspection and
field-level authorization; an OAuth/SAML-heavy instance is told to test
redirects, state, and audience. A technology needs at least two recorded
exposures before it changes the suggested plan.

### Self-audit and diagnostics

`self_audit` checks the local posture: the base directory and database modes,
secret-bearing state files (`control-plane.json`, `auth-profiles.json`,
`secrets.json`, `integrations.json`, `config.toml`), remote MCP URLs, and the
`NETCAST3R_MCP_ALLOW_REMOTE` switch. It returns a score, grade, and fixes.

`diagnostics` checks SQLite integrity, table counts, file modes, route count,
and tool count. Both are read-only and local; they do not scan the host or the
network.

`codeaudit_scan` walks a source tree (Python, JavaScript, TypeScript, Svelte,
Go, Ruby, PHP, Java, Kotlin, Rust) and reports defects with a known
consequence: a swallowed exception, a shell string built from input, SQL
assembled by formatting, insecure deserialisation, disabled TLS verification,
weak randomness, a committed private key. `codeaudit_rules` lists the rule
table. A line or file may carry `codeaudit: ignore[-file] <rules> -- reason`
to record a reviewed exception; suppressed matches are counted separately in
the report, never hidden. The default target is the workspace; the tool
resolves symlinks and refuses credential stores. It is a pattern pass, not a
proof: it cannot see a logic flaw or a missing authorization check.

The index database is created `0600` and the base directory `0700`. The recon
wrappers do not follow redirects: `httpx` and `whatweb` run without redirect
following and `katana` uses `-fs rdn -dr`. Request and sandbox stdin are capped
at 1 MiB. Burp and outbound MCP argument checks walk nested objects and lists
and scan every string for absolute URLs and `Host:` headers.


### Outbound MCP registry

NetCast3r can call other MCP servers, not only expose its own tools. Configure
them in `~/.netcast3r/integrations.json`:

```json
{
  "mcp_servers": {
    "hexstrike": {"transport": "stdio", "command": ["python3", "/opt/hexstrike/server.py"]},
    "hermes": {"transport": "http", "url": "http://127.0.0.1:9876", "token": ""}
  }
}
```

| Tool | Risk | Purpose |
| --- | --- | --- |
| `mcp_servers_list` | low | List configured servers and transports; tokens are hidden |
| `mcp_server_tools` | medium | Start one server, initialize it, and list its tools |
| `mcp_server_call` | high | Invoke one remote tool; URL/Host arguments are scope-checked |

`mcp_server_call` is high risk and needs an approval under supervised policy.
A remote tool is not an authorization: every target-bearing argument is checked
against the mission before the call, and the result is audited. This is the
bridge for Hermes Agent, Agent Zero, HexStrike, OpenCode, and an internal MCP
server.

### Continuous surface diff

`surface_diff` compares two runs' per-run inventories: subdomains, assets,
JavaScript files, endpoints, secret candidates, and findings. It returns added,
removed, and severity-changed items with counts and samples. It reads the run
databases as written; a missing run database is an error, not an empty surface.
Use it for weekly monitoring: run the same mission, diff against the previous
run, and triage only what changed.

### Sandbox

`sandbox_run` executes one short command in a locked-down Docker container:
no network, read-only root, all capabilities dropped, no-new-privileges, a
non-root user, 256 MB memory, one CPU, and no host mount. Use it to read or
reproduce a PoC without touching the host or a target. It is high risk and
needs an approval under supervised policy.

Allowlisted images: `python:3.12-slim`, `alpine:3.20`, `debian:12-slim`,
`ubuntu:24.04`. The command is an argv list, never a shell string.

### Report quality and payout ROI

`report_quality` scores one finding on title, impact, evidence, attached
artifacts, reproduction, CVSS/CVE context, and confidence. It returns the score,
a grade, and the exact missing pieces. This is report completeness, not a
prediction that the program will pay.

`program_rank` aggregates the submission ledger by program, platform, and
currency: submissions, acceptances, paid rows, bounty totals, acceptance rate,
and average bounty. It uses only rows you recorded, never estimated ranges, and
never converts currencies.

### STIX 2.1 and TAXII 2.1

`stix_export` turns findings into a STIX 2.1 bundle: an identity, one
`vulnerability` object per finding (with a CVE external reference when one is
present), and a `report` that references them. No indicators are invented from
scanner output.

`taxii_collections` discovers a configured TAXII 2.1 server and lists its
collections. `taxii_poll` reads objects from one collection with an optional
`added_after` cursor. Configure:

```json
{"taxii": {"url": "https://taxii.example/taxii2/", "token": ""}}
```

Polling is read-only. Pushing to a remote collection is a separate approved
action.






### Browser

The browser is a real, persistent Chromium profile, not a headless fetcher.
`browser_open` launches a detached process with a loopback DevTools port and
keeps the user-data directory under `~/.netcast3r/browsers/`. The process
survives an MCP restart, so a human can take over the visible window to solve
a challenge or finish an OAuth consent screen, and the agent can keep driving
the same session afterwards.

| Tool | Risk | Purpose |
| --- | --- | --- |
| `browser_open` | medium | Launch/reuse a profile and open a scoped URL |
| `browser_status` / `browser_list` | low | Live process, URL, title, profile state |
| `browser_goto` | medium | Navigate an existing profile |
| `browser_snapshot` | low | Visible text and interactive elements with refs |
| `browser_click` | medium | Click by snapshot ref or CSS selector |
| `browser_type` | medium | Fill an input; typed text is redacted from the audit |
| `browser_press` | medium | Press a key on an element or the page |
| `browser_wait` | low | Wait for time, URL, text, selector, or navigation |
| `browser_screenshot` | low | PNG under `~/.netcast3r/screenshots/` |
| `browser_capture` | medium | Copy the cookie jar into a named auth profile |
| `browser_eval` | high | Evaluate one JS expression; needs approval in supervised |
| `browser_close` | medium | Terminate the profile process |

Target navigation is scope-checked. `purpose="identity"` is the only bypass,
and it is restricted to a fixed list of identity providers (GitHub, Google,
Microsoft, Apple, Auth0, Okta, and similar) so an SSO consent screen can be
completed without widening the mission. Browser cookies never leave the sealed
profile until `browser_capture` writes them to `auth-profiles.json`.

Install the optional driver once:

```sh
pip install 'netcast3r[browser]'
```

NetCast3r uses the system Chromium/Chrome/Edge binary. Set
`NETCAST3R_CHROMIUM` when it is not on `PATH`.

### Mission agent

`agent_start` runs a bounded, deterministic plan on one mission:

1. `scope_check` the mission target.
2. One real `http_probe` (GET, bounded body).
3. A read-only inventory of linked runs, related runs, and findings.
4. A role-specific read-only inventory: `auth` profiles and browsers, `api`
   endpoints, `validator` findings, or `reporter` ledger rows.
5. Optional model analysis, stored as `unverified` and advisory only.
6. An independent verifier that clears only evidence-backed tasks.

`role` is one of `recon`, `auth`, `api`, `validator`, or `reporter`. The role
changes the inventory step and the advisory prompt; it never widens the tool
surface or the scope.

The runtime calls the same typed tools through the same registry as an external
client, with actor `agent:runtime`, so every step lands in `tool_calls` under
the mission. It defaults to 8 tasks, 600 seconds, and 2 model calls, clamped to
4–20 tasks, 30–7200 seconds, and 0–20 calls. `agent_pause` stops before the next
task, `agent_resume` continues from the first unfinished one, and `agent_stop`
marks pending tasks skipped. A database row whose worker died reads as
`interrupted` instead of pretending to be live.

The runtime cannot create a finding, change triage, widen scope, run a
destructive tool, or spend an approval. Reachability is reported as
reachability. Provider token counts are recorded; `cost_cents` stays empty
unless a provider reports a price, so the mission's USD cap is a recorded
ceiling, never an estimate.

---

## 4. Resources and prompts

Resources (read-only, JSON):

- `netcast3r://status`
- `netcast3r://missions`
- `netcast3r://runs`
- `netcast3r://findings`
- `netcast3r://submissions`
- `netcast3r://approvals`
- `netcast3r://tool-calls`
- `netcast3r://policy` (the active policy, catalogue, and operating rules)

Prompts:

- `recon-mission` — scoped recon with evidence discipline.
- `triage-findings` — cross-check validations before changing status.
- `write-report` — draft only from a real run; stop if nothing is verified.
- `review-approval` — summarize a high-risk action for a human.

Prompts are instructions, not data. They tell the model which tools to call;
they do not fabricate the result.

---

## 5. Audit and visibility

Every tool call writes one row to `tool_calls`:

```
id, tool, risk, status, actor, mission_id, run_id, approval_id,
args_json, result_json, error, duration_ms, created_at
```

Statuses: `ok`, `error`, `denied`, `approval_required`, `confirm_required`.
Credential-shaped argument keys are redacted before storage; payloads are
capped at 64 KiB with an explicit truncation marker.

Read it through:

- `GET /api/v1/tool-calls?tool=&status=&mission_id=&run_id=`
- `GET /api/v1/tool-calls/{id}`
- `GET /api/v1/mcp` — heartbeat, policy, backend, client, tool catalogue

The MCP process writes `~/.netcast3r/mcp-state.json` on start and after each
tool call. The UI can show whether an MCP client is alive without guessing.

---

## 6. Security boundary

- The control plane refuses non-loopback `Host` headers and requires the
  session token minted by the UI. The state file is `0600`.
- `ApiPlane` refuses non-local URLs unless `NETCAST3R_MCP_ALLOW_REMOTE=1`.
- Secret values stay masked in findings, search results, and audit rows.
- No tool exposes key management, provider key values, arbitrary HTTP headers,
  or arbitrary request bodies.
- The registry fails closed: an unknown policy, unknown tool, unknown argument,
  out-of-scope target, missing scope, or unspent approval is an error.
- Embedded mode deliberately does **not** call `jobs.recover()`, so an MCP
  process cannot mark a UI-run scan as interrupted.

---

## 7. Tests

`tests/test_mcp.py` covers:

- schema/catalogue consistency and 40 handlers;
- readonly denial and audit status;
- scope refusal, exclusion rules, and mission run linking;
- metadata-address probe refusal;
- real run execution through the embedded plane;
- finding triage and summary;
- single-use approvals, argument binding, and cross-mission refusal;
- operator-only decisions in supervised mode;
- full-policy confirmation;
- MCP initialize, tools, resources, prompts, notifications, and errors;
- newline and `Content-Length` framing;
- stdio round-trip and heartbeat cleanup;
- OpenCode config generation.

Run:

```sh
NETCAST3R_NO_KEYRING=1 .venv/bin/python -m pytest tests/test_mcp.py -q
```

The release gate is unchanged: MCP makes the platform usable, it does not by
itself produce a bounty. Real submissions and payouts must exist before a
release is claimed.
