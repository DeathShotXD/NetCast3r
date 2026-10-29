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

### Missions

| Tool | Risk | Purpose |
| --- | --- | --- |
| `missions_list` / `missions_get` | low | Read the portfolio |
| `missions_create` | medium | Create a scoped mission |
| `missions_update` | medium | Change fields or status |
| `missions_attach_run` | medium | Link an existing run |
| `mission_start_run` | medium | Start a scoped scan and link it |
| `agent_status` | low | Read the runtime plan, tasks, budget, and model calls |
| `agent_start` | medium | Plan and run the bounded mission agent |
| `agent_pause` / `agent_resume` / `agent_stop` | low | Control a live run |
| `missions_delete` | high | Delete mission, links, approvals |

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
