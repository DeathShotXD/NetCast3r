# NetCast3r Agentic Platform

**Product and architecture blueprint for the agentic bug bounty workspace.**

Status: proposal · 2026-10-27 · owner: DeathShot

---

## 0. The short version

NetCast3r already has the hard part most "AI pentest" tools fake: a
deterministic pipeline that finds, validates, and reports real credentials.
The next step is not another scanner. It is an operating system around that
pipeline:

> **A mission-based, proof-first, human-commanded workspace where a fleet of
> agents can plan, hunt, verify, and report across an entire bug bounty
> program.**

The recommended build is a native NetCast3r control plane with a pluggable
agent runtime. Hermes Agent, Claude Code, Codex, or a future model can drive
NetCast3r through MCP. NetCast3r should not become a fork of Hermes. It should
become the place where any capable agent does security work safely, with
evidence.

The first shippable milestone is a **Command Center** built on the existing
run/event/finding data, plus a real **Mission** object and an **Approval**
queue. That gives the product its new center of gravity without throwing away
the tested engine.

**Review artifacts:** the clickable UI prototype is
[`../design/command-center.html`](../design/command-center.html) with run
instructions in [`../design/README.md`](../design/README.md). It is static and
mock-driven; the blueprint below is the source of truth for production.

**Implementation status (2026-10-29):** Command Center v1 runs on real
runs/events/findings. The shell uses the Obsidian Signal system. Mission,
Approval, and ToolCall entities, their SQLite tables, APIs, and the Missions
portfolio screen exist. The MCP control plane is implemented: a local stdio
server, 40 typed tools, scope and approval gates, single-use approvals, rate
limits, resources, prompts, and a complete tool-call audit. The submission
ledger records filed reports, platform outcomes, and payouts by currency; it
never infers a submission from a finding. See [`MCP.md`](MCP.md).

The mission agent v1 is implemented as a bounded runtime
(`src/netcast3r/server/agent_runtime.py`): a deterministic five-step plan
(scope, probe, inventory, optional advisory analysis, verify) executed through
the same typed MCP tools, with pause/resume/stop, orphan detection, an
independent verifier, and caps on tasks, wall clock, and model calls. The
runtime creates no findings, cannot widen scope, and cannot spend an
approval. Model output is advisory and stored as `unverified`; token counts
come from the provider, and a price is recorded only when the provider reports
one. The planner that decomposes arbitrary objectives, a multi-agent fleet, and
the report builder are still proposed; no synthetic approvals, spend, or bounty
results are shown. The release gate (real bounty submissions) is not met.

---

## 1. What exists today

| Layer | Current state | Assessment |
| --- | --- | --- |
| Engine | Six-stage pipeline: crawl, read JS, hunt secrets, validate, escalate, report | Strong deterministic core |
| Detection | 310 patterns, 135 read-only recipes, 121 providers | Real coverage |
| Runtime | Python 3.10+, stdlib HTTP server, SQLite index, SSE event bus | Lightweight, local-first, easy to run |
| UI | Svelte 5 + Tailwind 4, single-file build, six screens | Distinctive but still a run inspector |
| Data | Runs, events, findings, providers, keys, settings, triage | Good base, missing mission/graph/approval entities |
| Quality | 254 tests, svelte-check clean | A real foundation |

### What is missing for the agentic product

- Runs are scans, not **missions** with objectives, hypotheses, budgets, and
  success criteria.
- Agents are fixed pipeline roles, not a **planner/executor/verifier** loop.
- No **tool registry**, no MCP server/client, no tool-level permissions.
- No **approval gate** for risky actions, no kill switch, no budget governor.
- No persistent **target knowledge graph** across runs.
- No **program/scope sync** from HackerOne, Bugcrowd, Intigriti, YesWeHack.
- No **skills**, **memory**, or **self-improvement** loop.
- No **replay/eval harness** for agent quality.
- The UI is a live scan dashboard, not a **command center** for a fleet.

---

## 2. What the state of the art proves

### 2.1 Hermes Agent: the agent workspace pattern

Hermes Agent (Nous Research, MIT) is the clearest reference for agent UX:

- **Skills** are on-demand procedural memory, loaded progressively
  (`skills_list` -> `skill_view` -> reference file). Compatible with the
  agentskills.io open standard.
- **Memory** is bounded and curated (`MEMORY.md`, `USER.md`), injected as a
  snapshot, with optional external memory providers.
- **Subagents** are isolated workers with their own context and limits.
- **MCP** connects external tools without writing native integrations.
- **Web dashboard** treats the agent as an installation to operate: status,
  sessions, chat, memory, skills, MCP, approvals, logs.
- **Checkpoints** snapshot the workspace before changes, with rollback.
- **Gateway** lets one agent live across CLI, Telegram, Discord, Slack, etc.

**Lesson:** the winning UI is not a chat box. It is an operations workspace
with chat as one input. Progressive disclosure, inspectable memory, and
approval cards matter more than a flashy prompt bar.

### 2.2 Autonomous pentest frameworks: orchestration is not enough

The 2026 open-source landscape includes PentAGI, PentestGPT, CAI, Strix,
Shannon, HexStrike AI, Cyberful, BugTrace-AI, xOffense, and others. Common
patterns:

- Multi-agent roles coordinated by a planner or blackboard.
- Sandboxed tool execution (Docker, Kali containers).
- A separate verifier or critic, not trusting the exploiter's claim.
- Proof-of-concept generation for every finding.
- Provider-agnostic model routing and fallbacks.

**Lesson:** the differentiator is not "more agents." It is the **control
plane, evidence model, and verification loop** around them.

### 2.3 ARTEMIS: the benchmark reality

The ARTEMIS study (arXiv 2512.09882) pitted agents against ten professional
penetration testers on a live ~8,000-host university network:

- ARTEMIS placed second overall: 9 valid findings, 82% valid submission rate,
  beating 9 of 10 humans.
- It sustained long-horizon work and parallelized sub-agents better than
  humans.
- It still had an ~18% false-positive rate; humans were near-perfect.
- It missed GUI-heavy and business-logic findings.
- Scaffolding mattered as much as the model.

**Lesson:** build for **parallel enumeration + independent verification +
human handoff**, not full autonomy. The human should own ambiguity, GUI
workflows, business logic, and final submission.

### 2.4 XBOW and the proof-first standard

XBOW's market position is simple: customers do not need more findings, they
need proof. Every finding should carry a working exploit, the exact request
and response, and reproduction steps. Deterministic checks confirm common
classes; preview classes are labeled.

**Lesson:** NetCast3r's four-state verdict is already aligned. Extend it into
a full **evidence chain** and a **verification ladder**.

### 2.5 OWASP Top 10 for Agentic Applications 2026

The risks that directly shape this design:

- **ASI01 Goal hijacking** - untrusted target content can steer the agent.
- **ASI02 Tool misuse** - legitimate tools used unsafely or over-privileged.
- **ASI03 Identity and privilege abuse** - inherited credentials, broad scope.
- **ASI04 Agentic supply chain** - malicious skills, tools, MCP servers.
- **ASI05 Unexpected code execution** - model output reaching a shell.
- **ASI06 Memory poisoning** - corrupted long-term context.
- **ASI07 Insecure inter-agent communication** - spoofed peer messages.
- **ASI08 Cascading failures** - one bad signal propagates through agents.
- **ASI09 Human-agent trust exploitation** - polished explanations bypass
  human judgment.
- **ASI10 Intent deviation** - the agent drifts from the declared goal.

**Lesson:** scope capsules, least-privilege tools, approval gates, immutable
logs, budgets, and evidence citations are product features, not backend
hygiene.

### 2.6 Bug bounty platform UX is the baseline

Bugcrowd's Security Inbox, YesWeHack's Vulnerability Center, Intake,
Seemplicity, and HuntBug converge on:

- Saved views, pinning, and split-screen triage.
- AI summaries and remediation suggestions with a human approval queue.
- Duplicate detection across history.
- SLA clocks, severity, priority, assignment, and payout tracking.
- Program/scope management and inbound report parsing.

**Lesson:** "AI finds a bug" is not the product. The product is the workflow
from program selection to accepted, paid report.

### 2.7 Scope infrastructure is a commodity; intelligence is not

bbscope, ScopesExtractor, ScopeVault, and Phoenix-Scope already normalize
HackerOne, Bugcrowd, Intigriti, and YesWeHack scopes, detect changes, and
export targets. NetCast3r should integrate this layer, then add what they do
not: **expected-value ranking, agent planning, and proof-backed execution**.

---

## 3. Product thesis

> **NetCast3r is the command center for human-agent bug bounty hunting.
> Every mission is scoped, every action is observable, every finding is
> proven, and every report is submission-ready.**

### Principles

1. **Human command, agent execution.** The human owns scope, risk, and final
   judgment. Agents propose, execute within policy, and prove.
2. **Proof over prose.** A model's claim is not a finding. A reproducible
   artifact is.
3. **Scope is a security boundary, not a setting.** Enforce it at the network
   layer with a signed mission capsule.
4. **One workspace, one source of truth.** Programs, assets, hypotheses,
   evidence, findings, reports, submissions, and retests live together.
5. **Local-first, cloud-optional.** A single hunter can run everything on a
   laptop with their own keys. Teams can add sync, RBAC, and SSO later.
6. **Observable by default.** Every tool call, token, dollar, and decision is
   recorded, replayable, and attributable.
7. **Composable through open standards.** MCP for tools, agentskills.io for
   skills, OpenAPI for the control plane. Bring your own brain.
8. **Beautiful is a feature.** Dense data is not an excuse for ugly data.

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Svelte 5 workspace                                                 │
│  Command Center · Missions · Target Graph · Findings · Agent Studio │
│  Programs · Evidence · Reports · Admin                              │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ REST + SSE / WebSocket
┌───────────────────────────────▼─────────────────────────────────────┐
│  Control plane                                                      │
│  Mission service · Policy/Approval · Program sync · Findings        │
│  Report builder · Search · Event store · Cost ledger · Audit        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│  Agent runtime                                                      │
│  Planner -> Task DAG -> Executor -> Verifier -> Reporter            │
│  Tool registry · Sandbox · Egress proxy · Skills · Memory · MCP     │
│  Native runtime | Hermes adapter | Claude Code / Codex adapter      │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│  Evidence plane                                                     │
│  SQLite (local) / Postgres (team) · object store · hash chain       │
│  Target knowledge graph · hypothesis ledger · artifact vault        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│  Integrations                                                       │
│  H1 · Bugcrowd · Intigriti · YesWeHack · Immunefi · Jira · Linear   │
│  Slack/Teams · Burp/ZAP/Nuclei/Subfinder · OpenAI/Anthropic/NVIDIA  │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.1 Control plane

Keep the current Python stack and evolve it. A modular monolith is the right
shape for a local-first product; microservices and a graph database can wait.

- **Mission service** - objective, scope, autonomy level, budget, plan,
  approvals, state machine.
- **Policy and approval service** - risk tiers, tool allowlists, human gates,
  kill switch, audit.
- **Program service** - platform connectors, normalized scopes, scope diffs,
  expected-value ranking, deadlines.
- **Findings service** - triage, dedup, severity, evidence links, report
  drafts, submissions, retests.
- **Event store** - append-only, sequenced, replayable; the source of truth
  for the UI and for evals.
- **Search** - SQLite FTS5 locally, Postgres full-text/vector for teams.
- **Cost ledger** - tokens, dollars, time, tool calls per mission and agent.

### 4.2 Agent runtime

A mission becomes a **task DAG**, not a single prompt.

```
Mission brief
  -> Planner: hypotheses + tasks + success criteria + budget
  -> Human approves plan (or auto-approves low-risk steps)
  -> Executor: runs tasks in parallel, each with a tool allowlist
  -> Verifier: independently reproduces every candidate finding
  -> Critic: challenges severity, scope, and duplicate risk
  -> Reporter: drafts platform-specific report with evidence
  -> Human reviews and submits
```

**Runtime adapters:**

- **Native** - deterministic Python tools + LLM planning. Default.
- **Hermes** - optional adapter through MCP, for users who already run Hermes.
- **Coding agents** - Claude Code, Codex, Cursor, or any MCP client can call
  NetCast3r tools and write evidence back into the control plane.

**Tool contract:**

```json
{
  "name": "http.probe",
  "description": "Send a single scoped HTTP request and record the exchange.",
  "risk": "read",
  "scope": "required",
  "schema": {"method": "string", "url": "string", "headers": "object"},
  "rate_limit": "20/s",
  "approval": "none",
  "idempotent": true,
  "cost": "free"
}
```

Every tool declares risk tier, scope requirement, rate limit, cost, approval
policy, and idempotency. The executor refuses calls that do not fit the
mission capsule.

### 4.3 Evidence plane

The evidence plane is what makes the product defensible.

- **Artifact** - request, response, screenshot, file, hash, timestamp,
  producer, redaction state.
- **Hypothesis** - statement, confidence, supporting and contradicting
  evidence, required next evidence, status.
- **Experiment** - tool calls and observations that test a hypothesis.
- **Finding** - only created when a verifier reproduces the impact.
- **Report** - platform-specific draft with evidence references.
- **Chain of custody** - append-only hash chain; any edit creates a new
  version.

**Verification ladder:**

1. Deterministic check (provider API, response diff, authz oracle).
2. Independent re-run with a fresh session and fresh context.
3. Critic agent challenges scope, severity, and duplicate likelihood.
4. Human review, with a one-click "show me the proof" replay.

### 4.4 Safety model

| Risk | Control |
| --- | --- |
| Scope creep | Signed mission capsule, egress allowlist, DNS pinning, network-layer enforcement |
| Prompt injection | Untrusted-content labels, taint tracking, tool output normalization, no instruction execution from target data |
| Tool misuse | Per-tool risk tier, allowlist, rate limit, budget, approval gate |
| Credential leakage | Secret vault, redaction at write time, no secrets in logs or model context |
| Cost runaway | Mission budget, per-agent budget, circuit breaker, kill switch |
| Supply chain | Signed skills, pinned MCP servers, tool version pinning, allowlist |
| Memory poisoning | Scoped memory, provenance, review gate for durable writes |
| Cascading failure | Fail-closed verifier, circuit breaker, independent checks |
| Human over-trust | Evidence citations, confidence calibration, mandatory approvals for high-risk actions |

### 4.5 Observability and evaluation

- Event-sourced sessions with replay and fork-from-event.
- OpenTelemetry GenAI spans for model calls, tool calls, and costs.
- Per-mission timeline: plan, actions, interventions, evidence, verdict.
- **Eval harness** - replay a corpus, compare precision/recall/cost against a
  baseline, and gate releases on regressions.

---

## 5. Data model

Core entities:

| Entity | Key fields |
| --- | --- |
| Organization | id, name, plan, retention policy |
| User / Team | id, role, permissions, preferences |
| Program | platform, handle, name, reward range, deadline, status |
| ScopeAsset | program, type, target, eligible, severity cap, notes |
| Engagement | program, organization, rules of engagement, dates |
| Mission | objective, engagement, autonomy, budget, state, plan |
| Task | mission, parent, agent, tool allowlist, status, result |
| AgentSession | agent, mission, model, tokens, cost, state |
| ToolCall | session, tool, arguments, result, risk, approval |
| Asset | host, service, technology, first_seen, last_seen |
| Endpoint | method, path, params, auth requirement, source |
| Identity | principal, role, tenant, session state |
| Credential | type, masked value, provider, validation state |
| Hypothesis | statement, confidence, status, evidence links |
| Experiment | hypothesis, tool calls, observations |
| Evidence | artifact, hash, producer, timestamp, redaction |
| Finding | title, severity, confidence, status, evidence, report |
| Report | platform, body, score, submission state |
| Submission | platform, report, status, payout, SLA |
| Retest | finding, result, evidence, date |
| Approval | action, risk, requester, approver, decision, nonce |
| Skill | name, version, source, content, signature, enabled |
| Memory | scope, kind, content, provenance, review state |
| Policy | scope, tools, budgets, approvals, retention |
| Event | seq, type, actor, payload, hash, timestamp |

Store locally in SQLite with FTS5; mirror to Postgres for team deployments.
Keep artifacts on disk with content hashes; use S3-compatible storage for
teams. Do not put a graph database in v1; model the graph in relational
tables and traverse it in the service layer.

---

## 6. UX and UI

### 6.1 Information architecture

```
Command Center        the default: missions, fleet, approvals, KPIs
Missions              list, composer, plan review, live room, replay
Findings              inbox, board, table, split detail, report builder
Programs              cross-platform programs, scope, EV ranking, deadlines
Target Graph          assets, endpoints, identities, hypotheses, attack paths
Evidence              artifact vault, chain of custody, replay
Reports               drafts, scoring, submissions, retests, payouts
Agent Studio          fleet, skills, tools, MCP, memory, evals, budgets
Intelligence          coverage, precision, cost, payout, benchmarks
Admin                 org, team, RBAC, SSO, audit, policies, integrations
```

### 6.2 The Command Center

The default screen answers five questions in one glance:

1. **What is running?** Live missions, agent fleet, current stage.
2. **What needs me?** Approval queue, human handoffs, blocked missions.
3. **What did we prove?** Verified findings, severity, bounty estimate.
4. **What is it costing?** Time, tokens, dollars, scope risk.
5. **What should happen next?** Next-best-action recommendations.

Layout:

- **KPI strip** - active missions, verified findings, valid rate, cost per
  proof, coverage.
- **Mission hero** - the primary live operation: target, program, elapsed,
  budget, scope, agents, pause/intervene/open.
- **Agent fleet** - one card per agent with role, status, current action,
  tokens, cost.
- **Approval queue** - risk-tiered action cards with "why this," scope,
  evidence, approve/reject.
- **Live operation** - chronological timeline of plan, tool calls, evidence,
  and interventions.
- **Evidence graph** - the attack path from asset to proof.
- **Findings in flight** - compact table with severity, confidence, status,
  bounty.
- **Right rail** - budget/risk rings, scope shield, next best actions, kill
  switch.

### 6.3 The Mission Composer

Natural language is the input, structure is the output.

1. **Brief** - target, program, objective, constraints, autonomy, budget.
2. **Plan preview** - editable task DAG with agents, tools, approval gates,
   estimated cost and time.
3. **Launch** - starts only after the human sees the plan.

The agent must never silently expand scope or tools. Any change to the plan
is a visible event with a reason.

### 6.4 AI UX rules

- **Plan before act.** Show the plan and the budget before execution.
- **Cite evidence.** Every claim links to an artifact or a tool result.
- **Show uncertainty.** Confidence is a first-class value, not a badge.
- **Ask when ambiguous.** A clarifying question is better than a wrong action.
- **Offer take-over.** Browser, 2FA, CAPTCHA, GUI, and business-logic work
  hand off to the human with a clear resume point.
- **No fake anthropomorphism.** No avatars that pretend to be people, no
  emotional manipulation, no "I feel."
- **No raw chain-of-thought.** Show decisions, evidence, and rationale
  summaries, not hidden reasoning.
- **Reversible by default.** Checkpoints, undo, replay, fork.

### 6.5 Design language: Obsidian Signal

Evolve the existing NetCast3r identity rather than replacing it.

- **Substrate:** true black and near-black tonal surfaces. No card-grey wash.
- **Signal:** acid `#C8F81A` for live, verified, primary action, focus.
  Under 8% of any screen.
- **Structure:** violet `#9F23DD` for edges, in-progress, graph links.
- **Type:** bone `#F5E9DC` for display; warm grey for body; monospace for
  data and labels.
- **Depth:** 1px hairlines, inset edges, very soft ambient shadow. Glow only
  on live acid elements.
- **Motion:** 120-240ms, state-reporting only. Respect reduced motion.
- **Density:** comfortable and compact modes, persisted per user.
- **Themes:** dark default, light "paper" theme for daylight triage.
- **Accessibility:** WCAG AA, focus rings, state words in addition to color,
  keyboard-first, screen-reader labels.

What changes from today:

- Remove the CRT scanline and grain from data views; keep them for the
  marketing/banner surfaces.
- Increase type size and line height; reduce the number of competing labels.
- Replace the wall of equal-weight panels with a clear hierarchy: one hero,
  three to five supporting cards, one table.
- Use violet for structure, not for large fills.
- Make the attack path and evidence chain the signature visual, not a
  decorative radar.

### 6.6 Signature components

- **Mission card** - target, objective, state, budget, scope, agents.
- **Agent fleet** - role, status, current action, cost, health.
- **Approval card** - action, risk, scope, evidence, approve/reject, nonce.
- **Evidence spine** - asset -> hypothesis -> experiment -> proof -> report.
- **Attack path canvas** - nodes and edges with severity and confidence.
- **Confidence waterfall** - how a candidate moved through the ladder.
- **Budget rings** - time, tokens, dollars, scope.
- **Scope shield** - always-visible in/out-of-scope state.
- **Command palette** - actions, navigation, natural language.
- **Copilot panel** - ask the fleet, explain this, draft report, next action.
- **Replay scrubber** - time travel through the mission.
- **Intervention queue** - human handoffs and blocked steps.

---

## 7. Feature catalog

Priorities: **P0** first release, **P1** next, **P2** later.

### Mission control

| Feature | Priority |
| --- | --- |
| Natural-language mission brief with structured plan preview | P0 |
| Editable task DAG with agents, tools, approvals, budget | P0 |
| Autonomy dial: Observe / Assist / Supervised / Autonomous | P0 |
| Live agent fleet with current action, tokens, cost | P0 |
| Pause, resume, stop, kill switch | P0 |
| Approval queue with risk tiers and evidence | P0 |
| Mission timeline and replay | P0 |
| Human handoff for browser/2FA/GUI work | P1 |
| Branch/fork a mission from any event | P1 |
| War room with presence, comments, assignments | P1 |
| Scheduled and continuous missions | P2 |
| Cross-mission portfolio view | P1 |

### Proof engine

| Feature | Priority |
| --- | --- |
| Evidence artifact vault with hashes | P0 |
| Deterministic verifiers per vulnerability class | P0 |
| Independent re-run in a fresh session | P0 |
| Critic agent for scope, severity, duplicates | P1 |
| Duplicate likelihood scoring | P1 |
| CVSS 4.0, CWE, ATT&CK mapping | P1 |
| Report quality score and redaction check | P1 |
| Submission-ready report builder per platform | P0 |
| Retest workflow and fix verification | P1 |
| Proof replay for humans | P0 |

### Target intelligence

| Feature | Priority |
| --- | --- |
| Persistent asset/endpoint/identity graph | P0 |
| Hypothesis ledger with supporting/contradicting evidence | P0 |
| Attack path visualization | P1 |
| Scope diff across runs | P0 |
| Coverage map and untested surface | P1 |
| Technology and auth map | P1 |
| Historical URL/JS inventory | P0 |
| Cross-run dedup and "seen before" | P0 |
| Natural-language search over the graph | P1 |

### Program intelligence

| Feature | Priority |
| --- | --- |
| HackerOne program and scope sync | P0 |
| Bugcrowd program and scope sync | P1 |
| Intigriti and YesWeHack sync | P1 |
| Scope change alerts | P0 |
| Expected-value ranking | P1 |
| Program briefs, reward ranges, deadlines | P1 |
| Submission tracking and SLA | P1 |
| Payout and tax export | P2 |
| Duplicate checks before submission | P1 |

### Agent Studio

| Feature | Priority |
| --- | --- |
| Agent roster with roles, models, tools, limits | P0 |
| Skill library with progressive disclosure | P0 |
| Skill editor and versioning | P1 |
| MCP client and server registry | P0 |
| Tool registry with risk tiers and schemas | P0 |
| Memory inspector and review gate | P1 |
| Model routing, fallback, credential pools | P1 |
| Cost and token budgets per agent | P0 |
| Prompt/version A/B tests | P2 |
| Eval harness with benchmark suites | P1 |
| Agent-created skills with approval | P2 |

### Enterprise trust

| Feature | Priority |
| --- | --- |
| Organizations, teams, roles, RBAC | P1 |
| SSO (OIDC/SAML) | P1 |
| Immutable audit log | P0 |
| Data retention and export | P1 |
| Encryption at rest and in transit | P1 |
| Air-gapped/local-only mode | P0 |
| Policy-as-code | P1 |
| SIEM/webhook export | P1 |
| Sandbox and egress allowlist | P0 |
| Secret vault and redaction | P0 |
| Multi-tenant isolation | P2 |
| Billing and usage metering | P2 |

### UX and platform

| Feature | Priority |
| --- | --- |
| Command palette and keyboard shortcuts | P0 |
| Saved views and pinned filters | P1 |
| Split-pane triage | P1 |
| Density modes and light/dark themes | P1 |
| Natural-language search | P1 |
| Notifications and digests | P1 |
| Mobile-responsive triage | P1 |
| Onboarding and sample mission | P1 |
| Plugin/marketplace surface | P2 |
| Public API and webhooks | P1 |

---

## 8. Roadmap

### Phase 0 - Foundation and Command Center (2 weeks)

- Design tokens and shell evolution.
- Mission entity, state machine, event schema.
- Approval entity and API.
- Command Center using real runs/events/findings.
- Agent fleet derived from live events.
- Command palette and keyboard navigation.
- Acceptance: a mission can be created, watched, paused, and approved from
  one screen; no regression in the existing pipeline.

### Phase 1 - Agent core (4 weeks)

- Native planner/executor/verifier loop.
- Tool registry with JSON schemas and risk tiers.
- MCP server exposing NetCast3r tools.
- Skills loader (agentskills.io-compatible).
- Mission budgets and kill switch.
- Replay and fork-from-event.
- Acceptance: one end-to-end mission with 3 agents, 2 approvals, and a
  replayable evidence bundle.

### Phase 2 - Proof engine and target graph (4 weeks)

- Evidence vault and hash chain.
- Hypothesis ledger.
- Deterministic verifiers for the top 10 classes.
- Findings inbox with split-pane triage.
- Report builder with quality score.
- Acceptance: every finding links to a reproducible artifact and a report
  draft.

### Phase 3 - Program intelligence (4 weeks)

- HackerOne and Bugcrowd connectors.
- Scope normalization and diffs.
- Expected-value ranking.
- Submission tracking and retests.
- Acceptance: a program can be synced, a mission scoped from it, and a report
  submitted with status tracked.

### Phase 4 - Enterprise and collaboration (4 weeks)

- RBAC, SSO, audit export.
- Team workspaces and comments.
- Policy-as-code and retention.
- Sandbox hardening and egress proxy.
- Acceptance: two users can collaborate on one engagement with a complete
  audit trail.

### Phase 5 - Marketplace and evals (ongoing)

- Skill/tool marketplace.
- Public benchmark harness.
- Community playbooks.
- Cloud sync and hosted option.

---

## 9. Success metrics

**North star:** verified, submission-ready findings per engaged hour.

| Metric | Target |
| --- | --- |
| Valid submission rate | > 90% |
| False-positive rate | < 5% |
| Cost per proof | < $15 |
| Time to first proof | < 30 min |
| Human intervention rate | < 1 per mission-hour |
| Scope violations | 0 |
| Secret leaks in logs/reports | 0 |
| Mission replay determinism | 100% of recorded events |
| UI p95 interaction | < 100 ms |
| Agent task success rate | > 85% |

Benchmark against XBOW-style and AutoPenBench suites, plus an internal
regression corpus of past NetCast3r runs.

---

## 10. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Agent false positives erode trust | Independent verifier, evidence citations, human review, valid-rate metric |
| Prompt injection from target content | Untrusted-content labels, taint tracking, tool allowlists, no instruction execution from data |
| Scope creep | Signed scope capsule, network-layer enforcement, egress proxy, mission diff review |
| Cost runaway | Budgets, rate limits, circuit breakers, per-agent caps |
| Over-reliance on agents | Show uncertainty, evidence, alternatives; require approval for high-risk actions |
| Complexity slows shipping | Modular monolith, phased roadmap, vertical slices |
| Platform API limits | Rate limiting, backoff, caching, manual fallback |
| Legal/ethical misuse | Authorized-testing gate, audit log, scope enforcement, responsible-use policy |

---

## 11. Decisions needed

1. **Runtime:** native NetCast3r runtime, Hermes adapter, or hybrid?
   Recommendation: native runtime + MCP adapters, with Hermes as one adapter.
2. **Stack:** keep Python + Svelte, or migrate the control plane to FastAPI?
   Recommendation: keep the engine and UI; introduce FastAPI when team
   features arrive, not before.
3. **Deployment:** local-first single-user first, or multi-tenant from day one?
   Recommendation: local-first with team-ready schema.
4. **First milestone:** Command Center + Mission + Approvals, or the agent
   runtime first?
   Recommendation: Command Center first; it creates the product surface and
   forces the data model.
5. **Brand:** keep the acid/violet identity, or move to a neutral enterprise
   palette?
   Recommendation: keep the identity, refine the execution.

---

## 12. References

- Hermes Agent features: https://hermes-agent.nousresearch.com/docs/user-guide/features/overview
- Hermes Agent architecture: https://hermes-agent.nousresearch.com/docs/developer-guide/architecture
- Hermes skills: https://hermes-agent.nousresearch.com/docs/user-guide/features/skills
- Hermes memory: https://hermes-agent.nousresearch.com/docs/user-guide/features/memory
- Hermes web dashboard: https://hermes-agent.nousresearch.com/docs/user-guide/features/web-dashboard
- Hermes Agent repository: https://github.com/NousResearch/hermes-agent
- ARTEMIS study: https://arxiv.org/html/2512.09882v2
- HackerOne hybrid security analysis: https://www.hackerone.com/blog/agentic-ai-vs-human-pentesters-benchmarking
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP AI Agent Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- XBOW: https://xbow.com/
- PentAGI: https://pentagi.com/
- PentestGPT: https://github.com/GreyDGL/PentestGPT
- CAI: https://github.com/aliasrobotics/cai
- Cyberful: https://github.com/cyberful/cyberful
- ShakerScan Hunt architecture: https://shakerscan.com/docs/open-source/hunt-architecture
- T3MP3ST: https://github.com/elder-plinius/T3MP3ST
- bountystrike: https://github.com/nilhemdot/bountystrike-community
- XuanMu: https://github.com/guaidao2/XuanMu-RedTeam-Agent
- Bugcrowd Security Inbox: https://docs.bugcrowd.com/changelog/customers/the-security-inbox/
- YesWeHack Vulnerability Center: https://helpcenter.yeswehack.io/en/articles/376666-vulnerability-center
- Bugcrowd API: https://docs.bugcrowd.com/api/usage/
- bbscope: https://github.com/sw33tLie/bbscope
- ScopesExtractor: https://github.com/JoshuaMart/ScopesExtractor
- ScopeVault: https://github.com/tikket1/ScopeVault
- agentskills.io: https://agentskills.io/
- Model Context Protocol: https://modelcontextprotocol.io/
