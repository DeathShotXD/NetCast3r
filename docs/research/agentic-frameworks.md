# Agentic security frameworks: research and integration plan

Research date: 2026-10-30. This note records what each framework actually
contributes, what NetCast3r already has, and the smallest next step that adds
real capability without weakening scope, approvals, or evidence.

## 1. What the landscape looks like

### Hermes Agent (Nous Research)

Open-source, self-hosted agent released in February 2026. The differentiator is
a built-in learning loop: it creates skills from experience and improves them
during use, with persistent memory and MCP support.

- Source: https://github.com/nousresearch/hermes-agent
- Docs: https://hermes-agent.nousresearch.com/docs/
- Guide: https://petronellatech.com/blog/hermes-agent-ai-guide/

What to adopt:

1. A skill lifecycle, not just a skill table: draft -> used -> revised ->
   retired, with a source and a success count.
2. Retrieval before planning. NetCast3r now does this with the `recall` task.
3. Memory compaction: keep the lesson, drop the raw transcript. NetCast3r
   already stores bounded records; the next step is a periodic summarizer that
   merges duplicate lessons and raises confidence only after repeated use.

### Agent Zero

Python framework that runs in Docker and treats the operating system as a
tool. It has multi-agent cooperation, persistent/vector memory, plugins, MCP,
A2A, browser control, and a skills scanner.

- Source: https://github.com/agent0ai/agent-zero
- Site: https://www.agent-zero.ai/
- Review: https://vibecoding.app/blog/agent-zero-review

What to adopt:

1. An optional Docker sandbox for untrusted tooling and exploit reproduction.
2. A plugin surface so a team can add a tool without editing core code.
3. A2A as a second protocol next to MCP for agent-to-agent delegation.

### HexStrike AI

A FastMCP server that exposes 150+ security tools to Claude, GPT, Copilot, and
other MCP clients, with a multi-agent execution layer.

- Source: https://github.com/0x4m4/hexstrike-ai
- Analysis: https://blog.checkpoint.com/executive-insights/hexstrike-ai-when-llms-meet-zero-day-exploitation/

What to adopt:

1. A broad tool catalogue behind one MCP endpoint.
2. A capability descriptor per tool (risk, target type, side effects).
3. A hard boundary: HexStrike-style execution must still pass NetCast3r's
   scope check, risk tier, and approval. Tool breadth is not authorization.

NetCast3r now has the outbound side of this: `mcp_servers_list`,
`mcp_server_tools`, and `mcp_server_call` can drive a configured HexStrike,
Hermes, Agent Zero, or OpenCode MCP server, with URL/Host arguments checked
against the mission scope.

### Strix (usestrix/strix)

Autonomous AI penetration-testing agents organized as a graph of specialized
agents, running code dynamically in a Docker environment and validating
findings with proof-of-concepts.

- Source: https://github.com/usestrix/strix
- Docs: https://docs.strix.ai/
- Comparison: https://blog.ostorlab.co/9-open-source-ai-pentest-tools-2026.html

What to adopt:

1. A graph of roles rather than one linear plan: recon, auth, API, exploit
   author, validator, reporter.
2. A validator that must reproduce the impact before a finding is recorded.
3. Disposable execution for PoCs; the host running the dashboard should not be
   the host executing a payload.

### STIX 2.1 and TAXII 2.1

STIX is the JSON data model for cyber threat intelligence; TAXII 2.1 is the
transport for exchanging it.

- TAXII intro: https://oasis-open.github.io/cti-documentation/taxii/intro.html
- TAXII 2.1 spec: https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html
- Microsoft Sentinel integration:
  https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-taxii

What to adopt:

1. Import indicators and reports from a TAXII collection into the threat-intel
   cache.
2. Export NetCast3r findings and lessons as STIX `indicator`, `vulnerability`,
   `malware`, and `report` objects for a client SOC.
3. Keep the source and confidence on every object. Do not turn a lesson into an
   indicator without evidence.

### MCP and A2A

MCP connects an agent to tools and data. A2A connects agents to other agents.
Production systems in 2026 use both.

- Comparison: https://leanware.co/insights/a2a-vs-mcp-protocol-comparison
- Protocol guide:
  https://jangwook.net/en/blog/en/mcp-vs-a2a-vs-open-responses-agent-protocol-comparison-2026/

NetCast3r already is an MCP server (stdio) and now an MCP client (HTTP and
stdio). A2A is the next protocol: an agent card, task submission, streaming
status, and artifact return. It should sit beside the MCP registry, not replace
it.

### Planner-executor patterns (CAI, PentestGPT, and similar)

The common pattern is a planner that decomposes the objective, an executor that
calls tools, and a validator that checks the result. NetCast3r's mission agent
is deliberately bounded and deterministic; the missing piece is not a bigger
prompt, it is a verifier with teeth and a memory that survives the run.

## 2. Where NetCast3r stands

| Capability | NetCast3r today | Gap |
| --- | --- | --- |
| MCP server | 93 typed tools, policies, approvals, audit | Tool search/ranking for large catalogues |
| MCP client | HTTP/SSE and stdio registry, scope-checked | Per-server tool allowlist and capability tags |
| Learning | SQLite lessons, skills, reflection, recall task | Skill lifecycle, merge/dedupe, success counters |
| Memory | Runs, events, findings, evidence, lessons | Vector/FTS retrieval, retention policy |
| Orchestration | Bounded mission agent with roles | Graph of agents, parallel branches, verifier |
| Sandbox | Local browser and scoped HTTP | Docker runner for untrusted tools/PoCs |
| Threat intel | NVD, KEV, GitHub, Sploitus, repro plan | STIX/TAXII import/export, EPSS, MISP/OpenCTI |
| Evidence | Artifacts, hashes, download URLs | Signed evidence bundles, chain of custody |
| Enterprise | Local auth, audit, single workspace | RBAC, SSO, multi-tenant, audit export |
| Interop | OpenCode MCP, Burp MCP | A2A, plugin SDK, framework presets |

## 3. Next upgrades, in order

### Phase 1: memory that compounds

1. Add `use_count`, `success_count`, `last_used_at`, and `status`
   (draft/active/retired) to skills.
2. Merge duplicate lessons by technique and target class; raise confidence only
   after repeated independent successes.
3. Add FTS5 search over lessons and skills, then optional embeddings.
4. Let `lesson_reflect` cite the exact tool call, run, and evidence artifact.

### Phase 2: graph orchestration and a real validator

1. Split the mission agent into a small graph: recon -> surface -> auth -> API
   -> exploit-author -> validator -> reporter.
2. Run independent branches in parallel with a shared budget and a single
   evidence store.
3. The validator must reproduce the impact on a disposable account and attach
   the request/response before `findings_create` is allowed to mark it
   confirmed.

### Phase 3: external frameworks and sandboxing

1. Per-server MCP allowlists: a configured server exposes only the tools the
   operator approved.
2. Docker runner for HexStrike/Strix-style tools and for PoC reproduction.
3. A2A agent card and task endpoint so another agent can delegate a scoped task.
4. Framework presets for Hermes Agent, Agent Zero, HexStrike, Strix, and
   OpenCode. A preset is config, not code.

### Phase 4: threat intel interoperability

1. TAXII 2.1 client: discovery, collections, objects, polling cursor.
2. STIX 2.1 export of findings, indicators, and reports.
3. EPSS and KEV scoring on every CVE dossier.
4. MISP/OpenCTI push as an explicit, approved action.

### Phase 5: enterprise release

1. RBAC and SSO on the dashboard; per-workspace isolation.
2. Audit export (JSONL/CEF) and signed evidence bundles.
3. Cost budgets per mission and per provider.
4. Plugin signing and a capability manifest.
5. Helm/Docker Compose deployment with health checks and migrations.

## 4. Safety rules that do not change

- External MCP tools are not authorization. Every target-bearing argument is
  scope-checked before the call.
- High-risk tools need a single-use approval bound to the arguments.
- A reproduction plan is not an execution. Running a PoC needs an explicit
  approval and a sandbox.
- A lesson is written from a stored record, never from a model's guess.
- A finding exists only when an operator or agent writes it with evidence.
