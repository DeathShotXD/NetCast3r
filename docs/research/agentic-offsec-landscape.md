# Agentic offensive-security landscape

What the leading open and closed agentic OffSec tools actually do, read from
their own primary sources, and what NetCast3r takes from each. This is a
capability map, not a source review: the internals of the closed products are
not public and are not claimed here.

## Sources

- **Penligent V3.0** - product site and public feature guide (`penligent.ai`,
  `github.com/penligent/penligent`). Desktop app; projects with a testing plan;
  Agent/Manual modes; Agent Console with `@`-mentions; attack graph with
  candidate-path verification; key findings with verify/ignore; tool results
  with command, purpose, duration, output; asset management with "verify
  again"; scheduled once/weekly tasks; PDF/Markdown reports with SOC 2 / ISO
  27001 framing; a claimed 200+ tool library.
- **HexStrike AI v6.0** (`github.com/0x4m4/hexstrike-ai`). An MCP server that
  wraps 150+ external security tools and 12+ "agents": an Intelligent Decision
  Engine (tool selection, parameter optimization, attack-chain discovery),
  process management (list/status/terminate, live dashboard), smart caching,
  graceful degradation, a headless-Chrome browser agent, CVE intelligence, and
  an "AI exploit generator". Tools are grouped network (nmap, masscan,
  rustscan, amass, ...), web (gobuster, ffuf, nuclei, sqlmap, dalfox, arjun,
  ...), auth (hydra, john, hashcat, netexec, evil-winrm), binary (gdb, radare2,
  ghidra, pwntools, angr), cloud (prowler, scout-suite, trivy, kube-hunter,
  kube-bench), OSINT, and CTF.
- **Strix** (`github.com/usestrix/strix`). Autonomous agents in a Docker
  sandbox: a full pentest toolkit (HTTP interception proxy via Caido, browser
  exploitation, shell/command execution, a Python "custom exploit runtime"),
  SAST + DAST, **real exploit validation with working PoCs**, a multi-agent
  "graph of agents", API testing straight from an OpenAPI/Swagger/Postman
  contract, CI/CD (GitHub Actions), SOC 2 / ISO 27001 / PCI DSS reports,
  auto-fix PRs, an MCP client, and a "continuous learning" claim.
- **CAI** (`github.com/aliasrobotics/cai`, archived). Notable for the research,
  not the runtime now: a guardrail framework against **prompt injection into
  the agents themselves**, a 6-level automation/autonomy taxonomy, benchmark
  work (CAIBench), and the observation that a **blackboard over several
  scaffolds beats any single harness** (19/33 vs 15/33 Cybench).

Adjacent work in the same line: PentestGPT (USENIX Security '24), XBOW,
AutoPenBench, Vulnhuntr (SAST), Nebula, RapidPen.

## What each gets right, and what we adopt

| Capability | Source | NetCast3r today | Action |
| --- | --- | --- | --- |
| Typed external tool library | HexStrike, Penligent | 6 passive tools, allowlisted | **Extend** to a tiered broker (this work) |
| Live process management | HexStrike | none | **Add** (this work) |
| API-spec targeting | Strix | none | **Add** (this work) |
| Working PoC per candidate | Strix | none | **Add** (this work) |
| Attack graph + path verify | Penligent | landed | keep |
| Multi-agent orchestration | Strix, Penligent | landed (mesh + director) | keep |
| Agent console / `@`-mentions | Penligent | landed (directions) | keep |
| Prompt-injection guardrails | CAI | partial (untrusted-data rule) | strengthen next |
| Scheduled tasks | Penligent | landed (director) | keep |
| Self-evolving / continuous learning | Strix, CAI | partial (selfmodel, KB) | next tranche |
| Sandboxed shell + exploit runtime | Strix | subprocess, no sandbox | gated, next |
| Compliance reports | Penligent, Strix | Markdown/SARIF | next |

## The design choice NetCast3r keeps

Both HexStrike and Strix will run a broad tool against a target and let the
agent interpret the output. NetCast3r keeps a stricter rule: an external tool
is a **source of leads, not findings**. Tool output is parsed into graph nodes,
endpoints, technologies, and **candidates** with raw evidence; a finding is
still a human-gated promotion. Scope is enforced before the binary runs, private
and loopback targets are only allowed when the mission scope names them, and a
high-risk tool stays behind the approval gate (or an authorized autonomous
mission).

The other choice, from CAI's benchmark: **no single harness wins**. NetCast3r's
answer is a blackboard (the graph + knowledge base) that several brains - hunt,
operator, mesh, module runner, external tools - read and write, so knowledge is
shared rather than trapped in one agent.

## What we deliberately do not copy

- A model-driven "exploit generator" that fabricates payloads or claims success
  without a reproduced effect. Our modules point at a test; the test produces
  evidence.
- A tool broker with no scope gate. Every run is checked against the mission
  scope first, and the metadata/link-local refusal is absolute.
- Hidden prompts or telemetry. Every call is audited.

## Why "self-learning" is real here and not marketing

The knowledge base is durable and provider-agnostic: technologies, endpoint
shapes, technique outcomes, dead ends, and verified chains survive a model
swap, and `learn_from_mission` writes them from stored evidence only. The
self-model keeps capability scores and writes human-gated upgrade proposals.
The honest claim is narrower than Strix's "continuous learning": the memory is
real and shared, the reasoning still depends on the model you connect.
