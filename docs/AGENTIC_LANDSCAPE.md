# The agentic OffSec landscape

**What public agent systems actually do, what NetCast3r already covers, and what
to build next.**

Status: working research note, 2026-11-02.

This note is deliberately evidence-marked. It separates what a project's
public README or paper says from what NetCast3r has verified in its own tests.
A vendor claim is not a capability until a reproduction exists.

---

## 1. The landscape in four families

### 1.1 Autonomous pentest agents

These take a target and run a plan-act-observe loop, usually with a sandbox and
a Kali toolset.

| Project | Public shape | What is genuinely useful |
| --- | --- | --- |
| **PentestGPT** | LLM-assisted pentest reasoning, originally a reasoning module plus a pentest task tree; later versions add tool execution and a benchmark | Task-tree decomposition and "what did I learn" reflection; a benchmark mindset |
| **PentAGI** | Multi-agent Go platform with a terminal, browser, search, and vector memory; Docker/Kali sandbox; observability | Durable long-horizon runs, a real execution sandbox, provider fallback, and a UI for watching the swarm |
| **Strix** | Open-source autonomous AI hackers in Docker; parallel agents per target; browser and shell tools; proof-oriented | Per-target isolation, graph-of-agents execution, and a developer-friendly local install |
| **CAI** | Open-source cybersecurity AI framework from Alias Robotics; agent patterns, tools, and orchestration | Composable agent/tool abstractions and an explicit offensive-security focus |
| **Shannon** | Autonomous white-box web pentest agent; source code plus running app; proof-of-concept validation | Source-to-sink analysis, parallel vulnerability-class workers, and a hard rule that a finding needs a working PoC |
| **Vulnhuntr** | LLM plus static analysis; traces remote user input through a full call chain to a dangerous sink | Call-chain reasoning for 0-days that pattern scanners miss; a focused, repeatable pipeline |

### 1.2 Agentic platforms and orchestrators

These are less "one agent, one target" and more "operate a fleet."

- **HexStrike AI** popularised an MCP server that exposes a large Kali tool
  surface to any LLM client.
- **BugTrace-AI**, **xOffense**, **Cyberful**, and similar projects wrap
  recon, exploitation, and reporting in a UI.
- **Hermes Agent** (not security-specific) is the clearest reference for
  skills, bounded memory, subagents, approvals, checkpoints, and a dashboard.
- **Claude Code / Codex / Cursor** show the value of a coding agent that can
  read a repository, run tests, and write a proof. They are useful as
  *workers*, not as the security control plane.

### 1.3 Commercial autonomous pentesting

Public information is marketing plus occasional third-party evaluations; treat
specific internals as unknown unless documented.

- **XBOW** sells proof-first autonomous web pentesting: a finding should carry
  the request, the response, and a reproducible exploit.
- **Horizon3 NodeZero** sells continuous internal and external attack-path
  validation, with an emphasis on safe exploitation and evidence.
- **Pentera** sells automated pentesting with attack-path context and
  remediation validation.
- **Aikido** and **ZeroThreat** combine scanner findings with AI triage and
  developer workflow, not fully autonomous exploitation.
- **BugBunny** and similar services target the bug-bounty workflow with
  AI-assisted triage and report writing.

The commercial lesson is consistent: buyers pay for **validated impact and
workflow**, not for a longer list of unverified findings.

### 1.4 Benchmarks and evaluations

- **AutoPenBench** evaluates autonomous penetration-testing agents on
  reproducible environments.
- **Cybench** measures agent capability on professional-level CTF tasks.
- **NYU CTF Bench** and **EnIGMA** measure tool-use and long-horizon solving.
- **ARTEMIS** (arXiv 2512.09882) compared an agent team with professional
  pentesters on a live university network and found strong throughput but a
  meaningful false-positive rate. The lesson is independent verification, not
  blind autonomy.

A benchmark score is not a bounty result. NetCast3r should report both, and
never mix them.

---

## 2. Capability matrix

Legend: **yes** = implemented and exercised by NetCast3r tests; **partial** =
exists but narrow or unverified; **no** = not present; **n/a** = not public.

| Capability | NetCast3r | PentAGI | PentestGPT | Strix | Shannon | Vulnhuntr | CAI | XBOW |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Deterministic recon and secret hunting | yes | partial | no | partial | partial | no | partial | partial |
| Multi-agent role mesh | yes | yes | partial | yes | yes | no | yes | n/a |
| Long-horizon director / scheduler | yes | yes | partial | partial | partial | no | partial | n/a |
| Scope enforcement at tool boundary | yes | partial | no | partial | partial | n/a | partial | n/a |
| Typed tool registry with risk tiers | yes | partial | no | partial | no | no | partial | n/a |
| Human approval gate | yes | partial | no | partial | no | n/a | partial | n/a |
| Persistent evidence graph | yes | partial | no | partial | partial | no | partial | n/a |
| Finding promotion only from evidence | yes | partial | no | partial | yes | no | partial | yes |
| Working PoC required before report | partial | partial | no | partial | yes | no | partial | yes |
| Browser-driven authenticated testing | yes | yes | no | yes | partial | no | partial | n/a |
| Source-code call-chain audit | partial | no | no | no | yes | yes | no | n/a |
| Program/scope brief ingestion | yes | no | no | no | no | no | no | n/a |
| Coverage checklist per mission | yes | no | no | no | no | no | no | n/a |
| Self-learning knowledge base | yes | partial | no | partial | no | no | partial | n/a |
| Benchmark harness | partial | partial | partial | partial | no | no | partial | n/a |
| Submission and payout ledger | yes | no | no | no | no | no | no | n/a |
| Public report submission without approval | never | unknown | no | unknown | no | no | no | no |

The matrix is a map, not a score. NetCast3r is ahead on authorisation,
provenance, and the operator control plane. It is behind on deep source
analysis and on a repeatable benchmark that proves agent quality.

---

## 3. What to copy, and what not to copy

### Copy

1. **A real sandbox.** Strix and PentAGI isolate tool execution. NetCast3r
   currently has a host shell and a browser, which is powerful but not
   disposable. A per-run container with a mounted evidence directory is the
   next safety and reproducibility win.
2. **Per-target parallel workers.** Strix's isolation and Shannon's
   vulnerability-class workers show that concurrency should be per objective,
   not per arbitrary tool call.
3. **Call-chain source analysis.** Vulnhuntr's lesson is that the high-value
   0-day path is source -> sink, not regex -> alert. NetCast3r's code audit is
   deterministic and useful, but it does not yet follow data across functions.
4. **Proof generation as a first-class artifact.** XBOW and Shannon are right:
   a finding without a replayable request or test is a lead.
5. **A benchmark gate.** PentestGPT and AutoPenBench make progress measurable.
   NetCast3r needs a local corpus and a release gate that runs it.
6. **Provider-agnostic routing with visible health.** PentAGI's fallback model
   is table stakes when one provider rate-limits mid-hunt.

### Do not copy

- **Automatic submission.** NetCast3r must keep human approval before any
  external report. A false positive sent to a program is worse than a missed
  lead.
- **Unbounded autonomy.** A loop that can widen scope, spend approvals, or
  hide its own failures is not autonomy; it is an incident.
- **Model output as evidence.** A model's claim is advisory. The artifact is
  the evidence.
- **"Scan everything" defaults.** The coverage checklist and the mission scope
  are the product. More requests are not more signal.
- **Synthetic metrics.** Never show a payout, a solved lab, or a submission
  that the ledger did not record.

---

## 4. NetCast3r's position

NetCast3r is not trying to be another Strix or PentAGI. Its differentiator is
the **control plane and proof discipline** around the agent:

- one domain or URL creates an authorised mission;
- the director keeps the portfolio moving without an external harness;
- the brain can steer but cannot widen scope, approve itself, or submit;
- every tool call is risk-tiered, scoped, rate-limited, and audited;
- every run matures the graph, the knowledge base, and the coverage map;
- a candidate becomes a finding only through an explicit promotion;
- the submission ledger is the only source of payout truth.

The missing pieces are not "more agents." They are:

1. **Depth:** source call-chain analysis and exploit PoC sandboxing.
2. **Proof:** a generated, replayable PoC for every promoted candidate.
3. **Program intelligence:** brief ingestion, scope diffing, and expected
   value ranking.
4. **Quality:** a benchmark corpus and a release gate.
5. **Resilience:** provider health and a deterministic fallback that keeps
   real targets moving when the model budget is dead.

---

## 5. Build order

### P0 - keep the hunt alive

- Provider health gate: when no model has answered recently, the director
  chooses the deterministic `hunt` brain instead of a model-only swarm.
- Run-level supervisor: detect repeated calls and stalled rounds, inject one
  deterministic alternative objective, then stop with a recorded reason.
- Program brief ingestion: CSV/JSON/brief -> mission scope, with exclusions
  and an explicit expansion gate. **Implemented in this tranche.**

### P1 - make findings provable

- Source call-chain audit: the Python route-to-sink tracer is implemented
  (`sourceflow_scan`); JavaScript/TypeScript, PHP, Java, Go, and Ruby front
  ends are next. Each chain carries a confidence and a suggested test.
- Sandbox runtime: per-run container, read-only target mount for source
  audits, evidence volume, no host secrets.
- PoC builder for every candidate class: HTTP replay, browser script,
  race packet, or source unit test.
- SARIF export for every finding class, not only secrets.

### P2 - make the portfolio smarter

- Program sync and scope diff: HackerOne/Bugcrowd/Intigriti/YesWeHack.
- Expected-value ranking: reward range, competition, scope freshness,
  historical acceptance, and cost per proof.
- Benchmark harness: the deterministic corpus and release gate are implemented
  (`bench_run`); the live-target replay - valid rate, false positives,
  time-to-proof, and cost-per-proof against a fixed baseline - is next.
- Multi-identity auth profiles and a session broker for cross-tenant tests.

### P3 - make it a platform

- Sandboxed plugin/skill registry with signatures.
- Team RBAC, SSO, and retention.
- Replay and fork from any event.
- Public API and webhooks.

---

## 6. Research sources

Primary project documentation read for this note:

- PentAGI: https://github.com/vxcontrol/pentagi
- PentestGPT: https://github.com/GreyDGL/PentestGPT
- Strix: https://github.com/usestrix/strix and https://docs.strix.ai
- Shannon: https://github.com/KeygraphHQ/shannon
- Vulnhuntr: https://github.com/protectai/vulnhuntr
- CAI: https://github.com/aliasrobotics/cai
- HexStrike AI: https://github.com/0x4m4/hexstrike-ai
- Hermes Agent: https://github.com/NousResearch/hermes-agent
- XBOW: https://xbow.com/
- Horizon3 NodeZero: https://horizon3.ai/
- Pentera: https://pentera.io/
- Aikido: https://www.aikido.dev/
- ZeroThreat: https://zerothreat.ai/
- AutoPenBench: https://arxiv.org/abs/2410.03225
- Cybench: https://arxiv.org/abs/2408.08926
- ARTEMIS: https://arxiv.org/html/2512.09882v2
- OWASP Top 10 for Agentic Applications 2026:
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

### Evidence note

The capability matrix reflects public documentation plus NetCast3r's own
tests. It does not claim access to any vendor's private implementation. Where
a public project documents a feature but NetCast3r has not reproduced it, the
mark is `partial`, not `yes`.
