# Penligent public comparison

This note records what can be verified from Penligent's public material. It is
not a source-code review.

## Penligent V3.0 public feature inventory

From the product site and the public GitHub README (2026):

- **Projects** with an authorized target and a testing plan (the default is
  "Comprehensive Deep Testing"); a legal-authorization confirmation.
- **Agent and Manual modes**, an **Agent Console** with `@`-mentions of an
  agent or key finding, and a task queue (Running, Interrupted, Completed,
  Ended, Total) with per-task stop and Interrupt Task.
- **Global overview**: total projects, active agents, total risks by severity,
  risk posture and trend, and asset security posture.
- **Project overview**: agent executions, risks found, agents currently
  running, recently discovered risks, and an attack-graph summary.
- **Target overview**: target info (type, location, cloud provider, region,
  ASN, subnet, IPs, domains), network info (open ports and services, DNS,
  reverse DNS, WAF/CDN), web app info (technology stack, TLS certificate).
- **Attack path management**: an attack graph of risk and credential nodes,
  candidate path selection, and one-click path **verification**.
- **Key findings**: filters (All, Ignored, Verifying, Credentials; severity),
  Verify/Ignore, evidence and PoC, remediation, and single-risk report export.
- **Tool results**: tool name, status, summary, command, purpose, start time,
  duration, and output.
- **Asset management**: assets with verified risk statistics, masked
  credentials, "view task", and "verify again".
- **Scheduled tasks**: a plan name, target, skill, task mode (New project /
  Verify again), Once or Weekly, and a run time.
- **Report export**: PDF and Markdown, project and single-risk, with SOC 2 and
  ISO/IEC 27001 framing.
- **Settings**: theme, language, font size, version and update check.
- A claimed library of **200+ Kali tools**, real-time CVE exploits with
  one-click PoC scripts, and "autonomous attack chains".

Because the runtime is closed source, any claim about Penligent's internal
prompts, agent loop, data model, or exploit chaining would be invented. This
project does not make those claims.

## NetCast3r differences that are real

| Area | NetCast3r | Penligent public material |
| --- | --- | --- |
| Interface | Local HTTP control plane, Svelte dashboard, MCP stdio server | Desktop application with its own UI |
| Tool contract | Typed MCP tools with JSON schemas, risk tiers, scope checks, single-use approvals, audit | 200+ tool integrations, agent/manual modes |
| Supervisory loop | Director + Prime: a durable in-process supervisor that ranks the portfolio and drives scoped runs | Not described publicly |
| Evidence | Hypothesis ledger, explicit finding write path, artifacts, report-quality scoring | Key findings, verify/ignore, evidence and remediation |
| Attack graph | Evidence-backed nodes and edges with provenance; candidate paths and step verification | Attack graph and candidate path verification (internals not public) |
| Training | Multi-source lab catalogue, evidence-gated lessons, research technique library | Hacking Labs / cyber range |
| Self-model | Deterministic capability scores, gaps, human-gated upgrade proposals | "Self-evolving" marketing claim; internals not public |
| Research | 38 sourced techniques, `technique_plan`, `hunt_plan`, `research_ingest` | Not described publicly |
| Reporting | Markdown, SARIF, quality gate, submission ledger | PDF and Markdown export, compliance framing |

## Gaps in order (updated)

1. **Attack graph** - landed. `graph_build` derives nodes and edges from real
   evidence, `paths_list` shows candidate chains, and `path_verify` tests a
   path step by step without creating a finding. See `docs/GRAPH.md`.
2. **Report export**: add a PDF/DOCX export path with the same redaction and
   quality gate as the Markdown report, plus a SOC 2 / ISO 27001 mapping.
3. **Scheduled missions**: a plan with Once/Weekly timing and a "verify again"
   mode that reuses a stored auth profile and records the diff. The director
   is the substrate; this adds the schedule and the diff.
4. **Target profile**: consolidate DNS, TLS, WAF/CDN, technology, and network
   data into one target object on the graph.
5. **Operator console**: inject a queued direction into a running mission.
6. **Desktop packaging**: useful for operators, but packaging, not capability.

## What not to copy

- A broad scanner in the active path. It produces noise and duplicate findings.
- An agent that can create findings without reproduced evidence.
- Any claim that an AI can guarantee critical findings. It cannot.
- Hidden prompt or data handling. Operators should be able to audit every call.
- A graph that shows speculative nodes as facts. Ours records provenance and
  confidence on every edge, and marks an unproven claim as a hypothesis.

## Conclusion

NetCast3r's advantage is **evidence discipline, an auditable supervisor, and
research depth**, not a larger tool count. Next: report export with compliance
mapping, scheduled verification, and the target profile.
