# Penligent public comparison

This note records what can be verified from Penligent's public material. It is
not a source-code review.

## What is actually public

- The GitHub repository `penligent/penligent` contains a README and images. It
  does not contain the application source, build files, or agent runtime.
  https://github.com/penligent/penligent
- The product site ships desktop installers for Windows, macOS, and Linux.
  https://www.penligent.ai
- The public feature guide documents:
  - project creation with an authorised target and a skill/testing plan;
  - Agent and Manual modes, an Agent Console, and per-task stop/interrupt;
  - key findings with verify/ignore states, evidence, and remediation;
  - an attack graph and candidate path verification;
  - tool results with command, purpose, duration, and output;
  - asset management and "verify again";
  - scheduled once/weekly projects;
  - PDF and Markdown report export with SOC 2 / ISO 27001 framing;
  - a claimed library of 200+ security tools.

Because the runtime is closed source, any claim about Penligent's internal
prompts, agent loop, data model, or exploit chaining would be invented. This
project does not make those claims.

## NetCast3r differences that are real

| Area | NetCast3r | Penligent public material |
| --- | --- | --- |
| Interface | Local HTTP control plane, Svelte dashboard, MCP stdio server | Desktop application with its own UI |
| Tool contract | Typed MCP tools with JSON schemas, risk tiers, scope checks, single-use approvals, audit | 200+ tool integrations, agent/manual modes |
| Evidence | Hypothesis ledger, explicit finding write path, artifacts, report-quality scoring | Key findings, verify/ignore, evidence and remediation |
| Training | Multi-source lab catalogue, evidence-gated lessons, research technique library | Not described publicly |
| Self-model | Deterministic capability scores, gaps, human-gated upgrade proposals | "Self-evolving" marketing claim; internals not public |
| Research | 38 sourced techniques, `technique_plan`, `hunt_plan`, `research_ingest` | Not described publicly |
| Reporting | Markdown, SARIF, quality gate, submission ledger | PDF and Markdown export, compliance framing |

## Gaps worth closing, in order

1. **Report export**: add a PDF/DOCX export path with the same redaction and
   quality gate as the Markdown report.
2. **Attack graph**: build a graph from stored assets, identities, findings,
   and hypotheses; keep edges evidence-backed, not speculative.
3. **Scheduled missions**: a scheduler that re-runs a scoped verification or a
   training session and records the diff. It must respect approvals.
4. **Desktop packaging**: a signed installer is useful for operators, but it is
   packaging, not a security capability.
5. **Tool breadth**: do not chase "200+ tools" for its own sake. Add a tool only
   when it has a typed contract, a scope gate, and a proof path.

## What not to copy

- A broad scanner in the active path. It produces noise and duplicate findings.
- An agent that can create findings without reproduced evidence.
- Any claim that an AI can guarantee critical findings. It cannot.
- Hidden prompt or data handling. Operators should be able to audit every call.

## Conclusion

NetCast3r's advantage should be **evidence discipline and research depth**, not
a larger tool count. The next work is report export, an evidence-backed attack
graph, and scheduled verification, in that order.
