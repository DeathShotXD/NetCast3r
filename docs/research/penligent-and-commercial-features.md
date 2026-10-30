# Penligent AI and the commercial agentic-pentest feature set

Research date: 2026-10-30. Public sources only: product pages, vendor blog
posts, and third-party comparisons. No proprietary code was copied and no
Penligent system was tested. The goal is to extract product patterns that are
useful for NetCast3r, not to clone a competitor.

## What Penligent presents publicly

- "Agentic AI hacker" positioned for users without deep pentest expertise:
  natural-language prompt, one-click assessment.
- A coordinated multi-agent system with a large tool orchestration layer
  (third-party comparisons cite 200+ tools).
- Continuous, 24/7 red-team simulations rather than a one-time scan.
- Verified findings and exploit chains, with reporting and remediation help.
- Published pricing in the market: a low-cost audit access tier and a much
  higher autonomous tier. Third-party comparisons put the audit entry around
  $49/month and autonomous engagements in the hundreds to thousands per month;
  treat those numbers as market signals, not official quotes.

Sources:

- https://www.penligent.ai/
- https://www.penligent.ai/hackinglabs/ai-pentesting-tools-in-2026-proof-beats-hype/
- https://www.penligent.ai/hackinglabs/ja/pentestgpt-vs-penligent-ai-in-real-engagements-from-llm-writes-commands-to-verified-findings/
- https://www.stackhawk.com/blog/ai-pentesting-tools/
- https://www.stingrai.io/blog/best-ai-pentesting-tools-2026
- https://xhack.io/blog/best-ai-pentesting-tools-2026

## The product pattern behind the marketing

1. **Prompt-to-assessment.** The user describes a target and an objective; the
   product turns that into a plan and a run. The hard part is not the prompt,
   it is the scope, budget, and evidence model behind it.
2. **Tool breadth as a moat.** A large catalogue is useful only if the agent can
   choose, sequence, and verify tools. NetCast3r's MCP registry is the bridge to
   that breadth without embedding every tool.
3. **Continuous monitoring.** A one-time scan is a commodity. A diff of the
   attack surface, new endpoints, new findings, and changed exposures is a
   subscription.
4. **Verified findings.** "Proof beats hype" is the market message. A finding
   that cannot be reproduced is a liability. This is why NetCast3r keeps
   evidence artifacts and an explicit write path.
5. **Report and fix.** The buyer wants a report an engineer can act on, not a
   scanner dump. Report quality and remediation guidance are part of the
   product, not an afterthought.

## What NetCast3r already does better or differently

- Local-first, self-hosted, and MCP-native; the operator owns the data.
- Scope, policy, approvals, and audit are first-class, not a wrapper.
- Findings require explicit recording and evidence artifacts.
- Threat intel and reproduction plans are cited and non-executing.
- Lessons and skills are derived from stored records, not model invention.
- It can drive Burp, HexStrike, Hermes, Agent Zero, OpenCode, or an internal
  MCP server without handing over authorization.

## Profit-making features to add

These are product features, not pricing promises. Each one is useful on its own
and can support a paid tier later.

### 1. Assessment presets

One-click missions for common buyer jobs:

- external attack surface review
- authenticated API review
- account-security review
- CI/CD and supply-chain review
- mobile/API review
- smart-contract review

A preset is a mission template with a scope, a plan, required approvals, and a
report skeleton. It turns the product into a repeatable service.

### 2. Attack-surface diff and continuous monitoring

Store a normalized inventory per run (subdomains, live hosts, endpoints, JS
assets, technologies, findings). On the next run, report:

- new and removed hosts
- new endpoints and parameters
- changed titles, headers, and technologies
- reopened or resolved findings
- new secrets or credential exposure

This is the feature that justifies a recurring subscription. It also feeds the
agent: a diff is a better next-action source than a fresh crawl.

### 3. Report quality gate

Score every report on title, impact, evidence, artifacts, reproduction, CVSS or
CVE context, and confidence. Block "ready to submit" until the score and the
evidence checks pass. This reduces N/A and duplicate submissions, which is the
cheapest way to increase realized payout per hour.

### 4. Payout ROI

Aggregate the submission ledger by program, platform, and currency: submissions,
acceptances, paid rows, bounty totals, acceptance rate, average bounty. Rank
programs by realized payout, never by an estimated range. This tells a team
where to spend the next week.

### 5. Verified-finding pipeline

A validator role that must reproduce the impact from a clean context and attach
the request/response before a finding can be marked confirmed. The verifier is
a separate agent with no write access to the finding except its verdict.

### 6. Continuous CI/CD gate

A GitHub App or CLI that runs a scoped assessment on pull requests, posts a
summary, and fails only on verified high/critical findings. This is a natural
recurring-revenue product for engineering teams and a strong differentiator
from one-off pentest reports.

### 7. Team workspaces and RBAC

Enterprise buyers need separate workspaces, roles (owner, operator, reviewer,
read-only), SSO, and audit export. The current single-workspace local model is
the main gap for enterprise sales.

### 8. Reviewed skill marketplace

A signed, reviewed library of playbooks (auth matrix, IDOR, SSRF, cloud,
mobile, smart contracts). Skills have versions, provenance, use/success counts,
and a retirement path. A marketplace is a network effect; the review process is
the quality moat.

### 9. Managed runs

A hosted control plane that runs the same missions for teams that do not want to
operate the stack. Keep the open-source engine local-first; sell operations,
retention, and support, not a fake license gate.

### 10. Evidence and compliance export

Signed evidence bundles, chain-of-custody metadata, and audit export
(JSONL/CEF/STIX). This is what regulated buyers ask for after the first
engagement.

## Packaging sketch

| Tier | What it is | Why someone pays |
| --- | --- | --- |
| Open core | local engine, MCP server/client, missions, evidence, lessons | individual researchers and teams that self-host |
| Pro | presets, surface diff, quality gate, payout ROI, report templates | small teams that hunt continuously |
| Enterprise | workspaces, RBAC/SSO, audit export, managed runs, support | security teams with compliance needs |

Do not implement billing or license enforcement until there is a real paid
customer and a clear entitlement model. The product value is the engine and the
evidence, not a lock.

## What to build next, concretely

1. Surface inventory + diff tables and a `surface_diff` tool.
2. Assessment presets as data, with a `missions_from_preset` tool.
3. A validator task that requires an evidence artifact before confirmation.
4. A "ready to submit" gate in the report workflow.
5. Workspace and role columns before any multi-user UI.
6. CI/CD command that runs a scoped mission and exits non-zero on verified
   high/critical findings.

The first three are direct extensions of the current schema and agent runtime;
they do not require a rewrite.
