# Leads and evidence

A **lead** in NetCast3r is a falsifiable hypothesis. It is not a finding, and it
is not proof. The Leads tab exists so a human can see exactly what happened to a
lead without reading the run log or asking the brain.

## Where to look

Mission detail -> **Leads**.

The list defaults to actionable leads. Archived and raw `observation` records
are hidden until **Show archived** is selected.

Each lead shows:

- status: `open`, `supported`, `refuted`, `inconclusive`, `promoted`,
  `archived`;
- technique and target;
- the proof criterion ("what would prove it");
- the recorded test and result, if any;
- related tool calls with the exact target and HTTP status;
- related observations with their timestamps;
- run ids, graph nodes, and the linked finding when promoted.

The same record is available at:

- `GET /api/v1/hypotheses/{id}`
- `GET /api/v1/hypotheses/{id}/evidence`
- `GET /api/v1/hypotheses/{id}/evidence.md` - a Markdown case file with the
  exact tool calls, observations, graph nodes, and proof criterion
- MCP `hypothesis_get`, `hypothesis_evidence`

The Leads detail panel has **Download brief**, which saves that Markdown file
for review or attachment to a report draft.

## What "open" means

`open` means the proof has not been recorded. It can mean untested, blocked by
a WAF, or tested but not yet given a verdict. It never means "found".

A candidate becomes a finding only through the explicit promotion path. A
finding becomes a submission only through the submission ledger and a human
decision.

## Observation-to-lead sync

`POST /api/v1/missions/{id}/leads/sync` reads recorded positive observations
(from `swarm.observation` notes) and creates a hypothesis only when a named
technique can be inferred. The source note id is stored in the rationale and
duplicates are skipped.

The director runs the same sync when a run matures, so a real observation does
not disappear into the log. Negative notes, dead ends, planning notes, and
inconclusive probes are not turned into leads.

## Current Instant Gaming example

The mission has an **Open redirect on /api/auth/callback** lead sourced from a
recorded 301 response. The SSRF hypothesis is still `open`; the recorded
metadata probes returned Cloudflare `403` with no callback or metadata body.
Those are two different claims:

- open redirect: a 301 to an attacker-controlled external URL;
- SSRF: the server fetches the URL and returns internal data.

Do not merge them. Each needs its own proof and its own report.