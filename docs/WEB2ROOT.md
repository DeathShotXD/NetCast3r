# Web2root

One public-facing seed. One authorised mission. NetCast3r maps the surface,
hunts with modern web and app checklists, and continues through chains when a
foothold appears — under scope, risk, and approval gates the whole way.

## Operator flow

```
seed URL or host
  -> mission (scope locked) + providers connected
  -> web2root_map (CT, passive DNS, resolve, HTTP/TLS, graph)
  -> surface_seed (operator host list, scope-checked, graph)
  -> coverage checklist + hunt / swarm
  -> candidate PoC verify -> promote
  -> on critical / internal pivot: post-ex plan (lateral, cloud, identity)
  -> live findings + Markdown/PDF report
  -> optional weekly verify-again schedule
```

## Guarantees

- Scope is law. Autonomy never widens it.
- If a wildcard apex does not answer, the hunt pivots to a live in-scope
  endpoint from the graph and re-checks scope before every probe.
- Hosts from the surface map are leads, not findings.
- A finding needs reproducible evidence (and a replayable PoC to promote).
- The brain and director steer; they never submit a report for you.
- Mid-hunt instructions (`brain_chat`, mission directions, `instruct`) are
  queued and picked up by the next cognition or run without restarting.

## Spectate and instruct

- Live SSE event stream for runs, tools, findings, and brain turns.
- Brain dock: journal, pause/resume, think-now, mid-hunt chat.
- Mission directions: queue text the director hands the next run; mention
  `@agent:<role>` or `@lead:<id>` / `@finding:<id>` when needed.
- `POST /api/v1/instruct` routes an operator follow-up to the brain, the
  director queue, or both.

## Surfaces

| Step | API / tool |
| --- | --- |
| Surface map | `web2root_map` |
| Operator host list | `surface_seed` |
| Coverage | mission Coverage tab / `coverage_*` |
| Hunt / swarm | director engage + mission autonomy |
| PoC | `candidate_poc`, `candidate_poc_verify` |
| Post-ex | `postex_plan` (auto-queued after foothold) |
| Report | `report.md`, `mission_report_pdf` |
| Retest | `schedule_create` |
