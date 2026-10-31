# Memory: the shared knowledge base, the campaign, and the profile

A model's context window is not memory. NetCast3r keeps its own durable,
provider-agnostic memory, so any model a user connects inherits the same
knowledge and each engagement leaves the whole platform more capable.

## The knowledge base

`src/netcast3r/kb.py` wraps a `kb_entries` table. Two scopes:

- **global** carries across every mission and every provider: a technology, an
  endpoint shape, a technique outcome, a dead end, a verified chain.
- a **mission id** keeps target-specific facts next to the mission.

Every brain reads a digest into its brief (`kb_digest`), so a different
provider starts from the same facts. `kb_write` records a fact an agent
observed; `kb_learn` derives entries from a mission's stored evidence only -
the technologies its graph shows, the endpoint shapes it saw, the technique
outcomes, the refuted leads, and the verified chains. It never invents a
result, and it is idempotent.

Endpoint shapes are stored host-agnostically: `/api/orders/42` becomes
`/api/orders/{n}`, so the shape transfers to the next target.

## The campaign

`src/netcast3r/campaign.py` is the stage machine that turns a bare domain into
a progressing engagement:

```
recon -> fingerprint -> surface -> hypotheses -> verify -> chain -> report
```

The stage is computed from stored evidence - the target profile, graph
endpoints, open leads, verified paths, findings - so it never claims progress
the mission did not make. Each stage names the brain that runs next. The
director re-derives the stage after every run, so a mission matures as the
evidence grows.

## The target profile

`src/netcast3r/target.py` consolidates what is actually known about the
target: host, IP, technology, WAF/CDN, and any observed TLS or DNS data. Every
value comes from a stored tool result or a graph node. A field that was never
observed stays empty; the profile never invents an ASN, a cloud provider, or a
certificate. Technology becomes graph nodes with a `runs` edge, so the profile
feeds chaining.

## The learning loop

When a run finishes, the director calls `_mature(mission_id)`:

1. rebuild the evidence graph from the new observations;
2. rebuild the target profile;
3. write the mission's lessons into the knowledge base;
4. re-derive and persist the campaign stage.

That is what makes each engagement leave the platform more capable. The memory
lives in the index, not in a model, so it is the same regardless of which
provider ran the work.

## Operator directions

`mission_directions` is a queue of operator instructions. `direction_add`
queues one; the director consumes up to three when it starts a run and puts the
first into the goal, so a chosen brain picks it up as a priority objective. A
direction can mention a lead or a finding with `@lead:<id>` or
`@finding:<id>`; the mentions are parsed and stored with it.

## Surface

HTTP: `GET/POST /api/v1/kb`, `GET /api/v1/kb/digest`, `GET /api/v1/kb/stats`,
`POST /api/v1/missions/{id}/kb/learn`, `GET/POST /api/v1/missions/{id}/profile`,
`GET /api/v1/missions/{id}/campaign`, and `GET/POST
/api/v1/missions/{id}/directions`.

MCP: `kb_search`, `kb_write`, `kb_digest`, `kb_stats`, `kb_learn`,
`target_profile`, `campaign_status`, `direction_add`, `directions_list`.
