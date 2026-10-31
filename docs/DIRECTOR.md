# The director: NetCast3r drives itself

NetCast3r does not need OpenCode, Hermes, Agent Zero, or any other harness to
hunt. The control plane ships its own supervisor. This document explains the
two layers that make that true, what they are allowed to do, and how to
control them.

## Two layers above the brains

The brains already existed. `hunt` is a deterministic read-only pass. The
`autopilot` is one operator voice. The `swarm` is five role identities. The
`agent` runtime is the durable per-mission pipeline. Each one runs to a budget
and stops. What was missing was something to keep them moving.

**Prime** (`src/netcast3r/prime.py`) is the portfolio brain. It scores every
scoped mission from real signals, picks the next answerable objective, and
names the brain that should run it. It is deterministic by default; a model
can be asked for a second opinion, but the model only reorders. It cannot add
a mission, change eligibility, or change scope.

**The director** (`src/netcast3r/server/director.py`) is the durable
supervisor. On each tick it asks Prime for the ranking, starts at most
`max_concurrent` runs, watches them to completion, and records whether each
mission actually moved. It starts with the control plane in `serve()` and
shuts down with it.

```
serve()
  └─ Director.start()                         # one daemon thread
       loop every tick_seconds
         ├─ _reap()                            # retire finished runs, count progress
         ├─ Prime.decide()                     # rank missions, pick objective + brain
         ├─ _start(mission, mode)              # hunt | autopilot | swarm
         │    └─ server._hunts()/_solvers()    # the same runners the API uses
         └─ index.director_log / agent_notes   # durable record
```

## How it chooses

Prime scores each active, non-training mission. Every term is a named rule, so
a score is always explainable in the director log:

| signal | effect |
| --- | --- |
| `active` status | +40 (a `draft` gets +12) |
| `autonomous` autonomy | +10 (a `manual` mission is pushed out of reach) |
| each open lead | +12, capped at four |
| each finding already recorded | +6, capped at three |
| never run | +8 |
| pending approval | -30 (a human owes it a decision) |
| idle time | up to +10, so a stale mission eventually gets a turn |

The brain is then chosen by maturity:

- an open lead, or a hypothesis objective, routes to the **mesh**;
- a mission that has never run routes to the deterministic **hunt**;
- everything else routes to the **operator**.

## What it may do

The director is bound by exactly the same gates as every other caller: the
mission scope, the tool risk tiers, single-use approvals, and the rate
limiter. On top of that:

- it only picks `active` missions that its `scope_filter` allows. The default
  filter is `autonomous`, so a mission has to be opted in. `supervised` and
  `all` include more;
- a `manual` mission is never picked up;
- a training mission is never picked up; labs run by recipe only;
- an autonomous mission runs the full chain in scope under the `full` policy;
  a supervised mission runs read/probe work and parks at the first high-risk
  requirement;
- it never creates a finding, never decides an approval, and never submits a
  report. A validated finding is still a separate, human-gated write.

## Progress, parking, and the kill switch

After each run the director compares a progress fingerprint (recorded actions,
non-director notes, open leads, findings). Its own plan notes are excluded, so
bookkeeping never looks like progress.

- no new progress once: the mission's cooldown doubles, up to fifteen minutes;
- no new progress twice, or three failures: the mission is **parked** and left
  alone until a human clears it or the work changes.

`POST /api/v1/director/kill` (or the **Kill** button, or `director_control`
with `action=kill`) is the kill switch. It cancels every run the director
started, and every run at all when `all=true`, then disengages and pauses.

## Surface

HTTP:

| method | path | purpose |
| --- | --- | --- |
| `GET` | `/api/v1/director` | state; add `?portfolio=1` for the ranking |
| `GET` | `/api/v1/director/eligibility` | per-mission allowed/skipped reason |
| `GET` | `/api/v1/director/log` | newest-first audit feed |
| `POST` | `/api/v1/director/control` | `engage`, `disengage`, `pause`, `resume`, `tune`, `tick`, `advise`, `kill` |
| `POST` | `/api/v1/director/kill` | the kill switch |

MCP exposes the same surface as `prime_portfolio`, `director_status`,
`director_control`, and `director_log`, so a harness that wants to co-drive
can read and steer the same supervisor.

The command center shows a Director strip: state chips, Engage, Pause,
Disengage, and Kill, the counters, the in-flight runs, and the last few log
lines. It polls every five seconds and never blocks the page.

## Tuning

```
POST /api/v1/director/control
{"action": "tune", "tick_seconds": 30, "max_concurrent": 2,
 "scope_filter": "all"}
```

`tick_seconds` is clamped to 5 to 300 seconds. `max_concurrent` is clamped to
1 to 4. `scope_filter` is one of `autonomous`, `supervised`, or `all`.

## State

Everything the director needs to resume lives in the index:

- `director_state` is one row: engaged, paused, filter, tick, concurrency,
  counters, and an `active_json` blob holding the in-flight runs and each
  mission's cooldown, progress fingerprint, failure count, and park flag;
- `director_log` is the bounded audit feed.

A restart reads that row and keeps scheduling. It never re-plans from scratch.
