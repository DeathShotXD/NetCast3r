# The proof engine: plans and verification gates

The roadmap asked for model-independent planning with deterministic
verification. This module pair is that layer. It sits on top of the existing
step executor (`steps.py`) and chain workflow (`chain_workflow.py`) and does not
replace them: a plan is a typed, gated step graph, and a gate is a data
assertion, not a prompt.

## Two modules

- `src/netcast3r/planner.py` - the plan compiler. A goal and observed signals
  become an ordered step graph over the real tool catalog. Every step names a
  tool that exists, the arguments known from the target, the arguments still
  missing, and the assertion the verifier must satisfy.
- `src/netcast3r/verifier.py` - the verification gate. One observation is judged
  against one assertion with no model.

## Why deterministic

A tool call is an observation, never a conclusion. When a provider is weak,
absent, or rate-limited, the planner still emits a plan and the verifier still
judges the evidence. A model may reorder candidate plans; it can never invent a
step, drop a gate, or turn a 200 into a finding.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `pass` | every check matched |
| `fail` | a check was evaluated and did not match |
| `repeat` | the observation was a transport refusal or lacked the field |

`repeat` is the important one: it keeps a transient timeout from being scored as
a definitive negative, and a missing field from being read as a pass.

## Assertion vocabulary

A check is an object with a `path` and one or more operators:

| Operator | Meaning |
| --- | --- |
| `eq` / `ne` | equality / inequality |
| `gte` / `lte` / `gt` / `lt` | numeric comparison |
| `contains` / `not_contains` | case-insensitive substring |
| `regex` | regular expression search |
| `in` | membership in a list |
| `present` (true/false) | the field exists / does not exist |
| `changed` | the value differs from the baseline at the same path |

Paths may index lists: `results.1.status`, `findings.0.id`. Multiple checks are
ANDed with `{"all": [ ... ]}`.

## Plan library

| Plan | Steps | Gate |
| --- | --- | --- |
| `idor-two-identity` | `access_control_compare` -> `idor_sequence_probe` | `distinct_responses >= 2` |
| `sqli-differential` | `injection_differential_probe` -> `oracle_extract` | `differentials >= 1`, `length >= 1` |
| `ssrf-oob` | `oast_create` -> `http_request` | callback session exists, request answered |
| `open-redirect` | `http_request` (no follow) | `status in [301,302,303,307,308]` and a `Location` |
| `file-read` | `source_disclosure_scan` | `files_scanned >= 1` |
| `takeover` | `takeover_scan` | `counts.vulnerable >= 1` |
| `cache-poison` | `cache_audit` | `poisoning.counts.poisoned >= 1` |
| `graphql-authz` | `graphql_probe` -> `access_control_compare` | a finding, then `distinct_responses >= 2` |
| `websocket-cswsh` | `ws_audit` | `verdict == cswsh` |
| `jwt-forge` | `jwt_forge` | a token is produced |
| `generic-recon` | `http_probe` | a status is returned |

Each plan also carries `followups` (anomaly cascade) and, where useful, a
`fallback` for when the first step is refused.

## Interface

- `plan_compile` - rank plans, validate every tool against the catalog, fill
  `{target}` / `{mission_id}`, report missing arguments, attach assertions.
- `plan_library` - browse the templates.
- `plan_step_verify` - judge one observation against one assertion.

## Non-goals

- The planner never executes a step. Execution stays with `steps.py` /
  `chain_workflow.py`, through the same scoped, risk-gated registry.
- The verifier never promotes a finding. It produces a verdict; a caller decides
  what to stage, and promotion still needs a replayable PoC.
- No plan relaxation under model pressure. A failing gate is a signal to deepen,
  not to lower the bar.

## Gates run before the model

`steps.execute_steps` checks a step's `verify` assertion first. A `pass` becomes
`supports` and a `fail` becomes `refutes` with no model call; only a `repeat`
(transport refusal or missing field) falls back to the model judge. A model can
therefore never override a deterministic gate. `VERIFY_ACTIONS` is the allowlist
of read/probe tools a gated step may run, and it now covers the precise probe
tools the plan library uses.

## Effort estimate

`plan_compile` returns an `estimate`: requests, model calls, seconds, and the
top risk, computed from a deterministic per-tool table. A step that carries a
verification assertion needs no model call, so a fully gated plan reports zero
model calls. The autonomy loop can use this to prefer a cheap plan before a loud
one.

## Running a plan

`plan_run` compiles the best plan for a goal and its signals, refuses to run
when arguments are missing, then executes each step through the real registry.
Every step is gated by its assertion before any model, and each supported step
contributes its plan's `followups` to a `cascade` list. The cascade is returned
as data: it names the next hypotheses to record, and stages no finding.
