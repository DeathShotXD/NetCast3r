# The regression bench

A security framework that cannot measure itself drifts. The bench is a small,
offline, deterministic corpus that runs the real engines and compares what they
detect with what the case says they must detect.

It is not a score of a target's security, and it is not a bounty result.

## What runs

| Kind | Engine | What it proves |
| --- | --- | --- |
| `scope` | `ScopeManager` | wildcard subdomains resolve in scope and exclusions win |
| `codeaudit` | `codeaudit.audit_text` | real defects are found and clean code stays clean |
| `sourceflow` | `sourceflow.analyze_text` | a route-to-sink chain is traced and safe SQL stays quiet |
| `secrets` | `reveng.analyze_js` | an exposed AWS key is categorised |
| `checklists` | `checklists` + `exploits` | every item has metadata and names a real module |

Every case is fixed input. No network, no model, no target, no time-of-day.

## Metrics

Each case returns:

- `expected` and `actual` label sets;
- `tp`, `fp`, `fn`;
- `precision`, `recall`;
- `passed`, which is true only when both `fp` and `fn` are zero.

The run aggregates the same counts, then F1 and wall time. The release gate is
strict because the corpus is deterministic:

- zero failed cases;
- precision >= 0.9;
- recall >= 0.9;
- at least one case ran.

A regression is a defect in the framework. It is never converted into a target
finding, and it never changes the submission ledger.

## Surface

- `GET /api/v1/bench`
- `GET /api/v1/bench?kind=sourceflow`
- `GET /api/v1/bench?case=sourceflow.route_to_eval&gate=1`
- MCP `bench_run`

## Adding a case

1. Add a small `BenchCase` with a stable id, kind, expected labels, and a
   function that calls the real engine.
2. Add the case to `CASES` in `src/netcast3r/bench.py`.
3. If the actual differs from the expected, decide which one is wrong before
   changing either. The bench exists to make that decision explicit.

The live-target benchmark - valid rate, duplicate rate, time to proof, cost per
proof - is a separate evaluation and must never be mixed with this corpus.