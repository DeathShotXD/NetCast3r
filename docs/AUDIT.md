# Source audit

A working record of the quality-assurance pass over the whole tree. It is a
snapshot, not a certificate. Date: 2026-11-01.

## Method

1. **Rule engine** - `src/netcast3r/codeaudit.py` (`scan`) over `src`: each
   match is a defect with a known consequence (swallowed exception, injected
   SQL, `eval`, shell string, disabled TLS, committed key, XSS sink).
2. **AST pass** - a throwaway analyser for defects a regex misses: unused
   imports, duplicate definitions, mutable defaults, truth comparison, stray
   `print`, `raise Exception`, functions over 220 lines.
3. **Manual review** - the trust boundary: the tool registry and its gates
   (scope, risk, approvals, rate limit, audit), the server routes (host,
   origin, token), SQL construction, JSON parsing of external and request
   data, and the new graph/memory/campaign code.
4. **Runtime** - the full test suite, the control-plane log, the director log,
   and the recent run history (failures and their causes).
5. **Frontend** - `svelte-check` at error threshold, plus a grep for `any`,
   `@ts-ignore`, `console.log`, and raw-HTML sinks.

## Result

- Rule engine: **score 100 / grade A**, 72 files, 0 high, 0 medium, 0 low,
  **33 info** (`py-swallowed-exception`), 8 reviewed suppressions.
- AST pass: **4 unused imports** (fixed), 6 stray `print` (entrypoints only,
  accepted), 0 duplicate defs, 0 mutable defaults, 0 `raise Exception`.
- Tests: **560 passed**. `svelte-check`: 0 errors, 0 warnings. Token drift:
  clean. ASCII: clean. Web build: 677.1 KB.
- Runtime: control-plane log clean; director **45 finishes, 0 mature errors**;
  recent run failures are honest domain failures (a lab that did not verify, a
  login with no CSRF token, a browser check that did not match) plus one
  recorded `JSONDecodeError` from an earlier build.

## Fixed

| # | File | Finding | Fix |
| - | ---- | ------- | --- |
| 1 | `cli.py` | unused import `Console` | removed |
| 2 | `integrations.py` | unused imports `tempfile`, `dataclass` | removed |
| 3 | `target.py` | unused import `graph as graph_module` | removed |
| 4 | `inputs.py` | `_har`/`load` parsed a saved file unguarded; a malformed HAR raised a traceback | clean `ValueError`, and `load` falls back to the plain-text reader on any parser failure |

## Accepted (by design, with rationale)

- **33 swallowed exceptions, all info.** The rule flags `except ...: pass`
  without a comment. Reviewed: every one is a deliberate best-effort probe -
  JSON decode fallbacks in `agents._first_json`, `queue.Full` in the event bus,
  `OSError` when a cache or control file is absent, `KeyboardInterrupt`/
  `BrokenPipeError` on shutdown. None hides a control-flow failure.
- **6 stray `print`.** All in entrypoints (`dashboard`, `server`, `tui`,
  `mcp/plane` stderr). Library code prints nothing.
- **SQL built with f-strings** (`index.py`, `surface.py`). The interpolated
  parts are a table name and column names chosen from fixed allowlists; every
  value is a bound parameter. Each such site carries a
  `codeaudit: ignore py-sql-fstring` reason.

## Limitations of this audit (worth knowing)

- **The rule engine matches one line at a time**, so a call whose argument
  starts on the next line (a multi-line SQL f-string) is not matched. That is
  why `surface._rows` was reviewed by hand: its `table` and `column` come from
  the literal `tables` dict, so it is safe.
- **The AST pass is approximate.** Unused-import detection is name-occurrence
  based and can miss a re-export; it does not track scope.
- **No dynamic analysis.** No route fuzzing, no concurrency stress on the
  single-director loop, no long soak.
- A clean pass does not prove safety; it proves the checked classes are absent.

## Security posture (verified, not assumed)

- **Request gate**: constant-time token compare (`_matches`) from header,
  query, or cookie; a host allowlist; an Origin check on every non-GET.
- **Scope gate**: `_require_scope` builds a scope manager from the mission and
  ignores caller-supplied extra scope when a mission id is present; metadata
  and link-local hosts are refused; the scope check is skipped only by a
  literal test of the target.
- **Risk gate**: `readonly` allows low only; high/critical needs a
  single-use, tool-bound, mission-bound, argument-hash-bound approval in
  `supervised`, or `confirm=true` in `full`.
- **Subprocess**: list arguments, no `shell=True`; `reveng` and outbound MCP
  use timeouts.
- **No** `eval`, `exec`, `os.system`, or `pickle` on untrusted data.

## Recommended next

1. Extend the rule engine to a three-line window so multi-line SQL and
   multi-line shell strings are matched (the window already exists for the
   `unless` clause).
2. A route contract test: every registered route returns a documented status
   for a malformed body, an oversized body, and a missing token.
3. A frontend accessibility pass (`aria-*`, focus order) and a check that no
   component renders untrusted text through `{@html}`.
4. A soak test of the director loop for a day against the local lab, watching
   for handle leaks and unbounded growth in `director_log` and `kb_entries`.
