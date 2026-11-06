# APT Plan: from scanner harness to 24/7 proof engine

Status: research roadmap, 2026-11-07. Scope: docs only, no code changes in this pass.
Grounding: current tree (258 MCP tools, director + kill switch, five-role mesh, brain loop, evidence graph, findings ledger, approvals, OAST, single_packet.py / lastbyte.py, chains.py, reveng.py static APK path).
Citation style: plain URLs inline. ASCII only. Estimated effort assumes one maintainer.

## 1. Executive summary (10 lines)

1. NetCast3r already ships the hard parts: local control plane, 258 typed scope-gated tools, durable director with kill switch, brain loop, five-role mesh, evidence graph, findings ledger, single-use approvals, OAST, h2 single-packet and last-byte race primitives, and a static APK analyzer.
2. The gap is not tools: it is model-independent multi-step planning with deterministic verification, wire-level depth, identity continuity, mobile runtime and post-exploitation, and crash-safe fleet durability.
3. 2025-2026 state of the art converges on one architecture: AI proposes, deterministic code verifies, evidence gates promotion, and every confirmed finding becomes fuel for an anomaly-driven next pass (https://portswigger.net/research/can-ai-do-novel-security-research).
4. Weak or free models are a design constraint: XBOW's fall 2026 evaluation measured cheap open-weight models as the best cost-per-proof at low budgets (https://xbow.com/blog/top-ai-models-for-offensive-security-fall-2026).
5. Phase 0 (hours to weeks) removes blockers: SQLite WAL, heartbeats, run journals, seed-file ingestion, persisted rate limits, budget accounting, disk retention, tool pinning.
6. Phase 1 (weeks) turns planning into data: a typed plan compiler over the tool catalog, verification gates between steps, fresh-context step execution, budget router, and a plan cache keyed by target fingerprint.
7. Phase 2 (weeks) takes the wire: desync ladder (CL.0, H2.CL, H2.TE, multipart/byteranges, CRLF, h2c), RQP with the dangling-byte technique, race baselines plus p-value confirmation, and TLS/JA3 fingerprint control (https://portswigger.net/research/smashing-the-state-machine).
8. Phase 3 (weeks) adds identity: storageState reuse, per-role cookie jars, token refresh, cross-identity authorization matrices, and an ATO primitive pack that survives 401/403 rotation.
9. Phase 4 (weeks to months) goes beyond the edge: Frida/objection/MobSF runtime, emulator farm, post-exploitation broker (impacket, NetExec, cloud CLIs), loot vault, continuous regression re-testing at fleet scale.
10. Success is scored by six metrics with a hard false-positive guardrail (section 5); explicit non-goals keep the roadmap honest (section 6).

## 2. Phase 0: remove blockers (one line each)

Every item blocks 24/7 operation across many gov/banking domains driven by weak models.

### Effort S (hours)

- store.py: enable `PRAGMA journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`, `foreign_keys=ON`, single-writer discipline per process (https://sqlite.org/wal.html).
- Supervisor heartbeat: director and brain write a heartbeat row each tick; a watchdog restarts a dead loop; `director_status` exposes last tick.
- Seed file ingestion: `netcast3r seed --file domains.txt --tag gov` creates one deduped mission per normalized host with per-batch concurrency, plus a `seed_file` MCP tool and `POST /api/v1/seeds`.
- Persist per-domain token buckets in the index so a restart does not resume full speed against a host that just rate-limited us.
- Model usage ledger: every provider call persists provider, model, tokens, cost, latency, mission (agent_runtime._cost_cents already computes it); surface totals in `status`.
- Degraded-mode switch: after N consecutive provider hard failures the director flips missions to deterministic-only, records `degraded`, and re-probes providers on a slow timer.
- Tool pinning: versions.toml for jadx, apktool, frida, objection, nuclei, ffuf, nxc; `host_capabilities` reports versions and the bench fails when a pin is missing or wrong.
- Nightly `sqlite3 .backup` of the index plus a results index snapshot; CI restores the backup and opens it read-only.
- Disk guard: results/ has passed 800 run directories; add `netcast3r prune --keep 200` (archive dashboard and results.json before delete) and a free-space check before runs.
- Kill-switch proof in CI: engage a run, trigger kill, assert child process groups (toolbox, host_shell) are dead and mission state is consistent.

### Effort M (days)

- Durable run journal: write a step row with an idempotency key before each network side effect and mark it done after; boot-time orphan handling resumes or aborts with a note; `runs_resume` reads the journal.
- Fleet budget accountant: per-mission and per-day caps for tokens, wall clock, and outbound requests; hitting a cap parks a mission as `budgeted-out` instead of failing it; caps live in the index.
- Auth profile binding: `http_request`, `http_probe`, and browser tools accept `auth_profile`; a cookie-jar table persists Set-Cookie per profile per host; `auth_profile_import` already reads Playwright storageState (https://playwright.dev/docs/auth).
- OAST default-on: any probe on an injectable parameter allocates a callback id; a background poller correlates callbacks to the triggering probe; blind testing stops being a manual step (https://github.com/projectdiscovery/interactsh).
- Desync ladder v1: one `desync_scan` wrapping the race primitives with baseline/burst differential, the H2 probe set, and a confirmation repeat before a hit counts.
- Lead taxonomy v2: classify candidates into exploit classes, group by (host, path, param, class), rank by class ROI from the outcome ledger, dedupe before reports.
- Schedule hardening: schedules survive restart, back off on repeated failure, and carry a `reopen_on_regression` flag for confirmed findings.

### Effort L (weeks)

- Mobile runtime lab: headless AVD + frida-server + objection + MobSF container under lab/, with emulator snapshot reuse so cold boot is paid once (https://github.com/MobSF/Mobile-Security-Framework-MobSF).
- Post-exploitation broker: impacket, NetExec, and aws/az/gcloud CLIs behind the toolbox allowlist, with a credential vault table and pivot graph nodes.
- Desync permutation engine: trigger corpus database (RFC fragments plus research), mutation and pairing combinator, and anomaly fingerprints stored as data instead of hard-coded checks.
- Continuous re-test fleet: per-finding replay schedule with drift detection and automatic reopen on regression, evidence regenerated on every replay.
- Fleet console: one portfolio view with cost burn, proofs per domain-hour, coverage closure, and degraded-mode banners, all read from the index.

## 3. Phased capability upgrades

## Phase 1: Proof Engine - model-independent planning with deterministic verification

**What it does.**

- Adds a plan compiler (`planner.py`): goals become typed step graphs over the existing 258-tool catalog, each step with preconditions, expected effect, cost, risk tier, and a deterministic fallback when no model answers.
- Adds verification gates (`verifier.py`): between steps a deterministic assertion decides pass / fail / repeat (status, marker, body hash, OAST hit, regex, length delta); a step alone can never promote a candidate.
- Fresh-context step execution: each step runs with only evidence and its step contract, mirroring the HTTP Terminator lesson that contaminated context destroys novelty and disposable AI-generated code is hard to iterate (https://portswigger.net/research/can-ai-do-novel-security-research).
- Budget router (`budget.py`): cheap sprints first (small/free models), escalation only when a lead exists or verification fails twice; per-budget model choice follows published cost curves (https://xbow.com/blog/top-ai-models-for-offensive-security-fall-2026).
- Plan cache keyed by target fingerprint (stack, framework, auth mode): a proof that worked on one portal replays as a plan template on the next, with steps re-verified rather than trusted.
- Anomaly cascade hook: confirmed steps enqueue follow-up hypotheses ("how to detect similar behavior elsewhere", "does the origin enable another attack"), the pattern that produced Shared Parser Confusion (https://portswigger.net/research/can-ai-do-novel-security-research).

**Why APT-level.** APT work is persistent multi-step exploitation under uncertainty, not one-shot scanning. This phase lets the framework chain foothold-shaped primitives into impact with all models offline, and keeps a weak model from being load-bearing for correctness.

**Main files/modules.** New: `src/netcast3r/planner.py`, `src/netcast3r/verifier.py`, `src/netcast3r/budget.py`. Change: `brain.py`, `prime.py`, `autopilot.py`, `swarm.py`, `steps.py`, `orchestrator.py`, `verdicts.py`, `mcp/tools.py`, `server/agent_runtime.py`.

**Interface.** MCP: `plan_compile`, `plan_run`, `plan_step_verify`, `budget_status`, `plan_cache_list`. Routes: `POST /api/v1/missions/{id}/plan`, `GET /api/v1/missions/{id}/plan`, `GET /api/v1/budget`.

**Acceptance test.** Lab: with all provider keys removed at start, a scripted mission (surface seed -> parameter discovery -> probe -> OAST confirm -> PoC replay) completes and its PoC passes `candidate_poc_verify`. Bench: a no-model mode in `bench_run` reaches parity with the model path on the planted-secret corpus. Budget: a 10-cent capped mission pauses at the cap with the exact step recorded and resumes when the cap is raised.

**Risks.** Over-brittle gates stall on cosmetic differences; stale plan cache must degrade to a miss, never a stop; gate false negatives need an audited "force with note" lane; cache and gates must not mask target drift.

## Phase 2: Wire Apex - desync, races, evasion, and OAST-first blind hunting

**What it does.**

- Desync ladder as first-class detection: CL.0, H2.CL, H2.TE, tunnelling confirmation, multipart/byteranges CL.0, CRLF in header values and names, `Expect: 100-continue` oddities, h2c smuggling via CONNECT (https://portswigger.net/research/http2, https://portswigger.net/research/http1-must-die, https://portswigger.net/research/crlf-powered-desync-attacks, https://github.com/assetnote/h2csmuggler).
- RQP weaponization: stacked-response management plus the dangling-byte technique that removes the race window, turning response queue poisoning into a repeatable evidence run (https://portswigger.net/research/can-ai-do-novel-security-research).
- Race methodology hardening: mandatory baseline sweep before any burst, clue classification (unexpected status, duplicate mail, token mismatch, timing anomaly), p-value over N repeats, escalation to multi-endpoint collisions via client-side delay or leaked rate-limit delay (https://portswigger.net/research/smashing-the-state-machine).
- TLS and H2 fingerprint control: curl-impersonate and uTLS presets so the wire looks like Chrome/Firefox/Safari, a JA3/JA4 self-check, and fingerprint-consistent egress selection per identity (https://github.com/lwthiker/curl-impersonate, https://github.com/refraction-networking/utls).
- OAST-first blind testing: parameter probes, SSRF, XXE, SSTI, blind SQLi allocate callbacks automatically; a self-hostable second-stage file server covers external DTD / XSLT / JNDI staging in one correlation stream (https://github.com/projectdiscovery/interactsh).

**Why APT-level.** Gov and bank estates terminate in CDN/WAF/L7 stacks where desync yields cross-user account takeover (2026 research compromised banks and government infrastructure at scan scale), and races crack the login/reset/payment state machines that hold the real value.

**Main files/modules.** New: `src/netcast3r/desync.py` (probe set, confirmation, RQP runner), `src/netcast3r/fingerprint.py` (JA3 self-check, profile selection). Change: `single_packet.py` (multi-endpoint batches, server-delay abuse, benchmark mode), `lastbyte.py` (dangling byte), `oast.py` (probe-id correlation, second-stage staging), `http.py` (raw h2 framing, per-identity pools), `egress.py`, `toolbox.py` (curl-impersonate), `checklists.py`, `mcp/tools.py`, `mcp/plane.py`.

**Interface.** MCP: `desync_scan`, `race_family`, `rqp_confirm`, `tls_fingerprint_check`, `oast_stage_file`. Routes: `POST /api/v1/desync`, `GET /api/v1/desync/{id}`, `POST /api/v1/fingerprint`.

**Acceptance test.** Desync farm in lab (H2.CL Netlify-style, H2.TE ALB-style, CL.0, multipart/byteranges): each is detected with one confirmation repeat and zero false positives on a control stack. Race: both classic labs (limit overrun, single-endpoint email confusion) are won in under 30 bursts with recorded baseline and p-value at 200 ms RTT. OAST: blind XXE and blind SQLi are proven from callback evidence alone with the triggering request reconstructed. Evasion: a JA3-checking lab sees the impersonated profile byte-for-byte at the Hello level.

**Risks.** Pipelining and client-side connection reuse cause the known desync false positive (encode it in the verifier, not a prompt); RQP steals live user responses, so evidence must record what was live and when; poisoned CDN entries stick, so tests need unambiguous cache keys and cooldowns.

## Phase 3: Identity Continuity - sessions, roles, and ATO primitives

**What it does.**

- Session reuse with storageState: export from an operator browser, import into an auth profile, bind to HTTP tools and Playwright contexts alike; bounded refresh on 401/403; an explicit `expired` state when refresh fails (https://playwright.dev/docs/auth).
- Per-role identities: anonymous, user, admin, and tenant contexts run the same checklist items independently; `access_control_compare` grows into a cross-identity resource matrix reporting where authorization diverges.
- Identity timeline: every session event (login, refresh, MFA step-up, role switch) becomes a graph node so evidence can state which identity saw what.
- ATO primitive pack: reset-token race and predictability, email change without re-auth, MFA enforcement gaps and OTP replay, session fixation, JWT mutation and alg confusion, OAuth redirect parser checks, cookie-scope takeover checks.
- Multi-identity race execution: the Phase 2 burst runner drives N sessions with isolated cookie jars, which is required for session-locking stacks (for example PHP) to expose database-layer races.

**Why APT-level.** Post-auth is where banks keep value and attackers operate with credentials; 2026 race research won account takeover by attacking identity-state transitions. This phase makes the framework an authenticated user, not a crawler.

**Main files/modules.** New: `src/netcast3r/identity.py` (matrix, timeline, refresh state machine), `src/netcast3r/ato.py` (primitive runners, verdicts). Change: `authstore.py` (jar persistence, refresh metadata, TTL), `browser.py` (storageState in/out, per-role contexts), `pivot.py`, `checklists.py`, `mcp/tools.py`, `server/index.py` (identity edges).

**Interface.** MCP: `identity_matrix`, `session_import`, `session_refresh`, `ato_scan`, `authz_diff`. Routes: `POST /api/v1/identities`, `GET /api/v1/missions/{id}/matrix`, `POST /api/v1/ato/scan`.

**Acceptance test.** Lab app with three roles and one broken object-level authorization bug: the matrix detects the leak from a non-owner identity and emits a PoC that fails for the owner and succeeds for the attacker. Setup: the reset-flow race replicates Devise-style token misrouting with two requests and a baseline comparison. Rotation: after the lab rotates the cookie, the next step refreshes; without refresh data the tool reports `expired`, not a false negative.

**Risks.** Shared accounts collide under concurrency (isolate jars per burst slot, document account concentration); CSRF and anti-automation churn require token extraction before bursts; storageState files hold live cookies (keep them out of reports, rotate accounts).

## Phase 4: Beyond the Edge - mobile runtime, post-exploitation, 24/7 durability

**What it does.**

- APK runtime: extend `reveng.py` from static jadx/apktool to a runtime lane: boot a headless emulator from snapshot, push frida-server or use the gadget on non-rooted images, run objection for SSL unpinning and storage dumps, drive scripted Frida hooks (crypto, SharedPreferences, okhttp) (https://github.com/frida/frida, https://github.com/sensepost/objection).
- MobSF dynamic pass: run the APK through MobSF for traffic capture and component testing in a clean container, then feed endpoints and secrets into the existing web2root graph so mobile and web missions share one surface (https://github.com/MobSF/Mobile-Security-Framework-MobSF).
- Post-exploitation broker: impacket and NetExec for AD/SMB, cloud CLIs for metadata-derived credentials; a loot vault stores credentials, hashes, and tokens with provenance and scope, and each loot item can spawn a mission or pivot edge (https://github.com/Pennyw0rth/NetExec, https://github.com/fortra/impacket).
- Crash-safe campaigns: journaled steps (Phase 0), per-fleet budgets, memory ceilings, per-process watchdogs, graceful degradation order (drop model calls, then parallelism, never durability), and a documented restart drill over SQLite WAL (https://sqlite.org/wal.html).
- Continuous re-testing: per-finding replay on schedules with drift detection (status, marker, TLS, headers, body hash), auto-reopen on regression, and rate-limit-aware queuing.
- PoC replay fleet: the candidate PoC format becomes the regression suite; every replay is timestamped evidence, and a failed replay demotes the finding to `stale` until reconfirmed.

**Why APT-level.** Footholds are table stakes; APTs live in the post-exploitation window and use the mobile client as the weakest trust boundary of gov/bank programs. Restart-proof execution is literally dwell time for an unattended agent.

**Main files/modules.** New: `src/netcast3r/mobile.py` (emulator lifecycle, frida driver, MobSF client), `src/netcast3r/vault.py` (loot, provenance), `lab/mobile/`. Change: `reveng.py` (runtime handoff), `postex.py` (broker plans), `pivot.py` (missions from loot), `toolbox.py` (impacket, cloud CLIs, adb), `schedule.py`, `poc.py` (fleet replay), `server/jobs.py` (watchdog), `director.py` (fleet budgets), `mcp/tools.py`.

**Interface.** MCP: `mobile_emulator`, `mobile_frida_hook`, `mobile_mobsf_scan`, `postex_run`, `loot_list`, `loot_add`, `retest_fleet`, `vault_put`. Routes: `POST /api/v1/mobile/emulator`, `GET /api/v1/fleet/retest`, `POST /api/v1/postex`.

**Acceptance test.** Mobile: a public APK is pulled, analyzed, booted, and a scripted hook dumps a storage secret the static pass missed; an endpoint from the hook joins the mission graph and is probed. Post-ex: a two-host AD lab is reached via NetExec with an SMB-derived credential, the pivot spawns a second mission, and provenance is recorded. Durability: `kill -9` mid-run three times; restart resumes or cleanly aborts, side effects never duplicate (idempotency keys hold), director resumes within one tick. Re-test: a lab finding is patched (replay fails, marked stale) then unpatched (replay passes, reopens), both transitions audited.

**Risks.** Emulator cost and flakiness (snapshot reuse, one shared lab image); Frida version drift (pin and fail loudly); credential sprawl (vault plus one masking boundary); loud AD enumeration (read-only by default, mission for state changes).

## 3.5 Sequencing, rollout, and kill criteria

- Dependency order: Phase 0 durability before Phase 1 planning; Phase 1 verifier before Phase 2 confirmation loops; Phase 2 OAST before Phase 3 multi-identity races; Phase 4 mobile is independent, its vault depends on Phase 0 journaling.
- Lab-first rule: no phase reaches the domain fleet before its lab fixtures pass in CI (desync farm, race labs, three-role app, AD lab, emulator image).
- Pilot ladder: lab -> 3 pilots (one gov, one bank, one SaaS) -> 20 domains -> full list; each rung needs one clean metric week before widening.
- Feature flags: `phases.desync`, `phases.identity`, `phases.mobile`, `phases.postex`, `director.conservative`; a flag off must leave behavior identical to today.
- Kill criteria: a phase that misses acceptance twice is split, not extended; the half that passes ships, the rest returns to design.
- Cost gate: above the daily burn, new work first drops to cheap models, then parallelism, and never stops the hunt entirely.
- Change cadence: one change per day per PLAN.md, tests plus lab green, bench score no worse than -5 percent.
- Evidence gate: a phase is done when a lab fixture yields a replayable proof and the six metrics move in the right direction.
- Throttle gate: widen the ladder only when the per-domain rate-limit error rate stays under 1 percent for a week.
- Rollback: every new tool is additive; disabling a phase drains the journal first so no run is orphaned.
- Review points: weekly metrics review, monthly kill-switch drill, quarterly re-read against new public research.
- Research intake: feedwatch plus `research_ingest` is the channel for new techniques; anything invalidating a phase becomes a recorded direction, never a silent patch.
- Non-regression: the duplicate guardrail and verifier false-positive gate are release-blocking at every rung.

## 4. Capability matrix

Effort: S <= 2 days, M <= 2 weeks, L > 2 weeks. Impact 1-5. Priority P0 (next), P1, P2, P3 (backlog).

| Capability | Current state | Gap | Effort | Impact | Priority |
| --- | --- | --- | --- | --- | --- |
| SQLite durability (WAL, busy_timeout) | plain sqlite3.connect | crash risk under parallel writers | S | 5 | P0 |
| Supervisor heartbeat + auto-restart | director thread, no liveness proof | silent thread death halts 24/7 | S | 5 | P0 |
| Seed file to missions | one --input per run | domain-list onboarding is manual | S | 5 | P0 |
| Persisted rate limits | in-memory sliding windows | restarts reset pacing | S | 4 | P0 |
| Usage ledger + degraded mode | cost computed, not persisted; no switch | budget blindness, model dependence | S | 4 | P0 |
| Durable run journal + resume | runs can be orphaned on crash | no idempotent step replay | M | 5 | P0 |
| OAST auto-correlation | manual oast_create/poll | blind bugs need hand wiring | M | 5 | P0 |
| Plan compiler + verification gates | brain prompts, no contracts | model quality is load-bearing | M | 5 | P0 |
| Budget router + plan cache | none | unbounded spend per mission | M | 4 | P1 |
| Desync ladder (H2.CL/TE, CL.0, CRLF) | two race primitives | no probe set, no confirmation | M | 5 | P1 |
| Desync lab fixture farm | none | no offline ground truth for wire bugs | M | 4 | P1 |
| Phase flags + conservative director | none | no safe rollout switch | S | 4 | P1 |
| RQP + dangling byte | none | cross-user ATO left on the table | M | 5 | P1 |
| Race baselining + p-value | burst runner only | clue detection is manual | M | 4 | P1 |
| TLS/JA3 fingerprint control | httpx default, simple proxy pool | WAF blocks, client fingerprinting | M | 4 | P1 |
| Session reuse (storageState) | authstore imports it; browser separate | HTTP and browser identities diverge | M | 4 | P1 |
| Cross-identity authz matrix | access_control_compare, two responses | no role matrix, no drift | M | 5 | P1 |
| ATO primitive pack | ad-hoc probes | no token-race / email-change pack | M | 4 | P2 |
| Mobile runtime (Frida/Objection/MobSF) | static jadx/apktool only | no runtime secrets or hooks | L | 5 | P2 |
| Post-ex broker + vault | postex_plan; nxc in catalog | no impacket/cloud, no loot store | L | 4 | P2 |
| Desync permutation engine | fixed probes | no micro-inspiration corpus DB | L | 4 | P2 |
| Continuous re-test fleet | schedule_create exists | no drift detect, no auto reopen | M | 4 | P2 |
| Per-provider SLO tracking | provider_test only | silent free-tier degradation | S | 3 | P1 |
| Scheduled kill-switch drill | manual kill works | no recurring proof | S | 3 | P2 |
| Redaction for new artifact types | report redaction exists | mobile/postex files uncovered | S | 3 | P2 |
| Fleet console + cost burn | single-mission views | no portfolio awareness | M | 3 | P3 |
| Screenshot evidence in findings | browser_capture one-off | not bound to findings | S | 3 | P3 |

## 5. Measure of merit

Score the framework, not the target. All inputs come from the index (journal, usage ledger, coverage rows, findings), so prose cannot inflate them. A "proof" is a candidate with a passing `candidate_poc_verify` replay inside 30 days.

- Time to first proof (TTFP): median minutes from mission activation to first verified proof per domain. Target < 60 min median at fleet scale, < 15 min on known-issue classes. Source: run journal timestamps.
- Proofs per domain-hour: verified proofs divided by summed active domain-hours. Target >= 0.02/h/host (about one proof per host per two days) without raising duplicates. Source: findings plus fleet clock.
- Duplicate rate: duplicates / verified proofs, where a duplicate is a second candidate for the same (host, path, parameter, class) or a triager rejection as already known. Target < 10 percent; this is the guardrail that keeps proofs-per-hour honest.
- Cost per proof: (provider spend + marginal infra) / verified proofs. Target < $2 blended, mode $0.10-$0.50 by running cheap sprints and escalating only after a lead. Source: usage ledger.
- Coverage closure: percent of the 103-item checklist closed (covered / vulnerable / blocked-with-reason) per domain within 30 days of activation. Target >= 80 percent; `blocked` requires concrete WAF or edge evidence. Source: mission_coverage.
- Model-independence ratio: (a) percent of stages with a passing deterministic fallback when providers are disabled (target 100 percent for detection, validation, dedupe, reporting); (b) percent of plan steps completing with zero model calls (target >= 60 percent). Source: bench no-model mode plus per-step usage counters.

Composite score (printed by bench_run, tracked over time):

score = 25*TTFP_ratio + 20*PPH_ratio + 15*(1 - dup_rate) + 15*cost_ratio + 15*coverage_ratio + 10*independence_ratio

Each ratio is capped at 1. Hard gates: duplicate rate > 20 percent or verifier false-positive rate > 5 percent fails the release regardless of score. A release may not regress the score by more than 5 percent without a CHANGELOG note.

Anti-gaming: TTFP counts only replayable proofs; PPH uses domain-hours, not wall-hours; cost includes failed retries; coverage counts `blocked` at half weight; duplicates are judged per class, not per severity.

## 6. Honest risks and non-goals

**Risks.**

- False positives are the top reputational risk: at fleet scale 5 percent is a flood. Verification gates and mandatory replay are the only defense; keep the duplicate guardrail hard.
- Model drift: free tiers change models and quotas without notice; the deterministic path must complete a full proof alone, and the plan cache must survive provider swaps.
- Live-domain side effects: RQP steals live responses, cache poisoning sticks across users, races leave test accounts in odd states. Cooldowns and live-request recording are required.
- Scope creep: more domains means more edge cases (IPv6, non-HTTP ports, wildcard collisions). Scope stays law; expansion stays human-approved.
- Mobile and emulator cost is the largest marginal infra item; snapshot reuse and one shared lab image bound it.
- Post-ex credential sprawl: every tool wants its own config; the vault plus a single masking boundary is mandatory.
- SQLite as fleet store: fine on one host with WAL, a single writer, and checkpoints; a network filesystem breaks WAL assumptions.
- Weak-model brittleness: cheap models over-anchor on context (documented in the HTTP Terminator work); keep step prompts small, fresh, and explicitly rule out low-value hypotheses.
- Approval burnout: supervised mode can stall a fleet; autonomous missions are the norm and approvals are reserved for host writes and scope changes.

**Non-goals (this window).**

- No binary-only fuzzing or kernel exploitation; binaries stay a static-plus-orchestration lane.
- No custom TCP/TLS stack; build on nghttp2 semantics, uTLS, and curl-impersonate.
- No unattended report submission; a human still decides what ships.
- No full browser automation of every flow; Playwright covers session and JavaScript reality only.
- No single-vendor dependence; default configuration must prove value on zero-dollar models.
- No DoS-tier scanning; roughly one request per second per domain unless a mission opts up.
- No finding without replay; a candidate unreplayable for 30 days is demoted, not reported.

## 7. Sources

- Race conditions, single-packet attack: https://portswigger.net/research/smashing-the-state-machine
- HTTP/2 desync, tunnelling, RQP foundations: https://portswigger.net/research/http2
- HTTP/1.1 desync endgame (0.CL, V-H): https://portswigger.net/research/http1-must-die
- CRLF-powered desync (2026): https://portswigger.net/research/crlf-powered-desync-attacks
- Autonomous research blueprint (HTTP Terminator): https://portswigger.net/research/can-ai-do-novel-security-research
- Turbo Intruder reference implementation: https://github.com/PortSwigger/turbo-intruder
- Model cost curves: https://xbow.com/blog/top-ai-models-for-offensive-security-fall-2026
- Agentic full-chain case study: https://xbow.com/blog/xbow-built-a-chrome-full-chain-exploit
- CAI framework (archived reference design): https://github.com/aliasrobotics/cai
- OAST and second-stage hosting: https://github.com/projectdiscovery/interactsh
- TLS impersonation: https://github.com/lwthiker/curl-impersonate
- ClientHello control: https://github.com/refraction-networking/utls
- h2c smuggling: https://github.com/assetnote/h2csmuggler
- Mobile static + dynamic: https://github.com/MobSF/Mobile-Security-Framework-MobSF
- Runtime instrumentation: https://github.com/frida/frida, https://github.com/sensepost/objection
- Session reuse semantics: https://playwright.dev/docs/auth
- SQLite WAL: https://sqlite.org/wal.html
- AD and SMB post-exploitation: https://github.com/Pennyw0rth/NetExec, https://github.com/fortra/impacket
