# The main brain

NetCast3r's top-level reasoner. It is not another bounded worker: it reads the
whole control plane, answers the operator, and steers the hunt on its own
never-ending cognition loop.

## What it can see

`brain_context` is the snapshot the brain reasons over, in one object:

- every mission with its **campaign stage**, run count, and open-lead count;
- the **director**: engaged, paused, tick, concurrency, in-flight runs, parked
  missions;
- recent **runs** with their mode and stop reason;
- the **tool-call audit** and a compact **traffic** view: tool, actor, target,
  arguments, exit code, and the shape of the result (secrets never included);
- the **log feed** (director and brain entries) and the mission directions;
- the **shared knowledge base** digest and open leads;
- staged **finding candidates** and the evidence graph counts;
- the **post-exploitation plan** for the focus mission;
- the **host** and which offensive tools are installed;
- the outbound **MCP connections** with transport and tool counts.

## The autonomy loop

`BrainLoop` starts with the control plane, beside the director. Every
`interval` seconds (default 150, floor 45) it runs one cognition turn:

1. pick the focus mission - a real target first, then an autonomous one, then
   the most recently touched (labs never outrank a real target);
2. read the snapshot, including its own previous turn so it does not repeat a
   move that produced nothing;
3. decide the single highest-value next move and apply at most three reversible
   actions;
4. write the turn to the **brain journal** and the **director log**, then wait.

The director executes; the brain decides. That separation is what keeps the
hunt moving without an external harness.

Guarantees, enforced in code rather than promised in prose:

- the loop **cannot pause the hunt** - only the operator can pause the director;
- `run_module` is refused unless the focus mission's autonomy is `autonomous`;
- a directive whose exact body already exists is not queued twice;
- it never creates a finding, never decides an approval, and never submits a
  report.

`brain_loop` controls it: `status`, `pause`, `engage`, `interval`, and `tick`
(think now, non-blocking). The pause flag is persisted, so a restart resumes the
operator's choice.

## Coverage and training

The snapshot also carries the focus mission's **coverage** (the 98-item checklist
from WSTG v4.2, the API and LLM Top 10, the 2025 research classes, cloud, mobile,
and supply chain) and the next highest-impact questions. The brain can mark an
item with `mark_coverage` using the evidence it actually has, and may run the
matching module with `run_module`.

Training is part of the loop. The snapshot lists the next unsolved labs. The
brain can start a scripted lab with `run_lab`, or solve any catalogued lab with
`solve_lab` (browser provisioning, bounded solver, banner verification), and
write the lesson with `record_lesson`; a solved lab is recorded only after its
verification banner is observed, and a lesson requires real evidence or a real
outcome.

## Talking to it

`brain_chat` takes a message and returns a reply, a one-line `focus`, and the
steering actions it applied. It is the room to ask "what next?", to give guidance
("focus the order API and test IDOR"), or to change the plan mid-hunt. Both the
operator message and the reply are journaled.

The brain can take four **reversible** actions:

- `directive` - queue an operator direction on a mission (the director hands it
  to the next run);
- `engage` / `pause` / `resume` - control the director;
- `tune` - set the director's scope filter;
- `run_module` - start one exploit module (autonomous missions only, in the
  loop).

It **cannot** create a finding, delete anything, or submit a report. A finding
stays a human-gated promotion; a submission stays a deliberate operator act.

## The persona

The system prompt is distilled from the operator's own hunter playbook: proof is
the only truth, never stop - pivot instead, scope is law. It thinks in chains,
not single bugs: hypothesis first, evidence before prose, minimal movement to
prove a boundary, and a P1-P4 severity priority (P1 RCE / full ATO / cloud
takeover / mass exfiltration; P2 SSRF-internal / SQLi dump / IDOR on other
users' data / auth bypass to admin; P3 stored XSS / state-changing CSRF / info
disclosure; P4 self-XSS / headers / verbose errors only when they enable a
chain).

The same doctrine ships as the `hunter-chain-doctrine` skill pack, so the mesh
roles inherit the escalation ladder and pivot rules too.

The model comes from the `prime` route. The default configuration points it at
`deepseek-v4.1-flash:free` on the primary provider, with the other providers as
ordered fallbacks when the free tier is rate-limited. The memory it reads is the
same regardless of provider.

## Surface

HTTP:

- `GET /api/v1/brain/context`
- `POST /api/v1/brain/chat`
- `GET /api/v1/brain/journal`
- `GET|POST /api/v1/brain/loop`

MCP: `brain_context`, `brain_chat`, `brain_journal`, `brain_loop`.

The command center has a **Main brain** panel with the journal and controls, and
a **main brain** dock on every screen for a quick conversation mid-hunt.
