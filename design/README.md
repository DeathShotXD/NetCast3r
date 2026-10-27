# NetCast3r — Command Center prototype

A clickable, framework-free prototype of the NetCast3r agentic control plane.
It exists to make the product direction reviewable before any of it is rebuilt
inside the Svelte app.

The full product and architecture plan lives in
[`../docs/AGENTIC_PLATFORM.md`](../docs/AGENTIC_PLATFORM.md).

## Run it

```bash
cd design
python3 -m http.server 7860 --bind 127.0.0.1
# open http://127.0.0.1:7860/command-center.html
```

No build step, no package install. Everything is static HTML, CSS, and JS.

## Screens

| Screen | What it demonstrates |
| --- | --- |
| **Command Center** | Live mission hero, KPI rail, agent fleet, approvals, event timeline, finding table, copilot entry point |
| **Missions** | Portfolio view with per-mission scope, budget, progress, next decision, pipeline, deadlines, and spend guardrails |
| **Findings** | Inbox + proof detail, evidence chain, report readiness, reproduction, submission actions, mobile drawer |
| **Agent Studio** | Agent roster, skills, tools, memory, evals, model routing, quality loop |

## Controls

- `Ctrl K` / `/` — command palette; searches findings and jumps between screens
- `N` — new mission composer
- `G` then `C`, `M`, `F`, `A` — Command Center, Missions, Findings, Agent Studio
- `?` — keyboard hint
- `Esc` — close palette, mission composer, finding drawer, or copilot

Clickable behaviors are intentionally honest: approval cards resolve, the kill
switch arms and confirms, pause changes mission state, the finding drawer and
copilot answer with grounded mock data, and every stubbed action says it is a
stub rather than pretending to work.

## What is mocked

- All mission, finding, agent, and telemetry data
- Copilot responses (canned, but phrased as an evidence-grounded assistant)
- Report readiness scores, duplicate checks, and cost numbers
- Every action that would mutate a real target or submit a report

## What is real

- The visual system: Obsidian dark theme and Paper light theme, acid/violet
  identity, dense enterprise layout, responsive behavior down to 430 px
- Interaction design: focus handling, keyboard shortcuts, approval and kill
  flows, empty states, command palette
- The information architecture the production Svelte app will implement

## Next step

After direction sign-off: port the shell and Command Center to Svelte against
real `runs`, `events`, and `findings` from the Python API, then add Mission and
Approval entities. The prototype is the spec, not the shipping frontend.

Those first two steps are now implemented in production: the Obsidian shell,
the real-data Command Center, and the Mission/Approval entities and Missions
screen. The prototype remains the visual reference for the agent runtime,
evidence graph, and report rooms that follow.
