# The main brain

NetCast3r's top-level reasoner. It is not another bounded worker: it reads the
whole control plane and both answers the operator and steers the hunt.

## What it can see

`brain_context` is the snapshot the brain reasons over, in one object:

- every mission with its **campaign stage**, run count, and open-lead count;
- the **director**: engaged, paused, tick, concurrency, in-flight runs, parked
  missions;
- recent **runs** with their mode and stop reason;
- the **tool-call audit** (tool, status, actor, target);
- the **shared knowledge base** digest and open leads;
- staged **finding candidates**;
- the **host** and which offensive tools are installed;
- the outbound **MCP connections**.

## Talking to it

`brain_chat` takes a message and returns a reply, a one-line `focus`, and the
steering actions it applied. It is the room to ask "what next?", to give guidance
("focus the order API and test IDOR"), or to change the plan mid-hunt.

The brain can take four **reversible** actions:

- `directive` - queue an operator direction on a mission (the director hands it
  to the next run);
- `engage` / `pause` / `resume` - control the director;
- `tune` - set the director's scope filter;
- `run_module` - start one exploit module.

It **cannot** create a finding, delete anything, or submit a report. A finding
stays a human-gated promotion; a submission stays a deliberate operator act.

## The persona

The system prompt is distilled from a working hunter playbook: hypothesis first,
evidence before prose, chains over single bugs, minimal movement to prove a
boundary, and a P1-P4 severity priority (P1 RCE / full ATO / cloud takeover /
mass exfiltration; P2 SSRF-internal / SQLi dump / IDOR on other users' data /
auth bypass to admin; P3 stored XSS / state-changing CSRF / info disclosure; P4
self-XSS / headers / verbose errors only when they enable a chain).

It is model-agnostic. Route the `prime` role to whichever model reasons best for
you; the memory it reads is the same regardless of provider.

## Surface

HTTP `GET /api/v1/brain/context` and `POST /api/v1/brain/chat`; MCP
`brain_context` and `brain_chat`. The command center has a **Main brain** panel:
a conversation with the brain, its `focus`, and the actions it applied.
