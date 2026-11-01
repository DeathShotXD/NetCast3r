# Self-evolution and post-exploitation

Two things that make the harness compound: it learns from what it actually
tried, and it plans the next step past a foothold.

## The outcome ledger

`src/netcast3r/evolve.py` turns stored evidence into a per-technique ledger:
supported, refuted, inconclusive, open hypotheses, staged candidates, exploit
runs, verified runs, and recorded dead ends, with a win rate and a net score.
Nothing is inferred - a row exists because a hypothesis, candidate, run, or
knowledge entry does.

Above it, `maturity` pairs the self-model's capability scores with what the
ledger shows worked (hot techniques) and what kept failing (cold techniques).

## The learning loop

The director already rebuilds the graph, the profile, the campaign stage, and
the shared knowledge after every finished run. It now also bumps the technology
expertise from the mission's real outcome (a supported lead is a success, a
refuted one a failure), so exposure counts track reality rather than repetition.

## Proposals, never auto-changes

`evolve_scan` writes **human-gated** upgrade proposals from two sources:

- the self-model's capability gaps (the existing `propose_gaps`);
- outcome-driven proposals: a technique that was refuted or dead-ended three or
  more times with no support gets a "record a working pattern for X, or stop
  spending on the class" proposal.

Proposals are a backlog. Nothing is applied automatically; an operator decides.

## Post-exploitation planning

`src/netcast3r/postex.py` reads the graph and the exploit catalog and proposes
ordered objectives past the first foothold: AD (LDAP, Kerberoast, AS-REP, ADCS),
cloud (public buckets, IMDS, anonymous Kubernetes), and lateral-movement
enumeration when open services exist. Each objective carries its preconditions
and the evidence it still needs.

It **plans only**. Every objective is a gated module; the identity and cloud
classes are high risk and run under the same scope, risk, and approval gates as
everything else. The main brain sees this plan in its context, so "what next
after this foothold?" is answerable.

## Surface

HTTP `GET /api/v1/evolve`, `GET /api/v1/evolve/ledger`, `POST /api/v1/evolve/scan`,
and `GET /api/v1/missions/{id}/postex`. MCP `evolve_status`, `evolve_ledger`,
`evolve_scan`, and `postex_plan`.
