# Architecture

NetCast3r runs one pipeline. Each stage writes to a shared evidence store and
hands the next stage what it found.

## Stages

- `recon.py` crawls from the seeds, stays inside scope, collects JavaScript,
  recurses into JavaScript that other JavaScript loads, extracts endpoints, and
  pulls historical URLs from the Wayback Machine. External tools (katana, gau,
  waybackurls, jsleak) are used when they are installed.
- `secrets.py` scans everything the crawler collected for candidate
  credentials. Patterns live in `patterns.toml` and can be replaced per run.
- `agents.py` holds the swarm. The exegete reads each JavaScript file and maps
  its logic. The prospector triages candidates. The assayer plans the check.
  The chainer maps the escalation. The scribe writes the finding.
- `validate.py` runs the validation recipes in `recipes.toml` and returns a
  status of verified, unverified, unknown, or skipped.
- `orchestrator.py` runs the stages, fans the exegete out across files, and
  falls back to the deterministic path when no provider is reachable.
- `report.py` writes the submission-ready report.
- `store.py` keeps everything in one SQLite file for replay and diffing.
- `egress.py` keeps a pool of working proxies and rotates on rate limits.
- `providers.py` is one OpenAI-compatible client across every provider.
- `tui.py` is the live console.

## Scope

`scope.py` reads one entry per line for both the in-scope and out-of-scope
files. The out-of-scope file wins. A host that is out of scope is recorded and
never fetched.

## Tiers

Runs default to the read tier. Validation recipes that change state are held
back until the tier is raised to write or full.

## Fallback

If no provider answers, the exegete and the model-assisted stages return
nothing and the deterministic path still produces a report.
