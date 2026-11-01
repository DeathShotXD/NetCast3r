# Capabilities: external tools, API specs, and PoCs

Beyond the built-in typed tools, NetCast3r drives the operator's own offensive
tooling and turns its output into leads, never findings.

## The toolbox broker

`src/netcast3r/toolbox.py` is a tiered, scope-checked catalog of external tools.
Each entry names its binary, category, risk, stage, scope, allowlisted options,
and an output parser.

Categories cover recon (`nmap`, `subfinder`, `httpx`, `katana`, `whatweb`), web
(`ffuf`, `gobuster`, `nuclei`, `sqlmap`, `nikto`, `wpscan`) and AD (`nxc`,
`enum4linux-ng`). `toolbox_catalog` reports which binaries are actually
installed.

Rules enforced before a binary starts:

- the target host must be in the **mission scope** (the caller computes the
  allowed set from the mission target and scope; private and loopback hosts are
  allowed only when the scope names them);
- cloud metadata and link-local addresses are **always refused**;
- arguments come only from an **allowlisted** flag set - no shell, ever;
- every run is audited, wall-clock bounded, and output-capped; a timed-out run's
  process group is killed.

Output is parsed (`nmap` services, `nuclei` findings, `sqlmap` vulnerability,
`httpx` technology, generic URLs) and persisted as graph nodes, technologies,
shared knowledge, and **candidates** with raw evidence. `toolbox_processes` and
`toolbox_kill` manage long runs.

## API-spec ingestion

`api_spec_ingest` reads an OpenAPI/Swagger or Postman contract and records every
declared endpoint and parameter as graph nodes, so a scoped API assessment starts
from the published surface instead of crawling it.

## Reproduction

`candidate_poc` turns a candidate's recorded steps into a minimal `curl` and a
`python` snippet a reviewer can re-run. It reproduces the request that was made;
it does not invent an exploit.

## The line that does not move

A tool's output, a spec's endpoint, and a module's observation are all **leads**.
They become graph nodes, technologies, and candidates. A **finding** is still a
human-gated promotion, and a submission is still a deliberate operator act.
