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

## Source-to-sink call chains

`sourceflow_scan` follows remote input through a local Python source tree. It
starts at a Flask or FastAPI route, tracks the `request` object through
assignments, branches, function arguments, and return values, and stops at a
real sink: `eval`/`exec`, shell execution, string-built SQL, SSRF, template
rendering, unsafe deserialisation, file access, or an open redirect.

The output is a chain, not a pattern match:

- the route and file that reach the sink;
- the exact source expression and assignment lines;
- the sink line, severity, and confidence;
- only routes and functions actually reachable from a route.

Safe parameterised SQL and `yaml.safe_load`/`SafeLoader` are deliberately not
reported. A lead still needs a reachable request and a reviewer; source flow
never creates a finding.

The same chains appear as `source-flow` observations in the **Reverse Lab**
when a source tree is analysed, so the UI and the standalone tool agree.

- `GET /api/v1/sourceflow?path=...`
- MCP `sourceflow_scan`

## Program and scope ingestion

`program_preview` and `program_import` normalise a HackerOne, Bugcrowd,
Intigriti, YesWeHack, or Immunefi CSV/JSON export, or a pasted program brief,
into one mission scope. The parser recognises target columns, status columns,
exclusions, max severity, and rules; it rejects anything that is not a host,
URL, wildcard, IP, or network.

The apply step is a boundary check, not a convenience:

- an exclusion is added immediately;
- an in-scope asset already covered by the mission is recorded explicitly;
- a new in-scope asset is **held back** unless `allow_expand=true`;
- an empty parse is an error, never a silent success.

The preview route shows the exact diff before anything is written. The MCP
tool is high risk because expanding scope changes authorisation, so supervised
deployments need a human approval.

- `POST /api/v1/missions/{id}/program/preview`
- `POST /api/v1/missions/{id}/program`
- `GET /api/v1/programs/formats`

## Reproduction

`candidate_poc` turns a candidate's recorded steps into a minimal `curl` and a
`python` snippet a reviewer can re-run. It reproduces the request that was made;
it does not invent an exploit.

## The line that does not move

A tool's output, a spec's endpoint, and a module's observation are all **leads**.
They become graph nodes, technologies, and candidates. A **finding** is still a
human-gated promotion, and a submission is still a deliberate operator act.
