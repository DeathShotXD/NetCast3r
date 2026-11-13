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

## Native DNS and takeover checks

`dnsq.py` speaks DNS over UDP and TCP with no third-party dependency: IDNA name
encoding, compression-pointer decoding with a loop guard, A/AAAA/CNAME/NS/MX/
TXT/SOA/SRV/DS/CAA parsing, rcode-as-data, CNAME-chain resolution, and AXFR.

`takeover_scan` matches a resolved CNAME chain against a pinned copy of the
can-i-take-over-xyz corpus (76 services, `data/takeover_fingerprints.json`) and
confirms with the provider's own unclaimed-name response. `dns_posture` reads
SPF, DMARC, DKIM, CAA, MX, NS, and SOA and can attempt an AXFR on request. Both
are read-only, scope-gated, and audited; a match is a lead, and claiming a name
stays a human action.

`vhost_scan` sends candidate Host values to one in-scope address and labels the
names that answer with a page different from the baseline and from a random
unclaimed name, so a catch-all server does not invent virtual hosts. Every
candidate Host is scope-checked before it is sent.

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

Every applied brief is persisted in `program_imports` with the platform,
parsed assets, rules, diff, filename, actor, and time. The mission scope stays
the live authorization; the history is its audit trail.

- `POST /api/v1/missions/{id}/program/preview`
- `POST /api/v1/missions/{id}/program`
- `GET /api/v1/missions/{id}/program/imports`
- `GET /api/v1/programs/formats`

## Reproduction

`candidate_poc` turns a candidate's recorded steps into a minimal `curl` and a
`python` snippet a reviewer can re-run. It attaches a matching research
technique when the module or title hints one. It reproduces the request that
was made; it does not invent an exploit.

`candidate_poc_verify` replays those steps against the authorised mission
target and scores expected status or marker assertions. A pass is evidence; a
fail is a refutation. Neither tool creates a finding.

Promotion (`candidate_promote`) requires a replayable PoC with at least one
recorded request step. An operator may pass `force=true` with notes to
override a missing PoC, or `verify=true` to demand a live assertion pass
before the finding is written. The finding evidence carries the PoC markdown.

## The line that does not move

A tool's output, a spec's endpoint, and a module's observation are all **leads**.
They become graph nodes, technologies, and candidates. A **finding** is still a
human-gated promotion, and a submission is still a deliberate operator act.
