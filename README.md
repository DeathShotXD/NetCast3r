# NetCast3r

<p align="center">
  <img src="assets/logo.webp" alt="NetCast3r logo" width="340">
</p>

Cast a net over the web. NetCast3r crawls a target, reads the JavaScript it
serves, hunts 310 secret patterns, and checks every candidate against its
provider with 135 recipes, read-only by default. It returns a four-state verdict, the
evidence behind it, and a report you can submit as-is.

<p align="center">
  <img src="assets/banner.webp" alt="NetCast3r - cast a net over the web" width="100%">
</p>

<p align="center">
  <img alt="tests passing" src="https://img.shields.io/github/actions/workflow/status/DeathShotXD/NetCast3r/tests.yml?branch=main&amp;style=for-the-badge&amp;label=tests&amp;labelColor=170F3F&amp;color=9F23DD">
  <img alt="python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-4C2377?style=for-the-badge&amp;labelColor=170F3F">
  <img alt="MIT license" src="https://img.shields.io/badge/license-MIT-281550?style=for-the-badge&amp;labelColor=170F3F">
  <img alt="security policy" src="https://img.shields.io/badge/security-policy-170F3F?style=for-the-badge&amp;labelColor=170F3F">
  <img alt="outputs: markdown, json, jsonl, sarif" src="https://img.shields.io/badge/outputs-MD%20%C2%B7%20JSON%20%C2%B7%20JSONL%20%C2%B7%20SARIF-6CA52E?style=for-the-badge&amp;labelColor=170F3F">
  <img alt="for authorized testing only" src="https://img.shields.io/badge/use-authorized%20testing%20only-C8F81A?style=for-the-badge&amp;labelColor=170F3F">
</p>

<p align="center">
  <b><a href="#install">Install</a></b> | <b><a href="#usage">Usage</a></b> | <b><a href="#outputs">Outputs</a></b> | <b><a href="#docs">Docs</a></b> | <b><a href="SECURITY.md">Security</a></b> | <b><a href="CONTRIBUTING.md">Contributing</a></b>
</p>

<p align="center">
  <img src="assets/stats.svg" alt="Automated web recon, JavaScript analysis, secret hunting, validation and reporting. 310 patterns, 135 recipes." width="100%">
</p>

Detection is only the first step. A pattern match says that something looks
like a key; NetCast3r asks the provider whether it is alive, records what that
key can reach, and escalates when write access is enabled. Every finding
leaves the pipeline with evidence, reproduction steps, and the value already
redacted, so the report can go straight into a program.

<details>
<summary>Contents</summary>

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [What it finds](#what-it-finds)
- [Coverage](#coverage)
- [Example run](#example-run)
- [Outputs](#outputs)
- [Dashboard](#dashboard)
- [Install](#install)
- [Usage](#usage)
- [Scope files](#scope-files)
- [Lab](#lab)
- [Model providers](#model-providers)
- [Docs](#docs)
- [Responsible use](#responsible-use)
- [License](#license)

</details>

## What it does

<p align="center">
  <img src="assets/cast.svg" alt="A radar sweep across a target field: each blip locks on as the sweep passes and lights up its line in the live endpoint log, while the yield meters fill: 121 hosts, 61 bundles, 128 routes, and 4 candidates." width="100%">
</p>

<p align="center">
  <img src="assets/checklist.svg" alt="Run checklist: crawl targets, collect JavaScript files, hunt secrets, validate credentials, escalate and report. More than just a crawler." width="100%">
</p>

- **Crawl** a target and every endpoint it can reach, then collect the JavaScript
- **Read** each bundle line by line to map the logic and surface weak spots
- **Hunt** for secrets, keys, tokens, and hardcoded credentials
- **Validate** each credential against its provider and report what it can access
- **Escalate** to the highest provable impact when write access is enabled
- **Report** with proof, redacted values, and reproduction steps

## How it works

<p align="center">
  <img src="assets/pipeline.svg" alt="Six stages and their agents: crawl with recon, read JavaScript with exegete, hunt with prospector, validate with assayer, escalate with chainer, report with scribe." width="100%">
</p>

The crawler maps the target's subdomains from certificate transparency and
DNS first, then walks each host and collects the JavaScript inside scope, and
finally pulls historical bundles from the Wayback Machine. The exegete reads
each file and maps its logic. The
prospector hunts credentials across 310 patterns. The classifier names any
candidate the patterns did not recognise, rates its confidence, and remembers
the answer for later runs. The assayer validates every candidate against its
provider with read-only recipes. The chainer maps the escalation, the sentinel
scores and de-duplicates, and the report is written with the values redacted.
If no provider answers, the deterministic path still produces a report.

See [docs/architecture.md](docs/architecture.md).

## What it finds

<p align="center">
  <img src="assets/caught.svg" alt="Masked credentials with their states, the report checklist, and the four validation states." width="100%">
</p>

Every candidate leaves the pipeline with one of four states: **CONFIRMED**
carries live proof and is ready to submit, **CORROBORATED** means a second
source agrees, **INFERRED** is a pattern match with no live check behind it,
and **UNRESOLVED** has no verdict yet. Values are masked before the report is
written.

The pattern catalog is built from the gitleaks rule set and the validation
recipes follow the keyhacks endpoints. Every candidate is scored for
confidence using its pattern, its entropy, its length, and the surrounding
code. Unknown values are handed to the classifier agent, which names the
service and can re-type the candidate so the right recipe runs. A route that
omits the model still works: detection and validation never depend on a model.

See [docs/architecture.md](docs/architecture.md).

## Coverage

<p align="center">
  <img src="assets/providers.svg" alt="Scrolling grid of the 121 providers NetCast3r can validate a candidate against, across 135 read-only recipes. Every check is read-only by default." width="100%">
</p>

310 patterns cover cloud, storage, payments, messaging, CI, and model
credentials, and each candidate can be put to 135 read-only recipes across 121
providers. Every check is read-only by default, `--tier write` opts in to the
ones that change state. A report is written either way, with no provider key
required.

## Example run

<p align="center">
  <img src="assets/demo.svg" alt="Animated terminal window running an example scan: recon reports 42 pages and 61 JavaScript files, the exegete reads them, the prospector finds 4 candidates, the assayer plans a read only check, an AWS key comes back confirmed and a database URL corroborated, and scribe writes report.md and dashboard.html." width="100%">
</p>

Recon collects, the exegete reads, the prospector ranks, the assayer puts each
candidate to its provider, and scribe writes the report and the dashboard.
With `--dashboard` the same run is mirrored live into the browser.

<p align="center">
  <img src="assets/stream.svg" alt="Live feed of a run: recon crawls and logs each status, the exegete parses bundles, the prospector surfaces four candidates, the assayer checks a key, an AWS key comes back confirmed, and the scribe writes the report." width="100%">
</p>

## Outputs

| File | What it is |
| --- | --- |
| `report.md` | the submission-ready report: impact, proof, reproduction, remediation |
| `results.json` | summary and findings, for scripts |
| `results.jsonl` | one finding per line, for streaming into other tools |
| `results.sarif` | SARIF 2.1.0, upload it to GitHub code scanning |
| `dashboard.html` | the self-contained dashboard, plus `dashboard.json` beside it |

## Dashboard

<p align="center">
  <img src="assets/dashboard-preview.webp" alt="The NetCast3r HTML dashboard with counters, the stage rail, the validation ladder, and the caught credentials." width="100%">
</p>

`--html` writes a self-contained dashboard next to the report. The file
carries its own artwork and styles, so it opens in any browser, attaches to
an email, or sits in a repository without a build step.

```bash
netcast3r dashboard --results results            open the run you just finished
netcast3r dashboard --demo --out dashboard.html  write the sample run and exit
```

The console uses the same palette and the same state names, so a run reads
the same in the terminal and in the browser. See [docs/DESIGN.md](docs/DESIGN.md).

<p align="center">
  <img src="assets/divider.svg" alt="" width="100%">
</p>

## Install

Python 3.10 or newer.

```bash
pipx install git+https://github.com/DeathShotXD/NetCast3r.git
netcast3r --version
```

## Usage

```bash
netcast3r recon --input target.com --scope scope.txt --out-of-scope oos.txt
netcast3r run   --input target.com --scope scope.txt --out-of-scope oos.txt --html
netcast3r run   --input target.com --scope scope.txt --json --jsonl --sarif
netcast3r providers
```

`--depth`, `--rate`, `--delay`, `--timeout`, and `--retries` tune the crawl.
Subdomain mapping runs by default for a domain target; pass `--no-subdomains`
to stay on the host you named.
`--tier` selects the action tier, `--resume` reuses earlier validations, and
`--fail` exits non-zero when findings exist.

### Agent control (MCP)

NetCast3r exposes its real workspace over MCP to OpenCode and any other MCP
client, and it drives itself without one:

```bash
netcast3r ui --no-open          # the director starts with the control plane
netcast3r mcp --print-config    # optional: paste into opencode.jsonc
opencode mcp list
```

The server has 209 typed tools with risk tiers, scope enforcement, single-use
approvals, rate limits, and a full tool-call audit, plus disposable inboxes,
OAST callbacks, named auth profiles, a scoped authenticated `http_request`, a
path-variant differential, run-to-run surface diffing, local reverse-engineering
analyzers for source, APKs, contracts, and binaries, allowlisted passive recon tools
and precise test cases, a Burp MCP bridge, an outbound MCP registry for HTTP and stdio
servers, a locked-down Docker sandbox, credential pivoting, threat-intel search
with CVE/PoC reproduction plans, STIX 2.1 export and TAXII 2.1 polling,
report-quality scoring and payout ROI, a persistent lesson/skill memory with a
per-technology expertise profile that the agent recalls before planning,
self-audit and diagnostics, and a bounded mission agent (`agent_start`) that
plans, probes, inventories, and verifies inside the mission's scope. See
[docs/MCP.md](docs/MCP.md).

It is its own harness. A **Prime** planner ranks every scoped mission from real
signals, and a durable **director** wakes on a ten-second tick, runs one scoped
pass at a time through the hunt, the operator, or the five-role mesh, watches it
to completion, and records whether the mission moved. An **active mission set
to `autonomous` is the authorization**: its in-scope chain runs without a
per-call approval step-up, audited as `authorized:autonomous`. Scope is still
enforced, approval decisions stay human-only, and it never fabricates findings:
`findings_create` records only what an operator or agent validated, every
bounty result still comes from verified runs, and the director never submits a
report. The command center has a Director strip with Engage, Pause, and Kill.
See [docs/DIRECTOR.md](docs/DIRECTOR.md).

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | the command finished |
| `1` | no input given, no command given, or `--fail` found something |
| `2` | the arguments could not be parsed |

## Scope files

Both scope files take one entry per line. Blank lines and lines starting with
`#` are ignored. The out-of-scope file wins over the in-scope file.

```
example.com            the host and all of its subdomains
*.example.com          subdomains only
https://example.com/p  scheme and path prefix
10.0.0.0/24            an IPv4 network
re:^api\.              a regular expression against the host
```

## Lab

The lab proves the pipeline with no provider key and nothing real:

```bash
bash lab/run_lab.sh
netcast3r run --input http://127.0.0.1:8099/ --out results \
  --patterns lab/patterns.toml --recipes lab/recipes.toml
```

See [lab/README.md](lab/README.md).

## Model providers

NetCast3r talks to any OpenAI-compatible endpoint. NVIDIA Nemotron reasoning
models are configured first by default, followed by OpenRouter, Ollama, and
OpenCode Zen. Run `netcast3r providers` to see what is configured. The
classifier is optional: detection and validation work without it.

The NVIDIA pool uses `nemotron-3-ultra-550b-a55b` for the strongest reasoning
pass, with `nemotron-3.5-lightning-30b-a3b` and the nano omni model as fast
fallbacks. Keys stay out of the config file: paste one in the dashboard, set
`NETCAST3R_NVIDIA_KEY`, or point `api_key_file` at a 0600 file. On a rate limit
the bus still rotates to the next provider, and a second provider is still
required before a candidate is marked corroborated.

<p align="center">
  <img src="assets/divider.svg" alt="" width="100%">
</p>

## Docs

- [Architecture](docs/architecture.md) - stages, scope, tiers, and the fallback path
- [MCP control plane](docs/MCP.md) - tools, policies, approvals, and OpenCode setup
- [Director](docs/DIRECTOR.md) - the autonomous supervisor, Prime, and the kill switch
- [Evidence graph](docs/GRAPH.md) - nodes, provenance, candidate paths, and verification
- [Memory](docs/MEMORY.md) - the shared knowledge base, campaign stages, and the profile
- [Exploits](docs/EXPLOITS.md) - the typed exploit module catalog and how it plans
- [Capabilities](docs/CAPABILITIES.md) - the external tool broker, API-spec ingestion, and PoCs
- [Host](docs/HOST.md) - the shell and filesystem, and the rules that gate them
- [Main brain](docs/BRAIN.md) - the top-level reasoner and how to steer it
- [Self-evolution](docs/EVOLVE.md) - the outcome ledger, proposals, and post-ex planning
- [Design](docs/DESIGN.md) - palette, type, and the validation ladder
- [Contributing](CONTRIBUTING.md) - the ground rules for a pull request
- [Security policy](SECURITY.md) - how to report a problem in NetCast3r
- [Changelog](CHANGELOG.md) - what changed in each version

## Responsible use

NetCast3r is built for authorized testing only. Run it against systems you own
or have explicit written permission to assess.

## License

MIT. See [LICENSE](LICENSE).
