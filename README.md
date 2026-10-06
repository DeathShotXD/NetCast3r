<p align="center">
  <img src="assets/banner.webp" alt="NetCast3r, cast a net over the web" width="100%">
</p>

<p align="center">
  <img src="assets/logo.webp" alt="NetCast3r logo" width="260">
</p>

# NetCast3r

<p align="center">
  <b>Cast a net over the web.</b><br>
  Crawl a target, read its JavaScript, hunt for secrets, validate every
  credential, and write a report you can submit.
</p>

<p align="center">
  <img alt="tests passing" src="https://img.shields.io/github/actions/workflow/status/DeathShotXD/NetCast3r/tests.yml?branch=main&amp;style=for-the-badge&amp;label=tests&amp;labelColor=170F3F&amp;color=9F23DD">
  <img alt="python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-4C2377?style=for-the-badge&amp;labelColor=170F3F">
  <img alt="MIT license" src="https://img.shields.io/badge/license-MIT-281550?style=for-the-badge&amp;labelColor=170F3F">
</p>

<p align="center">
  <img src="assets/stats.svg" alt="Automated web recon, JavaScript analysis, secret hunting, validation and reporting. 230 patterns, 26 recipes." width="100%">
</p>

The pipeline, the agent swarm, the validation engine, the evidence store, the
report writer, the live console, the HTML dashboard, the lab, and the test
suite are all in place.

## What it does

<p align="center">
  <img src="assets/checklist.svg" alt="Crawl targets, collect JavaScript files, hunt secrets, validate credentials, escalate and report. More than just a crawler." width="100%">
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

The crawler collects JavaScript inside scope, then pulls historical bundles
from the Wayback Machine. The exegete reads each file and maps its logic. The
prospector hunts credentials across 230 patterns. The classifier names any
candidate the patterns did not recognise, rates its confidence, and remembers
the answer for later runs. The assayer validates every candidate against its
provider with read-only recipes. The chainer maps the escalation, the sentinel
scores and de-duplicates, and the report is written with the values redacted.
If no provider answers, the deterministic path still produces a report.

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
```

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

## Providers

NetCast3r talks to any OpenAI-compatible endpoint. OpenCode Zen and OpenRouter
are configured first by default; Ollama and custom endpoints are supported.

## Responsible use

NetCast3r is built for authorized testing only. Run it against systems you own
or have explicit written permission to assess.

## License

MIT. See [LICENSE](LICENSE).
