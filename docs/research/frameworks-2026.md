# External framework study, 2026-11

Status: research note. Grounding: source actually read this pass, not summaries.
Scope: what the leading offensive frameworks do, where NetCast3r already covers
them, and the concrete integrations that followed from the gaps.

## 1. Method

Read directly:

- reconFTW `main` (six2dez/reconftw): `reconftw.sh` (881 lines) plus
  `modules/core.sh` (2389), `modules/modes.sh` (1699), `modules/subdomains.sh`
  (2406), `modules/web.sh` (2956), `modules/vulns.sh` (1181),
  `modules/osint.sh` (838), and the README feature list. The modules were read
  for structure, not copied.
- Penligent (penligent/penligent): the public repository is documentation and
  product imagery only, so the study is limited to the stated workflow (project
  and skill selection, agent console, packaged CLI, Python environment).
- can-i-take-over-xyz fingerprints (`fingerprints.json`, 76 services): the
  canonical dangling-CNAME corpus, pinned under `src/netcast3r/data/`.
- This project's own `docs/APT_PLAN.md` and `data/offsec_frameworks.json`
  (23 frameworks: 8 partial, 15 gap) so the study does not restate a roadmap it
  already has.

The point of the study is integration targets, not admiration. A capability
only counts if it can be expressed as a deterministic check with evidence.

## 2. reconFTW: what the source actually does

reconFTW is a modular Bash orchestrator. `reconftw.sh` parses options and
sources one module per job. The value is in the breadth of the pipeline and the
number of third-party binaries it drives, not in novel detection logic.

- **Subdomains** (`modules/subdomains.sh`, 2406 lines): passive APIs, crt.sh,
  NOERROR discovery, DNS bruteforce, permutations, TLS handshake names,
  Analytics IDs, reverse-IP, DNS zone transfer, subdomain takeover, and cloud
  bucket enumeration. This is the deepest module.
- **Web** (`modules/web.sh`, 2956 lines): live probing, screenshots, virtual
  host fuzzing, CMS detection, URL collection, URL pattern classification
  (gf), favicon tech recon, JavaScript secret/endpoint extraction, source-map
  recovery, GraphQL detection, parameter discovery, WebSocket auditing, gRPC
  reflection, directory fuzzing, and IIS shortname scanning.
- **Vulns** (`modules/vulns.sh`, 1181 lines): nuclei (CVE and DAST), dalfox
  (XSS), testssl (TLS), and gf-selected candidate pipelines.
- **OSINT** (`modules/osint.sh`, 838 lines): WHOIS, email/credential leak
  search, M365/Azure tenant mapping, document metadata, exposed APIs, Google
  dorking, GitHub org secret scanning, third-party misconfig detection, SPF and
  DMARC mail-hygiene review, and cloud storage enumeration.
- **Hosts** (`modules/core.sh`): IP geolocation, CDN detection, WAF detection,
  nmap/naabu port scanning, service fingerprinting, and password spraying
  (explicitly an opt-in engine).
- **Modes** (`modules/modes.sh`): named run modes and levels that gate which
  modules execute, plus parallel/continuous and monitor modes.

Design lessons that are portable:

1. Depth is a checklist problem. reconFTW's coverage lives in a fixed module
   order; NetCast3r already has the equivalent as the 104-item checklist.
2. The orchestrator is separate from the tools. reconFTW shells out; NetCast3r
   already has `toolbox.py` (allowlisted argv, scope-checked, output parsed
   into candidates) doing the same job.
3. Diffing between runs is first-class. NetCast3r has `surface.py` for that.

## 3. Penligent: the agentic shape

The public material describes a desktop app with a project-per-target model, a
selectable testing "skill" (default "Comprehensive Deep Testing"), an agent
console for mid-run direction, and a configured Python environment for tool
execution. That is the same architecture NetCast3r already ships in stronger
form: a mission with autonomy, a director loop, a Helix console with
`/brain`/`/queue`, and a native tool layer. There is no source to mine here, so
the study closes with: keep the skill-as-plan idea explicit, which the
checklist and `hunt_plan` already do.

## 4. Coverage versus the gap map

The existing `data/offsec_frameworks.json` records the C2, AD, credential, and
pivot gaps honestly. The recon-side gaps that were actionable this pass:

| reconFTW capability | NetCast3r before | Action |
| --- | --- | --- |
| Subdomain takeover | checklist item with no engine | integrated `takeover.py` + `takeover_scan` |
| DNS/email posture (SPF, DMARC, DKIM, CAA, AXFR) | absent | integrated `dnsposture.py` + `dns_posture` |
| Native DNS record layer | socket A-only | integrated `dnsq.py` (A, AAAA, CNAME, NS, MX, TXT, SOA, SRV, DS, CAA, AXFR) |
| Virtual host fuzzing | absent | planned |
| Favicon tech recon | absent | planned |
| GraphQL fuzzing | introspection probe only | planned |
| WebSocket auditing | absent | planned |
| IIS shortname | absent | planned |
| Cloud bucket enumeration | absent | planned |
| NOERROR subdomain discovery, permutations | passive + bruteforce only | planned |
| Screenshots bound to findings, notifications | one-off capture | planned |

## 5. Integrated this pass

- `src/netcast3r/dnsq.py`: pure-stdlib DNS over UDP and TCP. Name encoding with
  IDNA, compression-pointer decoding with a loop guard, A/AAAA/CNAME/NS/MX/TXT/
  SOA/SRV/DS/CAA parsing, rcode-as-data, and CNAME-chain resolution. No new
  dependency.
- `src/netcast3r/takeover.py`: dangling-CNAME detection. CNAME suffix matching
  against the pinned corpus, NXDOMAIN verdicts, provider body fingerprints,
  claimed detection, and a bounded `scan`. A match is a lead; claiming a name
  is always a human action.
- `src/netcast3r/dnsposture.py`: NS, MX, SOA, CAA, SPF, DMARC, DKIM, MTA-STS,
  BIMI reads and an opt-in AXFR. Findings are misconfigurations, not exploits.
- MCP: `takeover_scan` and `dns_posture` (read-only, open-world, scope-gated,
  audited). `hypothesis_route` now routes takeover and mail leads to them.
- Checklist: `wstg-info-06` (DNS/email posture) added; `cloud-05` now names the
  native takeover engine. Coverage count 103 -> 104.
- Durability: `store.py` moves to WAL with `synchronous=NORMAL` and a 5 s busy
  timeout; `server/index.py` adds the same timeout; read-only `surface.py`
  connections take the timeout so a diff never fails on a transient lock.

## 6. Next candidates, ranked

1. Virtual-host fuzzing and favicon-hash tech recon (native, cheap, high yield
   on shared hosting).
2. NOERROR and permutation subdomain discovery feeding `takeover_scan`.
3. GraphQL request/field fuzzing beyond introspection.
4. WebSocket handshake and origin audit.
5. Cloud bucket enumeration from the fingerprint and naming data already on
   hand.
6. Bind screenshots to findings; add notification sinks (Telegram, Discord,
   Slack) behind a mission opt-in.

Each candidate should arrive as a deterministic module with an injectable
transport, a checklist item, and tests, the way this pass was built.
