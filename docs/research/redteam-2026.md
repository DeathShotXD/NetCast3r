# Modern red-team techniques study, 2026-11

Status: research note. Scope: web, API, and identity classes that a
proof-first external hunter can actually test, mapped to what NetCast3r now
ships. Sources are named so a reader can re-derive every claim.

## 1. Sources read

- PortSwigger Research, **Top 10 web hacking techniques of 2025**
  (https://portswigger.net/research/top-10-web-hacking-techniques-of-2025):
  parser differentials, HTTP/2 CONNECT, cross-origin redirect leaks, Next.js
  cache chains, ETag length leaks, SOAPwn, Unicode normalization, SSRF redirect
  loops, ORM leaks, error-based SSTI.
- PayloadsAllTheThings, the category tree and the Web Cache Deception, OAuth
  Misconfiguration, Request Smuggling, and GraphQL Injection pages
  (https://github.com/swisskyrepo/PayloadsAllTheThings). 67 categories were
  enumerated; the module is the gap list.
- This project's own corpus: `docs/research/2025-2026-techniques.md`,
  `src/netcast3r/data/techniques.json` (38 entries), and
  `src/netcast3r/data/offsec_frameworks.json` (23 frameworks).
- can-i-take-over-xyz (dangling-CNAME fingerprints) from the previous pass.

Red-team tactic families beyond web were considered and deliberately not
implemented as active capability: C2 and implant lifecycle, Kerberos ticket
abuse, AD graph traversal, credential dumping, and host persistence. They are
recorded as gaps in `offsec_frameworks.json`; the external, proof-first model
does not need a foothold to deliver value, and building one would change the
risk profile of the tool.

## 2. Gap analysis against the PayloadsAllTheThings tree

| Class | 2025 relevance | NetCast3r before | This pass |
| --- | --- | --- | --- |
| Web Cache Deception | high (top-10 adjacent) | none | integrated `cache.py` + `cache_audit` |
| Web Cache Poisoning | high | none | integrated `cache.py` + `cache_audit` |
| OAuth / OIDC misconfiguration | high | flow inventory only | integrated `oauth.py` + `oauth_audit` |
| GraphQL (introspection, suggestions, batching) | high | introspection probe | integrated `graphql.py` + `graphql_probe` |
| Client-Side Path Traversal | high (top-10) | none | next |
| ORM leaks (Django, Prisma, OData) | high (top-10 #2) | none | next |
| Unicode normalization / parser differential | high (top-10 #4, #10) | path variants only | next |
| ETag / XS-Leak side channels | medium (top-10 #6) | none | next |
| Request smuggling / desync | high | race primitives only | next |
| SSRF redirect loops | medium (top-10 #3) | SSRF classify | next |
| WebSocket / CSWSH | medium | none | next |
| SAML injection | medium | none | next |
| Reverse-proxy misconfiguration | medium | none | next |

Already covered and left alone: JWT, SSRF, open redirect, IDOR, authz
comparison, path traversal, file upload, race conditions (HTTP/2 single packet
and HTTP/1 last byte), CRLF-adjacent normalization via `pathdiff.py`, API-spec
ingestion, and secret hunting.

## 3. Integrated this pass

### Web cache deception and poisoning (`src/netcast3r/cache.py`)

- **Deception.** Append static-looking suffixes (`/.css`, `;.css`, `%2f`,
  traversal-to-static) to one dynamic URL, request twice, and compare the
  response to the original page. A cache hit whose body equals the private page
  is a deception lead; a cacheable private page without a hit is a weaker one.
- **Poisoning.** Plant an inert, per-header canary in unkeyed headers
  (`X-Forwarded-Host`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`,
  and others), look for reflection in the body or response headers, then replay
  without the header: a canary that survives the replay is a poisonous cache.
- Cache state is read from `Age`, `X-Cache`, `CF-Cache-Status`, `X-Cache-Hits`,
  and `Cache-Control`. Nothing is planted beyond the canary.

### OAuth / OIDC misconfiguration (`src/netcast3r/oauth.py`)

- Static analysis of an authorize URL: implicit flow (`response_type=token`),
  missing `state`, missing PKCE on a code flow, missing `nonce` for OIDC, and
  redirect_uri weaknesses (plain HTTP, userinfo `@`, wildcard, fragment,
  embedded nested redirect, traversal).
- A redirect_uri mutation generator (suffix host, prefix host, userinfo, path
  append, nested param, fragment, downgrade, encoded slash) and an opt-in probe
  that reads where the server sends the browser. Callback analysis flags tokens
  in the URL and codes without state.

### GraphQL surface (`src/netcast3r/graphql.py`)

- Introspection on/off, field names leaked through `Did you mean` validation
  errors, batching enabled, GET execution, and exposed console paths. All
  read-only queries; no mutation is ever issued.

Each module is dependency-free, transport-injectable, and tested offline.

## 4. What remains, in order

1. Client-side path traversal: find user input reaching a URL path in a JS
   bundle (extends `reveng.py`) and pair it with a cross-site fetch.
2. ORM leak probes and parser differentials: operator injection against
   Django/Prisma/OData-style filters, with a differential oracle.
3. Unicode normalization and encoding-transformation variants folded into
   `pathdiff.py`.
4. ETag/length side-channel oracle added to `oracle_extract`.
5. Desync probes (CL.TE, TE.CL, CL.0, H2.CL, H2.TE) built on the existing race
   transport, with a confirmation repeat before a hit counts.
6. WebSocket handshake, origin, and CSWSH audit.

Every one should arrive the same way this pass did: a deterministic module, an
injectable transport, a scope-gated read-only tool, a checklist link, and
offline tests.
