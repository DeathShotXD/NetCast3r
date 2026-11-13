# Coverage: the testing checklist the hunt closes

A scanner reports what a template matched. A hunter works a checklist: every
class of question a target must answer, in priority order, with the evidence that
closes it. NetCast3r now carries that checklist as data and tracks it per
mission.

## What is in the catalog

104 falsifiable items, grounded in current public guidance:

| Framework | Source | Items |
| --- | --- | --- |
| WSTG | OWASP Web Security Testing Guide v4.2 | information gathering, configuration, identity, authentication, authorization, session, input validation, error handling, cryptography, business logic, client-side |
| API Top 10 | OWASP API Security Top 10 2023 | API1-API10 plus GraphQL and SOAP |
| LLM Top 10 | OWASP Top 10 for LLM Applications 2025 | LLM01-LLM10 |
| OWASP Top 10 | OWASP Top 10:2025 | access control, misconfiguration, supply chain, crypto, injection, insecure design, authentication, integrity, logging, exceptional conditions |
| 2025 Research | PortSwigger Top 10 Web Hacking Techniques of 2025 | error-based SSTI, ORM leaks, SSRF redirect loops, Unicode, SOAPwn, ETag leaks, Next.js cache, HTTP/2 CONNECT, parser differentials, open-redirect chains |
| Cloud | object storage, IMDS, Kubernetes, CI/CD, subdomain takeover | 5 items |
| MASVS | mobile application security | 3 items |

Each item names its objective, the exploit modules that can answer it, the
tools, the evidence that closes it, the expected impact, and its source.

## State

`mission_coverage` stores one row per (mission, item) with a status:

- `untested` - no row yet (the default);
- `in_progress` - a test is running or a partial observation exists;
- `covered` - the test ran and found nothing supporting;
- `vulnerable` - a candidate or a supported step exists; this is a lead, not a
  finding;
- `blocked` - the programme, the WAF, or the target prevented the test.

A deterministic hunt run marks the recon items it actually answered (endpoints,
pages, JavaScript). An exploit module run marks every item that references the
module. The brain may mark an item with the evidence it has.

## Autonomy

- `checklists.next_items` returns the highest-impact open questions first;
- the brain context carries the focus mission's coverage, counts, and next
  checks, and the brain can `mark_coverage`;
- when a mission has no open lead, Prime's next objective is the next checklist
  item, with its modules, so the director keeps moving through the guide;
- the Mission detail page has a **Coverage** tab with the closed percentage,
  category bars, and the next questions.

## Surface

- `GET /api/v1/checklists`
- `GET /api/v1/missions/{id}/coverage`
- `POST /api/v1/missions/{id}/coverage`
- MCP `checklist_catalog`, `coverage_get`, `coverage_mark`

## What this is not

Coverage is not a score of the target's security and it is not evidence. A
closed item means the question was asked; a vulnerable item still needs the
normal reproduction, evidence, and promotion before it becomes a finding.
