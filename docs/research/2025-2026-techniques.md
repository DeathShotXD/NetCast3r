# 2025-2026 technique corpus

This note records the public research that shaped the `techniques.json`
library. It is a curated corpus, not a claim to have read every write-up,
post, or talk. Each technique in the library keeps its own source URLs so a
reader can go back to the original.

The goal is not more payloads. It is choosing the less-saturated class that
matches a target's actual behavior, then proving the smallest real effect.

## Sources reviewed

- PortSwigger Research, Top 10 Web Hacking Techniques of 2025:
  https://portswigger.net/research/top-10-web-hacking-techniques-of-2025
- Zere, "Cache Deception + CSPT: Turning Non Impactful Findings into Account
  Takeover" (2025): https://zere.es/posts/cache-deception-cspt-account-takeover
- Doyensec, "Exploiting Client-Side Path Traversal to Perform Cross-Site
  Request Forgery" (CSPT2CSRF):
  https://blog.doyensec.com/2024/07/02/cspt2csrf.html
- Payloads All The Things, Client Side Path Traversal:
  https://swisskyrepo.github.io/PayloadsAllTheThings/Client%20Side%20Path%20Traversal
- Elttam, "ORM Leaking More Than You Joined For" (Django, Prisma, Beego,
  OData, Entity Framework):
  https://www.elttam.com/blog/leaking-more-than-you-joined-for
- SL Cyber, "Novel SSRF Technique Involving HTTP Redirect Loops" (Shubs):
  https://slcyber.io/research-center/novel-ssrf-technique-involving-http-redirect-loops/
- zhero, "Next.js, cache, and chains: the stale elixir":
  https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir
- Doyensec, "Common OAuth Vulnerabilities":
  https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html
- Doyensec, "SCIM Hunting - Beyond SSO":
  https://blog.doyensec.com/2025/05/08/scim-hunting.html
- Doyensec, "The MCP AuthN/Z Nightmare":
  https://blog.doyensec.com/2026/03/05/mcp-nightmare.html
- Vladislav Korchagin, Research_Successful_Errors (error-based SSTI):
  https://github.com/vladko312/Research_Successful_Errors
- Black Hat USA 2025, "Lost in Translation: Exploiting Unicode
  Normalizations":
  https://www.blackhat.com/us-25/briefings/schedule/#lost-in-translation-exploiting-unicode-normalizations-44926
- Takeshi Kaneko, ETag length leak:
  https://blog.arkark.dev/2025/12/26/etag-length-leak
- Salvatore Abello, cross-site subdomain leak:
  https://blog.babelo.xyz/posts/cross-site-subdomain-leak/
- flomb, HTTP/2 CONNECT:
  https://blog.flomb.net/posts/http2connect/
- Public hunter posts that informed the access-control/cache emphasis, for
  example tinopreter's Q1 2026 summary:
  https://x.com/tinopreter

## Technique families in the library

| Family | Examples | Why it is less saturated |
| --- | --- | --- |
| Client-side path traversal | CSPT, CSPT2CSRF, CSPT+cache deception | Reviewers look at server paths; the browser builds the path. |
| Cache | Next.js data-request poisoning, unkeyed headers, path-normalization deception | Cache keys and framework internals are poorly understood. |
| ORM leaks | Django relation traversal, Prisma operator injection, Beego/OData parser bypass | It looks like a normal filter, not SQL injection. |
| Template injection | Error-based and boolean-error SSTI | Blind SSTI is often written off as unexploitable. |
| Parser differentials | SAML XML, YAML, JSON, HTTP | Each layer believes it parsed the same bytes. |
| Identity | OAuth mutable claims, client confusion, scope upgrade, redirect parsers, SCIM, MCP | The bug is in the trust transition, not the login form. |
| Side channels | ETag length, connection-pool ordering, redirect timing | Impact is subtle but real when it discloses data. |
| Async access control | Second-order IDOR, worker/export jobs | Authorization is checked at write time, not at processing time. |
| Mobile | OAuth custom-scheme hijack, APK secret to API | The mobile client is a separate, older trust boundary. |
| Agentic | Indirect prompt injection, tool exfiltration, MCP audience confusion | New protocol, weak consent and resource binding. |

## How the library is used

1. Fingerprint the target: framework, identity provider, cache, API style,
   mobile client, CI system.
2. Call `technique_plan` with the target and observed signals.
3. Pick the highest-scoring technique whose prerequisites are actually true.
4. Run the smallest test from `steps`; stop at the first real effect.
5. Record the proof and a lesson; do not record a finding from a score.

`next_actions` also surfaces a research match, so the technique library is
part of the planning loop rather than a separate document.

## Non-claims

- The library does not guarantee critical or high findings. Targets differ,
  scope differs, and a technique still has to be proven.
- A high score is a reason to test, not evidence.
- The sources are public; do not reuse another researcher's target data,
  credentials, or private reports.
- Every test still needs an authorised mission or an explicit scope, and every
  finding still needs reproduced evidence.
