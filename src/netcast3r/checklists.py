"""The coverage engine: a modern testing checklist that the hunt can close.

A scanner reports what a template matched. A hunter works a checklist: every
class of question the target must answer, in priority order, with the evidence
that closes it. This module is that checklist as data plus the per-mission
state that tracks it.

The catalog is grounded in the current public guidance:

- OWASP Web Security Testing Guide v4.2 (the eleven testing categories);
- OWASP API Security Top 10 2023 (API1-API10);
- OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10);
- PortSwigger Top 10 Web Hacking Techniques of 2025;
- the cloud, mobile, and supply-chain classes a modern programme expects.

An item is a falsifiable question, not a scanner check. It names the exploit
modules and tools that can answer it, the evidence that closes it, and the
impact if it fails. Coverage state is per mission; a module run moves its items
forward automatically, and the brain may mark an item when it has the evidence.

This module never creates a finding. A `vulnerable` item is a lead that the
normal evidence and promotion path still has to prove.
"""

from __future__ import annotations

STATUSES = ("untested", "in_progress", "covered", "vulnerable", "blocked")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _item(item_id, framework, category, title, objective, modules=(),
          tools=(), evidence="", severity="medium", platforms=("web",),
          source="", tech=()):
    return {
        "id": item_id, "framework": framework, "category": category,
        "title": title, "objective": objective, "modules": list(modules),
        "tools": list(tools), "evidence": evidence, "severity": severity,
        "platforms": list(platforms), "source": source, "tech": list(tech),
    }


ITEMS = (
    # -- WSTG 4.1 information gathering ---------------------------------
    _item("wstg-info-01", "WSTG", "information-gathering",
          "Enumerate hosts, subdomains, and certificate names",
          "Every in-scope host and certificate name is known, with the ones that "
          "serve an application separated from parking and mail records.",
          tools=("subfinder", "dnsx", "httpx", "amass"), severity="info",
          evidence="a host table with live status and title",
          source="WSTG v4.2 4.1"),
    _item("wstg-info-02", "WSTG", "information-gathering",
          "Map entry points, parameters, and API routes",
          "Crawl and read JavaScript until every reachable route, parameter, and "
          "API version is inventoried.",
          tools=("katana", "gau", "waybackurls", "arjun"), severity="info",
          evidence="endpoint inventory with source and method",
          source="WSTG v4.2 4.1"),
    _item("wstg-info-03", "WSTG", "information-gathering",
          "Fingerprint the stack and its versions",
          "Identify server, framework, CMS, CDN/WAF, and client libraries with "
          "versions good enough to choose the attack class.",
          tools=("whatweb", "httpx", "nuclei"), severity="info",
          evidence="one line per surface: stack, version, and evidence",
          source="WSTG v4.2 4.1"),
    _item("wstg-info-04", "WSTG", "information-gathering",
          "Review robots, sitemaps, and well-known metadata",
          "robots.txt, sitemap, security.txt, and well-known paths are read for "
          "hidden routes and ownership clues.",
          tools=("ffuf", "feroxbuster"), severity="info",
          evidence="the paths and what they disclose",
          source="WSTG v4.2 4.1"),
    _item("wstg-info-05", "WSTG", "information-gathering",
          "Find archived and forgotten endpoints",
          "Wayback and common-crawl URLs are compared with the live surface; the "
          "difference is where old debug and API versions live.",
          tools=("gau", "waybackurls", "katana"), severity="low",
          evidence="archived URLs that still answer or differ",
          source="WSTG v4.2 4.1"),
    _item("wstg-info-06", "WSTG", "information-gathering",
          "Read DNS and email posture",
          "NS, MX, SOA, and CAA records plus SPF, DMARC, and DKIM policies are "
          "read; a permissive SPF, a monitor-only DMARC, or a missing CAA is a "
          "lead to corroborate.",
          tools=("dns_posture", "dig"), severity="low",
          evidence="the record set and the exact policy that is weak",
          source="WSTG v4.2 4.2 / M3AAWG sender best practice"),
    _item("wstg-info-07", "WSTG", "information-gathering",
          "Discover virtual hosts on one address",
          "Candidate Host values are compared against the baseline and against "
          "a random unclaimed name; a differing page is a vhost to scope and "
          "probe separately.",
          tools=("vhost_scan", "ffuf"), severity="low",
          evidence="the Host value and the differing status, length, and title",
          source="WSTG v4.2 4.1"),
    # -- WSTG 4.2 configuration and deployment --------------------------
    _item("wstg-conf-01", "WSTG", "configuration",
          "Test transport security and HSTS",
          "TLS versions, ciphers, redirect behaviour, and HSTS are checked; a "
          "downgrade or a plaintext origin is a lead.",
          tools=("httpx", "nmap"), severity="low",
          evidence="protocol and header transcript",
          source="WSTG v4.2 4.2"),
    _item("wstg-conf-02", "WSTG", "configuration",
          "Look for exposed administrative and debug surfaces",
          "Actuator, debug, graphiql, phpinfo, server-status, and admin consoles "
          "are enumerated and access-tested as the lowest role.",
          tools=("ffuf", "feroxbuster", "nuclei"), severity="high",
          evidence="the path, the response, and whether auth was enforced",
          source="WSTG v4.2 4.2"),
    _item("wstg-conf-03", "WSTG", "configuration",
          "Test CORS policy",
          "A reflected arbitrary origin with credentials, or a null origin, is "
          "tested on an authenticated JSON endpoint.",
          modules=("web-cors",), tools=("http_request",), severity="high",
          evidence="preflight and response headers for a hostile origin",
          source="WSTG v4.2 4.2"),
    _item("wstg-conf-04", "WSTG", "configuration",
          "Test security headers on sensitive responses",
          "CSP, frame-ancestors, nosniff, and referrer policy are checked on the "
          "pages that matter, not just the home page.",
          tools=("httpx",), severity="low",
          evidence="headers on the authenticated and money pages",
          source="WSTG v4.2 4.2"),
    _item("wstg-conf-05", "WSTG", "configuration",
          "Test HTTP methods and verb override",
          "TRACE, PUT, DELETE, and X-HTTP-Method-Override are tested where the "
          "route is guarded by method.",
          modules=("api-verb-tamper",), tools=("http_request",), severity="medium",
          evidence="a guarded action reached by an alternate method",
          source="WSTG v4.2 4.2"),
    _item("wstg-conf-06", "WSTG", "configuration",
          "Test host header and forwarded-header trust",
          "Host, X-Forwarded-Host, and X-Forwarded-For are reflected into links, "
          "redirects, or password-reset URLs.",
          modules=("server-host-header",), tools=("http_request",), severity="high",
          evidence="a reset link or redirect pointing at the attacker host",
          source="WSTG v4.2 4.2"),
    # -- WSTG 4.3 identity management -----------------------------------
    _item("wstg-id-01", "WSTG", "identity",
          "Enumerate roles and registration paths",
          "Every way an identity is created and every role it can hold is known, "
          "including invite, SSO, and API-key paths.",
          tools=("http_request",), severity="medium",
          evidence="a role matrix and the request that creates each identity",
          source="WSTG v4.2 4.3"),
    _item("wstg-id-02", "WSTG", "identity",
          "Test user enumeration",
          "Registration, login, reset, and invite flows are compared for a "
          "difference that reveals whether an account exists.",
          tools=("http_request",), severity="low",
          evidence="a stable status, body, or timing difference",
          source="WSTG v4.2 4.3"),
    _item("wstg-id-03", "WSTG", "identity",
          "Test account provisioning and role assignment",
          "A new account cannot choose its own role, tenant, or entitlements "
          "through the registration body.",
          modules=("api-mass-assignment",), severity="high",
          evidence="a created account with a role the UI never offered",
          source="WSTG v4.2 4.3"),
    # -- WSTG 4.4 authentication ----------------------------------------
    _item("wstg-auth-01", "WSTG", "authentication",
          "Test the login and credential policy",
          "Default credentials, lockout, and credential stuffing controls are "
          "checked without locking real users out.",
          modules=("auth-default-creds",), severity="high",
          evidence="a successful login with a documented default or a missing lockout",
          source="WSTG v4.2 4.4"),
    _item("wstg-auth-02", "WSTG", "authentication",
          "Test password reset end to end",
          "Token entropy, host-header influence, reuse, expiry, and the account "
          "binding of the reset token are tested.",
          modules=("auth-password-reset",), severity="critical",
          evidence="a reset token that is predictable, reusable, or misdirected",
          source="WSTG v4.2 4.4"),
    _item("wstg-auth-03", "WSTG", "authentication",
          "Test second-factor enforcement on every login path",
          "Password, code, OAuth, QR, and reset paths all enforce the second "
          "factor before a session is usable.",
          modules=("auth-mfa-bypass",), severity="critical",
          evidence="a session that reaches a protected page without the factor",
          source="WSTG v4.2 4.4"),
    _item("wstg-auth-04", "WSTG", "authentication",
          "Test JWT handling",
          "Signature verification, algorithm pinning, key id handling, and claim "
          "validation are tested with a self-signed token.",
          modules=("auth-jwt-alg-none", "auth-jwt-kid"), severity="critical",
          evidence="a forged token accepted by a protected endpoint",
          source="WSTG v4.2 4.4"),
    _item("wstg-auth-05", "WSTG", "authentication",
          "Test OAuth and OIDC flows",
          "redirect_uri matching, state, PKCE, and code binding are tested from "
          "an attacker-controlled client.",
          modules=("auth-oauth-redirect",), severity="critical",
          tools=("oauth_audit",),
          evidence="a code or token delivered to a host the client did not register",
          source="WSTG v4.2 4.4"),
    _item("wstg-auth-06", "WSTG", "authentication",
          "Test SAML assertion handling",
          "Signature position, audience, recipient, and replay are tested with a "
          "modified assertion.",
          modules=("auth-saml-xsw",), severity="critical",
          evidence="an altered assertion accepted after the signature check",
          source="WSTG v4.2 4.4"),
    _item("wstg-auth-07", "WSTG", "authentication",
          "Test authentication bypass on internal and legacy paths",
          "Legacy endpoints, alternate content types, and path variants cannot "
          "reach an authenticated handler unauthenticated.",
          tools=("http_request", "ffuf"), severity="critical",
          evidence="a 200 with protected data from an unauthenticated request",
          source="WSTG v4.2 4.4"),
    # -- WSTG 4.5 authorization -----------------------------------------
    _item("wstg-authz-01", "WSTG", "authorization",
          "Test object-level authorization with two identities",
          "Every endpoint that takes an object id is fetched as the other "
          "identity, including write and delete.",
          modules=("web-idor-object",), severity="critical",
          evidence="identity B reads or changes identity A's object",
          source="WSTG v4.2 4.5 / OWASP API1:2023"),
    _item("wstg-authz-02", "WSTG", "authorization",
          "Test function-level authorization across the role matrix",
          "Reader, writer, and admin tokens are replayed against every privileged "
          "function, including webhooks, billing, and team management.",
          modules=("api-bfla",), severity="critical",
          evidence="a lower role performs an admin function",
          source="WSTG v4.2 4.5 / OWASP API5:2023"),
    _item("wstg-authz-03", "WSTG", "authorization",
          "Test tenant and organization boundaries",
          "A second tenant cannot read, infer, or mutate the first tenant's "
          "objects through ids, slugs, or search.",
          tools=("http_request",), severity="critical",
          evidence="cross-tenant data or a cross-tenant write",
          source="WSTG v4.2 4.5"),
    _item("wstg-authz-04", "WSTG", "authorization",
          "Test forced browsing to privileged routes",
          "Admin and internal routes are requested directly with a low-privilege "
          "session; the server must not render them.",
          tools=("ffuf", "feroxbuster", "http_request"), severity="high",
          evidence="a privileged page rendered or its API answered",
          source="WSTG v4.2 4.5"),
    _item("wstg-authz-05", "WSTG", "authorization",
          "Test authorization on file and export endpoints",
          "Downloads, exports, invoices, and attachments are bound to the "
          "requesting identity, not just to a guessable filename.",
          tools=("http_request",), severity="high",
          evidence="another identity's export or attachment",
          source="WSTG v4.2 4.5"),
    # -- WSTG 4.6 session management ------------------------------------
    _item("wstg-sess-01", "WSTG", "session",
          "Test session cookie flags and scope",
          "Secure, HttpOnly, SameSite, domain, and path are correct; a sibling "
          "subdomain cannot set a cookie that the app trusts.",
          tools=("http_request",), severity="high",
          evidence="a cookie that is readable by script or shared too widely",
          source="WSTG v4.2 4.6"),
    _item("wstg-sess-02", "WSTG", "session",
          "Test session fixation and rotation",
          "A pre-set session id is not adopted at login, and the id rotates on "
          "privilege change and logout.",
          tools=("http_request",), severity="high",
          evidence="the same session id before and after login",
          source="WSTG v4.2 4.6"),
    _item("wstg-sess-03", "WSTG", "session",
          "Test CSRF on state-changing flows",
          "Email change, password change, role change, and money movement reject "
          "a cross-site request without a token or with an omitted Origin.",
          modules=("web-csrf",), severity="high",
          evidence="a state change from a cross-site request",
          source="WSTG v4.2 4.6"),
    _item("wstg-sess-04", "WSTG", "session",
          "Test logout and token revocation",
          "Logout invalidates server-side state; a stolen cookie or refresh token "
          "cannot be replayed after it.",
          tools=("http_request",), severity="medium",
          evidence="a replayed token still accepted after logout",
          source="WSTG v4.2 4.6"),
    # -- WSTG 4.7 input validation --------------------------------------
    _item("wstg-inpv-01", "WSTG", "input-validation",
          "Test reflected and stored cross-site scripting",
          "Every reflected parameter and stored field is tested in its real "
          "context: HTML, attribute, URL, script, and JSON.",
          modules=("web-reflected-xss", "web-dom-xss"), tools=("dalfox",),
          severity="high", evidence="script execution in the victim context",
          source="WSTG v4.2 4.7"),
    _item("wstg-inpv-02", "WSTG", "input-validation",
          "Test SQL and NoSQL injection",
          "String, numeric, order, and second-order contexts get a boolean pair; "
          "Mongo operators are tested on JSON APIs.",
          modules=("web-sqli-error", "web-nosqli-operator"), tools=("sqlmap",),
          severity="critical", evidence="a predicate-bound response difference",
          source="WSTG v4.2 4.7"),
    _item("wstg-inpv-03", "WSTG", "input-validation",
          "Test server-side template injection",
          "A math probe in every reflected template context; escalate the engine "
          "to file read or command execution.",
          modules=("web-ssti",), severity="critical",
          evidence="the evaluated expression and the engine fingerprint",
          source="WSTG v4.2 4.7 / PortSwigger Top 10 2025 #1"),
    _item("wstg-inpv-04", "WSTG", "input-validation",
          "Test OS command injection",
          "Time-based, output-based, and blind OOB probes are run where user input "
          "reaches a shell.",
          modules=("web-command-injection",), tools=("interactsh-client",),
          severity="critical", evidence="command output or an OOB callback",
          source="WSTG v4.2 4.7"),
    _item("wstg-inpv-05", "WSTG", "input-validation",
          "Test XML external entity injection",
          "File read, OOB, and parameter-entity probes are run on every XML and "
          "Office/SVG upload path.",
          modules=("web-xxe",), severity="critical",
          evidence="file contents or an OOB DNS/HTTP hit",
          source="WSTG v4.2 4.7"),
    _item("wstg-inpv-06", "WSTG", "input-validation",
          "Test unsafe deserialization",
          "Framework-specific gadget probes are run only where a serialized blob "
          "is accepted.",
          modules=("web-deserialization",), severity="critical",
          evidence="a gadget callback or a controlled object",
          source="WSTG v4.2 4.7"),
    _item("wstg-inpv-07", "WSTG", "input-validation",
          "Test file upload handling",
          "Extension, MIME, magic bytes, path, and execution are tested on every "
          "upload; the goal is execution or stored script, not just acceptance.",
          modules=("server-file-upload",), severity="critical",
          evidence="the uploaded file served and executed",
          source="WSTG v4.2 4.7"),
    _item("wstg-inpv-08", "WSTG", "input-validation",
          "Test path traversal and file read",
          "Encoded variants are tried on download, preview, and template paths.",
          modules=("server-path-traversal",), severity="high",
          evidence="a file outside the intended root",
          source="WSTG v4.2 4.7"),
    _item("wstg-inpv-09", "WSTG", "input-validation",
          "Test server-side request forgery",
          "Every URL-bearing parameter is pointed at an OAST host, then at "
          "metadata only if the programme allows it.",
          modules=("server-ssrf-metadata", "cloud-imds"),
          tools=("interactsh-client",), severity="critical",
          evidence="an OOB hit with the server's source address",
          source="WSTG v4.2 4.7 / OWASP API7:2023"),
    _item("wstg-inpv-10", "WSTG", "input-validation",
          "Test mass assignment on every body binder",
          "Protected fields (role, tenant, balance, verified) are added to update "
          "and create bodies.",
          modules=("api-mass-assignment",), severity="high",
          evidence="the protected field changed or was echoed",
          source="WSTG v4.2 4.7"),
    _item("wstg-inpv-11", "WSTG", "input-validation",
          "Test HTTP request smuggling",
          "CL.TE, TE.CL, H2.CL, and TE obfuscation are tested behind the CDN with "
          "a timing confirmation.",
          modules=("server-request-smuggling",), severity="critical",
          evidence="a delayed next request or a poisoned response",
          source="WSTG v4.2 4.7"),
    _item("wstg-inpv-12", "WSTG", "input-validation",
          "Test web cache poisoning and deception",
          "Unkeyed headers and path tricks are tested against a cacheable page; "
          "confirm with a second identity.",
          modules=("server-cache-poison", "server-cache-deception"),
          severity="high", tools=("cache_audit",),
          evidence="a poisoned or deceived response served to a second user",
          source="WSTG v4.2 4.7 / PortSwigger Top 10 2025 #7"),
    _item("wstg-inpv-13", "WSTG", "input-validation",
          "Test client-side path traversal and DOM sinks",
          "URL parameters consumed as paths, postMessage handlers, and innerHTML "
          "sinks are traced to a security-relevant effect.",
          modules=("client-cspt",), severity="high",
          tools=("csp_scan",),
          evidence="attacker-controlled content or request in the victim's context",
          source="WSTG v4.2 4.7 / PortSwigger Top 10 2025 #8"),
    _item("wstg-inpv-14", "WSTG", "input-validation",
          "Test prototype pollution",
          "JSON merge endpoints and client-side parsers are probed with __proto__ "
          "and constructor.prototype, then the sink is confirmed.",
          modules=("web-prototype-pollution",), severity="high",
          evidence="a polluted property that changes behaviour or reaches a sink",
          source="WSTG v4.2 4.7"),
    _item("wstg-inpv-15", "WSTG", "input-validation",
          "Test Unicode and parser differentials",
          "Normalization, case folding, and parser disagreement are used to bypass "
          "a filter or an authorization check.",
          modules=("web-unicode-normalization",), severity="high",
          evidence="the same input accepted by one layer and rejected by another",
          source="PortSwigger Top 10 2025 #4 and #10"),
    # -- WSTG 4.8 error handling ----------------------------------------
    _item("wstg-err-01", "WSTG", "error-handling",
          "Test error handling and stack trace disclosure",
          "Malformed input and boundary values do not return stack traces, SQL, "
          "or internal paths.",
          tools=("http_request", "nuclei"), severity="low",
          evidence="a response that discloses internals",
          source="WSTG v4.2 4.8"),
    _item("wstg-err-02", "WSTG", "error-handling",
          "Test for debug and trace endpoints",
          "trace.axd, elmah, actuator, and debug consoles are probed and read as "
          "the lowest role.",
          tools=("ffuf", "nuclei"), severity="high",
          evidence="a debug endpoint that returns runtime data",
          source="WSTG v4.2 4.8"),
    # -- WSTG 4.9 cryptography ------------------------------------------
    _item("wstg-cryp-01", "WSTG", "cryptography",
          "Test transport and certificate weaknesses",
          "Expired, mismatched, weak, or shared certificates and deprecated TLS "
          "are identified.",
          tools=("nmap", "httpx"), severity="low",
          evidence="the certificate and protocol transcript",
          source="WSTG v4.2 4.9"),
    _item("wstg-cryp-02", "WSTG", "cryptography",
          "Test secrets and weak randomness",
          "Reset tokens, API keys, invite codes, and session ids are checked for "
          "low entropy or predictability.",
          tools=("http_request",), severity="high",
          evidence="a repeated or predictable secret",
          source="WSTG v4.2 4.9"),
    _item("wstg-cryp-03", "WSTG", "cryptography",
          "Test password storage side channels",
          "Timing and error differences do not reveal password length or hash "
          "prefix.",
          tools=("http_request",), severity="low",
          evidence="a stable timing or error oracle",
          source="WSTG v4.2 4.9"),
    # -- WSTG 4.10 business logic ---------------------------------------
    _item("wstg-bus-01", "WSTG", "business-logic",
          "Test price, quantity, and currency tampering",
          "Negative, fractional, and client-supplied amounts are sent to checkout "
          "and order APIs.",
          tools=("http_request",), severity="critical",
          evidence="an order total that differs from the server's price",
          source="WSTG v4.2 4.10"),
    _item("wstg-bus-02", "WSTG", "business-logic",
          "Test coupon, gift-card, and credit races",
          "The same value is redeemed concurrently with a last-byte or h2 burst "
          "and the balance is read after.",
          modules=("server-race",), tools=("lastbyte", "single_packet"),
          severity="critical", evidence="more value consumed than the balance allows",
          source="WSTG v4.2 4.10"),
    _item("wstg-bus-03", "WSTG", "business-logic",
          "Test approval and workflow bypass",
          "A multi-step flow cannot skip, replay, or reorder a step to reach the "
          "final state.",
          tools=("http_request",), severity="high",
          evidence="a final state reached without a required step",
          source="WSTG v4.2 4.10"),
    _item("wstg-bus-04", "WSTG", "business-logic",
          "Test rate limits on money and messaging actions",
          "OTP, invite, comment, and transfer endpoints enforce a limit that is "
          "not trivially bypassed by a header or a new session.",
          modules=("api-rate-limit",), severity="medium",
          evidence="a burst beyond the documented limit with real cost",
          source="WSTG v4.2 4.10"),
    # -- WSTG 4.11 client-side ------------------------------------------
    _item("wstg-cli-01", "WSTG", "client-side",
          "Test DOM XSS sources and sinks",
          "location, postMessage, window.name, and storage sources are traced to "
          "eval, innerHTML, and navigation sinks.",
          modules=("web-dom-xss",), tools=("dalfox",), severity="high",
          evidence="script execution from a DOM source",
          source="WSTG v4.2 4.11"),
    _item("wstg-cli-02", "WSTG", "client-side",
          "Test clickjacking on sensitive actions",
          "Framing protection and frame-busting are checked on money and account "
          "actions.",
          tools=("http_request",), severity="low",
          evidence="a sensitive action frameable by a hostile origin",
          source="WSTG v4.2 4.11"),
    _item("wstg-cli-03", "WSTG", "client-side",
          "Test postMessage and WebSocket origin checks",
          "Handlers validate origin and schema; a hostile page cannot send or "
          "receive privileged messages.",
          modules=("web-websocket-cswsh",), severity="high",
          tools=("ws_audit",),
          evidence="a privileged message accepted from a hostile origin",
          source="WSTG v4.2 4.11"),
    _item("wstg-cli-04", "WSTG", "client-side",
          "Read JavaScript for secrets and internal hosts",
          "Bundles are scanned for keys, internal hostnames, feature flags, and "
          "undocumented endpoints, and each hit is confirmed live.",
          tools=("katana", "trufflehog", "gitleaks"), severity="high",
          evidence="a live secret or an internal host that answers",
          source="WSTG v4.2 4.11"),
    # -- API Top 10 2023 ------------------------------------------------
    _item("api-01", "API Top 10", "api",
          "API1: Broken object level authorization",
          "Object ids, slugs, and nested ids are swapped across two identities on "
          "every method.",
          modules=("web-idor-object",), severity="critical",
          evidence="cross-identity read or write",
          source="OWASP API1:2023"),
    _item("api-02", "API Top 10", "api",
          "API2: Broken authentication",
          "Token issuance, refresh, revocation, and password flows are tested for "
          "bypass and takeover.",
          modules=("auth-jwt-alg-none", "auth-mfa-bypass", "auth-password-reset"),
          severity="critical", evidence="a forged or replayed token accepted",
          source="OWASP API2:2023"),
    _item("api-03", "API Top 10", "api",
          "API3: Broken object property level authorization",
          "Responses do not leak fields the caller should not see, and bodies do "
          "not accept fields the caller should not set.",
          modules=("api-mass-assignment",), severity="high",
          evidence="an unexpected field read or written",
          source="OWASP API3:2023"),
    _item("api-04", "API Top 10", "api",
          "API4: Unrestricted resource consumption",
          "Pagination, batch, upload, and SMS/email endpoints are tested for "
          "cost-amplifying input.",
          modules=("api-rate-limit",), severity="medium",
          evidence="a request whose cost scales without a bound",
          source="OWASP API4:2023"),
    _item("api-05", "API Top 10", "api",
          "API5: Broken function level authorization",
          "Administrative and internal operations are replayed with a low role.",
          modules=("api-bfla",), severity="critical",
          evidence="a privileged function performed by a low role",
          source="OWASP API5:2023"),
    _item("api-06", "API Top 10", "api",
          "API6: Unrestricted access to sensitive business flows",
          "Purchase, booking, and comment flows are tested for automation that "
          "harms the business.",
          modules=("server-race",), severity="high",
          evidence="a flow completed far beyond the human rate",
          source="OWASP API6:2023"),
    _item("api-07", "API Top 10", "api",
          "API7: Server-side request forgery",
          "URL and webhook parameters are pointed at an OAST host and then at an "
          "internal service the programme allows.",
          modules=("server-ssrf-metadata",), tools=("interactsh-client",),
          severity="critical", evidence="an OOB hit or internal response",
          source="OWASP API7:2023"),
    _item("api-08", "API Top 10", "api",
          "API8: Security misconfiguration",
          "CORS, headers, debug, default accounts, and verbose errors are checked "
          "on the API origin, not just the web origin.",
          modules=("web-cors",), severity="high",
          evidence="a misconfiguration reachable from the internet",
          source="OWASP API8:2023"),
    _item("api-09", "API Top 10", "api",
          "API9: Improper inventory management",
          "Old versions, staging hosts, and undocumented endpoints are found and "
          "tested for weaker auth.",
          tools=("gau", "waybackurls", "ffuf"), severity="high",
          evidence="an old or staging API that answers with data",
          source="OWASP API9:2023"),
    _item("api-10", "API Top 10", "api",
          "API10: Unsafe consumption of third-party APIs",
          "Data from integrations is treated as untrusted; a hostile third-party "
          "response cannot redirect or execute.",
          tools=("http_request",), severity="high",
          evidence="a redirect or injection accepted from an upstream response",
          source="OWASP API10:2023"),
    _item("api-11", "API Top 10", "api",
          "GraphQL authorization and batching",
          "Introspection, node() lookups, mutation authz, and batched queries are "
          "tested across two identities.",
          modules=("api-graphql-introspection", "api-graphql-idor"),
          severity="critical", tools=("graphql_probe",),
          evidence="another identity's object or a privileged mutation",
          source="OWASP API5:2023 / GraphQL"),
    _item("api-12", "API Top 10", "api",
          "SOAP and WSDL client abuse",
          "WSDL-discovered operations and proxy-style clients are tested for "
          "SSRF, deserialization, and auth bypass.",
          modules=("server-soapwn",), severity="critical",
          evidence="an outbound request or object instantiation controlled by input",
          source="PortSwigger Top 10 2025 #5"),
    # -- LLM Top 10 2025 ------------------------------------------------
    _item("llm-01", "LLM Top 10", "ai",
          "LLM01: Prompt injection",
          "Direct and indirect prompts are tested against every model-backed "
          "feature, including documents and web content it reads.",
          modules=("ai-prompt-injection",), severity="high",
          evidence="the model follows attacker instructions over its own policy",
          source="OWASP LLM01:2025"),
    _item("llm-02", "LLM Top 10", "ai",
          "LLM02: Sensitive information disclosure",
          "The model is asked for other users' data, secrets, and system context "
          "through normal and injected prompts.",
          modules=("ai-prompt-injection",), severity="critical",
          evidence="another user's data or a secret in the output",
          source="OWASP LLM02:2025"),
    _item("llm-03", "LLM Top 10", "ai",
          "LLM03: Supply chain",
          "Model, plugin, and dependency provenance is checked; a compromised "
          "dependency is a lead.",
          tools=("trufflehog", "gitleaks"), severity="high",
          evidence="an unpinned or untrusted model/plugin dependency",
          source="OWASP LLM03:2025"),
    _item("llm-04", "LLM Top 10", "ai",
          "LLM04: Data and model poisoning",
          "Training and RAG ingestion paths are checked for untrusted content that "
          "can steer answers.",
          tools=("http_request",), severity="high",
          evidence="attacker content retained and reused later",
          source="OWASP LLM04:2025"),
    _item("llm-05", "LLM Top 10", "ai",
          "LLM05: Improper output handling",
          "Model output rendered as HTML, SQL, shell, or a URL is traced to a "
          "sink.",
          modules=("ai-prompt-injection",), severity="critical",
          evidence="model output executed or interpreted by a downstream sink",
          source="OWASP LLM05:2025"),
    _item("llm-06", "LLM Top 10", "ai",
          "LLM06: Excessive agency",
          "Tools granted to the model are enumerated and an injected prompt tries "
          "to use them beyond the user's intent.",
          modules=("ai-prompt-injection",), severity="critical",
          evidence="a tool action the user did not request",
          source="OWASP LLM06:2025"),
    _item("llm-07", "LLM Top 10", "ai",
          "LLM07: System prompt leakage",
          "The system prompt and hidden instructions are extracted through "
          "normal and adversarial prompts.",
          modules=("ai-prompt-injection",), severity="medium",
          evidence="the hidden prompt or policy text",
          source="OWASP LLM07:2025"),
    _item("llm-08", "LLM Top 10", "ai",
          "LLM08: Vector and embedding weaknesses",
          "RAG access control is tested: another tenant's document id cannot be "
          "retrieved through the vector store.",
          tools=("http_request",), severity="high",
          evidence="cross-tenant retrieval or embedding inversion",
          source="OWASP LLM08:2025"),
    _item("llm-09", "LLM Top 10", "ai",
          "LLM09: Misinformation",
          "The feature's claims and citations are checked where a wrong answer has "
          "a security or money impact.",
          tools=("http_request",), severity="low",
          evidence="a confidently wrong answer with real impact",
          source="OWASP LLM09:2025"),
    _item("llm-10", "LLM Top 10", "ai",
          "LLM10: Unbounded consumption",
          "Token, tool-call, and upload limits are tested for cost amplification.",
          modules=("api-rate-limit",), severity="medium",
          evidence="a prompt that multiplies cost without a bound",
          source="OWASP LLM10:2025"),
    # -- OWASP Top 10 2025 ----------------------------------------------
    _item("owasp-2025-a03", "OWASP Top 10", "supply-chain",
          "A03:2025 Software supply chain failures",
          "Third-party scripts, packages, CI tokens, and update channels are "
          "enumerated; an unpinned or untrusted dependency is a lead.",
          tools=("trufflehog", "gitleaks", "nuclei"), severity="high",
          evidence="an unpinned, unverified, or leaked dependency path",
          source="OWASP Top 10:2025 A03"),
    _item("owasp-2025-a06", "OWASP Top 10", "design",
          "A06:2025 Insecure design",
          "The business flow is tested for abuse the implementation cannot stop: "
          "automation, replay, trust-boundary confusion, and missing anti-abuse.",
          modules=("server-race", "api-rate-limit"), severity="high",
          evidence="a flow completed in a way the design did not intend",
          source="OWASP Top 10:2025 A06"),
    _item("owasp-2025-a08", "OWASP Top 10", "integrity",
          "A08:2025 Software or data integrity failures",
          "Deserialization, unsigned updates, and client-trusted state are tested "
          "for content the server accepts without verification.",
          modules=("web-deserialization",), severity="critical",
          evidence="server-accepted content that was never verified",
          source="OWASP Top 10:2025 A08"),
    _item("owasp-2025-a09", "OWASP Top 10", "logging",
          "A09:2025 Security logging and alerting failures",
          "Sensitive actions are checked for an audit trail; log injection and "
          "missing alerts on money and auth changes are leads.",
          tools=("http_request",), severity="medium",
          evidence="a sensitive action with no record or a forged log line",
          source="OWASP Top 10:2025 A09"),
    _item("owasp-2025-a10", "OWASP Top 10", "error-handling",
          "A10:2025 Mishandling of exceptional conditions",
          "Malformed and boundary input is tested for an error path that skips "
          "authorization, a limit, or a state check.",
          modules=("web-parser-differential",), severity="high",
          evidence="an error path that reached a protected action",
          source="OWASP Top 10:2025 A10"),
    # -- cloud and infrastructure ---------------------------------------
    _item("cloud-01", "Cloud", "cloud",
          "Test object storage permissions",
          "Public read, public write, list, and ACL escalation are tested on every "
          "bucket the app references.",
          modules=("cloud-s3-public",), severity="critical",
          evidence="anonymous read or write of an object",
          source="Cloud storage baseline"),
    _item("cloud-02", "Cloud", "cloud",
          "Test metadata service reachability",
          "SSRF and proxy paths are checked for IMDSv1/v2 access only where the "
          "programme permits it.",
          modules=("cloud-imds", "server-ssrf-metadata"), severity="critical",
          evidence="metadata JSON with a role and credentials",
          source="Cloud IMDS baseline"),
    _item("cloud-03", "Cloud", "cloud",
          "Test Kubernetes and container APIs",
          "Kubelet, etcd, dashboard, and service-account surfaces are checked for "
          "anonymous access.",
          modules=("cloud-k8s-api",), severity="critical",
          evidence="cluster data or a token from an anonymous request",
          source="Kubernetes baseline"),
    _item("cloud-04", "Cloud", "cloud",
          "Test CI/CD and package exposure",
          "Jenkins, GitLab, Actions, and registry tokens are checked for anonymous "
          "read or write.",
          tools=("trufflehog", "gitleaks", "nuclei"), severity="critical",
          evidence="pipeline access or a token with write scope",
          source="Supply chain baseline"),
    _item("cloud-05", "Cloud", "cloud",
          "Test subdomain takeover candidates",
          "Dangling CNAMEs and unclaimed SaaS names are identified and claimed "
          "only with a harmless marker.",
          tools=("takeover_scan", "subzy", "dnsx"), severity="high",
          evidence="an unclaimed host that serves attacker content",
          source="Taken over baseline"),
    # -- mobile ---------------------------------------------------------
    _item("mobile-01", "MASVS", "mobile",
          "Test APK secrets and endpoints",
          "The APK is decompiled; hardcoded keys, internal hosts, and API routes "
          "are confirmed live.",
          modules=("mobile-apk-secret",), severity="high",
          evidence="a live secret or internal endpoint from the APK",
          source="OWASP MASVS"),
    _item("mobile-02", "MASVS", "mobile",
          "Test certificate pinning and transport",
          "Pinning, cleartext, and trust anchors are checked; bypass only in an "
          "instrumented test build.",
          tools=("nmap",), severity="medium",
          evidence="a cleartext or unpinned connection",
          source="OWASP MASVS"),
    _item("mobile-03", "MASVS", "mobile",
          "Test exported components and deep links",
          "Exported activities, providers, and deep links are exercised with a "
          "benign intent.",
          tools=("http_request",), severity="high",
          evidence="an exported component that performs a privileged action",
          source="OWASP MASVS"),
    # -- modern 2025 research -------------------------------------------
    _item("mod-01", "2025 Research", "modern",
          "Error-based SSTI and polyglot detection",
          "A polyglot probe is used where the engine is unknown; error messages "
          "are read for the engine and the expression.",
          modules=("web-ssti",), severity="critical",
          evidence="an engine-specific error that evaluates the expression",
          source="PortSwigger Top 10 2025 #1"),
    _item("mod-02", "2025 Research", "modern",
          "ORM leaks through search and filters",
          "Search, filter, and ordering parameters are tested for field access and "
          "row leakage beyond the model.",
          modules=("server-orm-leak",), severity="high",
          tools=("orm_leak_probe", "oracle_extract"),
          evidence="a field or row the response should not include",
          source="PortSwigger Top 10 2025 #2"),
    _item("mod-03", "2025 Research", "modern",
          "Blind SSRF via redirect loops",
          "A redirect loop makes a blind SSRF observable through timing and "
          "connection behaviour.",
          modules=("server-ssrf-redirect-loop",), severity="critical",
          evidence="a timing or connection signal tied to the redirect chain",
          source="PortSwigger Top 10 2025 #3"),
    _item("mod-04", "2025 Research", "modern",
          "Unicode normalization bypass",
          "Full-width, combining, and mixed-script variants are tried against "
          "filters and authorization checks.",
          modules=("web-unicode-normalization",), severity="high",
          evidence="a normalized value that passes one layer and changes another",
          source="PortSwigger Top 10 2025 #4"),
    _item("mod-05", "2025 Research", "modern",
          "SOAP and WSDL client abuse",
          "WSDL-discovered operations are tested for SSRF, proxy abuse, and "
          "deserialization.",
          modules=("server-soapwn",), severity="critical",
          evidence="an outbound request or gadget triggered by a SOAP field",
          source="PortSwigger Top 10 2025 #5"),
    _item("mod-06", "2025 Research", "modern",
          "Cross-site ETag and length leaks",
          "ETag and content-length oracles are checked where a cross-origin "
          "attacker could read response size.",
          tools=("http_request",), severity="medium",
          evidence="a stable cross-origin size or ETag oracle",
          source="PortSwigger Top 10 2025 #6"),
    _item("mod-07", "2025 Research", "modern",
          "Next.js and internal cache poisoning",
          "Framework cache keys and internal caches are tested for stale or "
          "poisoned content with a second identity.",
          modules=("server-cache-poison",), severity="high",
          evidence="a second user receiving attacker-influenced content",
          source="PortSwigger Top 10 2025 #7"),
    _item("mod-08", "2025 Research", "modern",
          "HTTP/2 CONNECT abuse",
          "The edge's CONNECT handling is checked for internal port reach and "
          "tunnel establishment.",
          modules=("server-http2-connect",), severity="high",
          evidence="an internal service reached through the edge",
          source="PortSwigger Top 10 2025 #9"),
    _item("mod-09", "2025 Research", "modern",
          "Parser differentials across layers",
          "The same input is shaped to be parsed differently by the edge, the "
          "framework, and the data layer.",
          modules=("web-parser-differential",), severity="high",
          evidence="two layers disagree on the same request",
          source="PortSwigger Top 10 2025 #10"),
    _item("mod-10", "2025 Research", "modern",
          "Open redirect chains to auth flows",
          "Redirect parameters are chained into OAuth and SSO callbacks to steal a "
          "code or a token.",
          modules=("auth-oauth-redirect",), severity="critical",
          evidence="a code or token delivered to an attacker host",
          source="PortSwigger Top 10 2025 #8"),
)


def catalog() -> list[dict]:
    return [dict(item) for item in ITEMS]


def get(item_id: str) -> dict | None:
    for item in ITEMS:
        if item["id"] == item_id:
            return dict(item)
    return None


def by_category() -> dict:
    groups: dict = {}
    for item in ITEMS:
        groups.setdefault(item["category"], []).append(item["id"])
    return groups


def _row_map(index, mission_id: str) -> dict:
    try:
        return {row["item_id"]: row for row in index.list_coverage(mission_id)}
    except Exception:  # noqa: BLE001
        return {}


def summary(index, mission_id: str) -> dict:
    """Coverage for one mission, counting catalog items that have no row as
    untested. A `vulnerable` item still needs the evidence promotion path."""
    rows = _row_map(index, mission_id)
    counts = {status: 0 for status in STATUSES}
    categories: dict = {}
    for item in ITEMS:
        row = rows.get(item["id"]) or {}
        status = str(row.get("status") or "untested")
        if status not in counts:
            status = "untested"
        counts[status] += 1
        bucket = categories.setdefault(item["category"], {
            "total": 0, "covered": 0, "vulnerable": 0, "blocked": 0,
            "in_progress": 0, "untested": 0})
        bucket["total"] += 1
        if status == "covered":
            bucket["covered"] += 1
        elif status == "vulnerable":
            bucket["vulnerable"] += 1
        elif status == "blocked":
            bucket["blocked"] += 1
        elif status == "in_progress":
            bucket["in_progress"] += 1
        else:
            bucket["untested"] += 1
    total = len(ITEMS)
    closed = counts["covered"] + counts["vulnerable"]
    return {
        "mission_id": mission_id, "total": total, "counts": counts,
        "categories": categories,
        "percent": round((closed / total) * 100, 1) if total else 0.0,
        "open": counts["untested"] + counts["in_progress"],
    }


def next_items(index, mission_id: str, limit: int = 5, platform: str = "") -> list[dict]:
    """The next questions to answer: untested first, highest impact first."""
    rows = _row_map(index, mission_id)
    scored = []
    for item in ITEMS:
        row = rows.get(item["id"]) or {}
        status = str(row.get("status") or "untested")
        if status in {"covered", "vulnerable", "blocked"}:
            continue
        if platform and platform not in item["platforms"]:
            continue
        scored.append((
            0 if status == "in_progress" else 1,
            SEVERITY_ORDER.get(item["severity"], 5),
            item["id"],
            item,
        ))
    scored.sort(key=lambda row: (row[0], row[1], row[2]))
    out = []
    for _, _, _, item in scored[:max(1, int(limit))]:
        row = rows.get(item["id"]) or {}
        out.append({**item, "status": str(row.get("status") or "untested"),
                    "evidence": row.get("evidence", "")})
    return out


def _match_modules(module_id: str) -> list[str]:
    return [item["id"] for item in ITEMS if module_id in item.get("modules", [])]


def mark(index, mission_id: str, item_id: str, status: str,
         evidence: str = "", note: str = "", actor: str = "operator") -> dict:
    if status not in STATUSES:
        raise ValueError(f"unknown coverage status: {status}")
    if not get(item_id):
        raise ValueError(f"unknown checklist item: {item_id}")
    return index.upsert_coverage(mission_id, item_id, status,
                                 evidence=evidence, note=note, actor=actor)


def record_hunt_run(index, mission_id: str, counts: dict) -> list:
    """Mark the reconnaissance items a deterministic hunt actually answered."""
    if not mission_id or not isinstance(counts, dict):
        return []
    written = []
    endpoints = int(counts.get("endpoints") or 0)
    pages = int(counts.get("pages") or 0)
    js_files = int(counts.get("js_files") or 0)
    candidates = int(counts.get("candidates") or 0)
    if endpoints:
        written.append(mark(index, mission_id, "wstg-info-02", "covered",
                            evidence=f"{endpoints} endpoint(s) inventoried",
                            actor="agent:hunt"))
    if pages:
        written.append(mark(index, mission_id, "wstg-info-03", "covered",
                            evidence=f"{pages} page(s) fingerprinted",
                            actor="agent:hunt"))
    if js_files:
        written.append(mark(index, mission_id, "wstg-cli-04", "covered",
                            evidence=f"{js_files} JavaScript file(s) read",
                            actor="agent:hunt"))
    if candidates:
        written.append(mark(index, mission_id, "wstg-cli-04", "in_progress",
                            evidence=f"{candidates} secret candidate(s) need live confirmation",
                            actor="agent:hunt"))
    return written


def record_module_run(index, mission_id: str, module_id: str, result: dict) -> list:
    """Move every item this module answers forward from the real run outcome.
    A candidate is a vulnerable lead; supported steps are in progress; a clean
    run covers the item."""
    item_ids = _match_modules(module_id)
    if not item_ids or not mission_id:
        return []
    candidate = result.get("candidate") or {}
    if candidate:
        status = "vulnerable"
        evidence = f"candidate {candidate.get('id', '')}: {candidate.get('title', '')}"
    elif int(result.get("supports") or 0) > 0:
        status = "in_progress"
        evidence = f"{result.get('supports')} supported step(s) in {module_id}"
    elif int(result.get("blocked") or 0) > 0:
        status = "blocked"
        evidence = f"blocked by {result.get('blocked')} step(s) in {module_id}"
    else:
        refutes = int(result.get("refutes") or 0)
        ran = int(result.get("ran") or 0)
        if refutes > 0:
            status = "covered"
            evidence = f"{refutes} refuted step(s) in {module_id}"
        elif ran > 0:
            # A run whose steps were all inconclusive did not settle the item.
            status = "in_progress"
            evidence = f"{module_id} ran but every verdict was inconclusive"
        else:
            status = "covered"
            evidence = f"{module_id} ran with no supporting observation"
    written = []
    for item_id in item_ids:
        try:
            written.append(mark(index, mission_id, item_id, status,
                                evidence=evidence, actor="agent:exploit"))
        except Exception:  # noqa: BLE001
            continue
    return written
