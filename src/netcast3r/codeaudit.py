"""Static source audit: find real defects in a source tree.

This is not a linter and it is not a vulnerability scanner. It is a small,
deterministic rule engine whose rules were each chosen because a match is a
defect with a known consequence: a swallowed exception that hides a failure, a
shell string built from input, SQL assembled by formatting, a TLS check turned
off, a secret committed next to the code that uses it.

Two rules govern the design:

* a match is a defect, not a style opinion, so the report stays worth reading;
* the patterns never match this module's own rule table, because every payload
  character is regex-escaped in the pattern literal.

Absence of findings is not proof of safety. The report says so.
"""

from __future__ import annotations

import re
from pathlib import Path

DEFAULT_EXTENSIONS = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
                      ".svelte", ".go", ".rb", ".php", ".java", ".kt", ".rs")
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
             "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
             ".svelte-kit", "dist", "build", "vendor", "site-packages"}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 4000
MAX_FINDINGS = 1000
SEVERITY_WEIGHT = {"high": 25, "medium": 10, "low": 3, "info": 0}

_EXT_LANG = {
    ".py": "python", ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js",
    ".tsx": "js", ".jsx": "js", ".svelte": "js", ".go": "go", ".rb": "ruby",
    ".php": "php", ".java": "java", ".kt": "java", ".rs": "rust",
}


class Rule:
    __slots__ = ("id", "severity", "langs", "pattern", "message", "fix", "unless")

    def __init__(self, id: str, severity: str, langs: tuple, pattern: str,
                 message: str, fix: str, unless: str = ""):
        self.id = id
        self.severity = severity
        self.langs = langs
        self.pattern = re.compile(pattern)
        self.message = message
        self.fix = fix
        self.unless = unless


# Every pattern escapes the character that follows a keyword, so the rule table
# below cannot match its own source text and produce phantom findings.
_RULES: tuple[Rule, ...] = (
    Rule("py-bare-except", "medium", ("python",),
         r"\bexcept\s*:",
         "bare except catches every exception including KeyboardInterrupt and "
         "SystemExit, and hides the real failure",
         "catch Exception (or a specific type) and log or re-raise"),
    Rule("py-eval-exec", "high", ("python",),
         r"\b(?:eval|exec)\s*\(",
         "eval/exec executes a string as code",
         "replace with an explicit parser or a lookup table"),
    Rule("py-os-system", "high", ("python",),
         r"\bos\.system\s*\(",
         "os.system runs a shell command and is injection prone",
         "use subprocess.run with a list of arguments and shell=False"),
    Rule("py-shell-true", "high", ("python",),
         r"shell\s*=\s*True\b",
         "enabling shell execution makes the command line injectable from any "
         "interpolated value",
         "pass arguments as a list and keep shell disabled"),
    Rule("py-sql-fstring", "high", ("python",),
         r"\b(?:execute|executemany)\s*\(\s*f[\"']",
         "SQL built with an f-string interpolates into the statement; a value "
         "changes the query and an identifier must come from an allowlist",
         "use bound parameters: execute(sql, params)"),
    Rule("py-sql-percent", "high", ("python",),
         r"\b(?:execute|executemany)\s*\(\s*[\"'][^\"']*[\"']\s*%",
         "SQL built with %-formatting interpolates values into the statement",
         "use bound parameters: execute(sql, params)"),
    Rule("py-sql-concat", "high", ("python",),
         r"\b(?:execute|executemany)\s*\(\s*[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^\"']*[\"']\s*\+",
         "SQL built by string concatenation lets a value change the statement",
         "use bound parameters: execute(sql, params)"),
    Rule("py-tempfile-mktemp", "medium", ("python",),
         r"\btempfile\.mktemp\s*\(",
         "tempfile.mktemp is racy and unsafe",
         "use tempfile.mkstemp or NamedTemporaryFile"),
    Rule("py-yaml-unsafe", "medium", ("python",),
         r"\byaml\.load\s*\(",
         "yaml.load can construct arbitrary Python objects unless SafeLoader is set",
         "use yaml.safe_load or pass Loader=SafeLoader"),
    Rule("py-pickle", "medium", ("python",),
         r"\bpickle\.loads?\s*\(",
         "pickle deserialises arbitrary objects and is unsafe on untrusted bytes",
         "use json or another schema-checked format for untrusted data"),
    Rule("py-verify-false", "medium", ("python",),
         r"verify\s*=\s*False\b",
         "TLS certificate verification is disabled",
         "do not disable verification; trust the CA or pin a known certificate"),
    Rule("py-weak-hash", "low", ("python",),
         r"\b(?:md5|sha1)\s*\(",
         "MD5/SHA1 is broken for signatures, integrity, and password hashing",
         "use sha256 or better, and a password KDF for passwords"),
    Rule("py-random-secret", "medium", ("python",),
         r"\b(?:token|secret|password|passwd|nonce|otp|api_key|apikey|session)"
         r"\w*\s*=\s*random\.",
         "random is not cryptographically secure; a predictable token is a takeover",
         "use secrets.token_urlsafe / secrets.token_hex"),
    Rule("py-mutable-default", "low", ("python",),
         r"def\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\})\s*[,)]",
         "a mutable default argument is shared across every call",
         "default to None and create the container inside the function"),
    Rule("py-private-key", "high", ("python", "go", "ruby", "php", "java", "rust"),
         r"-{5}BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-{5}",
         "a private key is committed in the source tree",
         "remove the key from history and load it from a secret store"),
    Rule("py-subprocess-timeout", "low", ("python",),
         r"\bsubprocess\.(?:run|call|check_output|check_call)\s*\(",
         "a subprocess call without a timeout can hang a worker forever",
         "pass timeout=<seconds> and handle TimeoutExpired",
         unless="timeout"),
    Rule("js-inner-html", "medium", ("js",),
         r"\.innerHTML\s*=",
         "writing innerHTML interprets markup and enables XSS",
         "use textContent, or sanitize with a well-tested library"),
    Rule("js-document-write", "medium", ("js",),
         r"\bdocument\.write\s*\(",
         "document.write interprets markup and enables XSS",
         "build DOM nodes instead"),
    Rule("js-eval", "high", ("js",),
         r"\beval\s*\(",
         "eval executes a string as code",
         "replace with an explicit parser or a lookup table"),
    Rule("js-function-constructor", "medium", ("js",),
         r"\bnew\s+Function\s*\(",
         "the Function constructor executes a string as code",
         "replace with real functions or a lookup table"),
    Rule("js-dangerous-html", "medium", ("js",),
         r"dangerously\w*SetInnerHTML",
         "React's raw-HTML prop interprets markup and enables XSS",
         "render text, or sanitize with a well-tested library"),
    Rule("svelte-html", "medium", ("js",),
         r"\{@html\b",
         "Svelte's raw-HTML block injects unescaped markup and enables XSS",
         "interpolate as text, or sanitize before marking it safe"),
)

_SECRET_VALUE = re.compile(
    r"(?i)\b(?:password|passwd|secret|api_key|apikey|token|private_key|"
    r"client_secret|access_key)\b\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']")
_SECRET_PLACEHOLDER = ("example", "placeholder", "changeme", "xxx", "test",
                       "dummy", "your-", "your_", "<", "{", "}", "redacted",
                       "none", "null", "sample", "fake", "seed", "localhost")
_SUPPRESS = re.compile(
    r"codeaudit:\s*ignore(-file)?\b[ \t]*([A-Za-z0-9_,\-]*)")
_BROAD_HANDLER = re.compile(
    r"^\s*except\s*(?::|\(?\s*(?:Exception|BaseException)\b)")


def _suppression(text: str, rule_id: str) -> str | None:
    """Return a reason when the line suppresses this rule, else None."""
    match = _SUPPRESS.search(text)
    if not match:
        return None
    listed = [name.strip() for name in (match.group(2) or "").split(",") if name.strip()]
    if listed and rule_id not in listed:
        return None
    return text[match.end():].strip(" -:,") or "suppressed"


def _lang(path: Path) -> str:
    return _EXT_LANG.get(path.suffix.lower(), "")


def _is_secret(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in _SECRET_PLACEHOLDER):
        return False
    if value.startswith(("os.", "self.", "ctx.", "args.", "config.")):
        return False
    has_alpha = any(ch.isalpha() for ch in value)
    has_digit = any(ch.isdigit() for ch in value)
    has_symbol = any(ch in "_-+/=." for ch in value)
    return has_alpha and (has_digit or has_symbol)


def audit_text(text: str, lang: str, rel: str) -> tuple[list[dict], list[dict]]:
    """Apply every rule for one language to one file's text.

    Returns (findings, suppressed). A line or file may carry
    ``codeaudit: ignore[ rules] -- reason`` to record a reviewed exception; it
    is counted separately, never hidden.
    """
    findings: list[dict] = []
    suppressed: list[dict] = []
    lines = text.splitlines()
    file_ignore: set[str] = set()
    ignore_all_file = False
    for line in lines:
        match = _SUPPRESS.search(line)
        if match and match.group(1) == "-file":
            names = [n.strip() for n in (match.group(2) or "").split(",") if n.strip()]
            if names:
                file_ignore.update(names)
            else:
                ignore_all_file = True

    def record(rule_id: str, severity: str, index: int, source: str,
               message: str = "", fix: str = "", rule: Rule | None = None) -> None:
        reason = _suppression(source, rule_id)
        if reason is None and (ignore_all_file or rule_id in file_ignore):
            reason = "suppressed for the file"
        if reason is None:
            base = rule if rule is not None else Rule(
                rule_id, severity, (lang,), r"", message, fix)
            findings.append(_finding(base, rel, index, source,
                                     message=message, fix=fix))
        else:
            suppressed.append({"rule": rule_id, "severity": severity,
                               "file": rel, "line": index, "reason": reason,
                               "snippet": source.strip()[:200]})

    for index, line in enumerate(lines, start=1):
        window = " ".join(lines[index - 1:index + 2])
        for rule in _RULES:
            if lang and lang not in rule.langs:
                continue
            if rule.unless and rule.unless in window:
                continue
            if not rule.pattern.search(line):
                continue
            record(rule.id, rule.severity, index, line, rule=rule)
        if lang == "python" and re.match(r"^\s*except\b.*:\s*$", line):
            broad = bool(_BROAD_HANDLER.match(line))
            for follow in lines[index:index + 3]:
                if not follow.strip() or follow.strip().startswith("#"):
                    continue
                if follow.strip() == "pass":
                    explained = "#" in line or "#" in follow
                    if not explained:
                        record("py-swallowed-exception",
                               "medium" if broad else "info", index, line,
                               message=("the exception is silently discarded with "
                                        "pass and no comment, so the failure never "
                                        "surfaces"),
                               fix="log the exception or re-raise it",
                               rule=Rule("py-swallowed-exception",
                                         "medium" if broad else "info",
                                         ("python",), r"", "", ""))
                break
        if lang == "python":
            secret = _SECRET_VALUE.search(line)
            if secret and _is_secret(secret.group(1)):
                record("py-hardcoded-secret", "low", index, line,
                       message="a literal value is assigned to a secret-like name",
                       fix=("move it to the environment or the key store; if it is "
                            "a test fixture, rename the variable"),
                       rule=Rule("py-hardcoded-secret", "low", ("python",),
                                 r"", "", ""))
    return findings, suppressed


def _finding(rule: Rule, rel: str, line: int, text: str,
             message: str = "", fix: str = "") -> dict:
    return {
        "rule": rule.id,
        "severity": rule.severity,
        "file": rel,
        "line": line,
        "message": message or rule.message,
        "fix": fix or rule.fix,
        "snippet": text.strip()[:200],
    }


def _iter_files(root: Path, extensions: set[str], ignore_dirs: set[str],
                max_files: int):
    count = 0
    for path in sorted(root.rglob("*")):
        if count >= max_files:
            return
        if not path.is_file():
            continue
        if path.suffix.lower() not in extensions:
            continue
        if any(part in ignore_dirs for part in path.relative_to(root).parts[:-1]):
            continue
        yield path
        count += 1


def scan(root: str | Path, extensions=None, max_files: int = MAX_FILES,
         max_bytes: int = MAX_FILE_BYTES, ignore_dirs=None) -> dict:
    root = Path(root).expanduser()
    if not root.exists():
        raise ValueError(f"path does not exist: {root}")
    exts = set(extensions or DEFAULT_EXTENSIONS)
    ignored = set(ignore_dirs or ()) | SKIP_DIRS

    findings: list[dict] = []
    suppressed: list[dict] = []
    files_scanned = 0
    bytes_scanned = 0
    skipped_large = 0
    if root.is_file():
        files = [root]
        base = root.parent
    else:
        files = list(_iter_files(root, exts, ignored, max(1, int(max_files))))
        base = root

    for path in files:
        try:
            if path.stat().st_size > max_bytes:
                skipped_large += 1
                continue
            text = path.read_text("utf-8", errors="replace")
        except OSError:
            continue
        files_scanned += 1
        bytes_scanned += len(text)
        rel = str(path.relative_to(base)) if root.is_dir() else path.name
        file_findings, file_suppressed = audit_text(text, _lang(path), rel)
        findings.extend(file_findings)
        suppressed.extend(file_suppressed)

    findings.sort(key=lambda item: (SEVERITY_WEIGHT.get(item["severity"], 0),
                                    item["file"], item["line"]), reverse=True)
    by_severity: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_rule[finding["rule"]] = by_rule.get(finding["rule"], 0) + 1

    score = 100
    for severity, weight in SEVERITY_WEIGHT.items():
        score -= by_severity.get(severity, 0) * weight
    score = max(0, score)
    return {
        "root": str(root),
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "skipped_large": skipped_large,
        "findings": findings[:MAX_FINDINGS],
        "total_findings": len(findings),
        "truncated": len(findings) > MAX_FINDINGS,
        "suppressed": suppressed[:MAX_FINDINGS],
        "total_suppressed": len(suppressed),
        "by_severity": by_severity,
        "by_rule": by_rule,
        "score": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else
                 "C" if score >= 55 else "D" if score >= 35 else "F",
        "note": ("Static pattern matches only. A finding is a real defect in the "
                 "shape it names; the fix column says what to change. A "
                 "codeaudit: ignore comment records a reviewed exception and is "
                 "listed under suppressed. No findings does not prove the code is "
                 "safe, and this does not replace a review of the logic."),
    }


def rules() -> list[dict]:
    """The rule table, so the catalogue is discoverable without reading code."""
    return [{"id": rule.id, "severity": rule.severity,
             "languages": list(rule.langs), "message": rule.message,
             "fix": rule.fix} for rule in _RULES]
