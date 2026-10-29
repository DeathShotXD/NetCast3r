"""Local reverse-engineering analyzers.

The control plane already owns the network side of an engagement. This module
covers the other half: taking an artifact the operator legitimately holds (a
source tree, an APK, a Solidity project, a PE/ELF driver) and turning it into
structured, line-addressed observations that an agent can reason about and a
human can verify.

It is deliberately local and read-only. Nothing here contacts a target, runs a
sample, or executes the artifact. ``jadx``/``apktool`` and ``readelf`` are
invoked as parsers when present; every other check is plain text analysis so
the module works on a stock machine.

Results are observations, not findings. A caller records a finding only after
it validates the observation against the live target.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from collections import Counter
from pathlib import Path

KINDS = ("auto", "source", "apk", "contract", "binary")

MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 40_000_000
MAX_FILES = 4000
MAX_RESULTS = 400
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "out",
    "target", "bin", "obj", ".venv", "venv", "__pycache__", ".gradle",
    ".idea", ".next", ".nuxt", "coverage", "Pods",
}
SOURCE_EXTS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
    ".py", ".rb", ".php", ".java", ".kt", ".kts", ".scala", ".go", ".rs",
    ".cs", ".c", ".h", ".cc", ".cpp", ".hpp", ".m", ".mm", ".swift",
    ".sh", ".bash", ".zsh", ".ps1", ".sql", ".graphql", ".gql",
    ".html", ".htm", ".xml", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".conf", ".cfg", ".properties", ".env", ".txt", ".md",
}
TEXT_EXTS = SOURCE_EXTS | {".sol", ".vy", ".move", ".cairo", ".smali"}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# (name, pattern, severity, category, note)
SECRET_PATTERNS: list[tuple[str, re.Pattern, str, str, str]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high", "secret",
     "AWS access key id. Check whether it is live; do not use it beyond the program's rules."),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "medium", "secret",
     "Google API key. Check API restrictions before treating it as sensitive."),
    ("firebase_url", re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"), "medium", "secret",
     "Firebase database URL. Test read/write rules only if the program allows it."),
    ("firebase_app_id", re.compile(r"\b1:[0-9]{6,}:(android|web|ios):[0-9a-f]{8,}\b"), "low", "secret",
     "Firebase app id. Usually public; useful for mapping the backend project."),
    ("stripe_secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), "critical", "secret",
     "Live Stripe secret key. High-impact if valid; stop and report rather than charging."),
    ("stripe_test", re.compile(r"\bsk_test_[0-9a-zA-Z]{20,}\b"), "low", "secret",
     "Stripe test key. Confirm against the program before using it."),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"), "high", "secret",
     "GitHub token. Check scope with the provider's own endpoint, not by pushing."),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "high", "secret",
     "Slack token. Reading workspace data is out of scope unless the program says otherwise."),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"), "high", "secret",
     "npm token. Publishing or modifying packages is out of scope for recon."),
    ("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_\-]{20,}\b"), "high", "secret",
     "PyPI token. Do not publish to the registry."),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "high", "secret",
     "Anthropic API key. Do not spend the owner's quota."),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"), "high", "secret",
     "OpenAI-style key. Confirm validity with a single models call at most."),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"), "high", "secret",
     "SendGrid key. Sending mail is out of scope unless explicitly authorized."),
    ("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "medium", "secret",
     "Twilio API key candidate. Check the account SID context."),
    ("shopify_token", re.compile(r"\bshpat_[a-fA-F0-9]{32}\b"), "high", "secret",
     "Shopify admin token. Never modify store data outside the program."),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
     "high", "secret", "Private key block. Treat the key as compromised and report it."),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
     "medium", "secret", "JWT. Decode the claims only; do not replay it against third parties."),
    ("basic_auth_url", re.compile(r"https?://[^/\s:@]{1,64}:[^/\s:@]{1,64}@[^\s\"']+"),
     "high", "secret", "Credentials embedded in a URL."),
]

GENERIC_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|"
    r"password|passwd|pwd|private[_-]?key|session[_-]?secret)\b"
    r"\s*[:=]\s*[\"']([^\"'\s]{8,120})[\"']"
)

ENDPOINT_RE = re.compile(
    r"(?:(?:https?|wss?)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}"
    r"|(?<![\w.])/(?:api|v\d+|graphql|rest|internal|admin|auth|oauth|service|services|"
    r"mobile|user|users|account|payment|webhook|upload|download)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%{}-]{0,200})"
)
STATIC_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|map|mp4|webm|pdf|zip|gz|"
    r"js|mjs|chunk)(?:[?#].*)?$", re.I)

SINK_RULES: dict[str, list[tuple[str, re.Pattern, str, str]]] = {
    "js": [
        ("dynamic_code", re.compile(r"\b(?:eval|Function)\s*\("), "medium",
         "Dynamic code execution sink; trace whether any argument is attacker-controlled."),
        ("html_sink", re.compile(r"(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML)\b"),
         "medium", "DOM HTML sink; check whether the value is sanitized or trusted."),
        ("child_process", re.compile(r"(?:child_process|execSync|execFileSync|spawnSync)\b"),
         "medium", "Process execution surface; check for command construction from input."),
        ("tls_disabled", re.compile(r"(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED)"),
         "high", "TLS verification disabled in source; check whether it reaches production."),
    ],
    "python": [
        ("pickle", re.compile(r"\bpickle\.loads?\s*\("), "high",
         "Pickle deserialization; a reachable untrusted input is code execution."),
        ("yaml_load", re.compile(r"\byaml\.load\s*\("), "medium",
         "Unsafe YAML load unless Loader=SafeLoader is used."),
        ("subprocess_shell", re.compile(r"subprocess\.(?:run|call|Popen|check_output)\([^)]*shell\s*=\s*True"),
         "high", "Shell execution with a command string; check every interpolation."),
        ("eval_exec", re.compile(r"\b(?:eval|exec)\s*\("), "medium",
         "Dynamic execution sink."),
        ("template_string", re.compile(r"\brender_template_string\s*\("), "high",
         "Server-side template rendering from a string; a common SSTI sink."),
    ],
    "java": [
        ("runtime_exec", re.compile(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\("), "medium",
         "Process execution surface."),
        ("java_deserialization", re.compile(r"ObjectInputStream|readObject\s*\("), "high",
         "Java deserialization; gadget chains are a common RCE path."),
        ("sql_concat", re.compile(r"(?:createStatement|prepareStatement)\s*\([^)]*\+"), "high",
         "SQL built by concatenation; verify parameterization."),
    ],
    "go": [
        ("html_template", re.compile(r"template\.HTML\s*\("), "medium",
         "Unescaped HTML template output."),
        ("exec_command", re.compile(r"exec\.Command\s*\("), "medium",
         "Process execution surface."),
        ("tls_skip", re.compile(r"InsecureSkipVerify\s*:\s*true"), "high",
         "TLS verification disabled."),
    ],
    "php": [
        ("php_unserialize", re.compile(r"\bunserialize\s*\("), "high",
         "PHP object injection sink."),
        ("php_exec", re.compile(r"\b(?:system|shell_exec|passthru|popen|proc_open)\s*\("), "high",
         "Shell execution sink."),
        ("php_eval", re.compile(r"\beval\s*\("), "high", "Dynamic code execution sink."),
    ],
    "ruby": [
        ("ruby_yaml", re.compile(r"\bYAML\.load\s*\("), "high",
         "YAML.load can deserialize objects; prefer safe_load."),
        ("ruby_eval", re.compile(r"\b(?:eval|instance_eval|class_eval)\s*\("), "medium",
         "Dynamic evaluation sink."),
    ],
    "csharp": [
        ("binary_formatter", re.compile(r"\bBinaryFormatter\b"), "high",
         "BinaryFormatter deserialization is unsafe by design."),
        ("process_start", re.compile(r"\bProcess\.Start\s*\("), "medium",
         "Process execution surface."),
    ],
}

LANG_BY_EXT = {
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js",
    ".tsx": "js", ".vue": "js", ".svelte": "js",
    ".py": "python",
    ".java": "java", ".kt": "java", ".kts": "java", ".scala": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
}

CONTRACT_RULES: list[tuple[str, re.Pattern, str, str]] = [
    ("tx_origin", re.compile(r"\btx\.origin\b"), "high",
     "Authorization through tx.origin is phishable; use msg.sender."),
    ("delegatecall", re.compile(r"\.delegatecall\s*\("), "medium",
     "delegatecall executes in the caller's storage; verify the target is trusted and immutable."),
    ("selfdestruct", re.compile(r"\b(?:selfdestruct|suicide)\s*\("), "high",
     "Destructive primitive; check who can reach it."),
    ("low_level_call", re.compile(r"\.call\s*\{[^}]*\}\s*\("), "medium",
     "Low-level call; verify the success flag and reentrancy ordering."),
    ("unchecked_math", re.compile(r"\bunchecked\s*\{"), "medium",
     "Unchecked arithmetic; confirm bounds before the block."),
    ("timestamp_dependence", re.compile(r"\bblock\.timestamp\b"), "low",
     "Timestamp dependence; miners can nudge it within a small window."),
    ("inline_assembly", re.compile(r"\bassembly\s*\{"), "low",
     "Inline assembly; review memory safety and storage slots."),
    ("ecrecover", re.compile(r"\becrecover\s*\("), "medium",
     "ecrecover returns address(0) on failure; check the result."),
    ("floating_pragma", re.compile(r"pragma\s+solidity\s+[^;]*\^"), "low",
     "Floating pragma; pin the compiler for reproducible builds."),
    ("initialize_pattern", re.compile(r"function\s+initialize\s*\("), "medium",
     "Initializer; verify it can run only once and cannot be front-run."),
]

BINARY_DANGER = {
    "IoCreateDevice": ("high", "Creates a kernel device object; a user-mode path to this driver is a kernel surface."),
    "IoCreateSymbolicLink": ("medium", "Exposes a device name to user mode."),
    "MmMapIoSpace": ("high", "Maps physical memory into kernel space."),
    "MmMapLockedPagesSpecifyCache": ("high", "Maps locked pages into user or kernel space."),
    "ZwTerminateProcess": ("high", "Can terminate arbitrary processes from kernel mode."),
    "PsLookupProcessByProcessId": ("medium", "Resolves a process by PID; common in process-kill primitives."),
    "KeStackAttachProcess": ("high", "Attaches to another process address space."),
    "ObRegisterCallbacks": ("medium", "Can strip handle access; a common EDR-evasion primitive."),
    "IRP_MJ_DEVICE_CONTROL": ("medium", "IOCTL dispatch; enumerate the handler and its input validation."),
    "DeviceIoControl": ("low", "User-mode IOCTL caller."),
}

NETWORK_RE = re.compile(r"\b(?:https?|wss?)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _line_at(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _preview(text: str, start: int, end: int, pad: int = 40) -> str:
    left = max(0, start - pad)
    right = min(len(text), end + pad)
    return re.sub(r"\s+", " ", text[left:right]).strip()[:240]


def _finding(observations: list, title: str, severity: str, category: str,
             file: str, line: int, evidence: str, recommendation: str,
             confidence: float = 0.6) -> None:
    if len(observations) >= MAX_RESULTS:
        return
    observations.append({
        "title": title,
        "severity": severity,
        "category": category,
        "file": file,
        "line": line,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": round(confidence, 2),
    })


def _is_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTS:
        return True
    if path.suffix:
        return False
    try:
        with path.open("rb") as handle:
            chunk = handle.read(4096)
        return b"\x00" not in chunk
    except OSError:
        return False


def _iter_files(root: Path, max_files: int = MAX_FILES, max_bytes: int = MAX_TOTAL_BYTES):
    if root.is_file():
        try:
            if root.stat().st_size <= MAX_FILE_BYTES:
                yield root
        except OSError:
            return
        return
    total = 0
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".cache")]
        for name in filenames:
            path = Path(dirpath) / name
            if not _is_text(path):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                continue
            total += size
            seen += 1
            if total > max_bytes or seen > max_files:
                return
            yield path


def _read_text(path: Path) -> str:
    try:
        return path.read_text("utf-8", "ignore")
    except OSError:
        return ""


def _scan_text(text: str, rel: str, observations: list, endpoints: list,
               secrets: list, sinks: bool = True) -> None:
    seen_secret: set[tuple[str, str]] = set()
    for name, pattern, severity, category, note in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            key = (name, value)
            if key in seen_secret:
                continue
            seen_secret.add(key)
            line = _line_at(text, match.start())
            secrets.append({
                "type": name, "file": rel, "line": line,
                "preview": _mask(value), "length": len(value),
            })
            _finding(observations, f"{name.replace('_', ' ')} in source", severity,
                     category, rel, line, _preview(text, match.start(), match.end()),
                     note, 0.85 if severity in {"critical", "high"} else 0.6)

    for match in GENERIC_SECRET.finditer(text):
        name, value = match.group(1).lower(), match.group(2)
        if value.lower() in {"changeme", "password", "secret", "example", "test", "null",
                             "undefined", "true", "false", "none"}:
            continue
        if any(token in value for token in ("${", "{{", "<", ">", "process.env", "os.environ",
                                            "your_", "xxxx", "****", "…")):
            continue
        if len(value) < 12 or _entropy(value) < 3.1:
            continue
        key = ("generic", value)
        if key in seen_secret:
            continue
        seen_secret.add(key)
        line = _line_at(text, match.start())
        secrets.append({
            "type": "generic_credential", "file": rel, "line": line,
            "preview": _mask(value), "length": len(value),
        })
        _finding(observations, f"hardcoded {name} assignment", "medium", "secret",
                 rel, line, _preview(text, match.start(), match.end()),
                 "Remove the value from source; rotate it if it was ever live.", 0.55)

    endpoint_seen: set[str] = set()
    for match in ENDPOINT_RE.finditer(text):
        value = match.group(0).rstrip(".,;)\"'")
        if STATIC_EXT.search(value) or len(value) < 4:
            continue
        if value.startswith("/") and value.count("/") < 2:
            continue
        if value in endpoint_seen:
            continue
        endpoint_seen.add(value)
        if len(endpoints) < MAX_RESULTS:
            endpoints.append({"url": value, "file": rel,
                              "line": _line_at(text, match.start())})

    if not sinks:
        return
    language = LANG_BY_EXT.get(Path(rel).suffix.lower())
    if not language:
        return
    for name, pattern, severity, note in SINK_RULES.get(language, []):
        for match in pattern.finditer(text):
            line = _line_at(text, match.start())
            _finding(observations, f"review {name.replace('_', ' ')}", severity, "sink",
                     rel, line, _preview(text, match.start(), match.end()), note, 0.45)


def analyze_source(path: str, max_files: int = MAX_FILES) -> dict:
    root = Path(path).expanduser()
    if not root.exists():
        raise ValueError(f"path does not exist: {root}")
    observations: list = []
    endpoints: list = []
    secrets: list = []
    files = 0
    languages: Counter = Counter()
    for file in _iter_files(root, max_files=max_files):
        text = _read_text(file)
        if not text:
            continue
        try:
            rel = str(file.relative_to(root)) if root.is_dir() else file.name
        except ValueError:
            rel = file.name
        files += 1
        languages[file.suffix.lower() or "(none)"] += 1
        _scan_text(text, rel, observations, endpoints, secrets)
    return _result("source", str(root.resolve()), observations, endpoints, secrets,
                   {"files": files, "languages": dict(languages.most_common(20))})


def analyze_js(text: str, source: str = "<inline>") -> dict:
    observations: list = []
    endpoints: list = []
    secrets: list = []
    _scan_text(text, source, observations, endpoints, secrets)
    return _result("js", source, observations, endpoints, secrets, {"files": 1})


def analyze_contract(path: str) -> dict:
    root = Path(path).expanduser()
    if not root.exists():
        raise ValueError(f"path does not exist: {root}")
    observations: list = []
    endpoints: list = []
    secrets: list = []
    files = 0
    functions = 0
    for file in _iter_files(root):
        if file.suffix.lower() not in {".sol", ".vy", ".move", ".cairo"}:
            continue
        text = _read_text(file)
        if not text:
            continue
        files += 1
        functions += len(re.findall(r"\bfunction\s+\w+\s*\(", text))
        try:
            rel = str(file.relative_to(root)) if root.is_dir() else file.name
        except ValueError:
            rel = file.name
        for name, pattern, severity, note in CONTRACT_RULES:
            for match in pattern.finditer(text):
                line = _line_at(text, match.start())
                _finding(observations, f"contract: {name.replace('_', ' ')}", severity,
                         "smart-contract", rel, line,
                         _preview(text, match.start(), match.end()), note, 0.7)
        # A privileged name without a modifier on the same or next line is a
        # prompt to review, not proof of a missing check.
        for match in re.finditer(
                r"function\s+(setOwner|withdraw|withdrawAll|mint|burn|upgrade|setAdmin|"
                r"transferOwnership)\s*\([^)]*\)\s*(?:external|public)?[^{;]*\{", text):
            window = text[match.start():match.end() + 160]
            if not re.search(r"onlyOwner|onlyAdmin|onlyRole|requiresAuth|auth\b|initializer",
                             window, re.I):
                _finding(observations, "privileged function without an obvious guard",
                         "medium", "smart-contract", rel, _line_at(text, match.start()),
                         _preview(text, match.start(), match.end()),
                         "Confirm the authorization path; a public privileged function is a takeover.",
                         0.4)
        _scan_text(text, rel, observations, endpoints, secrets, sinks=False)
    return _result("contract", str(root.resolve()), observations, endpoints, secrets,
                   {"files": files, "functions": functions})


def _strings(data: bytes, minimum: int = 6) -> list[str]:
    found: list[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
        value = match.group().decode("ascii", "ignore").strip()
        if value:
            found.append(value)
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum, data):
        value = match.group().decode("utf-16le", "ignore").strip()
        if value:
            found.append(value)
    return found


def _run(command: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                              check=False)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def analyze_binary(path: str) -> dict:
    file = Path(path).expanduser()
    if not file.is_file():
        raise ValueError(f"file does not exist: {file}")
    data = file.read_bytes()
    observations: list = []
    endpoints: list = []
    secrets: list = []
    metadata: dict = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if data.startswith(b"MZ"):
        metadata["format"] = "PE"
    elif data.startswith(b"\x7fELF"):
        metadata["format"] = "ELF"
    elif data.startswith(b"\xcf\xfa\xed\xfe") or data.startswith(b"\xca\xfe\xba\xbe"):
        metadata["format"] = "Mach-O"
    else:
        metadata["format"] = "unknown"

    strings = _strings(data)
    blob = "\n".join(strings)
    _scan_text(blob, file.name, observations, endpoints, secrets, sinks=False)

    for name, (severity, note) in BINARY_DANGER.items():
        if name in blob:
            if len(observations) >= MAX_RESULTS:
                break
            _finding(observations, f"imports {name}", severity, "kernel-surface",
                     file.name, 0, name, note, 0.7)

    ioctls = sorted(set(re.findall(r"\bIOCTL_[A-Z0-9_]{3,}\b", blob)))
    if ioctls:
        metadata["ioctl_names"] = ioctls[:40]
    codes = sorted(set(re.findall(r"\b0x[0-9a-fA-F]{8}\b", blob)))
    if codes:
        metadata["hex_constants"] = codes[:40]

    if metadata["format"] == "ELF":
        if shutil.which("readelf"):
            _, header = _run(["readelf", "-h", str(file)], 30)
            if "DYN" in header:
                metadata["pie"] = True
            _, program = _run(["readelf", "-l", str(file)], 30)
            if re.search(r"GNU_STACK.*RWE", program):
                _finding(observations, "executable stack", "high", "hardening",
                         file.name, 0, "GNU_STACK RWE", "The stack is executable; check for stack-based exploits.", 0.75)
            _, symbols = _run(["readelf", "-s", str(file)], 30)
            metadata["stack_canary"] = "__stack_chk_fail" in symbols
            metadata["fortify"] = "__fortify_fail" in symbols
        if shutil.which("checksec"):
            _, out = _run(["checksec", "--file", str(file)], 30)
            metadata["checksec"] = out.strip()[:1200]

    urls = sorted({match.group(0) for match in NETWORK_RE.finditer(blob)})
    if urls:
        metadata["urls"] = urls[:40]
    ips = sorted({match.group(0) for match in IPV4_RE.finditer(blob)
                  if not match.group(0).startswith(("0.", "255."))})
    if ips:
        metadata["ipv4"] = ips[:40]
    return _result("binary", str(file.resolve()), observations, endpoints, secrets, metadata)


def _attrs(tag: str) -> dict:
    return {name: value for name, value in re.findall(r"([\w:]+)\s*=\s*\"([^\"]*)\"", tag)}


def analyze_apk(path: str, timeout: int = 240, keep: bool = False) -> dict:
    file = Path(path).expanduser()
    if not file.is_file():
        raise ValueError(f"file does not exist: {file}")
    if not zipfile.is_zipfile(file):
        raise ValueError("not an APK/ZIP file")
    if file.stat().st_size > 512 * 1024 * 1024:
        raise ValueError("APK is larger than 512 MB")
    work = Path(tempfile.mkdtemp(prefix="nc3r-apk-"))
    observations: list = []
    endpoints: list = []
    secrets: list = []
    metadata: dict = {"bytes": file.stat().st_size,
                      "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}

    tool = ""
    if shutil.which("jadx"):
        tool = "jadx"
        code, output = _run(["jadx", "-d", str(work / "jadx"), "--no-debug-info",
                             "-j", "2", str(file)], timeout)
        if code != 0:
            metadata["jadx_error"] = output[-600:]
    if not tool or not (work / "jadx").exists():
        if shutil.which("apktool"):
            tool = "apktool"
            code, output = _run(["apktool", "d", "-f", "-o", str(work / "apktool"), str(file)], timeout)
            if code != 0:
                metadata["apktool_error"] = output[-600:]
    if not tool:
        metadata["error"] = "neither jadx nor apktool is installed"
        return _result("apk", str(file.resolve()), observations, endpoints, secrets, metadata)
    metadata["decompiler"] = tool

    base = work / ("jadx" if (work / "jadx").exists() else "apktool")
    manifest_path = None
    for candidate in base.rglob("AndroidManifest.xml"):
        manifest_path = candidate
        break
    manifest = _read_text(manifest_path) if manifest_path else ""
    if manifest:
        metadata["package"] = (_attrs(re.search(r"<manifest\b[^>]*>", manifest).group(0))
                               .get("package", "") if re.search(r"<manifest\b[^>]*>", manifest) else "")
        app_match = re.search(r"<application\b[^>]*>", manifest, re.S)
        app = _attrs(app_match.group(0)) if app_match else {}
        if app.get("android:debuggable") == "true":
            _finding(observations, "application is debuggable", "high", "android",
                     "AndroidManifest.xml", 0, "android:debuggable=\"true\"",
                     "Debuggable builds allow attaching a debugger and dumping app data.", 0.9)
        if app.get("android:allowBackup") != "false":
            _finding(observations, "backup is not disabled", "medium", "android",
                     "AndroidManifest.xml", 0, "android:allowBackup is not false",
                     "ADB backup or cloud backup can expose private app data.", 0.6)
        if app.get("android:usesCleartextTraffic") == "true":
            _finding(observations, "cleartext traffic allowed", "medium", "android",
                     "AndroidManifest.xml", 0, "android:usesCleartextTraffic=\"true\"",
                     "HTTP traffic can be intercepted or modified on a hostile network.", 0.75)
        if app.get("android:networkSecurityConfig"):
            metadata["network_security_config"] = app["android:networkSecurityConfig"]
        permissions = sorted(set(re.findall(r"<uses-permission[^>]*android:name=\"([^\"]+)\"", manifest)))
        metadata["permissions"] = permissions[:60]
        dangerous = [p for p in permissions if any(k in p for k in (
            "READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
            "READ_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW",
            "REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE"))]
        if dangerous:
            _finding(observations, "sensitive Android permissions", "low", "android",
                     "AndroidManifest.xml", 0, ", ".join(dangerous[:6]),
                     "Review whether each permission is necessary and how the data is protected.", 0.5)

        components = 0
        for match in re.finditer(r"<(activity|activity-alias|service|receiver|provider)\b[^>]*>",
                                 manifest, re.S):
            tag = match.group(0)
            attrs = _attrs(tag)
            name = attrs.get("android:name", "")
            if not name:
                continue
            components += 1
            exported = attrs.get("android:exported")
            has_filter = bool(re.search(r"<intent-filter", manifest[match.start():match.start() + 1200]))
            permission = attrs.get("android:permission", "")
            if exported == "true" and not permission:
                severity = "medium" if match.group(1) in {"activity", "activity-alias"} else "high"
                _finding(observations, f"exported {match.group(1)} without permission",
                         severity, "android", "AndroidManifest.xml", 0,
                         name, "Any installed app can invoke this component; validate the input path.",
                         0.8)
            elif exported is None and has_filter and not permission:
                _finding(observations, f"{match.group(1)} with intent-filter (default exported)",
                         "medium", "android", "AndroidManifest.xml", 0, name,
                         "On older targets this component is exported by default.", 0.55)
        metadata["components"] = components

        for scheme, host in re.findall(
                r"<data[^>]*android:scheme=\"([^\"]+)\"[^>]*android:host=\"([^\"]*)\"", manifest):
            metadata.setdefault("deep_links", []).append(f"{scheme}://{host}")
            if scheme.lower() in {"http", "https"}:
                _finding(observations, "web deep link", "low", "android",
                         "AndroidManifest.xml", 0, f"{scheme}://{host}",
                         "Check whether the host is verified and whether parameters reach a sink.", 0.4)

    text_files = 0
    for file_path in _iter_files(base, max_files=6000, max_bytes=60_000_000):
        if file_path.suffix.lower() not in TEXT_EXTS and file_path.suffix.lower() not in {
                ".java", ".kt", ".smali", ".xml", ".json", ".properties"}:
            continue
        text = _read_text(file_path)
        if not text:
            continue
        text_files += 1
        try:
            rel = str(file_path.relative_to(base))
        except ValueError:
            rel = file_path.name
        _scan_text(text, rel, observations, endpoints, secrets)
        for marker, severity, note in (
                ("sha256/", "info", "Certificate pin declared."),
                ("CertificatePinner", "info", "OkHttp certificate pinner."),
                ("setSSLSocketFactory", "low", "Custom TLS trust; inspect the trust manager."),
                ("TrustAllCerts", "high", "A trust-all certificate implementation is present."),
                ("android:usesCleartextTraffic=\"true\"", "medium", "Cleartext policy found in a resource."),
        ):
            if marker in text:
                _finding(observations, marker[:60], severity, "android", rel,
                         _line_at(text, text.find(marker)), marker, note, 0.55)
        if len(observations) >= MAX_RESULTS:
            break

    for so in list(base.rglob("*.so"))[:10]:
        try:
            blob = "\n".join(_strings(so.read_bytes()[:10_000_000]))
        except OSError:
            continue
        for name, (severity, note) in BINARY_DANGER.items():
            if name in blob and len(observations) < MAX_RESULTS:
                _finding(observations, f"native library references {name}", severity,
                         "kernel-surface", str(so.relative_to(base)), 0, name, note, 0.5)
        metadata.setdefault("native_libs", []).append(str(so.relative_to(base)))

    metadata["text_files"] = text_files
    if not keep:
        shutil.rmtree(work, ignore_errors=True)
    else:
        metadata["work_dir"] = str(work)
    return _result("apk", str(file.resolve()), observations, endpoints, secrets, metadata)


def _result(kind: str, path: str, observations: list, endpoints: list,
            secrets: list, metadata: dict) -> dict:
    counts = Counter(item["severity"] for item in observations)
    observations.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9),
                                        item["file"], item["line"]))
    for index, item in enumerate(observations, 1):
        item["id"] = f"rev-{index:04d}"
    return {
        "ok": True,
        "kind": kind,
        "path": path,
        "generated_at": _now(),
        "summary": {
            "observations": len(observations),
            "severity": {name: counts.get(name, 0) for name in SEVERITY_ORDER},
            "endpoints": len(endpoints),
            "secrets": len(secrets),
            **metadata,
        },
        "observations": observations,
        "endpoints": endpoints[:MAX_RESULTS],
        "secrets": secrets[:MAX_RESULTS],
        "note": ("Observations are leads, not verified findings. Confirm each one against the "
                 "live target and the program's rules before recording or reporting it."),
    }


def detect_kind(path: str) -> str:
    file = Path(path).expanduser()
    if file.is_dir():
        if any(file.rglob("*.sol")):
            return "contract"
        return "source"
    suffix = file.suffix.lower()
    if suffix in {".apk", ".xapk", ".apks"}:
        return "apk"
    if suffix in {".sol", ".vy"}:
        return "contract"
    if suffix in {".exe", ".dll", ".sys", ".so", ".elf", ".dylib", ".bin", ".o"}:
        return "binary"
    if suffix in {".js", ".mjs", ".ts"}:
        return "source"
    try:
        with file.open("rb") as handle:
            head = handle.read(4)
        if head.startswith(b"MZ") or head.startswith(b"\x7fELF"):
            return "binary"
        if zipfile.is_zipfile(file):
            return "apk"
    except OSError:
        pass
    return "source"


def analyze(kind: str, path: str, **options) -> dict:
    kind = (kind or "auto").strip().lower()
    if kind == "auto":
        kind = detect_kind(path)
    if kind not in KINDS:
        raise ValueError(f"unknown analysis kind: {kind}")
    if kind == "source":
        return analyze_source(path, max_files=int(options.get("max_files", MAX_FILES)))
    if kind == "contract":
        return analyze_contract(path)
    if kind == "binary":
        return analyze_binary(path)
    if kind == "apk":
        return analyze_apk(path, timeout=int(options.get("timeout", 240)),
                           keep=bool(options.get("keep", False)))
    if kind == "js":
        return analyze_js(str(options.get("text", "")), str(options.get("source", "<inline>")))
    raise ValueError(f"unknown analysis kind: {kind}")


def render_markdown(result: dict, limit: int = 80) -> str:
    """A compact operator-facing summary for a report or a chat reply."""
    summary = result.get("summary", {})
    lines = [f"# {result.get('kind', 'analysis')} — {result.get('path', '')}", ""]
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- observations: {summary.get('observations', 0)}")
    severity = summary.get("severity", {})
    lines.append("- severity: " + ", ".join(f"{name} {value}" for name, value in severity.items()))
    lines.append(f"- endpoints: {summary.get('endpoints', 0)}")
    lines.append(f"- secrets: {summary.get('secrets', 0)}")
    for key in ("files", "components", "permissions", "decompile", "package"):
        if key in summary:
            value = summary[key]
            if isinstance(value, list):
                value = f"{len(value)} items"
            lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Observations")
    lines.append("")
    for item in (result.get("observations") or [])[:limit]:
        location = item.get("file", "")
        if item.get("line"):
            location += f":{item['line']}"
        lines.append(f"### {item.get('severity', '').upper()} — {item.get('title', '')}")
        lines.append("")
        lines.append(f"`{location}`")
        lines.append("")
        lines.append(item.get("evidence", ""))
        lines.append("")
        lines.append(f"*{item.get('recommendation', '')}*")
        lines.append("")
    if len(result.get("observations") or []) > limit:
        lines.append(f"_{len(result['observations']) - limit} more observations omitted._")
    return "\n".join(lines)
