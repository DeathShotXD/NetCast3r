"""Program and scope brief ingestion.

Every bounty platform publishes a different shape of the same fact: these
assets are in scope, those are not, and these rules apply. HackerOne and
Bugcrowd CSV exports, Intigriti and YesWeHack JSON, and a pasted program
brief all end up here.

The parser is deliberately conservative. It normalises only values it can
recognise as an asset, keeps the target and exclusion lists separate, and
never turns prose into a host. The apply step is conservative too: by default
it may add an exclusion or an asset that the mission already covers, but a
new in-scope asset needs an explicit ``allow_expand`` because that is a change
to the authorisation boundary, not a parsing convenience.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .scope import ScopeManager, parse_rule

MAX_ASSETS = 2000
MAX_TEXT = 2_000_000
PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "yeswehack",
             "immunefi", "other")

_TARGET_KEYS = {
    "identifier", "asset", "asset_identifier", "assetidentifier", "scope",
    "scoped", "url", "uri", "endpoint", "domain", "host", "hostname",
    "website", "application", "target", "targets", "asset_name", "assetname",
    "in_scope", "in_scope_asset", "in_scope_target",
}
_IN_KEYS = {
    "in_scope", "inscope", "eligible", "eligible_for_bounty",
    "eligible_for_submission", "eligibleforsubmission", "included",
    "scope_status", "status", "scope_eligible",
}
_OUT_KEYS = {
    "out_of_scope", "outofscope", "excluded", "exclusion", "exclusions",
    "ineligible", "not_eligible", "noteligible", "out_scope",
}
_TYPE_KEYS = {"asset_type", "assettype", "type", "category", "scope_type",
              "scopetype", "platform"}
_SEVERITY_KEYS = {"max_severity", "maxseverity", "severity", "severity_cap"}
_REWARD_KEYS = {"reward", "bounty", "max_bounty", "maxbounty", "reward_range"}
_NOTE_KEYS = {"instruction", "instructions", "description", "notes", "note",
              "detail", "details"}

_TRUTHY = {"1", "true", "yes", "y", "in", "included", "eligible",
           "in scope", "in-scope", "active", "allowed", "public"}
_FALSY = {"0", "false", "no", "n", "out", "excluded", "ineligible",
          "out of scope", "out-of-scope", "not eligible", "not_eligible",
          "disabled", "private", "denied"}

_IN_HEADING = re.compile(
    r"^(?:in[\s-]?scope|scope|targets?|assets?|eligible(?:\s+assets?)?|"
    r"domains?|urls?|applications?)\b", re.I)
_OUT_HEADING = re.compile(
    r"^(?:out[\s-]?of[\s-]?scope|out[\s-]?scope|excluded|exclusions?|"
    r"not\s+eligible|ineligible)\b", re.I)
_RULES_HEADING = re.compile(
    r"^(?:rules?(?:\s+of\s+engagement)?|program\s+rules?|constraints?|"
    r"limitations?|testing\s+rules?|notes?)\b", re.I)
_URL_RE = re.compile(r"https?://[^\s<>\"'`)\]}]+", re.I)
_CIDR_RE = re.compile(
    r"(?<![\w.:/-])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w/])")
_DOMAIN_RE = re.compile(
    r"(?<![\w@./:-])(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?::\d{1,5})?(?:/[^\s<>\"'`)\]}]*)?", re.I)
_BULLET_RE = re.compile(r"^\s*(?:[-*+>]+|\d+[.)])\s*")


class ProgramBriefError(ValueError):
    """The brief could not be parsed into any usable scope entry."""


@dataclass
class ProgramBrief:
    platform: str = "other"
    handle: str = ""
    name: str = ""
    url: str = ""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    assets: list[dict] = field(default_factory=list)
    source: str = "text"
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "platform": self.platform,
            "handle": self.handle,
            "name": self.name,
            "url": self.url,
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "rules": self.rules,
            "assets": self.assets,
            "source": self.source,
            "warnings": self.warnings,
            "counts": {"in_scope": len(self.in_scope),
                       "out_of_scope": len(self.out_of_scope),
                       "rules": len(self.rules)},
        }


def _norm_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _text(value) -> str:
    return str(value or "").strip()


def _truth(value: str) -> bool | None:
    text = _text(value).lower()
    if not text:
        return None
    if text in _TRUTHY:
        return True
    if text in _FALSY:
        return False
    return None


def _strip_noise(value: str) -> str:
    text = _text(value)
    text = text.replace("\u200b", "").replace("\ufeff", "")
    text = re.sub(r"^[`'\"<(\[]+", "", text)
    text = re.sub(r"[`'\"<>)\]}]+$", "", text)
    text = text.strip().rstrip(".,;:")
    return text


def clean_asset(value: str) -> str:
    """Return one canonical scope entry, or an empty string.

    This is the gate between a brief and an authorisation boundary. A value
    that is not a host, URL, wildcard domain, IP, or CIDR is not an asset,
    even if a spreadsheet called it one.
    """
    text = _strip_noise(value)
    if not text or text.startswith("#") or len(text) > 2048:
        return ""
    if text.startswith("re:"):
        return ""  # regex rules are powerful; require a hand-written rule
    if text.startswith("!"):
        text = text[1:].strip()
    urlish = text.startswith(("http://", "https://"))
    if urlish:
        try:
            parts = urlsplit(text)
        except ValueError:
            return ""
        host = (parts.hostname or "").strip().lower().rstrip(".")
        if not host or not _valid_host(host):
            return ""
        path = parts.path or "/"
        query = f"?{parts.query}" if parts.query else ""
        netloc = host
        if parts.port:
            netloc = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
            return str(network)
        except ValueError:
            host, _, path = text.partition("/")
            host = host.strip().lower().rstrip(".")
            if not _valid_host(host):
                return ""
            return f"{host}/{path.lstrip('/')}"
    if text.startswith("*."):
        tail = text[2:].strip().lower().rstrip(".")
        return f"*.{tail}" if _valid_host(tail) else ""
    host = text.lower().rstrip(".")
    if not _valid_host(host):
        return ""
    return host


def _valid_host(host: str) -> bool:
    host = host.strip().rstrip(".")
    if not host or len(host) > 253 or any(ch.isspace() for ch in host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label, flags=re.I):
            return False
    return bool(re.fullmatch(r"[a-z]{2,63}", labels[-1], flags=re.I))


def _canonical_key(asset: str) -> tuple:
    rule = parse_rule(asset)
    if rule is None:
        return ("raw", asset.lower())
    return (rule.kind, rule.value.lower(), rule.path,
            str(rule.net) if rule.net is not None else "")


def _add(assets: list[str], seen: set, value: str) -> bool:
    asset = clean_asset(value)
    if not asset:
        return False
    key = _canonical_key(asset)
    if key in seen:
        return False
    seen.add(key)
    assets.append(asset)
    return True


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set = set()
    for value in values:
        _add(out, seen, value)
    return out


def _detect_platform(text: str, filename: str, explicit: str = "") -> str:
    wanted = _text(explicit).lower()
    if wanted in PLATFORMS:
        return wanted
    haystack = f"{filename}\n{text[:5000]}".lower()
    for name in ("hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi"):
        if name in haystack:
            return name
    return "other"


def _header_map(row: list[str]) -> dict:
    mapping: dict[str, int] = {}
    for index, cell in enumerate(row):
        key = _norm_key(cell)
        if not key:
            continue
        if key in _TARGET_KEYS and "target" not in mapping:
            mapping["target"] = index
        if key in _OUT_KEYS and "out" not in mapping:
            mapping["out"] = index
        elif key in _IN_KEYS and "in" not in mapping:
            mapping["in"] = index
        if key in _TYPE_KEYS and "type" not in mapping:
            mapping["type"] = index
        if key in _SEVERITY_KEYS and "severity" not in mapping:
            mapping["severity"] = index
        if key in _REWARD_KEYS and "reward" not in mapping:
            mapping["reward"] = index
        if key in _NOTE_KEYS and "note" not in mapping:
            mapping["note"] = index
    return mapping


def _cell(row: list[str], mapping: dict, key: str) -> str:
    index = mapping.get(key)
    if index is None or index >= len(row):
        return ""
    return _text(row[index])


def _row_asset(row: list[str], mapping: dict) -> tuple[str, bool, dict] | None:
    target = _cell(row, mapping, "target")
    excluded = False
    out_value = _cell(row, mapping, "out")
    if out_value:
        state = _truth(out_value)
        if state is False or state is None:
            excluded = True
        if not target and clean_asset(out_value):
            target = out_value
    in_value = _cell(row, mapping, "in")
    if in_value:
        state = _truth(in_value)
        if state is False:
            excluded = True
    if not target:
        return None
    if target.startswith("!"):
        excluded = True
        target = target[1:].strip()
    asset = clean_asset(target)
    if not asset:
        return None
    meta = {
        "target": asset,
        "excluded": excluded,
        "type": _cell(row, mapping, "type"),
        "severity": _cell(row, mapping, "severity"),
        "reward": _cell(row, mapping, "reward"),
        "note": _cell(row, mapping, "note")[:500],
    }
    return asset, excluded, meta


def _parse_csv(text: str, brief: ProgramBrief) -> None:
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    try:
        rows = list(csv.reader(io.StringIO(text), dialect))
    except csv.Error as exc:
        raise ProgramBriefError(f"invalid CSV: {exc}") from exc
    if not rows:
        return
    header_at = -1
    mapping: dict = {}
    for index, row in enumerate(rows[:12]):
        candidate = _header_map(row)
        if "target" in candidate:
            header_at, mapping = index, candidate
            break
    if header_at < 0:
        # A headerless export is still usable when the first column is a host.
        mapping = {"target": 0}
        header_at = -1
    seen_in: set = set()
    seen_out: set = set()
    for row in rows[header_at + 1:]:
        if not row or not any(_text(cell) for cell in row):
            continue
        parsed = _row_asset(row, mapping)
        if not parsed:
            continue
        asset, excluded, meta = parsed
        target = seen_out if excluded else seen_in
        if _add(brief.out_of_scope if excluded else brief.in_scope,
                target, asset):
            brief.assets.append(meta)
    if header_at < 0:
        # The first row was data, not a header; it must not be lost.
        for row in rows[:1]:
            parsed = _row_asset(row, mapping)
            if parsed:
                asset, excluded, meta = parsed
                if _add(brief.out_of_scope if excluded else brief.in_scope,
                        seen_out if excluded else seen_in, asset):
                    brief.assets.append(meta)


def _json_walk(data, brief: ProgramBrief, in_seen: set, out_seen: set,
               depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(data, list):
        for item in data[:MAX_ASSETS]:
            _json_walk(item, brief, in_seen, out_seen, depth + 1)
        return
    if isinstance(data, str):
        _add(brief.in_scope, in_seen, data)
        return
    if not isinstance(data, dict):
        return
    target = ""
    for key in _TARGET_KEYS:
        if key in data and isinstance(data[key], str):
            candidate = clean_asset(data[key])
            if candidate:
                target = candidate
                break
    excluded = False
    for key in _OUT_KEYS:
        if key in data and data[key]:
            value = data[key]
            if isinstance(value, str) and clean_asset(value):
                _add(brief.out_of_scope, out_seen, value)
            excluded = True
    for key in _IN_KEYS:
        if key in data:
            state = _truth(str(data[key]))
            if state is False:
                excluded = True
            elif state is True and not target:
                pass
    if target:
        if _add(brief.out_of_scope if excluded else brief.in_scope,
                out_seen if excluded else in_seen, target):
            brief.assets.append({
                "target": target, "excluded": excluded,
                "type": _text(data.get("asset_type") or data.get("type")),
                "severity": _text(data.get("max_severity") or data.get("severity")),
                "reward": _text(data.get("reward") or data.get("bounty")),
                "note": _text(data.get("instruction") or data.get("description"))[:500],
            })
        return
    for key in ("in_scope", "inScope", "scope", "assets", "targets",
                "data", "results", "items", "program"):
        if key in data:
            _json_walk(data[key], brief, in_seen, out_seen, depth + 1)
    for key in ("out_of_scope", "outOfScope", "excluded", "exclusions"):
        if key in data:
            value = data[key]
            if isinstance(value, str):
                _add(brief.out_of_scope, out_seen, value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        _add(brief.out_of_scope, out_seen, item)
                    elif isinstance(item, dict):
                        text = _text(item.get("identifier") or item.get("target")
                                     or item.get("url") or item.get("asset"))
                        _add(brief.out_of_scope, out_seen, text)


def _extract_candidates(text: str) -> list[str]:
    found: list[str] = []
    seen: set = set()
    for match in _CIDR_RE.findall(text):
        _add(found, seen, match)
    for match in _URL_RE.findall(text):
        _add(found, seen, match)
    # URLs are masked first so a host inside a URL is not counted twice.
    masked = _URL_RE.sub(" ", text)
    for match in _DOMAIN_RE.findall(masked):
        _add(found, seen, match)
    return found


def _parse_text(text: str, brief: ProgramBrief) -> None:
    section = ""
    in_seen: set = set()
    out_seen: set = set()
    pending: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        heading = re.sub(r"^[#>*\-\s]+", "", line).strip().rstrip(":").strip()
        lower = heading.lower()
        if len(heading) <= 80:
            if _OUT_HEADING.match(lower):
                section = "out"
                pending = []
                continue
            if _IN_HEADING.match(lower):
                section = "in"
                pending = []
                continue
            if _RULES_HEADING.match(lower):
                section = "rules"
                pending = []
                continue
        if section == "rules":
            note = _BULLET_RE.sub("", line).strip()
            if note and len(brief.rules) < 100:
                brief.rules.append(note[:1000])
            continue
        if section in {"in", "out"}:
            body = _BULLET_RE.sub("", line)
            candidates = _extract_candidates(body)
            if not candidates:
                # A table row can put the asset in the first cell and the
                # status in a later one; parse each cell conservatively.
                for cell in re.split(r"\s*[|,;]\s*", body):
                    candidates.extend(_extract_candidates(cell))
            if candidates:
                target_list = (brief.out_of_scope if section == "out"
                               else brief.in_scope)
                target_seen = out_seen if section == "out" else in_seen
                for asset in candidates:
                    _add(target_list, target_seen, asset)
                continue
            if "|" in body and section in {"in", "out"}:
                pending.append(body)
            continue
    if not brief.in_scope and not brief.out_of_scope:
        # No heading at all: accept explicit URLs, networks, and host-shaped
        # bullet lines, but not every word in the prose.
        for line in text.splitlines():
            body = _BULLET_RE.sub("", line.strip())
            if not body:
                continue
            candidates = _extract_candidates(body)
            if not candidates:
                continue
            looks_explicit = (body.startswith(("http://", "https://", "!", "*."))
                              or len(body.split()) <= 2)
            if looks_explicit:
                for asset in candidates:
                    _add(brief.in_scope, in_seen, asset)


def parse(text: str, filename: str = "", platform: str = "") -> ProgramBrief:
    """Parse a scope export or brief without touching a mission."""
    raw = str(text or "")
    if not raw.strip():
        raise ProgramBriefError("the brief is empty")
    if len(raw) > MAX_TEXT:
        raise ProgramBriefError("the brief is larger than 2 MB")
    brief = ProgramBrief(platform=_detect_platform(raw, filename, platform))
    name = Path(filename).stem if filename else ""
    brief.handle = _detect_handle(raw, name)
    brief.name = name or brief.handle
    suffix = Path(filename).suffix.lower() if filename else ""
    stripped = raw.lstrip()
    is_json = suffix == ".json" or stripped.startswith(("{", "["))
    is_csv = suffix in {".csv", ".tsv"} or (
        not is_json and _looks_csv(raw))
    if is_json:
        try:
            data = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise ProgramBriefError(f"invalid JSON: {exc}") from exc
        brief.source = "json"
        _json_walk(data, brief, set(), set())
        if isinstance(data, dict):
            brief.url = _text(data.get("url") or data.get("program_url"))[:1000]
            brief.handle = _text(data.get("handle") or data.get("slug")
                                 or brief.handle)[:200]
            brief.name = _text(data.get("name") or data.get("title")
                               or brief.name)[:300]
    elif is_csv:
        brief.source = "csv"
        _parse_csv(raw, brief)
    else:
        brief.source = "text"
        _parse_text(raw, brief)
        if len(brief.in_scope) + len(brief.out_of_scope) == 0:
            # Last resort: a pasted URL list without headings.
            seen_in: set = set()
            for asset in _extract_candidates(raw):
                _add(brief.in_scope, seen_in, asset)
    brief.in_scope = _dedupe(brief.in_scope)
    brief.out_of_scope = _dedupe(brief.out_of_scope)
    if brief.out_of_scope:
        out_keys = {_canonical_key(item) for item in brief.out_of_scope}
        brief.in_scope = [item for item in brief.in_scope
                          if _canonical_key(item) not in out_keys]
    if len(brief.in_scope) + len(brief.out_of_scope) > MAX_ASSETS:
        brief.warnings.append(
            f"capped at {MAX_ASSETS} assets; split the brief by program")
        # Exclusions must survive the cap: a scope without them tests excluded
        # hosts. Reserve up to half the budget for them.
        out_cap = min(len(brief.out_of_scope), max(1, MAX_ASSETS // 2))
        in_cap = max(0, MAX_ASSETS - out_cap)
        dropped_in = max(0, len(brief.in_scope) - in_cap)
        dropped_out = max(0, len(brief.out_of_scope) - out_cap)
        brief.in_scope = brief.in_scope[:in_cap]
        brief.out_of_scope = brief.out_of_scope[:out_cap]
        if dropped_in or dropped_out:
            brief.warnings.append(
                f"dropped {dropped_in} in-scope and {dropped_out} exclusion(s) "
                "at the cap")
    if not brief.in_scope and not brief.out_of_scope:
        raise ProgramBriefError(
            "no hosts, URLs, IPs, or networks could be read from the brief")
    return brief


def _looks_csv(text: str) -> bool:
    first = "\n".join(text.splitlines()[:5])
    return any(delim in first for delim in (",", "\t", ";", "|"))


def _detect_handle(text: str, fallback: str) -> str:
    match = re.search(r"(?:hackerone|bugcrowd|intigriti|yeswehack)\.[a-z]+/"
                      r"([A-Za-z0-9_.-]+)", text, flags=re.I)
    if match:
        return match.group(1)[:200]
    return fallback[:200]


def _mission_assets(mission: dict) -> list[str]:
    entries = []
    target = _text(mission.get("target"))
    if target:
        entries.append(target)
    for entry in mission.get("scope") or []:
        text = _text(entry)
        if text:
            entries.append(text)
    return entries


def _covered(asset: str, manager: ScopeManager) -> bool:
    """True when the mission already authorises this asset."""
    candidate = asset
    if asset.startswith("*."):
        candidate = "scope-check." + asset[2:]
    if "/" in asset and not asset.startswith(("http://", "https://")):
        try:
            network = ipaddress.ip_network(asset, strict=False)
            # A network is covered only by a rule for the same network.
            for rule in manager.in_rules:
                if rule.net == network:
                    return True
            return False
        except ValueError:
            pass
    return manager.is_in_scope(candidate)


def preview(index, mission_id: str, brief: str, filename: str = "",
            platform: str = "", allow_expand: bool = False) -> dict:
    """Parse a brief and show exactly what applying it would change."""
    mission = index.get_mission(mission_id)
    if not mission:
        raise ProgramBriefError("mission not found")
    parsed = parse(brief, filename=filename, platform=platform)
    existing = _mission_assets(mission)
    manager = ScopeManager(in_scope=existing)
    existing_keys = {_canonical_key(item.lstrip("!")) for item in existing}
    add_in: list[str] = []
    add_out: list[str] = []
    already: list[str] = []
    expand: list[str] = []
    for asset in parsed.in_scope:
        if _canonical_key(asset) in existing_keys:
            already.append(asset)
        elif _covered(asset, manager):
            add_in.append(asset)
        else:
            expand.append(asset)
    for asset in parsed.out_of_scope:
        key = _canonical_key(asset)
        if ("!" + asset) in existing or key in existing_keys:
            already.append(asset)
        else:
            add_out.append(asset)
    applied_in = add_in + (expand if allow_expand else [])
    applied_out = add_out
    return {
        "mission_id": mission_id,
        "parsed": parsed.as_dict(),
        "diff": {
            "add_in_scope": applied_in,
            "add_exclusions": ["!" + item for item in applied_out],
            "already_present": already,
            "requires_allow_expand": [] if allow_expand else expand,
            "would_expand": bool(expand),
        },
        "allow_expand": bool(allow_expand),
        "scope_before": mission.get("scope") or [],
        "scope_after": (mission.get("scope") or []) + applied_in
                       + ["!" + item for item in applied_out],
    }


def apply(index, mission_id: str, brief: str, filename: str = "",
          platform: str = "", allow_expand: bool = False,
          actor: str = "") -> dict:
    """Apply a parsed brief to a mission's scope.

    Exclusions and already-covered in-scope assets apply without a flag. A
    new in-scope asset is held back unless ``allow_expand`` is explicit.
    Nothing is invented and an empty parse is an error.
    """
    result = preview(index, mission_id, brief, filename=filename,
                     platform=platform, allow_expand=allow_expand)
    diff = result["diff"]
    additions = list(diff["add_in_scope"]) + list(diff["add_exclusions"])
    if additions:
        mission = index.get_mission(mission_id)
        current = list(mission.get("scope") or [])
        seen = {_canonical_key(item.lstrip("!")) for item in current}
        merged = current
        for entry in additions:
            key = _canonical_key(entry.lstrip("!"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(entry)
        index.patch_mission(mission_id, scope=merged)
        parsed = result["parsed"]
        body = (f"Imported {parsed['platform']} scope from "
                f"{filename or parsed['source']}: "
                f"{len(diff['add_in_scope'])} in-scope, "
                f"{len(diff['add_exclusions'])} exclusion(s).")
        if diff["requires_allow_expand"]:
            body += (f" Held back {len(diff['requires_allow_expand'])} "
                     "asset(s) that would expand authorisation.")
        try:
            index.add_agent_note(mission_id, "program.ingest",
                                 "Program scope imported", body,
                                 run_id="")
        except Exception:  # noqa: BLE001 - a note is best effort
            pass
        try:
            index.add_program_import(
                mission_id, result["parsed"], diff,
                filename=filename, actor=actor)
        except Exception:  # noqa: BLE001 - history is best effort
            pass
    updated = index.get_mission(mission_id)
    result["applied"] = {
        "added": len(additions),
        "scope": (updated or {}).get("scope") or [],
        "mission_id": mission_id,
        "actor": actor,
    }
    return result
