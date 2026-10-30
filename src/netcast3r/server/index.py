"""SQLite index over runs, findings, events, providers, and settings.

The files a run writes stay authoritative. This index makes them searchable,
pageable, and diffable, and it remembers triage so a re-scan does not lose it.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    target TEXT,
    status TEXT,
    created_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    parent_run_id TEXT,
    results_dir TEXT,
    options_json TEXT,
    counts_json TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status, created_at DESC);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    seq INTEGER,
    ts REAL,
    type TEXT,
    level TEXT,
    stage TEXT,
    agent TEXT,
    payload_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, seq);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT,
    fingerprint TEXT,
    severity TEXT,
    title TEXT,
    secret_type TEXT,
    status TEXT,
    value TEXT,
    impact TEXT,
    evidence TEXT,
    source TEXT,
    confidence REAL,
    created_at TEXT,
    triage_status TEXT DEFAULT 'new',
    severity_override TEXT,
    tags_json TEXT,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_find_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_find_status ON findings(triage_status, severity);
CREATE INDEX IF NOT EXISTS idx_find_fp ON findings(fingerprint);

CREATE TABLE IF NOT EXISTS finding_artifacts (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    name TEXT,
    path TEXT,
    sha256 TEXT,
    bytes INTEGER,
    content_type TEXT,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifact_finding ON finding_artifacts(finding_id, created_at);

CREATE TABLE IF NOT EXISTS lessons (
    id TEXT PRIMARY KEY,
    mission_id TEXT,
    run_id TEXT,
    task_id TEXT,
    title TEXT,
    technique TEXT,
    context TEXT,
    outcome TEXT DEFAULT 'success',
    lesson TEXT,
    next_step TEXT,
    tags_json TEXT DEFAULT '[]',
    source TEXT DEFAULT '',
    confidence REAL DEFAULT 0.5,
    created_at TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_lessons_created ON lessons(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_lessons_mission ON lessons(mission_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_lessons_outcome ON lessons(outcome, created_at DESC);

CREATE TABLE IF NOT EXISTS skills (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE,
    title TEXT,
    description TEXT,
    body TEXT,
    tags_json TEXT DEFAULT '[]',
    source TEXT DEFAULT '',
    version INTEGER DEFAULT 1,
    created_at TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_skills_updated ON skills(updated_at DESC);

CREATE TABLE IF NOT EXISTS expertise (
    tech TEXT PRIMARY KEY,
    exposures INTEGER DEFAULT 0,
    successes INTEGER DEFAULT 0,
    failures INTEGER DEFAULT 0,
    last_seen TEXT,
    notes TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_expertise_seen ON expertise(last_seen DESC);

CREATE TABLE IF NOT EXISTS providers (
    id TEXT PRIMARY KEY,
    name TEXT,
    kind TEXT,
    base_url TEXT,
    model TEXT,
    key_name TEXT,
    healthy INTEGER DEFAULT 0,
    last_checked TEXT,
    meta_json TEXT,
    models_json TEXT DEFAULT '[]',
    priority INTEGER DEFAULT 100,
    enabled INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_json TEXT,
    is_secret INTEGER DEFAULT 0,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY,
    title TEXT,
    target TEXT,
    objective TEXT,
    status TEXT DEFAULT 'draft',
    autonomy TEXT DEFAULT 'supervised',
    budget_json TEXT DEFAULT '{}',
    scope_json TEXT DEFAULT '[]',
    plan_json TEXT DEFAULT '[]',
    created_at TEXT,
    updated_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    last_run_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_missions_status ON missions(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS mission_runs (
    mission_id TEXT,
    run_id TEXT,
    added_at TEXT,
    PRIMARY KEY (mission_id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_mission_runs_run ON mission_runs(run_id);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    mission_id TEXT,
    run_id TEXT,
    action TEXT,
    risk TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'pending',
    requested_by TEXT,
    decided_by TEXT,
    reason TEXT,
    payload_json TEXT DEFAULT '{}',
    nonce TEXT,
    created_at TEXT,
    decided_at TEXT,
    used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_mission ON approvals(mission_id, created_at DESC);

CREATE TABLE IF NOT EXISTS tool_calls (
    id TEXT PRIMARY KEY,
    tool TEXT,
    risk TEXT DEFAULT 'low',
    status TEXT DEFAULT 'ok',
    actor TEXT,
    mission_id TEXT,
    run_id TEXT,
    approval_id TEXT,
    args_json TEXT DEFAULT '{}',
    result_json TEXT DEFAULT '{}',
    error TEXT,
    duration_ms INTEGER DEFAULT 0,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_calls_created ON tool_calls(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tool_calls_tool ON tool_calls(tool, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tool_calls_mission ON tool_calls(mission_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tool_calls_status ON tool_calls(status, created_at DESC);

CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    mission_id TEXT,
    finding_id TEXT,
    run_id TEXT,
    platform TEXT,
    program TEXT,
    target TEXT,
    title TEXT,
    severity TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'draft',
    bounty_cents INTEGER DEFAULT 0,
    currency TEXT DEFAULT 'USD',
    external_id TEXT,
    url TEXT,
    report_path TEXT,
    notes TEXT,
    submitted_at TEXT,
    decided_at TEXT,
    paid_at TEXT,
    created_at TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_submissions_mission ON submissions(mission_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_submissions_finding ON submissions(finding_id);

CREATE TABLE IF NOT EXISTS agent_state (
    mission_id TEXT PRIMARY KEY,
    status TEXT DEFAULT 'idle',
    phase TEXT DEFAULT '',
    budget_json TEXT DEFAULT '{}',
    options_json TEXT DEFAULT '{}',
    summary TEXT DEFAULT '',
    current_task_id TEXT,
    stop_requested INTEGER DEFAULT 0,
    tasks_total INTEGER DEFAULT 0,
    tasks_done INTEGER DEFAULT 0,
    tasks_verified INTEGER DEFAULT 0,
    model_calls INTEGER DEFAULT 0,
    last_error TEXT,
    started_at TEXT,
    updated_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS agent_tasks (
    id TEXT PRIMARY KEY,
    mission_id TEXT,
    seq INTEGER DEFAULT 0,
    kind TEXT,
    title TEXT,
    tool TEXT,
    risk TEXT DEFAULT 'low',
    status TEXT DEFAULT 'pending',
    args_json TEXT DEFAULT '{}',
    result_json TEXT DEFAULT '{}',
    evidence_json TEXT DEFAULT '{}',
    verification TEXT DEFAULT '',
    verifier_notes TEXT DEFAULT '',
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_mission ON agent_tasks(mission_id, seq);

CREATE TABLE IF NOT EXISTS agent_model_calls (
    id TEXT PRIMARY KEY,
    mission_id TEXT,
    task_id TEXT,
    agent TEXT,
    provider TEXT,
    model TEXT,
    status TEXT DEFAULT 'ok',
    prompt_chars INTEGER DEFAULT 0,
    completion_chars INTEGER DEFAULT 0,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    cost_cents INTEGER,
    duration_ms INTEGER DEFAULT 0,
    error TEXT,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_model_calls_mission
    ON agent_model_calls(mission_id, created_at DESC);
"""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
TRIAGE_STATUSES = {"new", "in_progress", "confirmed", "escalated", "rejected", "false_positive"}
SORTS = {"created_at", "severity", "confidence", "title"}
MISSION_STATUSES = {"draft", "active", "paused", "done", "archived"}
AUTONOMY_LEVELS = {"manual", "supervised", "autonomous"}
AGENT_STATUSES = {"idle", "planning", "running", "paused", "stopping",
                  "stopped", "done", "error"}
AGENT_TASK_STATUSES = {"pending", "running", "verified", "unverified",
                       "failed", "skipped", "blocked"}
AGENT_TASK_KINDS = {"scope", "recall", "probe", "inventory", "analysis", "verify",
                    "auth_inventory", "api_inventory", "findings_inventory",
                    "reports_inventory"}
MODEL_CALL_STATUSES = {"ok", "error", "unavailable", "budget"}
APPROVAL_RISKS = {"low", "medium", "high", "critical"}
APPROVAL_DECISIONS = {"approved", "rejected"}
TOOL_CALL_STATUSES = {"ok", "error", "denied", "approval_required", "confirm_required"}
SUBMISSION_PLATFORMS = {"hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi", "other"}
SUBMISSION_STATUSES = {"draft", "ready", "submitted", "triaged", "accepted",
                       "informative", "duplicate", "rejected", "paid", "withdrawn"}
SUBMISSION_SEVERITIES = {"critical", "high", "medium", "low", "info"}
OUTCOME_STATUSES = {"accepted", "informative", "duplicate", "rejected", "paid"}
LESSON_OUTCOMES = {"success", "failure", "partial", "blocked"}
TECH_TAGS = {
    "wordpress", "php", "graphql", "oauth", "oidc", "saml", "jwt", "aws", "gcp",
    "azure", "kubernetes", "docker", "apache", "nginx", "nodejs", "nextjs", "nuxt",
    "react", "vue", "java", "spring", "rails", "django", "laravel", "shopify",
    "firebase", "cloudflare", "api", "rest", "jmap", "imap", "smtp", "redis",
    "mysql", "postgres", "mongodb", "s3", "idp", "sso", "mfa", "2fa", "idor",
    "ssrf", "xss", "sqli", "rce", "lfi", "csrf", "auth", "encoding", "scim",
    "wireguard", "vpn", "email", "dns", "cdn", "waf", "mobile", "android",
    "ios", "solana", "ethereum", "solidity", "defi", "driver", "kernel",
    "aspnet", "iis", "xmlrpc", "cpanel", "whm", "phpmyadmin",
}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


def _loads(text, default):
    try:
        return json.loads(text or "")
    except (ValueError, TypeError):
        return default


class Index:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()
        try:
            os.chmod(self.path, 0o600)
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass

    def _migrate(self) -> None:
        """Columns added after the first release, for existing databases."""
        have = {row["name"] for row in self.conn.execute("PRAGMA table_info(providers)")}
        for column, ddl in (
            ("models_json", "ALTER TABLE providers ADD COLUMN models_json TEXT DEFAULT '[]'"),
            ("priority", "ALTER TABLE providers ADD COLUMN priority INTEGER DEFAULT 100"),
            ("enabled", "ALTER TABLE providers ADD COLUMN enabled INTEGER DEFAULT 1"),
        ):
            if column not in have:
                self.conn.execute(ddl)
        approvals = {row["name"] for row in self.conn.execute("PRAGMA table_info(approvals)")}
        if "used_at" not in approvals:
            self.conn.execute("ALTER TABLE approvals ADD COLUMN used_at TEXT")
        skills = {row["name"] for row in self.conn.execute("PRAGMA table_info(skills)")}
        for column, ddl in (
            ("status", "ALTER TABLE skills ADD COLUMN status TEXT DEFAULT 'active'"),
            ("use_count", "ALTER TABLE skills ADD COLUMN use_count INTEGER DEFAULT 0"),
            ("success_count", "ALTER TABLE skills ADD COLUMN success_count INTEGER DEFAULT 0"),
            ("last_used_at", "ALTER TABLE skills ADD COLUMN last_used_at TEXT"),
        ):
            if column not in skills:
                self.conn.execute(ddl)

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # -- runs -------------------------------------------------------------
    def create_run(self, target: str, options: dict | None = None,
                   parent_run_id: str = "", results_dir: str = "") -> dict:
        run_id = _new_id("run")
        with self._lock:
            self.conn.execute(
                "INSERT INTO runs (id, target, status, created_at, parent_run_id, "
                "results_dir, options_json, counts_json) VALUES (?, ?, 'queued', ?, ?, ?, ?, '{}')",
                (run_id, target, _now(), parent_run_id, results_dir,
                 json.dumps(options or {}, default=str)),
            )
            self.conn.commit()
        return self.get_run(run_id)

    def update_run(self, run_id: str, **fields) -> dict | None:
        allowed = {"status", "started_at", "finished_at", "results_dir", "error", "counts_json"}
        sets, values = [], []
        for key, value in fields.items():
            if key not in allowed:
                continue
            sets.append(f"{key} = ?")
            values.append(json.dumps(value, default=str) if key == "counts_json" else value)
        if not sets:
            return self.get_run(run_id)
        values.append(run_id)
        with self._lock:
            self.conn.execute(f"UPDATE runs SET {', '.join(sets)} WHERE id = ?", values)
            self.conn.commit()
        return self.get_run(run_id)

    def get_run(self, run_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_row(row) if row else None

    def list_runs(self, status: str = "", q: str = "", limit: int = 50,
                  offset: int = 0) -> tuple[list[dict], int]:
        where, params = [], []
        if status:
            where.append("status = ?")
            params.append(status)
        if q:
            where.append("target LIKE ?")
            params.append(f"%{q}%")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self.conn.execute(f"SELECT COUNT(*) FROM runs {clause}", params).fetchone()[0]
            rows = self.conn.execute(
                f"SELECT * FROM runs {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [self._run_row(row) for row in rows], total

    def delete_run(self, run_id: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
            self.conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
            self.conn.execute("DELETE FROM events WHERE run_id = ?", (run_id,))
            self.conn.commit()
        return cur.rowcount > 0

    def results_dir_in_use(self, results_dir: str, exclude_run_id: str = "") -> bool:
        """Whether another run still points at the same evidence directory.

        Resumed runs share the parent's directory, so deleting one history row
        must not take the files another row still needs.
        """
        if not results_dir:
            return False
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, results_dir, counts_json FROM runs WHERE id != ?",
                (exclude_run_id,),
            ).fetchall()
        for row in rows:
            counts = _loads(row["counts_json"], {})
            effective = (counts.get("results_dir") if isinstance(counts, dict) else "") \
                or row["results_dir"] or ""
            if str(effective) == str(results_dir):
                return True
        return False

    @staticmethod
    def _run_row(row: sqlite3.Row) -> dict:
        run = dict(row)
        run["options"] = _loads(run.pop("options_json"), {})
        run["counts"] = _loads(run.pop("counts_json"), {})
        return run

    # -- events -----------------------------------------------------------
    def add_event(self, run_id: str, event: dict) -> None:
        # The counters ride inside the payload so replay keeps them; the
        # "progress" column does not exist, and a JSON key costs nothing.
        payload = dict(event.get("payload") or {})
        if event.get("progress"):
            payload["_progress"] = event["progress"]
        with self._lock:
            self.conn.execute(
                "INSERT INTO events (run_id, seq, ts, type, level, stage, agent, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, event.get("seq", 0), event.get("ts", time.time()), event.get("type", ""),
                 event.get("level", "info"), event.get("stage", ""), event.get("agent", ""),
                 json.dumps(payload, default=str)),
            )
            self.conn.commit()

    def list_events(self, run_id: str, since: int = 0, limit: int = 1000) -> list[dict]:
        # With `since`, page forward from that seq (reconnect replay). Without
        # it, return the most recent `limit` events so a late-joining client
        # still sees the tail of a long run instead of only its first page.
        with self._lock:
            if since:
                rows = self.conn.execute(
                    "SELECT * FROM events WHERE run_id = ? AND seq > ? ORDER BY seq LIMIT ?",
                    (run_id, since, limit),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM events WHERE run_id = ? ORDER BY seq DESC LIMIT ?",
                    (run_id, limit),
                ).fetchall()
                rows = rows[::-1]
        events = []
        for row in rows:
            payload = _loads(row["payload_json"], {})
            progress = payload.pop("_progress", None)
            event = {
                "id": row["seq"], "seq": row["seq"], "ts": row["ts"], "run_id": row["run_id"],
                "type": row["type"], "level": row["level"], "stage": row["stage"],
                "agent": row["agent"], "payload": payload,
            }
            if progress is not None:
                event["progress"] = progress
            events.append(event)
        return events

    # -- findings ---------------------------------------------------------
    def add_findings(self, run_id: str, findings: list[dict]) -> int:
        from .keys import mask

        added = 0
        with self._lock:
            for finding in findings:
                raw_value = str(finding.get("value", ""))
                fingerprint = finding.get("fingerprint") or self._fingerprint(finding)
                prior = self.conn.execute(
                    "SELECT triage_status, severity_override, tags_json, notes FROM findings "
                    "WHERE fingerprint = ? ORDER BY created_at DESC LIMIT 1", (fingerprint,),
                ).fetchone()
                triage = prior["triage_status"] if prior else "new"
                override = prior["severity_override"] if prior else None
                tags = prior["tags_json"] if prior else "[]"
                notes = prior["notes"] if prior else ""
                try:
                    confidence = float(finding.get("confidence", 0.0) or 0.0)
                except (TypeError, ValueError):
                    confidence = 0.0
                self.conn.execute(
                    "INSERT OR REPLACE INTO findings (id, run_id, fingerprint, severity, title, "
                    "secret_type, status, value, impact, evidence, source, confidence, created_at, "
                    "triage_status, severity_override, tags_json, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (_new_id("fnd"), run_id, fingerprint, finding.get("severity", "unknown"),
                     finding.get("title", ""), finding.get("secret_type", ""),
                     finding.get("status", ""), mask(raw_value),
                     finding.get("impact", ""), finding.get("evidence", ""),
                     finding.get("source", ""), confidence,
                     _now(), triage, override, tags, notes),
                )
                added += 1
            self.conn.commit()
        return added

    def create_finding(self, title: str, severity: str, run_id: str = "",
                       impact: str = "", evidence: str = "", source: str = "",
                       secret_type: str = "manual", value: str = "",
                       confidence: float = 0.0, tags: list | None = None,
                       notes: str = "", fingerprint: str = "") -> dict:
        """Record a finding an operator or agent actually validated.

        This is deliberately explicit: nothing infers a finding from a scan or
        a model response. Callers must supply the title and severity they are
        willing to defend. Secret values are masked before storage.
        """
        from .keys import mask

        title = (title or "").strip()
        if not title:
            raise ValueError("title required")
        severity = (severity or "").strip().lower()
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {severity}")
        run_id = (run_id or "").strip()
        if run_id and not self.get_run(run_id):
            raise ValueError(f"unknown run: {run_id}")
        try:
            confidence = float(confidence or 0.0)
        except (TypeError, ValueError):
            raise ValueError("confidence must be a number") from None
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        tags = [str(tag) for tag in (tags or []) if str(tag).strip()]
        secret_type = (secret_type or "manual").strip() or "manual"
        raw_value = str(value or "")
        if not fingerprint:
            import hashlib
            seed = "|".join([secret_type, raw_value or title, run_id, source])
            fingerprint = hashlib.sha256(seed.encode("utf-8", "ignore")).hexdigest()

        finding_id = _new_id("fnd")
        now = _now()
        with self._lock:
            self.conn.execute(
                "INSERT INTO findings (id, run_id, fingerprint, severity, title, secret_type, "
                "status, value, impact, evidence, source, confidence, created_at, "
                "triage_status, severity_override, tags_json, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (finding_id, run_id, fingerprint, severity, title, secret_type,
                 "", mask(raw_value), impact.strip(), evidence.strip(), source.strip(),
                 confidence, now, "new", None, json.dumps(tags), notes.strip()),
            )
            self.conn.commit()
        return self.get_finding(finding_id)

    # -- evidence artifacts ------------------------------------------------
    @staticmethod
    def _safe_artifact_name(name: str) -> str:
        name = Path(str(name or "")).name.strip()
        cleaned = "".join(char for char in name
                          if char.isalnum() or char in "._- ()[]")
        cleaned = cleaned.lstrip(".")[:120]
        return cleaned or "artifact.bin"

    def add_finding_artifact(self, finding_id: str, name: str, content: bytes,
                             content_type: str = "application/octet-stream") -> dict:
        """Store an evidence file next to the finding, with a hash and size.

        The finding row is the authority; the artifact is the bytes the operator
        wants to keep after the report leaves the conversation. Files are 0600
        and live under the NetCast3r base directory, not the repository.
        """
        import hashlib
        import os

        finding = self.get_finding(finding_id)
        if not finding:
            raise ValueError("finding not found")
        if not isinstance(content, (bytes, bytearray)):
            raise ValueError("content must be bytes")
        if len(content) == 0:
            raise ValueError("artifact is empty")
        if len(content) > 8 * 1024 * 1024:
            raise ValueError("artifact is larger than 8 MiB")
        safe_name = self._safe_artifact_name(name)
        artifact_id = _new_id("art")
        directory = self.path.parent / "artifacts" / finding_id
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / f"{artifact_id}-{safe_name}"
        with open(target, "wb") as handle:
            handle.write(bytes(content))
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        digest = hashlib.sha256(bytes(content)).hexdigest()
        with self._lock:
            self.conn.execute(
                "INSERT INTO finding_artifacts (id, finding_id, name, path, sha256, "
                "bytes, content_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (artifact_id, finding_id, safe_name, str(target), digest,
                 len(content), (content_type or "application/octet-stream")[:120], _now()),
            )
            self.conn.commit()
        return self.get_finding_artifact(finding_id, artifact_id)

    def list_finding_artifacts(self, finding_id: str) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM finding_artifacts WHERE finding_id = ? ORDER BY created_at",
                (finding_id,),
            ).fetchall()
        return [self._artifact_row(row) for row in rows]

    def get_finding_artifact(self, finding_id: str, artifact_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM finding_artifacts WHERE id = ? AND finding_id = ?",
                (artifact_id, finding_id),
            ).fetchone()
        return self._artifact_row(row) if row else None

    def delete_finding_artifact(self, finding_id: str, artifact_id: str) -> bool:
        artifact = self.get_finding_artifact(finding_id, artifact_id)
        if not artifact:
            return False
        try:
            Path(artifact["path"]).unlink(missing_ok=True)
        except OSError:
            pass
        with self._lock:
            self.conn.execute(
                "DELETE FROM finding_artifacts WHERE id = ? AND finding_id = ?",
                (artifact_id, finding_id),
            )
            self.conn.commit()
        return True

    @staticmethod
    def _artifact_row(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "finding_id": row["finding_id"], "name": row["name"],
            "path": row["path"], "sha256": row["sha256"], "bytes": row["bytes"],
            "content_type": row["content_type"], "created_at": row["created_at"],
            "download_url": f"/api/v1/findings/{row['finding_id']}/artifacts/"
                            f"{row['id']}?download=1",
        }

    # -- lessons and skills ------------------------------------------------
    def add_lesson(self, title: str, lesson: str, technique: str = "",
                   context: str = "", outcome: str = "success", next_step: str = "",
                   tags: list | None = None, mission_id: str = "", run_id: str = "",
                   task_id: str = "", source: str = "", confidence: float = 0.5) -> dict:
        title = (title or "").strip()
        lesson = (lesson or "").strip()
        if not title:
            raise ValueError("title required")
        if not lesson:
            raise ValueError("lesson required")
        outcome = (outcome or "success").strip().lower()
        if outcome not in LESSON_OUTCOMES:
            raise ValueError(f"unknown outcome: {outcome}")
        if mission_id and not self.get_mission(mission_id):
            raise ValueError(f"unknown mission: {mission_id}")
        try:
            confidence = float(confidence or 0.0)
        except (TypeError, ValueError):
            raise ValueError("confidence must be a number") from None
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        tags = [str(tag) for tag in (tags or []) if str(tag).strip()]
        lesson_id = _new_id("lsn")
        now = _now()
        with self._lock:
            self.conn.execute(
                "INSERT INTO lessons (id, mission_id, run_id, task_id, title, technique, "
                "context, outcome, lesson, next_step, tags_json, source, confidence, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (lesson_id, mission_id, run_id, task_id, title, technique.strip(),
                 context.strip(), outcome, lesson, next_step.strip(), json.dumps(tags),
                 source.strip(), confidence, now, now),
            )
            self.conn.commit()
        self.bump_expertise(tags, outcome)
        return self.get_lesson(lesson_id)

    def bump_expertise(self, tags: list, outcome: str = "success") -> None:
        """Raise the exposure count for every technology tag in a real lesson."""
        names = {str(tag).strip().lower() for tag in tags or []}
        techs = sorted(names & TECH_TAGS)
        if not techs:
            return
        success = 1 if outcome == "success" else 0
        failure = 1 if outcome in {"failure", "blocked"} else 0
        now = _now()
        with self._lock:
            for tech in techs:
                self.conn.execute(
                    "INSERT INTO expertise (tech, exposures, successes, failures, last_seen) "
                    "VALUES (?, 1, ?, ?, ?) "
                    "ON CONFLICT(tech) DO UPDATE SET exposures = exposures + 1, "
                    "successes = successes + excluded.successes, "
                    "failures = failures + excluded.failures, last_seen = excluded.last_seen",
                    (tech, success, failure, now))
            self.conn.commit()

    def list_expertise(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM expertise ORDER BY (successes + failures) DESC, "
                "exposures DESC, last_seen DESC LIMIT ?",
                (max(1, min(int(limit or 50), 200)),)).fetchall()
        items = []
        for row in rows:
            attempts = int(row["successes"] or 0) + int(row["failures"] or 0)
            confidence = round(int(row["successes"] or 0) / attempts, 2) if attempts else 0.0
            exposures = int(row["exposures"] or 0)
            level = ("expert" if exposures >= 10 and confidence >= 0.6 else
                     "familiar" if exposures >= 4 else "novice")
            items.append({
                "tech": row["tech"], "exposures": exposures,
                "successes": int(row["successes"] or 0),
                "failures": int(row["failures"] or 0),
                "confidence": confidence, "level": level,
                "last_seen": row["last_seen"], "notes": row["notes"],
            })
        return items

    def list_lessons(self, q: str = "", tag: str = "", outcome: str = "",
                     limit: int = 50) -> tuple[list[dict], int]:
        where, values = [], []
        if q:
            like = f"%{q}%"
            where.append("(title LIKE ? OR technique LIKE ? OR context LIKE ? OR "
                         "lesson LIKE ? OR next_step LIKE ? OR tags_json LIKE ?)")
            values.extend([like] * 6)
        if tag:
            where.append("tags_json LIKE ?")
            values.append(f"%{tag}%")
        if outcome:
            where.append("outcome = ?")
            values.append(outcome)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self.conn.execute(
                f"SELECT COUNT(*) AS n FROM lessons{clause}", values).fetchone()["n"]
            rows = self.conn.execute(
                f"SELECT * FROM lessons{clause} ORDER BY created_at DESC LIMIT ?",
                [*values, max(1, min(int(limit or 50), 500))]).fetchall()
        return [self._lesson_row(row) for row in rows], total

    def get_lesson(self, lesson_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM lessons WHERE id = ?",
                                    (lesson_id,)).fetchone()
        return self._lesson_row(row) if row else None

    def delete_lesson(self, lesson_id: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM lessons WHERE id = ?", (lesson_id,))
            self.conn.commit()
        return cur.rowcount > 0

    @staticmethod
    def _lesson_row(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "mission_id": row["mission_id"], "run_id": row["run_id"],
            "task_id": row["task_id"], "title": row["title"],
            "technique": row["technique"], "context": row["context"],
            "outcome": row["outcome"], "lesson": row["lesson"],
            "next_step": row["next_step"], "tags": _loads(row["tags_json"], []),
            "source": row["source"], "confidence": row["confidence"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def upsert_skill(self, name: str, body: str, title: str = "",
                     description: str = "", tags: list | None = None,
                     source: str = "") -> dict:
        name = (name or "").strip().lower().replace(" ", "-")
        if not name or len(name) > 120:
            raise ValueError("skill name is required and must be at most 120 characters")
        body = (body or "").strip()
        if not body:
            raise ValueError("skill body is required")
        title = (title or name.replace("-", " ").title()).strip()
        tags = [str(tag) for tag in (tags or []) if str(tag).strip()]
        now = _now()
        with self._lock:
            row = self.conn.execute("SELECT * FROM skills WHERE name = ?",
                                    (name,)).fetchone()
            if row:
                self.conn.execute(
                    "UPDATE skills SET title = ?, description = ?, body = ?, tags_json = ?, "
                    "source = ?, version = version + 1, updated_at = ? WHERE name = ?",
                    (title, (description or "").strip(), body, json.dumps(tags),
                     (source or row["source"] or "").strip(), now, name),
                )
                skill_id = row["id"]
            else:
                skill_id = _new_id("skl")
                self.conn.execute(
                    "INSERT INTO skills (id, name, title, description, body, tags_json, "
                    "source, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (skill_id, name, title, (description or "").strip(), body,
                     json.dumps(tags), (source or "").strip(), 1, now, now),
                )
            self.conn.commit()
        return self.get_skill(skill_id)

    def list_skills(self, q: str = "", limit: int = 50, status: str = "") -> tuple[list[dict], int]:
        where, values = [], []
        if q:
            like = f"%{q}%"
            where.append("(name LIKE ? OR title LIKE ? OR description LIKE ? OR body LIKE ?)")
            values.extend([like] * 4)
        if status:
            where.append("status = ?")
            values.append(status)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self.conn.execute(
                f"SELECT COUNT(*) AS n FROM skills{clause}", values).fetchone()["n"]
            rows = self.conn.execute(
                f"SELECT * FROM skills{clause} ORDER BY "
                "CASE status WHEN 'active' THEN 0 ELSE 1 END, use_count DESC, updated_at DESC "
                "LIMIT ?", [*values, max(1, min(int(limit or 50), 200))]).fetchall()
        return [self._skill_row(row) for row in rows], total

    def use_skill(self, name_or_id: str, success: bool = True) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM skills WHERE id = ? OR name = ?",
                (name_or_id, name_or_id)).fetchone()
            if not row:
                return None
            self.conn.execute(
                "UPDATE skills SET use_count = use_count + 1, "
                "success_count = success_count + ?, last_used_at = ?, updated_at = ? "
                "WHERE id = ?",
                (1 if success else 0, _now(), _now(), row["id"]))
            self.conn.commit()
        return self.get_skill(row["id"])

    def set_skill_status(self, name_or_id: str, status: str) -> dict | None:
        if status not in {"draft", "active", "retired"}:
            raise ValueError("skill status must be draft, active, or retired")
        with self._lock:
            row = self.conn.execute(
                "SELECT id FROM skills WHERE id = ? OR name = ?",
                (name_or_id, name_or_id)).fetchone()
            if not row:
                return None
            self.conn.execute(
                "UPDATE skills SET status = ?, updated_at = ? WHERE id = ?",
                (status, _now(), row["id"]))
            self.conn.commit()
        return self.get_skill(row["id"])

    def get_skill(self, name_or_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM skills WHERE id = ? OR name = ?",
                (name_or_id, name_or_id)).fetchone()
        return self._skill_row(row) if row else None

    def delete_skill(self, name_or_id: str) -> bool:
        with self._lock:
            cur = self.conn.execute(
                "DELETE FROM skills WHERE id = ? OR name = ?", (name_or_id, name_or_id))
            self.conn.commit()
        return cur.rowcount > 0

    @staticmethod
    def _skill_row(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "name": row["name"], "title": row["title"],
            "description": row["description"], "body": row["body"],
            "tags": _loads(row["tags_json"], []), "source": row["source"],
            "version": row["version"], "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "status": row["status"] if "status" in row.keys() else "active",
            "use_count": row["use_count"] if "use_count" in row.keys() else 0,
            "success_count": row["success_count"] if "success_count" in row.keys() else 0,
            "last_used_at": row["last_used_at"] if "last_used_at" in row.keys() else None,
        }

    @staticmethod
    def _fingerprint(finding: dict) -> str:
        import hashlib
        # Hash the whole value: JWTs often share a header, so truncating at 64
        # characters made different tokens inherit one another's triage.
        raw = "|".join([
            str(finding.get("secret_type", "")), str(finding.get("value", "")),
        ])
        return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()

    def list_findings(self, run_id: str = "", severity: str = "", status: str = "",
                      q: str = "", sort: str = "created_at", limit: int = 50,
                      offset: int = 0) -> tuple[list[dict], int]:
        where, params = [], []
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        if severity:
            where.append("COALESCE(severity_override, severity) = ?")
            params.append(severity)
        if status:
            where.append("triage_status = ?")
            params.append(status)
        if q:
            where.append("(title LIKE ? OR secret_type LIKE ? OR source LIKE ?)")
            params.extend([f"%{q}%"] * 3)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        order = sort if sort in SORTS else "created_at"
        with self._lock:
            total = self.conn.execute(f"SELECT COUNT(*) FROM findings {clause}", params).fetchone()[0]
            rows = self.conn.execute(
                f"SELECT * FROM findings {clause} ORDER BY {order} DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        items = [self._finding_row(row) for row in rows]
        if sort == "severity":
            items.sort(key=lambda item: SEVERITY_ORDER.get(
                (item.get("severity_override") or item.get("severity") or "").lower(), 9))
        return items, total

    def get_finding(self, finding_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return self._finding_row(row) if row else None

    def patch_finding(self, finding_id: str, status: str = "", notes: str | None = None,
                      tags: list | None = None, severity_override: str = "") -> dict | None:
        if status and status not in TRIAGE_STATUSES:
            raise ValueError(f"unknown triage status: {status}")
        sets, values = [], []
        if status:
            sets.append("triage_status = ?")
            values.append(status)
        if notes is not None:
            sets.append("notes = ?")
            values.append(notes)
        if tags is not None:
            sets.append("tags_json = ?")
            values.append(json.dumps(tags))
        if severity_override:
            sets.append("severity_override = ?")
            values.append(severity_override)
        if sets:
            values.append(finding_id)
            with self._lock:
                self.conn.execute(f"UPDATE findings SET {', '.join(sets)} WHERE id = ?", values)
                self.conn.commit()
        return self.get_finding(finding_id)

    @staticmethod
    def _finding_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["tags"] = _loads(item.pop("tags_json"), [])
        return item

    def summary(self, run_id: str) -> dict:
        with self._lock:
            rows = self.conn.execute(
                "SELECT COALESCE(severity_override, severity) AS sev, COUNT(*) AS n FROM findings "
                "WHERE run_id = ? GROUP BY sev", (run_id,),
            ).fetchall()
            triage = self.conn.execute(
                "SELECT triage_status, COUNT(*) AS n FROM findings WHERE run_id = ? "
                "GROUP BY triage_status", (run_id,),
            ).fetchall()
        return {
            "severity": {row["sev"]: row["n"] for row in rows},
            "triage": {row["triage_status"]: row["n"] for row in triage},
        }

    # -- index counters ---------------------------------------------------
    def totals(self) -> dict:
        """Whole-index counters for the dashboard home screen."""
        with self._lock:
            runs = self.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            active = self.conn.execute(
                "SELECT COUNT(*) FROM runs WHERE status IN ('queued', 'running')"
            ).fetchone()[0]
            findings = self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            triage = {
                row["k"]: row["n"] for row in self.conn.execute(
                    "SELECT triage_status AS k, COUNT(*) AS n FROM findings GROUP BY triage_status"
                )
            }
            severity = {
                row["k"]: row["n"] for row in self.conn.execute(
                    "SELECT COALESCE(severity_override, severity) AS k, COUNT(*) AS n "
                    "FROM findings GROUP BY k"
                )
            }
            missions = self.conn.execute("SELECT COUNT(*) FROM missions").fetchone()[0]
            active_missions = self.conn.execute(
                "SELECT COUNT(*) FROM missions WHERE status = 'active'"
            ).fetchone()[0]
            pending_approvals = self.conn.execute(
                "SELECT COUNT(*) FROM approvals WHERE status = 'pending'"
            ).fetchone()[0]
            tool_calls = self.conn.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
        recent, _ = self.list_runs(limit=1)
        return {"runs": runs, "active_runs": active, "findings": findings,
                "triage": triage, "severity": severity,
                "missions": missions, "active_missions": active_missions,
                "pending_approvals": pending_approvals, "tool_calls": tool_calls,
                "last_run": recent[0] if recent else None}

    # -- missions ---------------------------------------------------------
    def create_mission(self, title: str, target: str, objective: str = "",
                       status: str = "draft", autonomy: str = "supervised",
                       budget: dict | None = None, scope: list | None = None,
                       plan: list | None = None) -> dict:
        title = (title or "").strip()
        target = (target or "").strip()
        if not title:
            raise ValueError("title required")
        if not target:
            raise ValueError("target required")
        if status not in MISSION_STATUSES:
            raise ValueError(f"unknown mission status: {status}")
        if autonomy not in AUTONOMY_LEVELS:
            raise ValueError(f"unknown autonomy level: {autonomy}")
        now = _now()
        mission_id = _new_id("msn")
        with self._lock:
            self.conn.execute(
                "INSERT INTO missions (id, title, target, objective, status, autonomy, "
                "budget_json, scope_json, plan_json, created_at, updated_at, started_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (mission_id, title, target, objective, status, autonomy,
                 json.dumps(budget or {}), json.dumps(scope or []), json.dumps(plan or []),
                 now, now, now if status == "active" else None),
            )
            self.conn.commit()
        return self.get_mission(mission_id) or {}

    def list_missions(self, status: str = "", limit: int = 50,
                      offset: int = 0) -> tuple[list[dict], int]:
        clause, params = "", []
        if status:
            clause = "WHERE m.status = ?"
            params.append(status)
        with self._lock:
            total = self.conn.execute(
                f"SELECT COUNT(*) FROM missions m {clause}", params
            ).fetchone()[0]
            rows = self.conn.execute(
                f"""SELECT m.*,
                    (SELECT COUNT(*) FROM mission_runs mr WHERE mr.mission_id = m.id) AS run_count,
                    (SELECT COUNT(*) FROM findings f JOIN mission_runs mr ON mr.run_id = f.run_id
                     WHERE mr.mission_id = m.id) AS finding_count,
                    (SELECT COUNT(*) FROM approvals a WHERE a.mission_id = m.id
                     AND a.status = 'pending') AS pending_approvals
                    FROM missions m {clause}
                    ORDER BY m.updated_at DESC LIMIT ? OFFSET ?""",
                [*params, limit, offset],
            ).fetchall()
        return [self._mission_row(row) for row in rows], total

    def get_mission(self, mission_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                """SELECT m.*,
                   (SELECT COUNT(*) FROM mission_runs mr WHERE mr.mission_id = m.id) AS run_count,
                   (SELECT COUNT(*) FROM findings f JOIN mission_runs mr ON mr.run_id = f.run_id
                    WHERE mr.mission_id = m.id) AS finding_count,
                   (SELECT COUNT(*) FROM approvals a WHERE a.mission_id = m.id
                    AND a.status = 'pending') AS pending_approvals
                   FROM missions m WHERE m.id = ?""",
                (mission_id,),
            ).fetchone()
            if not row:
                return None
            runs = self.conn.execute(
                """SELECT r.* FROM runs r JOIN mission_runs mr ON mr.run_id = r.id
                   WHERE mr.mission_id = ? ORDER BY r.created_at DESC""",
                (mission_id,),
            ).fetchall()
        mission = self._mission_row(row)
        mission["runs"] = [self._run_row(run) for run in runs]
        return mission

    def patch_mission(self, mission_id: str, **fields) -> dict | None:
        current = self.get_mission(mission_id)
        if not current:
            return None
        sets, values = [], []
        for column in ("title", "target", "objective", "autonomy", "last_run_id"):
            if column in fields and fields[column] is not None:
                value = str(fields[column]).strip()
                if column in {"title", "target"} and not value:
                    raise ValueError(f"{column} required")
                sets.append(f"{column} = ?")
                values.append(value)
        if "status" in fields and fields["status"] is not None:
            status = str(fields["status"]).strip()
            if status not in MISSION_STATUSES:
                raise ValueError(f"unknown mission status: {status}")
            sets.append("status = ?")
            values.append(status)
            if status == "active":
                if not current.get("started_at"):
                    sets.append("started_at = ?")
                    values.append(_now())
                sets.append("finished_at = NULL")
            if status == "done":
                sets.append("finished_at = ?")
                values.append(_now())
        if "autonomy" in fields and fields["autonomy"] is not None:
            if fields["autonomy"] not in AUTONOMY_LEVELS:
                raise ValueError(f"unknown autonomy level: {fields['autonomy']}")
        for key, column in (("budget", "budget_json"), ("scope", "scope_json"), ("plan", "plan_json")):
            if key in fields and fields[key] is not None:
                sets.append(f"{column} = ?")
                values.append(json.dumps(fields[key]))
        if sets:
            sets.append("updated_at = ?")
            values.append(_now())
            values.append(mission_id)
            with self._lock:
                self.conn.execute(
                    f"UPDATE missions SET {', '.join(sets)} WHERE id = ?", values
                )
                self.conn.commit()
        return self.get_mission(mission_id)

    def delete_mission(self, mission_id: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM missions WHERE id = ?", (mission_id,))
            self.conn.execute("DELETE FROM mission_runs WHERE mission_id = ?", (mission_id,))
            self.conn.execute("DELETE FROM approvals WHERE mission_id = ?", (mission_id,))
            self.conn.execute("DELETE FROM agent_tasks WHERE mission_id = ?", (mission_id,))
            self.conn.execute("DELETE FROM agent_state WHERE mission_id = ?", (mission_id,))
            self.conn.execute(
                "DELETE FROM agent_model_calls WHERE mission_id = ?", (mission_id,))
            self.conn.commit()
        return cur.rowcount > 0

    def add_mission_run(self, mission_id: str, run_id: str) -> dict | None:
        with self._lock:
            mission = self.conn.execute(
                "SELECT id FROM missions WHERE id = ?", (mission_id,)
            ).fetchone()
            run = self.conn.execute("SELECT id FROM runs WHERE id = ?", (run_id,)).fetchone()
            if not mission or not run:
                return None
            self.conn.execute(
                "INSERT OR IGNORE INTO mission_runs (mission_id, run_id, added_at) VALUES (?, ?, ?)",
                (mission_id, run_id, _now()),
            )
            self.conn.execute(
                "UPDATE missions SET last_run_id = ?, updated_at = ? WHERE id = ?",
                (run_id, _now(), mission_id),
            )
            self.conn.commit()
        return self.get_mission(mission_id)

    @staticmethod
    def _mission_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["budget"] = _loads(item.pop("budget_json"), {})
        item["scope"] = _loads(item.pop("scope_json"), [])
        item["plan"] = _loads(item.pop("plan_json"), [])
        return item

    # -- mission agent runtime --------------------------------------------
    def ensure_agent_state(self, mission_id: str) -> dict:
        now = _now()
        with self._lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO agent_state (mission_id, status, phase, "
                "budget_json, options_json, summary, stop_requested, tasks_total, "
                "tasks_done, tasks_verified, model_calls, last_error, updated_at) "
                "VALUES (?, 'idle', '', '{}', '{}', '', 0, 0, 0, 0, 0, '', ?)",
                (mission_id, now),
            )
            self.conn.commit()
        return self.get_agent_state(mission_id) or {}

    def get_agent_state(self, mission_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM agent_state WHERE mission_id = ?", (mission_id,)
            ).fetchone()
        return self._agent_state_row(row) if row else None

    def patch_agent_state(self, mission_id: str, **fields) -> dict | None:
        allowed = {"status", "phase", "summary", "current_task_id", "stop_requested",
                   "tasks_total", "tasks_done", "tasks_verified", "model_calls",
                   "last_error", "started_at", "finished_at"}
        sets, values = [], []
        for key in allowed:
            if key in fields and fields[key] is not None:
                value = int(fields[key]) if key in {
                    "stop_requested", "tasks_total", "tasks_done", "tasks_verified",
                    "model_calls"} else str(fields[key])
                if key == "status" and value not in AGENT_STATUSES:
                    raise ValueError(f"unknown agent status: {value}")
                sets.append(f"{key} = ?")
                values.append(value)
        for key, column in (("budget", "budget_json"), ("options", "options_json")):
            if key in fields and fields[key] is not None:
                sets.append(f"{column} = ?")
                values.append(json.dumps(fields[key], default=str))
        if "current_task_id" in fields and fields["current_task_id"] is None:
            sets.append("current_task_id = NULL")
        if sets:
            sets.append("updated_at = ?")
            values.extend([_now(), mission_id])
            with self._lock:
                self.conn.execute(
                    f"UPDATE agent_state SET {', '.join(sets)} WHERE mission_id = ?",
                    values,
                )
                self.conn.commit()
        return self.get_agent_state(mission_id)

    def reset_agent_run(self, mission_id: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM agent_tasks WHERE mission_id = ?", (mission_id,))
            self.conn.execute(
                "DELETE FROM agent_model_calls WHERE mission_id = ?", (mission_id,))
            self.conn.execute(
                "UPDATE agent_state SET status = 'idle', phase = '', summary = '', "
                "current_task_id = NULL, stop_requested = 0, tasks_total = 0, "
                "tasks_done = 0, tasks_verified = 0, model_calls = 0, last_error = '', "
                "started_at = NULL, finished_at = NULL, updated_at = ? "
                "WHERE mission_id = ?",
                (_now(), mission_id),
            )
            self.conn.commit()

    def create_agent_task(self, mission_id: str, seq: int, kind: str, title: str,
                          tool: str = "", risk: str = "low",
                          args: dict | None = None) -> dict:
        if kind not in AGENT_TASK_KINDS:
            raise ValueError(f"unknown agent task kind: {kind}")
        now = _now()
        task_id = _new_id("atk")
        with self._lock:
            self.conn.execute(
                "INSERT INTO agent_tasks (id, mission_id, seq, kind, title, tool, risk, "
                "status, args_json, result_json, evidence_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, '{}', '{}', ?, ?)",
                (task_id, mission_id, int(seq), kind, title, tool, risk,
                 json.dumps(args or {}, default=str), now, now),
            )
            self.conn.commit()
        return self.get_agent_task(task_id) or {}

    def get_agent_task(self, task_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM agent_tasks WHERE id = ?", (task_id,)
            ).fetchone()
        return self._agent_task_row(row) if row else None

    def list_agent_tasks(self, mission_id: str) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM agent_tasks WHERE mission_id = ? ORDER BY seq, created_at",
                (mission_id,),
            ).fetchall()
        return [self._agent_task_row(row) for row in rows]

    def patch_agent_task(self, task_id: str, **fields) -> dict | None:
        allowed = {"status", "result", "evidence", "verification", "verifier_notes",
                   "started_at", "finished_at", "tool", "risk", "title"}
        sets, values = [], []
        for key in allowed:
            if key in fields and fields[key] is not None:
                value = fields[key]
                if key == "status":
                    value = str(value)
                    if value not in AGENT_TASK_STATUSES:
                        raise ValueError(f"unknown agent task status: {value}")
                elif key in {"result", "evidence"}:
                    sets.append(f"{key}_json = ?")
                    values.append(json.dumps(value, default=str))
                    continue
                sets.append(f"{key} = ?")
                values.append(str(value) if key != "status" else value)
        if sets:
            sets.append("updated_at = ?")
            values.extend([_now(), task_id])
            with self._lock:
                self.conn.execute(
                    f"UPDATE agent_tasks SET {', '.join(sets)} WHERE id = ?", values
                )
                self.conn.commit()
        return self.get_agent_task(task_id)

    def agent_task_counts(self, mission_id: str) -> dict:
        with self._lock:
            rows = self.conn.execute(
                "SELECT status, COUNT(*) AS n FROM agent_tasks WHERE mission_id = ? "
                "GROUP BY status", (mission_id,)
            ).fetchall()
        counts = {row["status"]: row["n"] for row in rows}
        return {"total": sum(counts.values()), "by_status": counts,
                "verified": counts.get("verified", 0),
                "done": sum(count for status, count in counts.items()
                            if status != "pending")}

    def add_agent_model_call(self, mission_id: str, task_id: str = "", agent: str = "",
                             provider: str = "", model: str = "", status: str = "ok",
                             prompt_chars: int = 0, completion_chars: int = 0,
                             prompt_tokens: int | None = None,
                             completion_tokens: int | None = None,
                             cost_cents: float | None = None,
                             duration_ms: int = 0, error: str = "") -> dict:
        if status not in MODEL_CALL_STATUSES:
            raise ValueError(f"unknown model call status: {status}")
        call_id = _new_id("amc")
        with self._lock:
            self.conn.execute(
                "INSERT INTO agent_model_calls (id, mission_id, task_id, agent, provider, "
                "model, status, prompt_chars, completion_chars, prompt_tokens, "
                "completion_tokens, cost_cents, duration_ms, error, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (call_id, mission_id, task_id, agent, provider, model, status,
                 int(prompt_chars), int(completion_chars), prompt_tokens,
                 completion_tokens, cost_cents, int(duration_ms), error, _now()),
            )
            self.conn.commit()
        return self.get_agent_model_call(call_id) or {}

    def get_agent_model_call(self, call_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM agent_model_calls WHERE id = ?", (call_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_agent_model_calls(self, mission_id: str, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM agent_model_calls WHERE mission_id = ? "
                "ORDER BY created_at DESC LIMIT ?", (mission_id, int(limit))
            ).fetchall()
        return [dict(row) for row in rows]

    def agent_model_usage(self, mission_id: str) -> dict:
        """Report only what providers actually returned.

        ``cost_cents`` stays null when no provider reported a price. The
        runtime never multiplies tokens by an invention.
        """
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS calls, "
                "SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END) AS ok_calls, "
                "SUM(prompt_tokens) AS prompt_tokens, "
                "SUM(completion_tokens) AS completion_tokens, "
                "SUM(cost_cents) AS cost_cents, "
                "COUNT(cost_cents) AS priced_calls "
                "FROM agent_model_calls WHERE mission_id = ?", (mission_id,)
            ).fetchone()
        return {
            "calls": int(row["calls"] or 0),
            "ok_calls": int(row["ok_calls"] or 0),
            "prompt_tokens": row["prompt_tokens"],
            "completion_tokens": row["completion_tokens"],
            "cost_cents": row["cost_cents"] if row["priced_calls"] else None,
            "cost_reported": bool(row["priced_calls"]),
        }

    @staticmethod
    def _agent_state_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["budget"] = _loads(item.pop("budget_json"), {})
        item["options"] = _loads(item.pop("options_json"), {})
        return item

    @staticmethod
    def _agent_task_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["args"] = _loads(item.pop("args_json"), {})
        item["result"] = _loads(item.pop("result_json"), {})
        item["evidence"] = _loads(item.pop("evidence_json"), {})
        return item

    # -- approvals --------------------------------------------------------
    def list_approvals(self, status: str = "", mission_id: str = "",
                       limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
        where, params = [], []
        if status:
            if status not in {"pending"} | APPROVAL_DECISIONS:
                raise ValueError(f"unknown approval status: {status}")
            where.append("a.status = ?")
            params.append(status)
        if mission_id:
            where.append("a.mission_id = ?")
            params.append(mission_id)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self.conn.execute(
                f"SELECT COUNT(*) FROM approvals a {clause}", params
            ).fetchone()[0]
            rows = self.conn.execute(
                f"""SELECT a.*, m.title AS mission_title, m.target AS mission_target
                    FROM approvals a LEFT JOIN missions m ON m.id = a.mission_id
                    {clause} ORDER BY a.created_at DESC LIMIT ? OFFSET ?""",
                [*params, limit, offset],
            ).fetchall()
        return [self._approval_row(row) for row in rows], total

    def get_approval(self, approval_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                """SELECT a.*, m.title AS mission_title, m.target AS mission_target
                   FROM approvals a LEFT JOIN missions m ON m.id = a.mission_id
                   WHERE a.id = ?""",
                (approval_id,),
            ).fetchone()
        return self._approval_row(row) if row else None

    def create_approval(self, mission_id: str, action: str, risk: str = "medium",
                        requested_by: str = "agent", reason: str = "",
                        payload: dict | None = None, run_id: str = "") -> dict | None:
        action = (action or "").strip()
        if not action:
            raise ValueError("action required")
        if risk not in APPROVAL_RISKS:
            raise ValueError(f"unknown risk tier: {risk}")
        with self._lock:
            mission = self.conn.execute(
                "SELECT id FROM missions WHERE id = ?", (mission_id,)
            ).fetchone()
            if not mission:
                return None
            approval_id = _new_id("apr")
            self.conn.execute(
                "INSERT INTO approvals (id, mission_id, run_id, action, risk, status, "
                "requested_by, reason, payload_json, nonce, created_at) "
                "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)",
                (approval_id, mission_id, run_id, action, risk, requested_by, reason,
                 json.dumps(payload or {}), secrets.token_hex(12), _now()),
            )
            self.conn.commit()
        return self.get_approval(approval_id)

    def decide_approval(self, approval_id: str, decision: str,
                        decided_by: str = "operator", reason: str = "") -> dict | None:
        if decision not in APPROVAL_DECISIONS:
            raise ValueError(f"unknown approval decision: {decision}")
        with self._lock:
            row = self.conn.execute(
                "SELECT status FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
            if not row:
                return None
            if row["status"] != "pending":
                raise ValueError("approval already decided")
            self.conn.execute(
                "UPDATE approvals SET status = ?, decided_by = ?, reason = ?, decided_at = ? "
                "WHERE id = ?",
                (decision, decided_by, reason, _now(), approval_id),
            )
            self.conn.commit()
        return self.get_approval(approval_id)

    def consume_approval(self, approval_id: str) -> dict | None:
        """Mark an approved action as used, exactly once.

        Approval is a capability, not a mood: a gate that can be replayed is
        not a gate. The UI keeps showing the decision and when it was spent.
        """
        with self._lock:
            row = self.conn.execute(
                "SELECT status, used_at FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
            if not row:
                return None
            if row["status"] != "approved":
                raise ValueError("approval is not approved")
            if row["used_at"]:
                raise ValueError("approval already used")
            self.conn.execute(
                "UPDATE approvals SET used_at = ? WHERE id = ?", (_now(), approval_id)
            )
            self.conn.commit()
        return self.get_approval(approval_id)

    @staticmethod
    def _approval_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["payload"] = _loads(item.pop("payload_json"), {})
        return item

    # -- tool-call audit --------------------------------------------------
    def add_tool_call(self, tool: str, risk: str = "low", status: str = "ok",
                      actor: str = "", mission_id: str = "", run_id: str = "",
                      approval_id: str = "", args: dict | None = None,
                      result=None, error: str = "", duration_ms: int = 0) -> dict:
        if status not in TOOL_CALL_STATUSES:
            raise ValueError(f"unknown tool-call status: {status}")
        call_id = _new_id("tcl")
        args_json = json.dumps(args or {}, default=str)
        result_json = json.dumps(result, default=str)
        # An audit row is not a data warehouse. Keep pathological tool output
        # bounded while preserving the fact that it was truncated.
        if len(args_json) > 65536:
            args_json = json.dumps({"_truncated": True, "preview": args_json[:65000]})
        if len(result_json) > 65536:
            result_json = json.dumps({"_truncated": True, "preview": result_json[:65000]})
        with self._lock:
            self.conn.execute(
                "INSERT INTO tool_calls (id, tool, risk, status, actor, mission_id, run_id, "
                "approval_id, args_json, result_json, error, duration_ms, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (call_id, tool, risk, status, actor, mission_id, run_id, approval_id,
                 args_json, result_json, error, int(duration_ms), _now()),
            )
            self.conn.commit()
        return self.get_tool_call(call_id) or {}

    def list_tool_calls(self, tool: str = "", status: str = "", mission_id: str = "",
                        run_id: str = "", limit: int = 50,
                        offset: int = 0) -> tuple[list[dict], int]:
        where, params = [], []
        if tool:
            where.append("tool = ?")
            params.append(tool)
        if status:
            if status not in TOOL_CALL_STATUSES:
                raise ValueError(f"unknown tool-call status: {status}")
            where.append("status = ?")
            params.append(status)
        if mission_id:
            where.append("mission_id = ?")
            params.append(mission_id)
        if run_id:
            where.append("run_id = ?")
            params.append(run_id)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self.conn.execute(
                f"SELECT COUNT(*) FROM tool_calls {clause}", params
            ).fetchone()[0]
            rows = self.conn.execute(
                f"SELECT * FROM tool_calls {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [self._tool_call_row(row) for row in rows], total

    def get_tool_call(self, call_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM tool_calls WHERE id = ?", (call_id,)
            ).fetchone()
        return self._tool_call_row(row) if row else None

    @staticmethod
    def _tool_call_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["args"] = _loads(item.pop("args_json"), {})
        item["result"] = _loads(item.pop("result_json"), None)
        return item

    # -- submissions ------------------------------------------------------
    def create_submission(self, title: str, platform: str = "other", program: str = "",
                          target: str = "", severity: str = "medium",
                          status: str = "draft", mission_id: str = "",
                          finding_id: str = "", run_id: str = "",
                          bounty_cents: int = 0, currency: str = "USD",
                          external_id: str = "", url: str = "",
                          report_path: str = "", notes: str = "") -> dict | None:
        title = (title or "").strip()
        if not title:
            raise ValueError("title required")
        platform = (platform or "other").strip().lower()
        if platform not in SUBMISSION_PLATFORMS:
            raise ValueError(f"unknown submission platform: {platform}")
        severity = (severity or "medium").strip().lower()
        if severity not in SUBMISSION_SEVERITIES:
            raise ValueError(f"unknown severity: {severity}")
        status = (status or "draft").strip().lower()
        if status not in SUBMISSION_STATUSES:
            raise ValueError(f"unknown submission status: {status}")
        bounty_cents = self._bounty_cents(bounty_cents)
        currency = self._currency(currency)
        url = self._submission_url(url)
        mission_id, finding_id, run_id = self._submission_links(
            mission_id, finding_id, run_id)
        now = _now()
        submission_id = _new_id("sub")
        submitted_at = now if status not in {"draft", "ready"} else None
        decided_at = now if status in OUTCOME_STATUSES else None
        paid_at = now if status == "paid" else None
        with self._lock:
            self.conn.execute(
                "INSERT INTO submissions (id, mission_id, finding_id, run_id, platform, "
                "program, target, title, severity, status, bounty_cents, currency, "
                "external_id, url, report_path, notes, submitted_at, decided_at, paid_at, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "?, ?, ?, ?, ?, ?, ?)",
                (submission_id, mission_id, finding_id, run_id, platform, program.strip(),
                 target.strip(), title, severity, status, bounty_cents, currency,
                 external_id.strip(), url, report_path.strip(), notes.strip(),
                 submitted_at, decided_at, paid_at, now, now),
            )
            self.conn.commit()
        return self.get_submission(submission_id)

    def list_submissions(self, status: str = "", mission_id: str = "",
                         finding_id: str = "", platform: str = "",
                         limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
        where, params = [], []
        if status:
            if status not in SUBMISSION_STATUSES:
                raise ValueError(f"unknown submission status: {status}")
            where.append("s.status = ?")
            params.append(status)
        if platform:
            if platform not in SUBMISSION_PLATFORMS:
                raise ValueError(f"unknown submission platform: {platform}")
            where.append("s.platform = ?")
            params.append(platform)
        if mission_id:
            where.append("s.mission_id = ?")
            params.append(mission_id)
        if finding_id:
            where.append("s.finding_id = ?")
            params.append(finding_id)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self.conn.execute(
                f"SELECT COUNT(*) FROM submissions s {clause}", params
            ).fetchone()[0]
            rows = self.conn.execute(
                f"""SELECT s.*, m.title AS mission_title, f.title AS finding_title,
                    r.target AS run_target
                    FROM submissions s
                    LEFT JOIN missions m ON m.id = s.mission_id
                    LEFT JOIN findings f ON f.id = s.finding_id
                    LEFT JOIN runs r ON r.id = s.run_id
                    {clause} ORDER BY s.updated_at DESC LIMIT ? OFFSET ?""",
                [*params, limit, offset],
            ).fetchall()
        return [self._submission_row(row) for row in rows], total

    def get_submission(self, submission_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                """SELECT s.*, m.title AS mission_title, f.title AS finding_title,
                   r.target AS run_target
                   FROM submissions s
                   LEFT JOIN missions m ON m.id = s.mission_id
                   LEFT JOIN findings f ON f.id = s.finding_id
                   LEFT JOIN runs r ON r.id = s.run_id
                   WHERE s.id = ?""",
                (submission_id,),
            ).fetchone()
        return self._submission_row(row) if row else None

    def patch_submission(self, submission_id: str, **fields) -> dict | None:
        current = self.get_submission(submission_id)
        if not current:
            return None
        sets, values = [], []
        for column in ("title", "program", "target", "external_id", "url",
                       "report_path", "notes"):
            if column in fields and fields[column] is not None:
                value = str(fields[column]).strip()
                if column == "title" and not value:
                    raise ValueError("title required")
                if column == "url":
                    value = self._submission_url(value)
                sets.append(f"{column} = ?")
                values.append(value)
        if "platform" in fields and fields["platform"] is not None:
            platform = str(fields["platform"]).strip().lower()
            if platform not in SUBMISSION_PLATFORMS:
                raise ValueError(f"unknown submission platform: {platform}")
            sets.append("platform = ?")
            values.append(platform)
        if "severity" in fields and fields["severity"] is not None:
            severity = str(fields["severity"]).strip().lower()
            if severity not in SUBMISSION_SEVERITIES:
                raise ValueError(f"unknown severity: {severity}")
            sets.append("severity = ?")
            values.append(severity)
        if "bounty_cents" in fields and fields["bounty_cents"] is not None:
            sets.append("bounty_cents = ?")
            values.append(self._bounty_cents(fields["bounty_cents"]))
        if "currency" in fields and fields["currency"] is not None:
            sets.append("currency = ?")
            values.append(self._currency(fields["currency"]))
        if any(key in fields for key in ("mission_id", "finding_id", "run_id")):
            mission_id, finding_id, run_id = self._submission_links(
                fields.get("mission_id", current.get("mission_id") or ""),
                fields.get("finding_id", current.get("finding_id") or ""),
                fields.get("run_id", current.get("run_id") or ""))
            for column, value in (("mission_id", mission_id), ("finding_id", finding_id),
                                  ("run_id", run_id)):
                if column in fields:
                    sets.append(f"{column} = ?")
                    values.append(value)
        if "status" in fields and fields["status"] is not None:
            status = str(fields["status"]).strip().lower()
            if status not in SUBMISSION_STATUSES:
                raise ValueError(f"unknown submission status: {status}")
            sets.append("status = ?")
            values.append(status)
            now = _now()
            if status not in {"draft", "ready"} and not current.get("submitted_at"):
                sets.append("submitted_at = ?")
                values.append(now)
            if status in OUTCOME_STATUSES and not current.get("decided_at"):
                sets.append("decided_at = ?")
                values.append(now)
            if status == "paid" and not current.get("paid_at"):
                sets.append("paid_at = ?")
                values.append(now)
        if sets:
            sets.append("updated_at = ?")
            values.append(_now())
            values.append(submission_id)
            with self._lock:
                self.conn.execute(
                    f"UPDATE submissions SET {', '.join(sets)} WHERE id = ?", values)
                self.conn.commit()
        return self.get_submission(submission_id)

    def delete_submission(self, submission_id: str) -> bool:
        with self._lock:
            cur = self.conn.execute(
                "DELETE FROM submissions WHERE id = ?", (submission_id,))
            self.conn.commit()
        return cur.rowcount > 0

    def submission_summary(self) -> dict:
        """Aggregate only what was recorded. No estimate is invented here."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT status, bounty_cents, currency, paid_at FROM submissions"
            ).fetchall()
        by_status: dict[str, int] = {}
        currencies: dict[str, dict[str, int]] = {
            "USD": {"awarded_cents": 0, "paid_cents": 0}}
        for row in rows:
            status = str(row["status"] or "draft")
            by_status[status] = by_status.get(status, 0) + 1
            currency = self._currency(row["currency"])
            bucket = currencies.setdefault(
                currency, {"awarded_cents": 0, "paid_cents": 0})
            amount = int(row["bounty_cents"] or 0)
            if status in {"accepted", "paid"}:
                bucket["awarded_cents"] += amount
            if status == "paid" or row["paid_at"]:
                bucket["paid_cents"] += amount
        return {
            "total": len(rows),
            "by_status": by_status,
            "awaiting": by_status.get("submitted", 0) + by_status.get("triaged", 0),
            "accepted": by_status.get("accepted", 0) + by_status.get("paid", 0),
            "paid": by_status.get("paid", 0),
            "by_currency": currencies,
        }

    def _submission_links(self, mission_id, finding_id, run_id):
        mission_id = str(mission_id or "").strip()
        finding_id = str(finding_id or "").strip()
        run_id = str(run_id or "").strip()
        with self._lock:
            if mission_id and not self.conn.execute(
                    "SELECT id FROM missions WHERE id = ?", (mission_id,)).fetchone():
                raise ValueError("mission not found")
            if finding_id and not self.conn.execute(
                    "SELECT id FROM findings WHERE id = ?", (finding_id,)).fetchone():
                raise ValueError("finding not found")
            if run_id and not self.conn.execute(
                    "SELECT id FROM runs WHERE id = ?", (run_id,)).fetchone():
                raise ValueError("run not found")
        return mission_id, finding_id, run_id

    @staticmethod
    def _bounty_cents(value) -> int:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("bounty_cents must be a number")
        amount = int(value)
        if amount < 0:
            raise ValueError("bounty_cents cannot be negative")
        if amount > 10_000_000_000:
            raise ValueError("bounty_cents is implausibly large")
        return amount

    @staticmethod
    def _currency(value) -> str:
        currency = (str(value or "USD")).strip().upper()
        if len(currency) != 3 or not currency.isalpha():
            raise ValueError("currency must be a three-letter code")
        return currency

    @staticmethod
    def _submission_url(value) -> str:
        url = str(value or "").strip()
        if url and not (url.startswith("https://") or url.startswith("http://")):
            raise ValueError("url must start with http:// or https://")
        return url

    @staticmethod
    def _submission_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["bounty_cents"] = int(item.get("bounty_cents") or 0)
        return item

    # -- providers --------------------------------------------------------
    def add_provider(self, name: str, kind: str = "openai", base_url: str = "",
                     model: str = "", key_name: str = "", models: list[str] | None = None,
                     priority: int = 100, enabled: int = 1) -> dict:
        provider_id = _new_id("prv")
        rows = [str(item) for item in (models or []) if str(item).strip()]
        if not rows and model:
            rows = [model]
        with self._lock:
            self.conn.execute(
                "INSERT INTO providers (id, name, kind, base_url, model, key_name, "
                "models_json, priority, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (provider_id, name, kind, base_url, model, key_name,
                 json.dumps(rows), int(priority), int(enabled)),
            )
            self.conn.commit()
        return self.get_provider(provider_id)

    def get_provider(self, provider_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM providers WHERE id = ?", (provider_id,)).fetchone()
        return self._provider_row(row) if row else None

    def list_providers(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM providers ORDER BY priority, name").fetchall()
        return [self._provider_row(row) for row in rows]

    @staticmethod
    def _provider_row(row) -> dict:
        item = dict(row)
        try:
            item["models"] = [str(m) for m in json.loads(item.get("models_json") or "[]")]
        except (ValueError, TypeError):
            item["models"] = []
        if not item["models"] and item.get("model"):
            item["models"] = [item["model"]]
        item["priority"] = int(item.get("priority") or 100)
        item["enabled"] = int(item.get("enabled", 1) or 0)
        return item

    def update_provider(self, provider_id: str, **fields) -> dict | None:
        allowed = {"name", "kind", "base_url", "model", "key_name", "healthy",
                   "last_checked", "priority", "enabled"}
        sets, values = [], []
        for key, value in fields.items():
            if key == "models":
                rows = [str(item) for item in (value or []) if str(item).strip()]
                sets.append("models_json = ?")
                values.append(json.dumps(rows))
                sets.append("model = ?")
                values.append(rows[0] if rows else "")
            elif key in allowed:
                sets.append(f"{key} = ?")
                values.append(int(value) if key in {"priority", "enabled", "healthy"} else value)
        if sets:
            values.append(provider_id)
            with self._lock:
                self.conn.execute(f"UPDATE providers SET {', '.join(sets)} WHERE id = ?", values)
                self.conn.commit()
        return self.get_provider(provider_id)

    def delete_provider(self, provider_id: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM providers WHERE id = ?", (provider_id,))
            self.conn.commit()
        return cur.rowcount > 0

    # -- settings ---------------------------------------------------------
    def get_setting(self, key: str, default=None):
        with self._lock:
            row = self.conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
        return _loads(row["value_json"], default) if row else default

    def set_setting(self, key: str, value, is_secret: bool = False) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO settings (key, value_json, is_secret, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (key, json.dumps(value, default=str), 1 if is_secret else 0, _now()),
            )
            self.conn.commit()

    def list_settings(self) -> dict:
        with self._lock:
            rows = self.conn.execute("SELECT key, value_json, is_secret FROM settings").fetchall()
        return {row["key"]: _loads(row["value_json"], None) for row in rows}
