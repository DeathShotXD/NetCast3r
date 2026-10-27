"""SQLite index over runs, findings, events, providers, and settings.

The files a run writes stay authoritative. This index makes them searchable,
pageable, and diffable, and it remembers triage so a re-scan does not lose it.
"""

from __future__ import annotations

import json
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
    decided_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_mission ON approvals(mission_id, created_at DESC);
"""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
TRIAGE_STATUSES = {"new", "in_progress", "confirmed", "escalated", "rejected", "false_positive"}
SORTS = {"created_at", "severity", "confidence", "title"}
MISSION_STATUSES = {"draft", "active", "paused", "done", "archived"}
AUTONOMY_LEVELS = {"manual", "supervised", "autonomous"}
APPROVAL_RISKS = {"low", "medium", "high", "critical"}
APPROVAL_DECISIONS = {"approved", "rejected"}


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
        recent, _ = self.list_runs(limit=1)
        return {"runs": runs, "active_runs": active, "findings": findings,
                "triage": triage, "severity": severity,
                "missions": missions, "active_missions": active_missions,
                "pending_approvals": pending_approvals,
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

    @staticmethod
    def _approval_row(row: sqlite3.Row) -> dict:
        item = dict(row)
        item["payload"] = _loads(item.pop("payload_json"), {})
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
