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
"""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SORTS = {"created_at", "severity", "confidence", "title"}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


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

    @staticmethod
    def _run_row(row: sqlite3.Row) -> dict:
        run = dict(row)
        run["options"] = json.loads(run.pop("options_json") or "{}")
        run["counts"] = json.loads(run.pop("counts_json") or "{}")
        return run

    # -- events -----------------------------------------------------------
    def add_event(self, run_id: str, event: dict) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO events (run_id, seq, ts, type, level, stage, agent, payload_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, event.get("seq", 0), event.get("ts", time.time()), event.get("type", ""),
                 event.get("level", "info"), event.get("stage", ""), event.get("agent", ""),
                 json.dumps(event.get("payload") or {}, default=str)),
            )
            self.conn.commit()

    def list_events(self, run_id: str, since: int = 0, limit: int = 1000) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM events WHERE run_id = ? AND seq > ? ORDER BY seq LIMIT ?",
                (run_id, since, limit),
            ).fetchall()
        events = []
        for row in rows:
            events.append({
                "id": row["seq"], "seq": row["seq"], "ts": row["ts"], "run_id": row["run_id"],
                "type": row["type"], "level": row["level"], "stage": row["stage"],
                "agent": row["agent"], "payload": json.loads(row["payload_json"] or "{}"),
            })
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
                self.conn.execute(
                    "INSERT OR REPLACE INTO findings (id, run_id, fingerprint, severity, title, "
                    "secret_type, status, value, impact, evidence, source, confidence, created_at, "
                    "triage_status, severity_override, tags_json, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (_new_id("fnd"), run_id, fingerprint, finding.get("severity", "unknown"),
                     finding.get("title", ""), finding.get("secret_type", ""),
                     finding.get("status", ""), mask(raw_value),
                     finding.get("impact", ""), finding.get("evidence", ""),
                     finding.get("source", ""), float(finding.get("confidence", 0.0) or 0.0),
                     _now(), triage, override, tags, notes),
                )
                added += 1
            self.conn.commit()
        return added

    @staticmethod
    def _fingerprint(finding: dict) -> str:
        import hashlib
        raw = "|".join([
            str(finding.get("secret_type", "")), str(finding.get("value", ""))[:64],
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

    def patch_finding(self, finding_id: str, status: str = "", notes: str = "",
                      tags: list | None = None, severity_override: str = "") -> dict | None:
        sets, values = [], []
        if status:
            sets.append("triage_status = ?")
            values.append(status)
        if notes:
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
        item["tags"] = json.loads(item.pop("tags_json") or "[]")
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
        recent, _ = self.list_runs(limit=1)
        return {"runs": runs, "active_runs": active, "findings": findings,
                "triage": triage, "severity": severity,
                "last_run": recent[0] if recent else None}

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
                if rows and not fields.get("model"):
                    sets.append("model = ?")
                    values.append(rows[0])
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
        return json.loads(row["value_json"]) if row else default

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
        return {row["key"]: json.loads(row["value_json"]) for row in rows}
