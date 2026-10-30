"""Evidence store.

Everything a run learns lands in one SQLite file so it can be replayed, diffed
between runs, and cited in the report. The store is also the run's memory: when
a scan stops halfway, whatever reached the store is what a resume picks up.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    kind TEXT,
    status INTEGER,
    seen_at REAL
);
CREATE TABLE IF NOT EXISTS js_files (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    size INTEGER,
    sha256 TEXT,
    seen_at REAL
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    source TEXT,
    seen_at REAL
);
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY,
    type TEXT,
    value TEXT,
    source TEXT,
    context TEXT,
    confidence REAL DEFAULT 0,
    seen_at REAL,
    UNIQUE(type, value)
);
CREATE TABLE IF NOT EXISTS validations (
    id INTEGER PRIMARY KEY,
    type TEXT,
    value TEXT,
    status TEXT,
    provider TEXT,
    detail TEXT,
    evidence TEXT,
    seen_at REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    title TEXT,
    severity TEXT,
    secret_type TEXT,
    value TEXT,
    impact TEXT,
    evidence TEXT,
    source TEXT DEFAULT '',
    status TEXT DEFAULT '',
    confidence REAL DEFAULT 0,
    reproduction TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    narrative TEXT DEFAULT '',
    model_steps TEXT DEFAULT '',
    model_severity TEXT DEFAULT '',
    model_impact TEXT DEFAULT '',
    corroboration TEXT DEFAULT '',
    created_at REAL
);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY,
    source TEXT,
    kind TEXT,
    detail TEXT,
    severity TEXT,
    seen_at REAL
);
CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY,
    type TEXT,
    value TEXT,
    source TEXT,
    severity TEXT,
    detail TEXT,
    steps TEXT,
    seen_at REAL
);
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY,
    host TEXT UNIQUE,
    resolved INTEGER DEFAULT 0,
    seen_at REAL
);
CREATE TABLE IF NOT EXISTS checkpoints (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at REAL
);
CREATE TABLE IF NOT EXISTS stages (
    name TEXT PRIMARY KEY,
    status TEXT,
    detail TEXT,
    started_at REAL,
    finished_at REAL
);
CREATE TABLE IF NOT EXISTS bodies (
    url TEXT PRIMARY KEY,
    kind TEXT,
    text TEXT,
    seen_at REAL
);
CREATE TABLE IF NOT EXISTS notes (
    url TEXT PRIMARY KEY,
    data TEXT,
    seen_at REAL
);
CREATE TABLE IF NOT EXISTS corroborations (
    id INTEGER PRIMARY KEY,
    type TEXT,
    value TEXT,
    validator TEXT,
    verdict TEXT,
    confidence REAL DEFAULT 0,
    detail TEXT,
    seen_at REAL
);
"""

FINDING_COLUMNS = (
    ("source", "TEXT DEFAULT ''"),
    ("status", "TEXT DEFAULT ''"),
    ("confidence", "REAL DEFAULT 0"),
    ("reproduction", "TEXT DEFAULT ''"),
    ("notes", "TEXT DEFAULT ''"),
    ("narrative", "TEXT DEFAULT ''"),
    ("model_steps", "TEXT DEFAULT ''"),
    ("model_severity", "TEXT DEFAULT ''"),
    ("model_impact", "TEXT DEFAULT ''"),
    ("corroboration", "TEXT DEFAULT ''"),
)

SECRET_COLUMNS = (
    ("confidence", "REAL DEFAULT 0"),
)

MAX_BODY_CHARS = 1_500_000


def _loads(text, fallback):
    try:
        return json.loads(text) if text else fallback
    except (TypeError, ValueError):
        return fallback


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.executescript(SCHEMA)
        self._ensure_column("findings", FINDING_COLUMNS)
        self._ensure_column("secrets", SECRET_COLUMNS)
        self.conn.commit()

    def _ensure_column(self, table: str, columns) -> None:
        """Add missing columns to a database written by an older version."""
        existing = {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}  # codeaudit: ignore py-sql-fstring -- table is a module constant
        for name, decl in columns:
            if name not in existing:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")  # codeaudit: ignore py-sql-fstring -- name and decl are module constants

    def close(self) -> None:
        self.conn.close()

    # -- raw evidence -----------------------------------------------------

    def add_asset(self, url: str, kind: str, status: int) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO assets (url, kind, status, seen_at) VALUES (?, ?, ?, ?)",
            (url, kind, status, time.time()),
        )
        self.conn.commit()

    def add_js(self, url: str, body: str) -> None:
        digest = hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()
        self.conn.execute(
            "INSERT OR IGNORE INTO js_files (url, size, sha256, seen_at) VALUES (?, ?, ?, ?)",
            (url, len(body), digest, time.time()),
        )
        self.conn.commit()
        if body:
            self.save_body(url, "js", body)

    def add_endpoint(self, url: str, source: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO endpoints (url, source, seen_at) VALUES (?, ?, ?)",
            (url, source, time.time()),
        )
        self.conn.commit()

    def add_secret(self, secret_type: str, value: str, source: str, context: str,
                   confidence: float = 0.0) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO secrets (type, value, source, context, confidence, seen_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (secret_type, value, source, context, float(confidence or 0.0), time.time()),
        )
        self.conn.commit()

    def add_validation(self, secret_type: str, value: str, status: str,
                       provider: str, detail: str, evidence: str) -> None:
        self.conn.execute(
            "INSERT INTO validations (type, value, status, provider, detail, evidence, seen_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (secret_type, value, status, provider, detail, evidence, time.time()),
        )
        self.conn.commit()

    def add_corroboration(self, secret_type: str, value: str, validator: str,
                          verdict: str, confidence: float = 0.0, detail: str = "") -> None:
        self.conn.execute(
            "INSERT INTO corroborations (type, value, validator, verdict, confidence, detail, seen_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (secret_type, value, validator, verdict, float(confidence or 0.0), detail, time.time()),
        )
        self.conn.commit()

    def add_finding(self, title: str, severity: str, secret_type: str,
                    value: str, impact: str, evidence: str, source: str = "",
                    status: str = "", confidence: float = 0.0,
                    reproduction: list | None = None, notes: str = "",
                    narrative: str = "", model_steps: list | None = None,
                    model_severity: str = "", model_impact: str = "",
                    corroboration: dict | None = None) -> None:
        self.conn.execute(
            "INSERT INTO findings (title, severity, secret_type, value, impact, evidence, "
            "source, status, confidence, reproduction, notes, narrative, model_steps, "
            "model_severity, model_impact, corroboration, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (title, severity, secret_type, value, impact, evidence,
             source, status, float(confidence or 0.0),
             json.dumps(reproduction or []), notes, narrative,
             json.dumps(model_steps or []), model_severity, model_impact,
             json.dumps(corroboration or {}), time.time()),
        )
        self.conn.commit()

    def update_finding_details(self, secret_type: str, value: str, **fields) -> None:
        """Fold later work (escalation, narrative) into the stored finding row."""
        allowed = {"title", "severity", "impact", "evidence", "source", "status",
                   "reproduction", "notes", "narrative", "model_steps",
                   "model_severity", "model_impact", "corroboration", "confidence"}
        sets, values = [], []
        for key, raw in fields.items():
            if key not in allowed:
                continue
            if key in ("reproduction", "model_steps"):
                raw = json.dumps(raw or [])
            elif key == "corroboration":
                raw = json.dumps(raw or {})
            sets.append(f"{key} = ?")
            values.append(raw)
        if not sets:
            return
        values.extend([secret_type, value])
        self.conn.execute(
            f"UPDATE findings SET {', '.join(sets)} WHERE id = "
            f"(SELECT MAX(id) FROM findings WHERE secret_type = ? AND value = ?)",
            values,
        )
        self.conn.commit()

    def add_review(self, source: str, kind: str, detail: str, severity: str = "") -> None:
        self.conn.execute(
            "INSERT INTO reviews (source, kind, detail, severity, seen_at) VALUES (?, ?, ?, ?, ?)",
            (source, kind, detail, severity, time.time()),
        )
        self.conn.commit()

    def add_candidate(self, secret_type: str, value: str, source: str, severity: str,
                      detail: str, steps: list | None = None) -> None:
        self.conn.execute(
            "INSERT INTO candidates (type, value, source, severity, detail, steps, seen_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (secret_type, value, source, severity, detail,
             json.dumps(steps or []), time.time()),
        )
        self.conn.commit()

    def add_subdomain(self, host: str, resolved: int = 0) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO subdomains (host, resolved, seen_at) VALUES (?, ?, ?)",
            (host, int(resolved), time.time()),
        )
        self.conn.commit()

    # -- run memory -------------------------------------------------------

    def save_body(self, url: str, kind: str, text: str) -> None:
        text = text or ""
        if len(text) > MAX_BODY_CHARS:
            text = text[:MAX_BODY_CHARS]
        self.conn.execute(
            "INSERT OR REPLACE INTO bodies (url, kind, text, seen_at) VALUES (?, ?, ?, ?)",
            (url, kind, text, time.time()),
        )
        self.conn.commit()

    def bodies_map(self) -> dict:
        rows = self.conn.execute("SELECT url, text FROM bodies").fetchall()
        return {url: text or "" for url, text in rows}

    def save_note(self, url: str, data: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO notes (url, data, seen_at) VALUES (?, ?, ?)",
            (url, json.dumps(data or {}), time.time()),
        )
        self.conn.commit()

    def notes_map(self) -> dict:
        rows = self.conn.execute("SELECT url, data FROM notes").fetchall()
        return {url: _loads(data, {}) for url, data in rows}

    def set_checkpoint(self, key: str, value: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO checkpoints (key, value, updated_at) VALUES (?, ?, ?)",
            (key, json.dumps(value or {}), time.time()),
        )
        self.conn.commit()

    def get_checkpoint(self, key: str) -> dict | None:
        row = self.conn.execute("SELECT value FROM checkpoints WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        return _loads(row[0], {}) or None

    def clear_checkpoint(self, key: str) -> None:
        self.conn.execute("DELETE FROM checkpoints WHERE key = ?", (key,))
        self.conn.commit()

    def stage_begin(self, name: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO stages (name, status, detail, started_at, finished_at) "
            "VALUES (?, 'running', '', ?, NULL)",
            (name, time.time()),
        )
        self.conn.commit()

    def stage_end(self, name: str, status: str = "done", detail: str = "") -> None:
        self.conn.execute(
            "INSERT INTO stages (name, status, detail, started_at, finished_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET status = excluded.status, "
            "detail = excluded.detail, finished_at = excluded.finished_at",
            (name, status, detail, time.time(), time.time()),
        )
        self.conn.commit()

    def stages(self) -> dict:
        rows = self.conn.execute(
            "SELECT name, status, detail, started_at, finished_at FROM stages"
        ).fetchall()
        return {
            name: {"status": status, "detail": detail,
                   "started_at": started_at, "finished_at": finished_at}
            for name, status, detail, started_at, finished_at in rows
        }

    def stage_done(self, name: str) -> bool:
        row = self.conn.execute(
            "SELECT status FROM stages WHERE name = ?", (name,)
        ).fetchone()
        return bool(row and row[0] == "done")

    # -- reads ------------------------------------------------------------

    def counts(self) -> dict:
        result = {}
        for table in ("assets", "js_files", "endpoints", "secrets", "validations",
                      "findings", "reviews", "candidates", "subdomains",
                      "corroborations"):
            row = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # codeaudit: ignore py-sql-fstring -- table comes from a fixed tuple
            result[table] = row[0] if row else 0
        return result

    def count_assets(self, kind: str) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM assets WHERE kind = ?", (kind,)).fetchone()
        return row[0] if row else 0

    def list_asset_urls(self, kind: str = "") -> list:
        if kind:
            rows = self.conn.execute(
                "SELECT url FROM assets WHERE kind = ? ORDER BY url", (kind,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT url FROM assets ORDER BY url").fetchall()
        return [url for (url,) in rows]

    def list_endpoint_urls(self) -> list:
        rows = self.conn.execute("SELECT url FROM endpoints ORDER BY url").fetchall()
        return [url for (url,) in rows]

    def validations_map(self) -> dict:
        rows = self.conn.execute(
            "SELECT type, value, status, provider, detail, evidence FROM validations"
        ).fetchall()
        result = {}
        for secret_type, value, status, provider, detail, evidence in rows:
            result[(secret_type, value)] = {
                "status": status, "provider": provider,
                "detail": detail, "evidence": evidence,
            }
        return result

    def finding_keys(self) -> set:
        rows = self.conn.execute("SELECT secret_type, value FROM findings").fetchall()
        return {(secret_type, value) for secret_type, value in rows}

    def secrets_all(self) -> list:
        rows = self.conn.execute(
            "SELECT type, value, source, context, confidence FROM secrets ORDER BY id"
        ).fetchall()
        return [{"type": t, "value": v, "source": s or "", "context": c or "",
                 "confidence": float(conf or 0.0)}
                for t, v, s, c, conf in rows]

    def findings_full(self, limit: int = 0) -> list:
        query = ("SELECT title, severity, secret_type, value, impact, evidence, source, "
                 "status, confidence, reproduction, notes, narrative, model_steps, "
                 "model_severity, model_impact, corroboration FROM findings ORDER BY id")
        if limit:
            query += f" LIMIT {int(limit)}"
        rows = self.conn.execute(query).fetchall()
        findings = []
        for (title, severity, secret_type, value, impact, evidence, source, status,
             confidence, reproduction, notes, narrative, model_steps, model_severity,
             model_impact, corroboration) in rows:
            findings.append({
                "title": title or "", "severity": severity or "info",
                "secret_type": secret_type or "", "value": value or "",
                "impact": impact or "", "proof": evidence or "",
                "source": source or "", "status": status or "",
                "confidence": float(confidence or 0.0),
                "reproduction": _loads(reproduction, []),
                "notes": notes or "", "narrative": narrative or "",
                "model_steps": _loads(model_steps, []),
                "model_severity": model_severity or "",
                "model_impact": model_impact or "",
                "corroboration": _loads(corroboration, {}),
            })
        return findings

    # -- dashboard reads --------------------------------------------------

    def list_assets(self, kind: str = "", limit: int = 2000) -> list:
        limit = max(1, min(int(limit or 2000), 5000))
        if kind:
            rows = self.conn.execute(
                "SELECT url, kind, status FROM assets WHERE kind = ? ORDER BY id LIMIT ?",
                (kind, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT url, kind, status FROM assets ORDER BY id LIMIT ?", (limit,)
            ).fetchall()
        return [{"url": url, "kind": kind, "status": status} for url, kind, status in rows]

    def list_js(self, limit: int = 2000) -> list:
        query = "SELECT url, size, sha256 FROM js_files ORDER BY id"
        params: list = []
        if limit:
            query += " LIMIT ?"
            params.append(max(1, min(int(limit), 5000)))
        rows = self.conn.execute(query, params).fetchall()
        return [{"url": url, "size": size or 0, "sha256": sha or ""}
                for url, size, sha in rows]

    def list_endpoints(self, limit: int = 5000) -> list:
        limit = max(1, min(int(limit or 5000), 10000))
        rows = self.conn.execute(
            "SELECT url, source FROM endpoints ORDER BY id LIMIT ?", (limit,)
        ).fetchall()
        return [{"url": url, "source": source or ""} for url, source in rows]

    def list_secrets(self, limit: int = 2000) -> list:
        limit = max(1, min(int(limit or 2000), 5000))
        rows = self.conn.execute(
            "SELECT type, value, source, context, confidence FROM secrets ORDER BY id LIMIT ?",
            (limit,),
        ).fetchall()
        return [{"type": t, "value": v, "source": s or "", "context": c or "",
                 "confidence": float(conf or 0.0)} for t, v, s, c, conf in rows]

    def list_validations(self, limit: int = 2000) -> list:
        limit = max(1, min(int(limit or 2000), 5000))
        rows = self.conn.execute(
            "SELECT type, value, status, provider, detail, evidence FROM validations "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [{"type": t, "value": v, "status": status, "provider": p or "",
                 "detail": d or "", "evidence": e or ""}
                for t, v, status, p, d, e in rows]

    def list_reviews(self, limit: int = 1000) -> list:
        query = "SELECT source, kind, detail, severity FROM reviews ORDER BY id"
        params: list = []
        if limit:
            query += " LIMIT ?"
            params.append(max(1, min(int(limit), 5000)))
        rows = self.conn.execute(query, params).fetchall()
        return [{"source": s or "", "kind": k or "", "detail": d or "",
                 "severity": sev or ""} for s, k, d, sev in rows]

    def list_findings(self, limit: int = 0) -> list:
        return self.findings_full(limit=limit)

    def list_secret_candidates(self, limit: int = 2000) -> list:
        query = "SELECT type, value, source, severity, detail, steps FROM candidates ORDER BY id"
        params: list = []
        if limit:
            query += " LIMIT ?"
            params.append(max(1, min(int(limit), 5000)))
        rows = self.conn.execute(query, params).fetchall()
        return [{"type": t, "value": v, "source": s or "", "severity": sev or "",
                 "detail": d or "", "steps": _loads(steps, [])}
                for t, v, s, sev, d, steps in rows]

    def list_subdomains(self) -> list:
        rows = self.conn.execute(
            "SELECT host, resolved FROM subdomains ORDER BY host"
        ).fetchall()
        return [{"host": host, "resolved": int(resolved or 0)}
                for host, resolved in rows]

    def list_corroborations(self, limit: int = 2000) -> list:
        limit = max(1, min(int(limit or 2000), 5000))
        rows = self.conn.execute(
            "SELECT type, value, validator, verdict, confidence, detail FROM corroborations "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [{"type": t, "value": v, "validator": validator, "verdict": verdict,
                 "confidence": float(conf or 0.0), "detail": d or ""}
                for t, v, validator, verdict, conf, d in rows]

    def corroborations_map(self) -> dict:
        rows = self.conn.execute(
            "SELECT type, value, validator, verdict, confidence, detail FROM corroborations "
            "ORDER BY id"
        ).fetchall()
        result: dict = {}
        for t, v, validator, verdict, conf, d in rows:
            result.setdefault((t, v), []).append({
                "validator": validator, "verdict": verdict,
                "confidence": float(conf or 0.0), "detail": d or "",
            })
        return result
