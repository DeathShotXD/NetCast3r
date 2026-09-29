"""Evidence store.

Everything a run learns lands in one SQLite file so it can be replayed, diffed
between runs, and cited in the report.
"""

from __future__ import annotations

import hashlib
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
    created_at REAL
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

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

    def add_endpoint(self, url: str, source: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO endpoints (url, source, seen_at) VALUES (?, ?, ?)",
            (url, source, time.time()),
        )
        self.conn.commit()

    def add_secret(self, secret_type: str, value: str, source: str, context: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO secrets (type, value, source, context, seen_at) VALUES (?, ?, ?, ?, ?)",
            (secret_type, value, source, context, time.time()),
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

    def add_finding(self, title: str, severity: str, secret_type: str,
                    value: str, impact: str, evidence: str) -> None:
        self.conn.execute(
            "INSERT INTO findings (title, severity, secret_type, value, impact, evidence, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (title, severity, secret_type, value, impact, evidence, time.time()),
        )
        self.conn.commit()

    def counts(self) -> dict:
        result = {}
        for table in ("assets", "js_files", "endpoints", "secrets", "validations", "findings"):
            row = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            result[table] = row[0] if row else 0
        return result

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
