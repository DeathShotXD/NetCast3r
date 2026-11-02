"""The regression bench.

A framework that cannot measure itself drifts. The bench runs a small corpus of
deterministic cases through the real engines - scope resolution, the source
rule engine, secret detection, the checklist catalog, and the Python
source-to-sink tracer - and scores detection against an expected set.

Every case is offline and reproducible. A case fails on a missed detection
(false negative) or an invented one (false positive). The gate is intentionally
strict: a deterministic unit gate should be exact, because the corpus is fixed.
Live-target quality is a different benchmark and is never mixed with this one.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import checklists, codeaudit, exploits, reveng, sourceflow
from .scope import ScopeManager


@dataclass
class BenchResult:
    case_id: str
    kind: str
    description: str
    expected: list[str]
    actual: list[str]
    error: str = ""
    duration_ms: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def passed(self) -> bool:
        return not self.error and self.fp == 0 and self.fn == 0

    def as_dict(self) -> dict:
        precision = (self.tp / (self.tp + self.fp)
                     if (self.tp + self.fp) else 1.0)
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0
        return {
            "id": self.case_id, "kind": self.kind,
            "description": self.description,
            "passed": self.passed, "error": self.error,
            "expected": sorted(self.expected), "actual": sorted(self.actual),
            "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "duration_ms": self.duration_ms,
        }


@dataclass
class BenchCase:
    case_id: str
    kind: str
    description: str
    expected: set[str]
    run: object
    tags: list[str] = field(default_factory=list)


def _sourceflow_labels(source: str) -> set[str]:
    result = sourceflow.analyze_text(source, "bench.py")
    return {f"{lead['severity']}:{lead['sink']}" for lead in result["leads"]}


def _case_sourceflow_rce() -> set[str]:
    return _sourceflow_labels(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/run')\n"
        "def run():\n"
        "    command = request.args.get('cmd')\n"
        "    return eval(command)\n")


def _case_sourceflow_sql() -> set[str]:
    return _sourceflow_labels(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/user')\n"
        "def user():\n"
        "    uid = request.args['id']\n"
        "    cursor.execute(f'select * from users where id = {uid}')\n"
        "    return 'ok'\n")


def _case_sourceflow_safe() -> set[str]:
    return _sourceflow_labels(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/user')\n"
        "def user():\n"
        "    cursor.execute('select * from users where id = ?', (request.args['id'],))\n"
        "    return 'ok'\n")


def _case_codeaudit_shell() -> set[str]:
    findings, _ = codeaudit.audit_text(
        "import subprocess\n\ndef run(command):\n"
        "    return subprocess.run(command, shell=True)\n",
        "python", "bench.py")
    return {finding["rule"] for finding in findings}


def _case_codeaudit_safe() -> set[str]:
    findings, _ = codeaudit.audit_text(
        "def add(left, right):\n    return left + right\n",
        "python", "bench.py")
    return {finding["rule"] for finding in findings}


def _case_scope_resolution() -> set[str]:
    manager = ScopeManager(in_scope=["example.com", "*.api.example.com",
                                     "!admin.example.com"])
    probes = [("app.example.com", "in"), ("api.example.com", "unknown"),
              ("admin.example.com", "out"), ("evil.example.net", "unknown")]
    return {f"{host}:{manager.classify(host)}" for host, _ in probes}


def _case_checklist_integrity() -> set[str]:
    known = {module["id"] for module in exploits.catalog()}
    problems: set[str] = set()
    for item in checklists.catalog():
        if not item.get("id") or not item.get("evidence"):
            problems.add(f"missing-metadata:{item.get('id') or 'unknown'}")
        for module_id in item.get("modules") or []:
            if module_id not in known:
                problems.add(f"unknown-module:{item['id']}:{module_id}")
    return problems


def _case_secret_detection() -> set[str]:
    result = reveng.analyze_js('const key = "AKIAIOSFODNN7EXAMPLE";\n')
    return {f"{item['severity']}:{item['category']}" for item in result["observations"]}


CASES: tuple[BenchCase, ...] = (
    BenchCase(
        "sourceflow.route_to_eval", "sourceflow",
        "A Flask route that evals request data is a critical chain.",
        {"critical:eval()"}, _case_sourceflow_rce, ["rce", "python"]),
    BenchCase(
        "sourceflow.route_to_sql", "sourceflow",
        "A Flask route that formats request data into SQL is a high chain.",
        {"high:cursor.execute()"}, _case_sourceflow_sql, ["sqli", "python"]),
    BenchCase(
        "sourceflow.parameterised_sql_is_safe", "sourceflow",
        "Parameterised SQL must not be reported as a chain.",
        set(), _case_sourceflow_safe, ["precision", "python"]),
    BenchCase(
        "codeaudit.shell_true", "codeaudit",
        "shell=True and the missing timeout are both real defects.",
        {"py-shell-true", "py-subprocess-timeout"}, _case_codeaudit_shell,
        ["python"]),
    BenchCase(
        "codeaudit.clean_function", "codeaudit",
        "A clean function must produce no defect.",
        set(), _case_codeaudit_safe, ["precision"]),
    BenchCase(
        "scope.wildcard_and_exclusion", "scope",
        "Wildcard subdomains resolve in scope and an exclusion wins.",
        {"app.example.com:in", "api.example.com:in",
         "admin.example.com:out", "evil.example.net:unknown"},
        _case_scope_resolution, ["scope"]),
    BenchCase(
        "checklists.catalog_integrity", "checklists",
        "Every checklist item has metadata and names a real exploit module.",
        set(), _case_checklist_integrity, ["catalog"]),
    BenchCase(
        "secrets.aws_key", "secrets",
        "An exposed AWS key is detected with the secret category.",
        {"high:secret"}, _case_secret_detection, ["secret"]),
)


def _run_case(case: BenchCase) -> BenchResult:
    started = time.monotonic()
    error = ""
    try:
        actual = set(case.run())
    except Exception as exc:  # noqa: BLE001 - a broken case is still a result
        actual = set()
        error = f"{type(exc).__name__}: {exc}"
    duration = int((time.monotonic() - started) * 1000)
    expected = set(case.expected)
    result = BenchResult(
        case_id=case.case_id, kind=case.kind, description=case.description,
        expected=sorted(expected), actual=sorted(actual), error=error,
        duration_ms=duration)
    result.tp = len(expected & actual)
    result.fp = len(actual - expected)
    result.fn = len(expected - actual)
    return result


def run(kind: str = "", case_id: str = "") -> dict:
    """Run the whole corpus, or one slice of it. Never touches a target."""
    wanted_kind = str(kind or "").strip().lower()
    wanted_case = str(case_id or "").strip()
    selected = [
        case for case in CASES
        if (not wanted_kind or case.kind == wanted_kind)
        and (not wanted_case or case.case_id == wanted_case)
    ]
    started = time.monotonic()
    results = [_run_case(case) for case in selected]
    total_tp = sum(result.tp for result in results)
    total_fp = sum(result.fp for result in results)
    total_fn = sum(result.fn for result in results)
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 1.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 1.0
    failures = [result.as_dict() for result in results if not result.passed]
    return {
        "cases": len(results),
        "passed": sum(1 for result in results if result.passed),
        "failed": len(failures),
        "tp": total_tp, "fp": total_fp, "fn": total_fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round((2 * precision * recall / (precision + recall))
                    if (precision + recall) else 0.0, 4),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "results": [result.as_dict() for result in results],
        "failures": failures,
        "kinds": sorted({case.kind for case in CASES}),
        "tags": sorted({tag for case in CASES for tag in case.tags}),
        "note": ("Deterministic offline corpus. A failing case is a regression "
                 "to fix, never a target finding."),
    }


def gate(result: dict, min_precision: float = 0.9,
         min_recall: float = 0.9) -> dict:
    """A release gate for the deterministic corpus."""
    checks = {
        "no_failed_cases": int(result.get("failed") or 0) == 0,
        "precision": float(result.get("precision") or 0.0) >= float(min_precision),
        "recall": float(result.get("recall") or 0.0) >= float(min_recall),
        "cases_run": int(result.get("cases") or 0) > 0,
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "min_precision": float(min_precision),
        "min_recall": float(min_recall),
        "precision": result.get("precision"),
        "recall": result.get("recall"),
    }


def save(path: str | Path, result: dict) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, default=str))
    return target
