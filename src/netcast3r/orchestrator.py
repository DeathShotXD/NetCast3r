"""Orchestrator.

Runs the pipeline: recon, then the prospector and the exegete side by side,
then the assayer, the chainer, the sentinel, and the report. Every agent is
optional. When no provider is reachable the run falls back to the
deterministic path and still produces a report.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .agents import Roster
from .egress import ProxyPool
from .knowledge import Knowledge
from .providers import ProviderBus
from .recon import Recon
from .report import save as save_report
from .secrets import Extractor, Secret
from .store import Store
from .tui import Console
from .validate import Validator, load_recipes


SEVERITY_BY_TYPE = {
    "aws": "critical",
    "private_key": "critical",
    "stripe_live": "critical",
    "github": "high",
    "gitlab": "high",
    "sendgrid": "high",
    "slack": "high",
    "google_api": "medium",
    "jwt": "medium",
    "generic": "medium",
}


@dataclass
class RunSummary:
    target: str
    pages: int = 0
    js_files: int = 0
    endpoints: int = 0
    candidates: int = 0
    verified: int = 0
    findings: int = 0
    report: str = ""


class Orchestrator:
    def __init__(self, config, scope, store: Store, console: Console | None = None,
                 bus: ProviderBus | None = None, use_agents: bool = True,
                 validator: Validator | None = None, extractor: Extractor | None = None):
        self.config = config
        self.scope = scope
        self.store = store
        self.console = console or Console()
        self.egress = ProxyPool(config.egress)
        self.bus = bus if bus is not None else ProviderBus(config, self.egress)
        self.knowledge = Knowledge()
        self.roster = Roster(self.bus, self.knowledge)
        self.use_agents = use_agents
        self.validator = validator or Validator(recipes=load_recipes(), tier=config.run.action_tier)
        self.extractor = extractor or Extractor()

    def run(self, seeds: list[str]) -> RunSummary:
        target = seeds[0] if seeds else ""
        self.console.header(target)

        recon = Recon(self.scope, self.config)
        result = recon.crawl(seeds)
        self.console.line("recon", f"{len(result.pages)} pages, {len(result.js_urls)} js files, "
                                   f"{len(result.endpoints)} endpoints, "
                                   f"{len(result.out_of_scope)} skipped out of scope")
        for url in result.pages:
            self.store.add_asset(url, "page", 200)
        for url in result.js_urls:
            self.store.add_js(url, result.js_text.get(url, ""))
        for url in result.endpoints:
            self.store.add_endpoint(url, "js")
        for url in result.out_of_scope:
            self.store.add_asset(url, "out-of-scope", 0)

        candidates = self._prospect(result.js_text)
        self.console.line("prospector", f"{len(candidates)} candidates")

        exegete_notes = self._exegete(result.js_text)

        findings = self._assay(candidates)
        findings = self._chainer(findings)
        findings = self._sentinel(findings)

        for finding in findings:
            self.store.add_finding(finding["title"], finding["severity"],
                                   finding["secret_type"], finding["value"],
                                   finding["impact"], finding["proof"])

        summary = {
            "pages": len(result.pages),
            "js_files": len(result.js_urls),
            "endpoints": len(result.endpoints),
            "candidates": len(candidates),
            "verified": len(findings),
            "findings": len(findings),
            "files_read": len(exegete_notes),
        }
        report_path = save_report(target, summary, findings, self.store.path.parent,
                                  result.out_of_scope)
        self.console.line("scribe", f"report written to {report_path}")
        self.console.summary({**summary, "report": str(report_path)})
        return RunSummary(target=target, pages=summary["pages"], js_files=summary["js_files"],
                          endpoints=summary["endpoints"], candidates=summary["candidates"],
                          verified=summary["verified"], findings=summary["findings"],
                          report=str(report_path))

    def _prospect(self, js_text: dict) -> list[Secret]:
        candidates: list[Secret] = []
        seen: set[tuple[str, str]] = set()
        for url, text in js_text.items():
            for secret in self.extractor.scan(text, source=url):
                key = (secret.type, secret.value)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(secret)
                self.store.add_secret(secret.type, secret.value, secret.source, secret.context)
        return candidates

    def _exegete(self, js_text: dict) -> dict:
        if not self.use_agents or not self.roster.exegete.available() or not js_text:
            self.console.line("exegete", "no provider reachable, deterministic path in use")
            return {}
        notes: dict = {}
        self.console.line("exegete", f"reading {len(js_text)} files")

        def reason(text: str) -> None:
            self.console.reasoning("exegete", text)

        with ThreadPoolExecutor(max_workers=min(8, len(js_text))) as pool:
            futures = {pool.submit(self.roster.exegete.analyze, url, text, reason): url
                       for url, text in js_text.items()}
            for future in as_completed(futures):
                result = future.result()
                if result.data:
                    notes[futures[future]] = result.data
        return notes

    def _assay(self, candidates: list[Secret]) -> list[dict]:
        findings: list[dict] = []
        for secret in candidates:
            validation = self.validator.validate(secret.type, secret.value, secret.source)
            self.store.add_validation(secret.type, secret.value, validation.status,
                                      validation.provider, validation.detail, validation.evidence)
            self.console.finding(validation.status, secret.type, secret.value, validation.detail)
            if validation.status == "verified":
                findings.append(self._finding(secret, validation))
        return findings

    def _finding(self, secret: Secret, validation) -> dict:
        severity = SEVERITY_BY_TYPE.get(secret.type, "high")
        provider = validation.provider or secret.type
        return {
            "title": f"{provider} credential exposed in client JavaScript",
            "severity": severity,
            "secret_type": secret.type,
            "value": secret.value,
            "source": secret.source,
            "status": f"{validation.status} ({validation.detail})",
            "impact": (f"A live {secret.type} credential is shipped to every visitor in "
                       f"{secret.source}. Anyone can read it and use it as the account."),
            "proof": validation.evidence or validation.detail,
            "reproduction": self._escalation(secret.type),
        }

    def _escalation(self, secret_type: str) -> list[str]:
        steps = self.knowledge.escalation(secret_type)
        if steps:
            return steps
        return ["Repeat the proof request to confirm the credential is still live."]

    def _chainer(self, findings: list[dict]) -> list[dict]:
        return findings

    def _sentinel(self, findings: list[dict]) -> list[dict]:
        unique: dict[tuple[str, str], dict] = {}
        for finding in findings:
            unique.setdefault((finding["secret_type"], finding["value"]), finding)
        return list(unique.values())
