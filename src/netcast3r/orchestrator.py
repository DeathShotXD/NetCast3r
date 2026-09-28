"""Orchestrator.

Runs the pipeline: recon, then the prospector and the exegete side by side,
then the assayer, the chainer, the sentinel, and the report. Every model stage
is optional. When no provider is reachable the run falls back to the
deterministic path and still produces a report. A run that is stopped early
still writes what it has.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from .agents import Roster
from .egress import ProxyPool
from .http import Session, StopRun
from .knowledge import Knowledge
from .providers import ProviderBus
from .recon import Recon
from .report import save as save_report
from .report import save_json, save_jsonl
from .secrets import Extractor, Secret, load_patterns
from .store import Store
from .tui import Console, Progress
from .validate import Recipe, Validator, load_recipes
from .wordlist import Wordlist


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
                 validator: Validator | None = None, extractor: Extractor | None = None,
                 session: Session | None = None, seed_bodies: dict | None = None):
        self.config = config
        self.scope = scope
        self.store = store
        self.console = console or Console(show_reasoning=config.run.verbosity > 1,
                                          color=config.run.color)
        self.egress = ProxyPool(config.egress)
        self.bus = bus if bus is not None else ProviderBus(config, self.egress)
        self.knowledge = Knowledge()
        self.roster = Roster(self.bus, self.knowledge)
        self.use_agents = use_agents
        self.session = session or Session(config, self.egress)
        patterns = load_patterns(Path(config.run.patterns_file)) if config.run.patterns_file else None
        recipes = load_recipes(Path(config.run.recipes_file)) if config.run.recipes_file else None
        self.validator = validator or Validator(recipes=recipes or load_recipes(),
                                                tier=config.run.action_tier,
                                                timeout=config.run.timeout,
                                                session=self.session)
        self.extractor = extractor or Extractor(patterns=patterns)
        self._out_of_scope: list[str] = []
        self.seed_bodies = seed_bodies or {}
        self.last_findings: list[dict] = []

    def run(self, seeds: list[str]) -> RunSummary:
        target = seeds[0] if seeds else ""
        self.console.header(target)
        summary: dict = {"pages": 0, "js_files": 0, "endpoints": 0, "candidates": 0,
                         "verified": 0, "findings": 0, "files_read": 0}
        findings: list[dict] = []
        try:
            summary, findings = self._pipeline(seeds)
        except StopRun as exc:
            self.console.line("run", f"stop condition met: {exc}")
        except KeyboardInterrupt:
            self.console.line("run", "interrupted, writing what we have")

        self.last_findings = findings
        report_path = save_report(target, summary, findings, self.store.path.parent, self._out_of_scope)
        if self.config.run.output_format == "json":
            save_json(self.store.path.parent, summary, findings)
        elif self.config.run.output_format == "jsonl":
            save_jsonl(self.store.path.parent, findings)
        self.console.line("scribe", f"report written to {report_path}")
        self.console.summary({**summary, **self.session.stats.as_dict(), "report": str(report_path)})
        self.session.close()
        return RunSummary(target=target, pages=summary["pages"], js_files=summary["js_files"],
                          endpoints=summary["endpoints"], candidates=summary["candidates"],
                          verified=summary["verified"], findings=summary["findings"],
                          report=str(report_path))

    def _pipeline(self, seeds: list[str]):
        recon = Recon(self.scope, self.config, session=self.session)
        result = recon.crawl(seeds)
        self._out_of_scope = result.out_of_scope
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

        self._wordlist(result)

        scan_text = dict(result.js_text)
        scan_text.update(self.seed_bodies)
        candidates = self._prospect(scan_text)
        self.console.line("prospector", f"{len(candidates)} candidates")
        candidates = self._triage(candidates)

        self._exegete(result.js_text)
        findings = self._assay(candidates)

        for finding in findings:
            steps, narrative = self._escalate(finding)
            finding["reproduction"] = steps
            if narrative:
                finding.setdefault("notes", narrative)
            self._scribe(finding)
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
        }
        return summary, findings

    def _wordlist(self, result) -> None:
        words = Wordlist()
        for text in result.page_text.values():
            words.add_text(text)
        for text in result.js_text.values():
            words.add_text(text)
        for url in result.endpoints:
            words.add_url(url)
        for url in result.js_urls:
            words.add_url(url)
        if words.words():
            words.save(self.store.path.parent / "wordlist.txt")
            self.console.line("recon", f"{len(words.words())} words saved to wordlist.txt")

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

    def _triage(self, candidates: list[Secret]) -> list[Secret]:
        if not (self.use_agents and candidates and self.roster.prospector.available()):
            return candidates
        payload = [{"type": s.type, "value": s.value[:24], "source": s.source} for s in candidates]
        result = self.roster.prospector.triage(payload, on_reasoning=self._reason("prospector"))
        data = result.data or {}
        order = {}
        for item in data.get("items", []):
            if isinstance(item, dict) and item.get("value"):
                order[str(item["value"])[:24]] = int(item.get("priority", 100))
        if not order:
            return candidates
        ranked = sorted(candidates, key=lambda s: order.get(s.value[:24], 100))
        self.console.line("prospector", "candidates ranked by the model")
        return ranked

    def _exegete(self, js_text: dict) -> dict:
        if not (self.use_agents and self.roster.exegete.available() and js_text):
            self.console.line("exegete", "no provider reachable, deterministic path in use")
            return {}
        self.console.line("exegete", f"reading {len(js_text)} files")
        notes: dict = {}
        with ThreadPoolExecutor(max_workers=min(8, len(js_text))) as pool:
            futures = {pool.submit(self.roster.exegete.analyze, url, text,
                                   self._reason("exegete")): url
                       for url, text in js_text.items()}
            for future in as_completed(futures):
                result = future.result()
                if result.data:
                    notes[futures[future]] = result.data
        return notes

    def _assay(self, candidates: list[Secret]) -> list[dict]:
        findings: list[dict] = []
        progress = Progress(self.console, len(candidates), "validating") if candidates else None
        for secret in candidates:
            self._ensure_recipe(secret.type)
            validation = self.validator.validate(secret.type, secret.value, secret.source)
            self.store.add_validation(secret.type, secret.value, validation.status,
                                      validation.provider, validation.detail, validation.evidence)
            self.console.finding(validation.status, secret.type, secret.value, validation.detail)
            if validation.status == "verified":
                findings.append(self._finding(secret, validation))
            if progress:
                progress.advance()
        if progress:
            progress.close()
        return findings

    def _ensure_recipe(self, secret_type: str) -> None:
        if secret_type in self.validator.recipes:
            return
        if not (self.use_agents and self.config.run.allow_model_checks
                and self.roster.assayer.available()):
            return
        result = self.roster.assayer.plan(secret_type, "", on_reasoning=self._reason("assayer"))
        data = result.data or {}
        url = str(data.get("url") or "")
        if not url.startswith("http"):
            return
        self.validator.recipes[secret_type] = Recipe(
            type=secret_type,
            provider=str(data.get("provider") or secret_type),
            method=str(data.get("method") or "GET").upper(),
            url=url,
            headers=dict(data.get("headers") or {}),
            success_match=str(data.get("success_marker") or ""),
        )
        self.console.line("assayer", f"planned a read only check for {secret_type}")

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
            "reproduction": [],
        }

    def _escalate(self, finding: dict):
        steps = self.knowledge.escalation(finding["secret_type"])
        narrative = ""
        if self.use_agents and self.roster.chainer.available():
            result = self.roster.chainer.escalate(finding["secret_type"], finding["status"],
                                                  on_reasoning=self._reason("chainer"))
            data = result.data or {}
            ai_steps = [str(step.get("command")) for step in data.get("steps", [])
                        if isinstance(step, dict) and step.get("command")]
            if ai_steps:
                steps = ai_steps + steps
            if data.get("impact"):
                finding["impact"] = str(data["impact"])
            if data.get("severity"):
                finding["severity"] = str(data["severity"]).lower()
            narrative = str(data.get("notes") or "")
        if not steps:
            steps = ["Repeat the proof request to confirm the credential is still live."]
        return steps, narrative

    def _scribe(self, finding: dict) -> None:
        if not (self.use_agents and self.roster.scribe.available()):
            return
        result = self.roster.scribe.write(finding, on_reasoning=self._reason("scribe"))
        if result.text.strip():
            finding["narrative"] = result.text.strip()

    def _sentinel(self, findings: list[dict]) -> list[dict]:
        unique: dict[tuple[str, str], dict] = {}
        for finding in findings:
            unique.setdefault((finding["secret_type"], finding["value"]), finding)
        return list(unique.values())

    def _reason(self, agent: str):
        def sink(text: str) -> None:
            self.console.reasoning(agent, text)
        return sink
