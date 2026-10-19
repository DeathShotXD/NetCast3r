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
import ipaddress
from pathlib import Path
import socket
from urllib.parse import urlsplit

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
from .validate import Recipe, Validation, Validator, load_recipes
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

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class RunSummary:
    target: str
    pages: int = 0
    js_files: int = 0
    endpoints: int = 0
    candidates: int = 0
    verified: int = 0
    findings: int = 0
    corroborated: int = 0
    report: str = ""


class Orchestrator:
    def __init__(self, config, scope, store: Store, console: Console | None = None,
                 bus: ProviderBus | None = None, use_agents: bool = True,
                 validator: Validator | None = None, extractor: Extractor | None = None,
                 session: Session | None = None, seed_bodies: dict | None = None,
                 resume: bool = False, observer=None):
        self.config = config
        self.scope = scope
        self.store = store
        self.console = console or Console(show_reasoning=config.run.verbosity > 1,
                                          color=config.run.color)
        self.egress = ProxyPool(config.egress)
        self.bus = bus if bus is not None else ProviderBus(config, self.egress,
                                                           observer=observer)
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
        self.extractor = extractor or Extractor(patterns=patterns,
                                                max_scan=config.run.max_scan_bytes)
        self._out_of_scope: list[str] = []
        self._classified = 0
        self.seed_bodies = seed_bodies or {}
        self.last_findings: list[dict] = []
        self._unverified: list[dict] = []
        self._review: dict = {"endpoints": [], "loopholes": []}
        self.resume = resume
        self._known = store.validations_map() if resume else {}
        self._existing_findings = store.finding_keys() if resume else set()
        self._last_crawl_state: dict | None = None

    def run(self, seeds: list[str], should_stop=None) -> RunSummary:
        target = seeds[0] if seeds else ""
        self.console.header(target)
        summary: dict = {"pages": 0, "js_files": 0, "endpoints": 0, "candidates": 0,
                         "verified": 0, "findings": 0, "files_read": 0}
        findings: list[dict] = []
        try:
            summary, findings = self._pipeline(seeds, should_stop)
        except StopRun as exc:
            self.console.line("run", f"stop condition met: {exc}")
            summary = self._rebuild_from_store(summary)
            findings = self.last_findings
        except KeyboardInterrupt:
            self.console.line("run", "interrupted, writing what we have")
            summary = self._rebuild_from_store(summary)
            findings = self.last_findings
        except Exception as exc:  # noqa: BLE001 - a bad stage must still produce a report
            self.console.line("run", f"stage error ({type(exc).__name__}: {exc}); "
                                     f"writing what we have")
            summary = self._rebuild_from_store(summary)
            findings = self.last_findings

        self.last_findings = findings
        report_path = save_report(target, summary, findings, self.store.path.parent,
                                  self._out_of_scope, unverified=self._unverified,
                                  review=self._review)
        if self.config.run.write_json or self.config.run.output_format == "json":
            save_json(self.store.path.parent, summary, findings)
        if self.config.run.write_jsonl or self.config.run.output_format == "jsonl":
            save_jsonl(self.store.path.parent, findings)
        self.console.line("scribe", f"report written to {report_path}")
        self.console.summary({**summary, **self.session.stats.as_dict(), "report": str(report_path)})
        self.session.close()
        return RunSummary(target=target, pages=summary["pages"], js_files=summary["js_files"],
                          endpoints=summary["endpoints"], candidates=summary["candidates"],
                          verified=summary["verified"], findings=summary["findings"],
                          corroborated=summary.get("corroborated", 0),
                          report=str(report_path))

    @staticmethod
    def _stop_requested(should_stop) -> bool:
        try:
            return bool(should_stop and should_stop())
        except Exception:
            return False

    def _pipeline(self, seeds: list[str], should_stop=None):
        sink = getattr(self.console, "fetch", None)
        feed = sink if callable(sink) else None
        recon = Recon(self.scope, self.config, session=self.session, on_fetch=feed)

        result = self._crawl_stage(recon, seeds, should_stop)
        if self._stop_requested(should_stop):
            raise StopRun("stopped by request")
        self._out_of_scope = result.out_of_scope
        self.console.line("recon", f"{len(result.pages)} pages, {len(result.js_urls)} js files, "
                                   f"{len(result.endpoints)} endpoints, "
                                   f"{len(result.out_of_scope)} skipped out of scope")
        self.console.counts(pages=len(result.pages), js_files=len(result.js_urls),
                            endpoints=len(result.endpoints))

        candidates = self._hunt_stage(result)
        if self._stop_requested(should_stop):
            raise StopRun("stopped by request")

        review_notes = self._read_stage(result)
        candidates = self._expand_stage(recon, result, candidates, review_notes)
        if self._stop_requested(should_stop):
            raise StopRun("stopped by request")

        findings, unverified = self._validate_stage(candidates)
        if self._stop_requested(should_stop):
            raise StopRun("stopped by request")

        self._escalate_stage(findings, should_stop)

        confidence = (round(sum(self._as_float(f.get("confidence", 0)) for f in findings)
                            / len(findings), 2)
                      if findings else 0.0)
        summary = {
            "pages": len(result.pages),
            "js_files": len(result.js_urls),
            "endpoints": len(result.endpoints),
            "candidates": len(candidates),
            "classified": self._classified,
            "unvalidated": len([c for c in candidates if c.type not in self.validator.recipes]),
            "verified": len(findings),
            "findings": len(findings),
            "confidence": confidence,
            "corroborated": sum(1 for f in findings
                                if (f.get("corroboration") or {}).get("total")),
        }
        return summary, findings

    # -- stages -----------------------------------------------------------

    def _stage_done(self, name: str) -> bool:
        if not self.resume:
            return False
        try:
            return self.store.stage_done(name)
        except Exception:  # noqa: BLE001 - an old store has no stage table
            return False

    def _crawl_stage(self, recon: Recon, seeds: list[str], should_stop):
        if self._stage_done("crawl"):
            result = self._load_recon_result()
            self.console.line("recon", f"crawl already done: {len(result.pages)} pages, "
                                       f"{len(result.js_urls)} js files loaded from the store")
            return result
        self.store.stage_begin("crawl")
        self._last_crawl_state = None
        checkpoint = self.store.get_checkpoint("crawl") if self.resume else None
        if checkpoint is not None:
            result = self._load_recon_result()
            queue = checkpoint.get("queue") or []
            seen = checkpoint.get("seen") or []
            self.console.line("recon", f"resuming crawl: {len(seen)} urls already read, "
                                       f"{len(queue)} still queued")
            result = recon.crawl(seeds, should_stop=should_stop,
                                 resume=(queue, seen, result),
                                 on_discover=self._discover,
                                 on_checkpoint=self._checkpoint)
        else:
            seeds = self._map_subdomains(recon, seeds)
            result = recon.crawl(seeds, should_stop=should_stop,
                                 on_discover=self._discover,
                                 on_checkpoint=self._checkpoint)
        interrupted = bool(self._last_crawl_state
                           and self._last_crawl_state.get("queue"))
        if not interrupted:
            discovered = recon.discover_apis(seeds)
            discovered += recon.discover_wellknown(seeds)
            if discovered:
                result.endpoints = sorted(set(result.endpoints) | set(discovered))
            if self.config.run.wayback:
                self._augment_wayback(recon, seeds, result)
            self._wordlist(result)
        self._persist_recon(result)
        if interrupted:
            # keep the checkpoint and leave the stage running so a resume
            # walks the remaining queue instead of starting over
            return result
        self.store.clear_checkpoint("crawl")
        self.store.stage_end("crawl", detail=f"{len(result.pages)} pages, "
                                             f"{len(result.js_urls)} js files, "
                                             f"{len(result.endpoints)} endpoints")
        return result

    def _discover(self, kind: str, url: str, text: str | None = None) -> None:
        """One new artifact, persisted the moment the crawler finds it."""
        try:
            if kind == "page":
                self.store.add_asset(url, "page", 200)
                if text:
                    self.store.save_body(url, "page", text)
            elif kind == "js":
                self.store.add_js(url, text or "")
            elif kind == "endpoint":
                self.store.add_endpoint(url, "js")
            elif kind == "out-of-scope":
                self.store.add_asset(url, "out-of-scope", 0)
        except Exception:  # noqa: BLE001 - persistence must never stop a crawl
            pass

    def _checkpoint(self, state: dict) -> None:
        self._last_crawl_state = state
        try:
            self.store.set_checkpoint("crawl", state)
        except Exception:  # noqa: BLE001 - a bad write must never stop a crawl
            pass

    def _persist_recon(self, result) -> None:
        for url in result.pages:
            self.store.add_asset(url, "page", 200)
            body = result.page_text.get(url, "")
            if body:
                self.store.save_body(url, "page", body)
        for url in result.js_urls:
            self.store.add_js(url, result.js_text.get(url, ""))
        for url in result.endpoints:
            self.store.add_endpoint(url, "js")
        for url in result.out_of_scope:
            self.store.add_asset(url, "out-of-scope", 0)

    def _load_recon_result(self):
        from .recon import ReconResult
        result = ReconResult()
        bodies = self.store.bodies_map()
        for url in self.store.list_asset_urls("page"):
            result.pages.append(url)
            result.page_text[url] = bodies.get(url, "")
        for row in self.store.list_js(limit=0):
            url = row["url"]
            result.js_urls.append(url)
            result.js_text[url] = bodies.get(url, "")
        result.endpoints = self.store.list_endpoint_urls()
        result.out_of_scope = self.store.list_asset_urls("out-of-scope")
        return result

    def _hunt_stage(self, result):
        if self._stage_done("hunt"):
            candidates = self._load_candidates()
            self.console.line("prospector", f"{len(candidates)} candidates loaded "
                                            f"from the store")
            self.console.counts(candidates=len(candidates))
            return candidates
        self.store.stage_begin("hunt")
        scan_text = dict(result.js_text)
        scan_text.update(self.seed_bodies)
        scan_text.update(self._inline_scripts(result.page_text))
        candidates = self._prospect(scan_text)
        self.console.line("prospector", f"{len(candidates)} candidates")
        self.console.counts(candidates=len(candidates))
        candidates = self._classify(candidates)
        candidates = self._triage(candidates)
        self.store.stage_end("hunt", detail=f"{len(candidates)} candidates")
        return candidates

    def _load_candidates(self) -> list[Secret]:
        candidates = []
        for row in self.store.secrets_all():
            candidates.append(Secret(
                type=str(row["type"]), value=str(row["value"]), pattern_id="",
                source=str(row["source"] or ""), context=str(row["context"] or ""),
                confidence=self._as_float(row.get("confidence"))))
        return candidates

    def _read_stage(self, result) -> dict:
        if self._stage_done("readjs"):
            notes = self.store.notes_map()
            self._review = self._review_summary(notes)
            self.console.line("exegete", f"{len(notes)} file notes loaded from the store")
            return notes
        self.store.stage_begin("readjs")
        notes = self._exegete(result.js_text)
        for url, data in notes.items():
            self.store.save_note(url, data)
        self._review = self._review_summary(notes)
        self.store.stage_end("readjs", detail=f"{len(notes)} files")
        return notes

    def _expand_stage(self, recon: Recon, result, candidates, review_notes):
        if self._stage_done("expand"):
            return candidates
        self.store.stage_begin("expand")
        refs = self._ai_refs(review_notes)
        added = self._expand_js(recon, result, refs)
        extra = 0
        if added:
            found = self._prospect(added)
            extra = len(found)
            candidates.extend(found)
        self.store.stage_end("expand", detail=f"{len(added)} files, {extra} candidates")
        return candidates

    @staticmethod
    def _ai_refs(notes: dict) -> list[tuple[str, str]]:
        """Module paths the exegete saw inside each file, as (source, spec)."""
        refs: list[tuple[str, str]] = []
        for source, data in (notes or {}).items():
            if not isinstance(data, dict):
                continue
            for item in data.get("imports", []) or []:
                if isinstance(item, str):
                    spec = item
                elif isinstance(item, dict):
                    spec = item.get("path") or item.get("url") or ""
                else:
                    spec = ""
                spec = str(spec).strip()
                if spec:
                    refs.append((source, spec))
        return refs[:300]

    def _expand_js(self, recon: Recon, result, refs: list[tuple[str, str]],
                   limit: int = 40) -> dict:
        """Fetch the script files the model spotted inside other scripts."""
        added: dict = {}
        queue = list(refs)
        tried: set[str] = set()
        while queue and len(added) < limit:
            source, spec = queue.pop(0)
            for url in self._expand_candidates(source, spec):
                if url in tried:
                    continue
                tried.add(url)
                if url in result.js_text or not self.scope.is_in_scope(url):
                    continue
                status, text, content_type = recon.fetch(url)
                if status != 200 or not text:
                    continue
                if "text/html" in content_type:
                    continue
                result.js_urls.append(url)
                result.js_text[url] = text
                added[url] = text
                self.store.add_js(url, text)
                from .recon import ENDPOINT_RE
                from urllib.parse import urljoin
                for endpoint in ENDPOINT_RE.findall(text):
                    absolute = urljoin(url, endpoint)
                    if absolute not in result.endpoints:
                        result.endpoints.append(absolute)
                        self.store.add_endpoint(absolute, "js")
                for child in recon.js_children(url, text, cap=20):
                    if self.scope.is_in_scope(child) and child not in result.js_text:
                        queue.append((url, child))
                break
        if added:
            self.console.line("exegete", f"{len(added)} more js files hunted down and read")
        return added

    @staticmethod
    def _expand_candidates(source: str, spec: str) -> list[str]:
        from urllib.parse import urljoin
        base = urljoin(source, spec) if spec else ""
        if not base:
            return []
        candidates = [base]
        path = base.split("?")[0].lower()
        if not path.endswith((".js", ".mjs", ".cjs", ".jsx")):
            candidates.append(base + ".js")
            candidates.append(base.rstrip("/") + "/index.js")
        return candidates

    def _validate_stage(self, candidates):
        if self._stage_done("validate"):
            findings = self.store.findings_full()
            unverified = self._load_unverified()
            self._unverified = unverified
            self.console.line("assayer", f"{len(findings)} findings loaded from the store")
            return findings, unverified
        self.store.stage_begin("validate")
        findings, unverified = self._assay(candidates)
        findings = self._sentinel(findings)
        findings, unverified = self._corroborate(findings, unverified)
        self._unverified = unverified
        for item in unverified:
            self.store.add_candidate(item["type"], item["value"], item["source"],
                                     item["severity"], item["detail"], item["steps"])
        for source, kind, detail, severity in self._review_rows():
            self.store.add_review(source, kind, detail, severity)
        self._persist_findings(findings)
        self.store.stage_end("validate", detail=f"{len(findings)} verified, "
                                                f"{len(unverified)} unverified")
        return findings, unverified

    def _persist_findings(self, findings: list[dict]) -> None:
        for finding in findings:
            key = (finding["secret_type"], finding["value"])
            if key in self._existing_findings:
                continue
            self.store.add_finding(finding["title"], finding["severity"],
                                   finding["secret_type"], finding["value"],
                                   finding["impact"], finding["proof"],
                                   source=finding.get("source", ""),
                                   status=finding.get("status", ""),
                                   confidence=self._as_float(finding.get("confidence")),
                                   corroboration=finding.get("corroboration"))
            self._existing_findings.add(key)

    def _corroborate(self, findings: list[dict], unverified: list[dict]):
        """Check every verified finding again, then put it to a model panel.

        A second request to the same provider endpoint proves the answer is
        repeatable rather than a one-off. Then two models from different
        providers read the claim and the evidence and give a verdict. A
        finding that fails either check is demoted to the unverified list
        instead of being reported.
        """
        if not findings:
            return findings, unverified
        remaining: list[dict] = []
        for finding in findings:
            demoted = ""
            if getattr(self.config.run, "recheck_live", True):
                recipe = (self.validator.recipes.get(finding["secret_type"])
                          or self.validator.recipes.get(f"{finding['secret_type']}_write"))
                needs_pair = bool(recipe and recipe.pair_type
                                  and not finding.get("pair_value"))
                if not needs_pair:
                    again = self.validator.validate(finding["secret_type"], finding["value"],
                                                    finding.get("source", ""),
                                                    finding.get("pair_value", ""))
                    self.store.add_corroboration(finding["secret_type"], finding["value"],
                                                 "recheck", again.status, 0.0, again.detail)
                    if again.status == "unverified":
                        demoted = f"a second live check returned {again.detail or 'unverified'}"
            verdicts = [] if demoted else self._model_verdicts(finding)
            if verdicts:
                live = sum(1 for verdict in verdicts if verdict["live"])
                total = len(verdicts)
                finding["corroboration"] = {"live": live, "total": total,
                                            "verdicts": verdicts}
                finding["confidence"] = round(0.7 + 0.3 * (live / total), 2)
                if total >= 2 and live == 0:
                    demoted = (f"{total} models from different providers found no sign "
                               f"the credential is live")
                elif live < total:
                    finding["status"] = (f"{finding['status']} "
                                         f"(disputed by {total - live} of {total} models)")
            if demoted:
                self.console.finding("unverified", finding["secret_type"], finding["value"],
                                     f"{demoted} (corroboration)")
                steps = self.knowledge.escalation(finding["secret_type"]) or [
                    "Send the value to the provider's identity endpoint.",
                    "Confirm the account or resource it controls, then rotate it.",
                ]
                unverified.append({
                    "type": finding["secret_type"],
                    "value": finding["value"],
                    "source": finding.get("source", ""),
                    "severity": finding.get("severity", "medium"),
                    "detail": demoted,
                    "steps": steps,
                })
                continue
            remaining.append(finding)
        return remaining, unverified

    def _model_verdicts(self, finding: dict) -> list[dict]:
        calls = int(getattr(self.config.run, "corroboration_calls", 2) or 0)
        if not (self.use_agents and calls > 0):
            return []
        verdicts: list[dict] = []
        used: set[str] = set()
        for _ in range(calls):
            if not self.roster.verifier.available():
                break
            result = self.roster.verifier.corroborate(
                finding["secret_type"], finding["value"], finding.get("status", ""),
                finding.get("proof", ""), on_reasoning=self._reason("verifier"),
                exclude_providers=used)
            if not result.used_model or not result.provider:
                break
            used.add(result.provider)
            data = result.data if isinstance(result.data, dict) else {}
            live = self._truthy(data.get("live"))
            confidence = self._as_float(data.get("confidence"))
            reason = str(data.get("reason") or "").strip()
            verdicts.append({"provider": result.provider, "model": result.model,
                             "live": live, "confidence": confidence, "reason": reason})
            self.store.add_corroboration(finding["secret_type"], finding["value"],
                                         f"{result.provider}/{result.model}",
                                         "live" if live else "suspect",
                                         confidence, reason)
        return verdicts

    def _escalate_stage(self, findings: list[dict], should_stop) -> None:
        if self._stage_done("escalate"):
            return
        self.store.stage_begin("escalate")
        for finding in findings:
            if self._stop_requested(should_stop):
                raise StopRun("stopped by request")
            if finding.get("reproduction"):
                continue
            steps, narrative = self._escalate(finding)
            finding["reproduction"] = steps
            if narrative:
                finding.setdefault("notes", narrative)
            self._scribe(finding)
            self.store.update_finding_details(
                finding["secret_type"], finding["value"],
                reproduction=steps, notes=finding.get("notes", ""),
                narrative=finding.get("narrative", ""),
                model_steps=finding.get("model_steps"),
                model_severity=finding.get("model_severity", ""),
                model_impact=finding.get("model_impact", ""))
        self.console.counts(verified=len(findings), findings=len(findings))
        self.store.stage_end("escalate", detail=f"{len(findings)} findings written up")

    def _load_unverified(self) -> list[dict]:
        items = []
        for row in self.store.list_secret_candidates(limit=0):
            items.append({"type": row["type"], "value": row["value"],
                          "source": row["source"], "severity": row["severity"],
                          "detail": row["detail"], "steps": row["steps"]})
        return items

    def _rebuild_from_store(self, base: dict) -> dict:
        """What the run knows, read straight from the store after a stop."""
        try:
            counts = self.store.counts()
            findings = self.store.findings_full()
        except Exception:  # noqa: BLE001 - never fail a report over a read
            return base
        self.last_findings = findings
        if not self._unverified:
            self._unverified = self._load_unverified()
        if not (self._review.get("endpoints") or self._review.get("loopholes")):
            self._review = self._load_review()
        if not self._out_of_scope:
            self._out_of_scope = self.store.list_asset_urls("out-of-scope")
        confidence = (round(sum(self._as_float(f.get("confidence", 0)) for f in findings)
                            / len(findings), 2)
                      if findings else 0.0)
        return {
            "pages": self.store.count_assets("page"),
            "js_files": counts.get("js_files", 0),
            "endpoints": counts.get("endpoints", 0),
            "candidates": counts.get("secrets", 0),
            "classified": self._classified,
            "unvalidated": 0,
            "verified": len(findings),
            "findings": len(findings),
            "confidence": confidence,
            "corroborated": sum(1 for f in findings
                                if (f.get("corroboration") or {}).get("total")),
        }

    def _load_review(self) -> dict:
        review = {"endpoints": [], "loopholes": []}
        for row in self.store.list_reviews(limit=0):
            if row["kind"] == "endpoint":
                review["endpoints"].append({"source": row["source"],
                                            "path": row["detail"],
                                            "method": "", "note": ""})
            elif row["kind"] == "loophole":
                review["loopholes"].append({"source": row["source"],
                                            "detail": row["detail"],
                                            "severity": row["severity"],
                                            "evidence": ""})
        return review

    @staticmethod
    def _inline_scripts(page_text: dict) -> dict:
        from .recon import inline_scripts
        blocks: dict = {}
        for url, text in page_text.items():
            for index, body in enumerate(inline_scripts(text)):
                blocks[f"{url} [inline {index + 1}]"] = body
        return blocks

    def _map_subdomains(self, recon: Recon, seeds: list[str]) -> list[str]:
        added = recon.expand_seeds(seeds)
        hosts = set()
        for url in seeds + added:
            host = url.split("//")[-1].split("/")[0].split(":")[0].strip(".")
            if host:
                hosts.add(host)
        for host in sorted(hosts):
            self.store.add_subdomain(host)
        if added:
            self.console.line("recon", f"{len(added)} subdomains mapped, crawling each one")
        return seeds + added

    def _seed_domains(self, seeds: list[str]) -> list[str]:
        domains: list[str] = []
        for seed in seeds:
            host = seed.split("//")[-1].split("/")[0].split(":")[0].lower()
            if not host or host in domains:
                continue
            try:
                ipaddress.ip_address(host)
                continue
            except ValueError:
                pass
            domains.append(host)
        return domains

    def _augment_wayback(self, recon: Recon, seeds: list[str], result) -> None:
        domains = self._seed_domains(seeds)
        if not domains:
            return
        known = set(result.js_text)
        urls = recon.historical_js(domains, limit=self.config.run.wayback_limit,
                                   max_js=self.config.run.wayback_js_max)
        added = 0
        for url in urls:
            if url in known:
                continue
            status, text, content_type = recon.fetch(url)
            if status == 200 and text:
                result.js_urls.append(url)
                result.js_text[url] = text
                added += 1
        if added:
            self.console.line("recon", f"{added} historical js files from the wayback machine")

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

    @staticmethod
    def _as_float(value, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _as_int(value, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

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
                self.store.add_secret(secret.type, secret.value, secret.source,
                                      secret.context, confidence=secret.confidence)
        return candidates

    def _classify(self, candidates: list[Secret]) -> list[Secret]:
        if not (self.use_agents and candidates and self.roster.classifier.available()):
            return candidates
        unknown: list[Secret] = []
        for secret in candidates:
            known = self.knowledge.classification(secret.value)
            if known and known.get("type"):
                if known["type"] in self.validator.recipes:
                    secret.type = known["type"]
                    secret.confidence = max(secret.confidence,
                                            self._as_float(known.get("confidence")))
                    continue
            if secret.type == "generic" or secret.type not in self.validator.recipes:
                unknown.append(secret)
        if not unknown:
            return candidates
        payload = [{"value": s.value[:64], "context": s.context[:120]} for s in unknown[:40]]
        result = self.roster.classifier.classify(payload, on_reasoning=self._reason("classifier"))
        data = result.data if isinstance(result.data, dict) else {}
        items = data.get("items")
        items = items if isinstance(items, list) else []
        by_value = {}
        for item in items:
            if isinstance(item, dict) and item.get("value"):
                by_value[str(item["value"])[:64]] = item
        retyped = 0
        for secret in unknown:
            item = by_value.get(secret.value[:64])
            if not item:
                continue
            new_type = str(item.get("type", "")).strip().lower().replace(" ", "_")
            provider = str(item.get("provider", "")).strip().lower().replace(" ", "_")
            confidence = self._as_float(item.get("confidence"))
            self.knowledge.remember_classification(secret.value, {
                "type": new_type or provider,
                "provider": provider,
                "confidence": confidence,
                "is_secret": self._truthy(item.get("is_secret")),
            })
            if not self._truthy(item.get("is_secret")):
                continue
            resolved = new_type if new_type in self.validator.recipes else provider
            if resolved in self.validator.recipes:
                secret.type = resolved
                secret.confidence = max(secret.confidence, round(confidence, 2))
                retyped += 1
        if retyped:
            self._classified = retyped
            self.console.line("classifier", f"{retyped} candidates re-typed by the model")
        return candidates

    def _triage(self, candidates: list[Secret]) -> list[Secret]:
        if not (self.use_agents and candidates and self.roster.prospector.available()):
            return candidates
        payload = [{"type": s.type, "value": s.value[:24], "confidence": s.confidence,
                    "context": s.context[:80], "source": s.source} for s in candidates]
        result = self.roster.prospector.triage(payload, on_reasoning=self._reason("prospector"))
        data = result.data if isinstance(result.data, dict) else {}
        items = data.get("items")
        items = items if isinstance(items, list) else []
        order = {}
        for item in items:
            if isinstance(item, dict) and item.get("value"):
                order[str(item["value"])[:24]] = self._as_int(item.get("priority"), 100)
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
        # every file streams its own reasoning tokens; into one sink they
        # interleave into noise, so each file buffers and flushes in order,
        # tagged with the path it is thinking about
        from threading import Lock

        lock = Lock()
        buffers: dict[str, list[str]] = {}

        def sink(url: str):
            def absorb(text: str) -> None:
                with lock:
                    buffers.setdefault(url, []).append(text)
            return absorb

        def flush(url: str) -> None:
            text = " ".join(buffers.pop(url, [])).strip()
            if not text:
                return
            head = url.rsplit("/", 1)[-1][:40]
            self.console.reasoning("exegete", f"[{head}] {text[:400]}")

        with ThreadPoolExecutor(max_workers=min(8, len(js_text))) as pool:
            futures = {pool.submit(self.roster.exegete.analyze, url, text,
                                   sink(url)): url
                       for url, text in js_text.items()}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                except Exception:  # noqa: BLE001 - one bad file must not lose the rest
                    continue
                flush(url)
                if result.data:
                    notes[url] = result.data
        return notes

    @staticmethod
    def _truthy(value) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes")
        return bool(value)

    @staticmethod
    def _review_summary(notes: dict) -> dict:
        """Fold the exegete's per-file notes into one review of endpoints and weak points."""
        endpoints: list[dict] = []
        loopholes: list[dict] = []
        if isinstance(notes, dict):
            for source, data in notes.items():
                if not isinstance(data, dict):
                    continue
                for item in data.get("endpoints", []) or []:
                    if isinstance(item, dict):
                        endpoints.append({"source": source, "path": str(item.get("path", "")),
                                          "method": str(item.get("method", "")),
                                          "note": str(item.get("note", ""))})
                for item in data.get("loopholes", []) or []:
                    if isinstance(item, dict):
                        loopholes.append({"source": source, "detail": str(item.get("detail", "")),
                                          "severity": str(item.get("severity", "")),
                                          "evidence": str(item.get("evidence", ""))})
        return {"endpoints": endpoints, "loopholes": loopholes}

    def _review_rows(self) -> list[tuple[str, str, str, str]]:
        rows: list[tuple[str, str, str, str]] = []
        for item in self._review.get("endpoints", [])[:200]:
            rows.append((item.get("source", ""), "endpoint",
                         f"{item.get('method', '').upper()} {item.get('path', '')} "
                         f"{item.get('note', '')}".strip(), ""))
        for item in self._review.get("loopholes", [])[:200]:
            rows.append((item.get("source", ""), "loophole", item.get("detail", ""),
                         item.get("severity", "")))
        return rows

    def _assay(self, candidates: list[Secret]) -> tuple[list[dict], list[dict]]:
        findings: list[dict] = []
        unverified: list[dict] = []
        show_progress = bool(candidates) and not getattr(self.console, "is_dashboard", False)
        progress = Progress(self.console, len(candidates), "validating") if show_progress else None
        by_source: dict[tuple[str, str], str] = {}
        by_type: dict[str, str] = {}
        for candidate in candidates:
            by_type.setdefault(candidate.type, candidate.value)
            if candidate.source:
                by_source.setdefault((candidate.source, candidate.type), candidate.value)
        for secret in candidates:
            key = (secret.type, secret.value)
            value2 = ""
            if self.resume and key in self._known:
                known = self._known[key]
                validation = Validation(secret.type, secret.value, known["status"],
                                        provider=known["provider"], detail=known["detail"],
                                        evidence=known["evidence"])
                self.console.finding(validation.status, secret.type, secret.value,
                                     f"{validation.detail} (reused)")
            else:
                self._ensure_recipe(secret.type)
                pair = ""
                for name in (secret.type, f"{secret.type}_write"):
                    recipe = self.validator.recipes.get(name)
                    if recipe is not None and recipe.pair_type:
                        pair = recipe.pair_type
                        break
                value2 = ""
                if pair:
                    value2 = (by_source.get((secret.source, pair), "")
                              or by_type.get(pair, ""))
                validation = self.validator.validate(secret.type, secret.value, secret.source, value2)
                self.store.add_validation(secret.type, secret.value, validation.status,
                                          validation.provider, validation.detail, validation.evidence)
                self.console.finding(validation.status, secret.type, secret.value, validation.detail)
            if validation.status == "verified":
                if key not in self._existing_findings:
                    finding = self._finding(secret, validation)
                    finding["pair_value"] = value2
                    findings.append(finding)
            else:
                severity = SEVERITY_BY_TYPE.get(secret.type, "medium")
                if severity in ("critical", "high"):
                    steps = self.knowledge.escalation(secret.type) or [
                        "Send the value to the provider's identity endpoint.",
                        "Confirm the account or resource it controls, then rotate it.",
                    ]
                    unverified.append({
                        "type": secret.type, "value": secret.value,
                        "source": secret.source, "severity": severity,
                        "detail": validation.detail or validation.status,
                        "steps": steps,
                    })
            if progress:
                progress.advance()
        if progress:
            progress.close()
        return findings, unverified

    def _ensure_recipe(self, secret_type: str) -> None:
        if secret_type in self.validator.recipes:
            return
        if not (self.use_agents and self.config.run.allow_model_checks
                and self.roster.assayer.available()):
            return
        result = self.roster.assayer.plan(secret_type, "", on_reasoning=self._reason("assayer"))
        data = result.data if isinstance(result.data, dict) else {}
        url = str(data.get("url") or "")
        method = str(data.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            return
        if method == "POST" and self.config.run.action_tier not in ("write", "full"):
            method = "GET"
        if not self._safe_check(url):
            self.console.line("assayer", f"rejected an unsafe check for {secret_type}")
            return
        raw_headers = data.get("headers")
        raw_headers = raw_headers if isinstance(raw_headers, dict) else {}
        self.validator.recipes[secret_type] = Recipe(
            type=secret_type,
            provider=str(data.get("provider") or secret_type),
            method=method,
            url=url,
            headers={str(k): str(v) for k, v in raw_headers.items()},
            success_match=str(data.get("success_marker") or ""),
            write=(method != "GET"),
        )
        self.console.line("assayer", f"planned a read only check for {secret_type}")

    @staticmethod
    def _safe_check(url: str) -> bool:
        try:
            parts = urlsplit(url)
        except Exception:
            return False
        if parts.scheme != "https":
            return False
        host = (parts.hostname or "").lower()
        if not host or host in ("localhost", "0.0.0.0", "::1", "169.254.169.254"):
            return False
        if host.endswith((".local", ".internal", ".localhost")):
            return False
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        except ValueError:
            pass
        # A name that resolves to a private address is still an SSRF target,
        # so resolve before trusting it. An unresolvable name is allowed here:
        # the request itself will fail.
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError:
            return True
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0])
            except ValueError:
                continue
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                return False
        return True

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
            "confidence": secret.confidence,
            "reproduction": [],
        }

    def _escalate(self, finding: dict):
        steps = self.knowledge.escalation(finding["secret_type"])
        narrative = ""
        if self.use_agents and self.roster.chainer.available():
            result = self.roster.chainer.escalate(finding["secret_type"], finding["status"],
                                                  on_reasoning=self._reason("chainer"))
            data = result.data if isinstance(result.data, dict) else {}
            raw_steps = data.get("steps")
            raw_steps = raw_steps if isinstance(raw_steps, list) else []
            ai_steps = [str(step.get("command")) for step in raw_steps
                        if isinstance(step, dict) and step.get("command")]
            if ai_steps:
                finding["model_steps"] = ai_steps
            severity = str(data.get("severity") or "").strip().lower()
            if severity in VALID_SEVERITIES:
                finding["model_severity"] = severity
            impact = str(data.get("impact") or "").strip()
            if impact:
                finding["model_impact"] = impact
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
