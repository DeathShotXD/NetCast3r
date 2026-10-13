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
        except KeyboardInterrupt:
            self.console.line("run", "interrupted, writing what we have")
        except Exception as exc:  # noqa: BLE001 - a bad stage must still produce a report
            self.console.line("run", f"stage error ({type(exc).__name__}: {exc}); "
                                     f"writing what we have")

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
        originals = list(seeds)
        seeds = self._map_subdomains(recon, seeds)
        result = recon.crawl(seeds)
        if self._stop_requested(should_stop):
            raise StopRun("stopped by request")
        discovered = recon.discover_apis(seeds)
        discovered += recon.discover_wellknown(seeds)
        if discovered:
            result.endpoints = sorted(set(result.endpoints) | set(discovered))
        self._out_of_scope = result.out_of_scope
        if self.config.run.wayback:
            self._augment_wayback(recon, originals, result)
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
        self.console.counts(pages=len(result.pages), js_files=len(result.js_urls),
                            endpoints=len(result.endpoints))

        scan_text = dict(result.js_text)
        scan_text.update(self.seed_bodies)
        candidates = self._prospect(scan_text)
        self.console.line("prospector", f"{len(candidates)} candidates")
        self.console.counts(candidates=len(candidates))
        candidates = self._classify(candidates)
        candidates = self._triage(candidates)
        if self._stop_requested(should_stop):
            raise StopRun("stopped by request")

        review_notes = self._exegete(result.js_text)
        self._review = self._review_summary(review_notes)
        unvalidated = len([c for c in candidates if c.type not in self.validator.recipes])
        findings, unverified = self._assay(candidates)
        findings = self._sentinel(findings)
        self._unverified = unverified
        for item in unverified:
            self.store.add_candidate(item["type"], item["value"], item["source"],
                                     item["severity"], item["detail"], item["steps"])
        for source, kind, detail, severity in self._review_rows():
            self.store.add_review(source, kind, detail, severity)
        confidence = (round(sum(self._as_float(f.get("confidence", 0)) for f in findings)
                            / len(findings), 2)
                      if findings else 0.0)

        for finding in findings:
            self.store.add_finding(finding["title"], finding["severity"],
                                   finding["secret_type"], finding["value"],
                                   finding["impact"], finding["proof"])

        for finding in findings:
            if self._stop_requested(should_stop):
                raise StopRun("stopped by request")
            steps, narrative = self._escalate(finding)
            finding["reproduction"] = steps
            if narrative:
                finding.setdefault("notes", narrative)
            self._scribe(finding)
        self.console.counts(verified=len(findings), findings=len(findings))

        summary = {
            "pages": len(result.pages),
            "js_files": len(result.js_urls),
            "endpoints": len(result.endpoints),
            "candidates": len(candidates),
            "classified": self._classified,
            "unvalidated": unvalidated,
            "verified": len(findings),
            "findings": len(findings),
            "confidence": confidence,
        }
        return summary, findings

    def _map_subdomains(self, recon: Recon, seeds: list[str]) -> list[str]:
        added = recon.expand_seeds(seeds)
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
                self.store.add_secret(secret.type, secret.value, secret.source, secret.context)
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
                    findings.append(self._finding(secret, validation))
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
