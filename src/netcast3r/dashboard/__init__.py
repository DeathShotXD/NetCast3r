"""HTML dashboard.

Renders one self-contained HTML file from a run. No build step, no network,
no framework: the template carries its own CSS and JavaScript, the palette is
injected from netcast3r.theme, and the run data is injected as JSON.

Open the file directly, or hand it to the local server.
"""

from __future__ import annotations

import base64
import json
import time
import webbrowser
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from .. import theme as T

TEMPLATE_NAME = "template.html"
OUTPUT_NAME = "dashboard.html"


def template_text() -> str:
    """Read the shipped template from the installed package."""
    return resources.files("netcast3r.dashboard").joinpath(TEMPLATE_NAME).read_text("utf-8")


@lru_cache(maxsize=4)
def _data_uri(name: str) -> str:
    """Packaged artwork as a data URI so the file stays self contained."""
    raw = resources.files("netcast3r.dashboard").joinpath(name).read_bytes()
    return "data:image/webp;base64," + base64.b64encode(raw).decode("ascii")


def render(data: dict) -> str:
    """Fill the template with the palette, the artwork, and the run data."""
    payload = json.dumps(data, default=str, indent=None, separators=(",", ":"))
    # A literal close script tag inside JSON would end the block early.
    payload = payload.replace("</", "<\\/")
    html = template_text()
    html = html.replace("__NETCAST3R_VARS__", T.css_vars())
    html = html.replace("__NETCAST3R_LOGO__", _data_uri("logo.webp"))
    html = html.replace("__NETCAST3R_BANNER__", _data_uri("banner.webp"))
    html = html.replace("__NETCAST3R_DATA__", payload)
    return html


def build_data(*, target: str = "", summary: dict | None = None,
               findings: list[dict] | None = None, counts: dict | None = None,
               events: list[dict] | None = None, stages: list[str] | None = None,
               elapsed_ms: int = 0, running: bool = False,
               generated: str = "") -> dict:
    """Assemble the JSON the template expects."""
    return {
        "target": target or "-",
        "generated": generated or time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_ms": int(elapsed_ms or 0),
        "running": bool(running),
        "summary": dict(summary or {}),
        "counts": dict(counts or {}),
        "findings": list(findings or []),
        "log": list(events or []),
        "stages": list(stages or []),
    }


def save(out_dir: str | Path, data: dict, name: str = OUTPUT_NAME) -> Path:
    """Write the dashboard next to the rest of the run output."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(render(data))
    (directory / path.with_suffix(".json").name).write_text(
        json.dumps(data, indent=2, default=str)
    )
    return path


def save_data(out_dir: str | Path, data: dict) -> Path:
    """Write the raw dashboard payload so the file can be reopened later."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "dashboard.json"
    path.write_text(json.dumps(data, indent=2, default=str))
    return path


def load(path: str | Path) -> dict:
    """Read a dashboard payload, or a results.json as a fallback."""
    source = Path(path)
    if source.is_dir():
        for name in ("dashboard.json", "results.json"):
            candidate = source / name
            if candidate.exists():
                source = candidate
                break
    raw = json.loads(source.read_text("utf-8"))
    if "summary" in raw or "findings" in raw:
        return build_data(
            target=str(raw.get("target", "")),
            summary=raw.get("summary") or {},
            findings=raw.get("findings") or [],
            counts=raw.get("counts") or {},
            events=raw.get("log") or [],
            stages=raw.get("stages") or [],
            elapsed_ms=int(raw.get("elapsed_ms") or 0),
        )
    return raw


def stages_completed(events: list[dict]) -> list[str]:
    """Work out which of the six stages actually ran, from the log."""
    order = [stage["key"] for stage in T.STAGES]
    seen: set[str] = set()
    for event in events:
        agent = str(event.get("agent", "")).lower()
        index = T.stage_index(agent)
        if index < 0:
            continue
        # A later agent implies the earlier stages already ran.
        for earlier in order[: index + 1]:
            seen.add(earlier)
    return [key for key in order if key in seen]


# -- demo --------------------------------------------------------------------

def demo_data() -> dict:
    """A complete sample run, so the dashboard can be viewed on its own."""
    findings = [
        {
            "title": "AWS secret access key in bundle.js",
            "severity": "critical",
            "secret_type": "aws_secret_access_key",
            "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "source": "https://target.example/assets/bundle.js",
            "status": "confirmed",
            "confidence": 0.97,
            "impact": "Full control of the account identity attached to the key. "
                      "Read access to every bucket the role can reach.",
            "proof": "$ aws sts get-caller-identity\n"
                     "{\"Account\":\"123456789012\",\"Arn\":\"arn:aws:iam::123456789012:user/ci\"}",
        },
        {
            "title": "Stripe live secret in checkout flow",
            "severity": "high",
            "secret_type": "stripe_secret_key",
            "value": "sk_live_" + "51H8xQaKz9VbTtT3d9Yb2nCmQwErTyUi",
            "source": "https://target.example/js/checkout.min.js",
            "status": "corroborated",
            "confidence": 0.88,
            "impact": "Charge and refund on live cards. The key is shipped to "
                      "every browser on the checkout page.",
            "proof": "curl -u sk_live_...: https://api.stripe.com/v1/balance\n"
                     "{\"livemode\":true,\"available\":[{\"amount\":482050,\"currency\":\"usd\"}]}",
        },
        {
            "title": "Postgres connection string in config.js",
            "severity": "high",
            "secret_type": "database_url",
            "value": "postgresql://app_prod:S3cr3tP@ss@db.internal:5432/appdb",
            "source": "https://target.example/config.js",
            "status": "inferred",
            "confidence": 0.71,
            "impact": "Direct read and write to the production database if the "
                      "host is reachable from the internet.",
            "proof": "connection string found in a publicly served script",
        },
        {
            "title": "Discord webhook in analytics snippet",
            "severity": "medium",
            "secret_type": "discord_webhook",
            "value": "https://discord.com/api/webhooks/1187452300112233445/abCdEfGhIjKlMnOpQrStUvWx",
            "source": "https://target.example/analytics.js",
            "status": "unresolved",
            "confidence": 0.44,
            "impact": "Post arbitrary messages into an internal channel.",
            "proof": "no live check configured for this provider",
        },
    ]

    events = [
        {"kind": "header", "agent": "run", "text": "target=https://target.example"},
        {"kind": "line", "agent": "recon", "text": "41 pages, 27 js files, 188 endpoints, 6 skipped out of scope"},
        {"kind": "line", "agent": "recon", "text": "132 words saved to wordlist.txt"},
        {"kind": "line", "agent": "prospector", "text": "64 candidates"},
        {"kind": "line", "agent": "classifier", "text": "41 candidates re-typed by the model"},
        {"kind": "line", "agent": "exegete", "text": "reading 27 files"},
        {"kind": "line", "agent": "assayer", "text": "planned a read only check for aws_secret_access_key"},
        {"kind": "line", "agent": "assayer", "text": "rejected an unsafe check for database_url"},
        {"kind": "finding", "status": "confirmed", "type": "aws_secret_access_key",
         "value": findings[0]["value"], "detail": "read tier, account is live"},
        {"kind": "finding", "status": "corroborated", "type": "stripe_secret_key",
         "value": findings[1]["value"], "detail": "livemode balance readable"},
        {"kind": "finding", "status": "inferred", "type": "database_url",
         "value": findings[2]["value"], "detail": "read tier, host not reachable"},
        {"kind": "finding", "status": "unresolved", "type": "discord_webhook",
         "value": findings[3]["value"], "detail": "no recipe for this provider"},
        {"kind": "line", "agent": "chainer", "text": "1 escalation step from the knowledge base"},
        {"kind": "line", "agent": "scribe", "text": "report written to results/report.md"},
        {"kind": "summary", "agent": "run", "text": "run complete",
         "data": {"pages": 41, "js_files": 27, "endpoints": 188, "candidates": 64,
                  "verified": 4, "findings": 4}},
    ]

    summary = {
        "pages": 41, "js_files": 27, "endpoints": 188, "candidates": 64,
        "classified": 41, "unvalidated": 12, "verified": 4, "findings": 4,
        "confidence": 0.75, "files_read": 27,
    }
    counts = {"assets": 47, "js_files": 27, "endpoints": 188,
              "secrets": 64, "validations": 22, "findings": 4}

    return build_data(
        target="https://target.example",
        summary=summary,
        findings=findings,
        counts=counts,
        events=events,
        stages=[s["key"] for s in T.STAGES],
        elapsed_ms=96_000,
        running=False,
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
    )


# -- local server ------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    """Serves one rendered file and refreshes it when the data changes."""

    path_file: Path = Path(OUTPUT_NAME)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            body = self.path_file.read_text("utf-8").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt: str, *args) -> None:
        return


def serve(path: str | Path, port: int = 8899, open_browser: bool = True,
          host: str = "127.0.0.1") -> None:
    """Serve a rendered dashboard locally."""
    target = Path(path).resolve()
    handler = type("Handler", (_Handler,), {"path_file": target})
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{port}/"
    print(f"dashboard  {target}")
    print(f"serving    {url}   (ctrl-c to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("")
        server.shutdown()
