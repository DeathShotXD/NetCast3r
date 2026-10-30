"""Local UI/UX audit for the dashboard.

This is a real SQA pass, not a screenshot gallery. It opens the local control
plane in Chromium, visits the requested screens, records console errors and
failed requests, measures horizontal overflow, and writes one screenshot per
screen. It is read-only and never leaves the machine.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .browser import find_chromium
from .control import base_dir, read_private_json


def _plane(base: str | Path | None) -> tuple[str, str]:
    root = base_dir(base)
    config = read_private_json(root / "control-plane.json") or {}
    port = str(config.get("port") or "7857")
    token = str(config.get("token") or "")
    return f"http://127.0.0.1:{port}", token


def _slug(route: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", (route or "home").lower()).strip("-")
    return value or "home"


def _overflow(page) -> dict:
    script = """
    () => {
      const vw = window.innerWidth;
      const bad = [];
      for (const el of document.querySelectorAll('body *')) {
        const r = el.getBoundingClientRect();
        if (r.width <= 0) continue;
        if (r.right > vw + 2 || r.left < -2) {
          bad.push({
            tag: el.tagName.toLowerCase(),
            cls: String(el.className || '').slice(0, 80),
            text: String(el.innerText || '').replace(/\\s+/g, ' ').slice(0, 80),
            left: Math.round(r.left), right: Math.round(r.right),
          });
          if (bad.length >= 8) break;
        }
      }
      return {
        inner_width: vw,
        scroll_width: document.documentElement.scrollWidth,
        body_width: document.body.getBoundingClientRect().width,
        overflow: bad,
      };
    }
    """
    return page.evaluate(script)


def audit_pages(base: str | Path | None = None, routes: list | None = None,
                viewport: dict | None = None, headless: bool = True,
                base_url: str = "", token: str = "") -> dict:
    """Audit dashboard screens and return concrete layout/runtime findings."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("Playwright is not installed") from exc
    root = base_dir(base)
    default_url, default_token = _plane(base)
    base_url = (base_url or default_url).rstrip("/")
    token = token or default_token
    if not token:
        raise ValueError("a control-plane token is required")
    routes = [str(item).strip() for item in (routes or
              ["missions", "live", "findings", "reveng"]) if str(item).strip()]
    width = int((viewport or {}).get("width") or 1440)
    height = int((viewport or {}).get("height") or 900)
    shot_dir = root / "artifacts" / "ui-audit"
    shot_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(shot_dir, 0o700)
    except OSError:
        pass

    pages = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=find_chromium(),
                                     headless=headless)
        page = browser.new_page(viewport={"width": width, "height": height})
        console: list[str] = []
        failed: list[str] = []
        page.on("console", lambda msg: console.append(msg.text)
                if msg.type == "error" else None)
        page.on("requestfailed", lambda req: failed.append(
            f"{req.method} {req.url} {req.failure}") if req.failure else None)
        page.on("pageerror", lambda exc: console.append(f"pageerror: {exc}"))
        page.goto(f"{base_url}/?token={token}", wait_until="networkidle",
                  timeout=60000)
        for route in routes:
            console.clear()
            failed.clear()
            url = f"{base_url}/#/{route.lstrip('#/')}"
            page.goto(url, wait_until="networkidle", timeout=60000)
            page.wait_for_timeout(900)
            layout = _overflow(page)
            slug = _slug(route)
            shot = shot_dir / f"{slug}.png"
            page.screenshot(path=str(shot), full_page=False)
            try:
                os.chmod(shot, 0o600)
            except OSError:
                pass
            issues = []
            if console:
                issues.append({"kind": "console", "items": console[:8]})
            if failed:
                issues.append({"kind": "network", "items": failed[:8]})
            if layout["scroll_width"] > layout["inner_width"] + 2:
                issues.append({"kind": "horizontal-overflow",
                               "items": layout["overflow"]})
            pages.append({
                "route": route,
                "url": url,
                "title": page.title(),
                "screenshot": str(shot),
                "ok": not issues,
                "issues": issues,
                "layout": layout,
            })
        browser.close()
    return {
        "base_url": base_url,
        "viewport": {"width": width, "height": height},
        "pages": pages,
        "ok": all(item["ok"] for item in pages),
        "note": ("This checks runtime errors, failed requests, and horizontal "
                 "overflow on the local dashboard. It does not judge copy or "
                 "visual taste."),
    }
