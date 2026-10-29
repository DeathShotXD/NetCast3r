"""Persistent, agent-driven browser sessions.

NetCast3r owns a real Chromium profile instead of a headless fetcher. The
control plane launches Chromium as a detached process with a loopback DevTools
port, writes a small state file, and attaches over CDP for each operation. The
browser therefore survives an MCP server restart, and a human can take over the
same window to solve a challenge or finish an OAuth consent screen while the
agent keeps driving it afterwards.

What this module deliberately does not do:

* it does not solve, replay, or fabricate CAPTCHA tokens;
* it does not return cookie values or typed secrets;
* it does not navigate an explicit target outside the mission scope.

Playwright is an optional dependency: ``pip install netcast3r[browser]``. The
system Chromium/Chrome/Edge binary is used, so no second browser download is
required on a normal desktop.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from .control import base_dir, read_private_json, write_private_json

PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
STATE_DIR = "browsers"
DEFAULT_TIMEOUT = 20_000
MAX_TEXT = 12_000
MAX_ITEMS = 250


class BrowserError(RuntimeError):
    """A browser action was rejected or the browser is unavailable."""

    def __init__(self, message: str, detail: str = ""):
        super().__init__(message)
        self.detail = detail


def _root(base: str | Path | None = None) -> Path:
    return base_dir(base) / STATE_DIR


def _state_path(profile: str, base: str | Path | None = None) -> Path:
    return _root(base) / f"{profile}.json"


def _log_path(profile: str, base: str | Path | None = None) -> Path:
    return _root(base) / f"{profile}.log"


def _check_profile(profile: str) -> str:
    name = (profile or "").strip()
    if not PROFILE_RE.match(name):
        raise BrowserError("invalid profile name",
                           "use letters, digits, dot, dash, or underscore")
    return name


def find_chromium() -> str:
    """Locate a Chromium-family binary without downloading one."""
    configured = os.environ.get("NETCAST3R_CHROMIUM", "").strip()
    candidates = [configured] if configured else []
    names = ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
             "chrome", "microsoft-edge", "msedge"]
    for name in names:
        found = shutil.which(name)
        if found:
            candidates.append(found)
    if sys.platform == "win32":
        for root in (os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                     os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
                     os.environ.get("LOCALAPPDATA", "")):
            if not root:
                continue
            for suffix in (r"Google\Chrome\Application\chrome.exe",
                           r"Microsoft\Edge\Application\msedge.exe",
                           r"Chromium\Application\chrome.exe"):
                candidates.append(os.path.join(root, suffix))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise BrowserError("Chromium not found",
                       "install Chromium/Chrome/Edge or set NETCAST3R_CHROMIUM")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        result = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                                capture_output=True, text=True)
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _http_ready(port: int, timeout: float = 20.0) -> bool:
    import httpx

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"http://127.0.0.1:{port}/json/version", timeout=1.0)
            if response.status_code == 200:
                return True
        except Exception:  # noqa: BLE001 - startup polling
            pass
        time.sleep(0.25)
    return False


def state(profile: str, base: str | Path | None = None) -> dict:
    name = _check_profile(profile)
    raw = read_private_json(_state_path(name, base)) or {}
    pid = int(raw.get("pid") or 0)
    port = int(raw.get("port") or 0)
    running = bool(pid and port and _pid_alive(pid) and _http_ready(port, 0.6))
    return {
        "profile": name,
        "running": running,
        "pid": pid if running else 0,
        "port": port if running else 0,
        "url": str(raw.get("url") or ""),
        "user_data_dir": str(raw.get("user_data_dir") or ""),
        "started_at": float(raw.get("started_at") or 0),
        "headless": bool(raw.get("headless")),
        "log_path": str(_log_path(name, base)),
    }


def launch(profile: str, url: str = "about:blank", base: str | Path | None = None,
           headless: bool = False) -> dict:
    """Launch a detached Chromium for ``profile`` or reuse the live one."""
    name = _check_profile(profile)
    current = state(name, base)
    if current["running"]:
        if url and url != "about:blank":
            goto(name, url, base=base)
        return state(name, base)

    binary = find_chromium()
    root = _root(base)
    data_dir = root / f"{name}-profile"
    data_dir.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    args = [
        binary,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-session-crashed-bubble",
        "--hide-crash-restore-bubble",
        "--disable-features=Translate",
        "--window-size=1440,1000",
    ]
    if headless:
        args.append("--headless=new")
    args.append(url or "about:blank")

    log = open(_log_path(name, base), "ab", buffering=0)
    kwargs = {"stdout": log, "stderr": log, "stdin": subprocess.DEVNULL,
              "cwd": str(root)}
    if sys.platform == "win32":
        kwargs["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP
                                   | subprocess.DETACHED_PROCESS)
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen(args, **kwargs)
    log.close()
    if not _http_ready(port, 25.0):
        raise BrowserError("browser did not expose a DevTools port",
                           f"see {_log_path(name, base)}")
    write_private_json(_state_path(name, base), {
        "profile": name, "pid": process.pid, "port": port,
        "url": url or "about:blank", "user_data_dir": str(data_dir),
        "started_at": time.time(), "headless": bool(headless),
    })
    return state(name, base)


def close(profile: str, base: str | Path | None = None) -> dict:
    name = _check_profile(profile)
    current = state(name, base)
    if current["running"]:
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/PID", str(current["pid"]), "/T", "/F"],
                               capture_output=True)
            else:
                os.kill(current["pid"], signal.SIGTERM)
        except OSError:
            pass
    write_private_json(_state_path(name, base), {})
    return {"profile": name, "closed": True, "was_running": current["running"]}


async def _with_page(profile: str, base, action):
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise BrowserError("browser support is not installed",
                           "pip install 'netcast3r[browser]'") from exc
    current = state(profile, base)
    if not current["running"]:
        raise BrowserError("browser is not running", f"open it first: profile {profile}")
    playwright = await async_playwright().start()
    try:
        browser = await playwright.chromium.connect_over_cdp(
            f"http://127.0.0.1:{current['port']}")
        contexts = browser.contexts
        if not contexts:
            raise BrowserError("browser has no context")
        context = contexts[0]
        pages = context.pages
        page = pages[0] if pages else await context.new_page()
        result = await action(page, context)
        write_private_json(_state_path(profile, base), {
            "profile": profile, "pid": current["pid"], "port": current["port"],
            "url": page.url, "user_data_dir": current["user_data_dir"],
            "started_at": current["started_at"], "headless": current["headless"],
        })
        return result
    finally:
        # Stopping the driver disconnects CDP without sending Browser.close, so
        # the human's window stays open for the next call.
        await playwright.stop()


def _run(profile: str, base, action):
    return asyncio.run(_with_page(profile, base, action))


def goto(profile: str, url: str, base: str | Path | None = None,
         timeout: int = DEFAULT_TIMEOUT) -> dict:
    async def action(page, _context):
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        return {"url": page.url, "title": await page.title(),
                "status": response.status if response else None}
    return _run(profile, base, action)


def status(profile: str, base: str | Path | None = None) -> dict:
    current = state(profile, base)
    if not current["running"]:
        return current

    async def action(page, _context):
        return {"url": page.url, "title": await page.title()}

    try:
        live = _run(profile, base, action)
    except Exception as exc:  # noqa: BLE001 - a crashed page is still a status
        live = {"url": current["url"], "title": "", "error": str(exc)[:200]}
    current.update(live)
    return current


def snapshot(profile: str, base: str | Path | None = None,
             include_text: bool = True) -> dict:
    script = """
    () => {
      document.querySelectorAll('[data-nc3r-ref]').forEach(
        (node) => node.removeAttribute('data-nc3r-ref'));
      const selector = 'a,button,input,textarea,select,[role=button],[role=link],' +
        '[contenteditable=true],[onclick],summary,label[for]';
      const seen = new Set();
      const items = [];
      for (const node of document.querySelectorAll(selector)) {
        if (items.length >= %d) break;
        const rect = node.getBoundingClientRect();
        const style = getComputedStyle(node);
        if (rect.width < 2 || rect.height < 2 || style.visibility === 'hidden' ||
            style.display === 'none' || seen.has(node)) continue;
        seen.add(node);
        const ref = 'e' + items.length;
        node.setAttribute('data-nc3r-ref', ref);
        const type = (node.getAttribute('type') || '').toLowerCase();
        let value = '';
        if ('value' in node && type !== 'password' && type !== 'hidden') {
          value = String(node.value || '').slice(0, 160);
        }
        const text = (node.innerText || node.getAttribute('aria-label') ||
          node.getAttribute('placeholder') || node.value || '').trim();
        items.push({
          ref, tag: node.tagName.toLowerCase(), type,
          name: node.getAttribute('name') || '', id: node.id || '',
          role: node.getAttribute('role') || '',
          text: text.slice(0, 140), value,
          href: node.href || '', disabled: !!node.disabled,
          checked: !!node.checked,
          x: Math.round(rect.x), y: Math.round(rect.y),
          w: Math.round(rect.width), h: Math.round(rect.height)
        });
      }
      const body = document.body ? document.body.innerText : '';
      return {title: document.title, url: location.href,
              text: %s ? body.slice(0, %d) : '', items};
    }
    """ % (MAX_ITEMS, "true" if include_text else "false", MAX_TEXT)

    async def action(page, _context):
        data = await page.evaluate(script)
        data["frames"] = len(page.frames)
        return data

    return _run(profile, base, action)


def click(profile: str, base: str | Path | None = None, ref: str = "",
          selector: str = "", button: str = "left", timeout: int = 10_000) -> dict:
    target = f'[data-nc3r-ref="{ref}"]' if ref else selector
    if not target:
        raise BrowserError("click needs a ref or a selector")

    async def action(page, _context):
        locator = page.locator(target).first
        await locator.click(button=button, timeout=timeout)
        await page.wait_for_timeout(250)
        return {"url": page.url, "title": await page.title()}

    return _run(profile, base, action)


def type_text(profile: str, text: str, base: str | Path | None = None,
              ref: str = "", selector: str = "", submit: bool = False,
              clear: bool = True, timeout: int = 10_000) -> dict:
    target = f'[data-nc3r-ref="{ref}"]' if ref else selector
    if not target:
        raise BrowserError("type needs a ref or a selector")

    async def action(page, _context):
        locator = page.locator(target).first
        if clear:
            await locator.fill("", timeout=timeout)
        await locator.fill(text, timeout=timeout)
        if submit:
            await locator.press("Enter")
            await page.wait_for_timeout(300)
        return {"url": page.url, "title": await page.title(), "submitted": submit}

    return _run(profile, base, action)


def press(profile: str, key: str, base: str | Path | None = None,
          ref: str = "", selector: str = "") -> dict:
    target = f'[data-nc3r-ref="{ref}"]' if ref else (selector or "body")

    async def action(page, _context):
        await page.locator(target).first.press(key)
        await page.wait_for_timeout(250)
        return {"url": page.url, "title": await page.title()}

    return _run(profile, base, action)


def wait(profile: str, base: str | Path | None = None, until: str = "time",
         value: str = "", timeout: int = 30_000) -> dict:
    """Wait for a human or a condition.

    ``until`` is one of ``time``, ``url``, ``text``, ``selector``, ``navigation``.
    ``navigation`` records the URL when the wait starts and returns as soon as
    the page moves somewhere else - the shape of a manual login redirect.
    """
    if until not in {"time", "url", "text", "selector", "navigation"}:
        raise BrowserError("invalid wait condition",
                           "until must be time, url, text, selector, or navigation")

    async def action(page, _context):
        started = page.url
        deadline = time.monotonic() + timeout / 1000
        while True:
            if until == "time" and time.monotonic() >= deadline:
                break
            if until == "url" and value and value in page.url:
                break
            if until == "navigation" and page.url != started:
                break
            if until == "text" and value:
                try:
                    body = await page.inner_text("body")
                except Exception:  # noqa: BLE001 - navigations race the read
                    body = ""
                if value in body:
                    break
            if until == "selector" and value:
                if await page.locator(value).count():
                    break
            if time.monotonic() >= deadline:
                return {"url": page.url, "matched": False, "timed_out": True}
            await page.wait_for_timeout(500)
        return {"url": page.url, "matched": True, "title": await page.title(),
                "changed": page.url != started}

    return _run(profile, base, action)


def screenshot(profile: str, base: str | Path | None = None,
               full_page: bool = False) -> dict:
    folder = base_dir(base) / "screenshots"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = folder / f"browser-{_check_profile(profile)}-{stamp}.png"

    async def action(page, _context):
        await page.screenshot(path=str(path), full_page=full_page)
        return {"path": str(path), "url": page.url, "title": await page.title()}

    return _run(profile, base, action)


JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
TOKEN_KEYS = {"token", "access_token", "accesstoken", "id_token", "jwt",
              "auth_token", "authorization"}


def capture(profile: str, name: str, base: str | Path | None = None,
            domain: str = "", storage_key: str = "", header: str = "") -> dict:
    """Copy cookies and one local-storage token into a sealed auth profile.

    Cookie and storage values are written to ``auth-profiles.json`` and are
    never returned. The response names the storage keys it saw so an operator
    can confirm which key became the Authorization header.
    """
    from . import authstore

    async def cookies_action(page, context):
        cookies = await context.cookies()
        selected = {}
        wanted = domain.lower().lstrip(".")
        for cookie in cookies:
            host = str(cookie.get("domain") or "").lower().lstrip(".")
            if wanted and not (host == wanted or host.endswith("." + wanted)):
                continue
            value = str(cookie.get("value") or "")
            if cookie.get("name") and value:
                selected[str(cookie["name"])] = value
        storage = await page.evaluate("""() => {
          const out = {};
          for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i); out[k] = localStorage.getItem(k) || '';
          }
          return out;
        }""")
        keys = sorted(storage)
        token = ""
        used_key = ""
        if storage_key:
            token = str(storage.get(storage_key) or "")
            used_key = storage_key if token else ""
        else:
            for key in keys:
                value = str(storage.get(key) or "")
                if key.lower() in TOKEN_KEYS and value:
                    token, used_key = value, key
                    break
            if not token:
                for key in keys:
                    value = str(storage.get(key) or "")
                    if JWT_RE.match(value):
                        token, used_key = value, key
                        break
        headers = {}
        if token:
            header_name = (header or "Authorization").strip()
            headers[header_name] = (f"Bearer {token}"
                                    if header_name.lower() == "authorization"
                                    else token)
        if not selected and not headers:
            raise BrowserError("nothing to capture",
                               f"domain filter: {domain or '(any)'}")
        saved = authstore.set_profile(
            name, headers=headers or None,
            cookies=selected or None, base=base,
            note=f"captured from browser profile {_check_profile(profile)}")
        return {"profile": saved, "cookies": len(selected), "domain": domain,
                "storage_keys": keys, "token_key": used_key,
                "header_set": bool(headers)}

    return _run(profile, base, cookies_action)


def evaluate(profile: str, expression: str, base: str | Path | None = None):
    """Evaluate one expression in the page and return its JSON value."""
    async def action(page, _context):
        return await page.evaluate(expression)

    return _run(profile, base, action)


def profiles(base: str | Path | None = None) -> list[dict]:
    root = _root(base)
    if not root.exists():
        return []
    items = []
    for path in sorted(root.glob("*.json")):
        name = path.stem
        if PROFILE_RE.match(name):
            items.append(state(name, base))
    return items
