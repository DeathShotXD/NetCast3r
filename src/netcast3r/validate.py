"""Credential validation.

Each candidate is matched to a recipe and checked against the provider. Only
read recipes run by default; recipes that touch state are held back until the
run tier allows them. Every result is one of verified, unverified, or unknown,
and every result carries the evidence that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import httpx

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


RECIPES_FILE = Path(__file__).with_name("recipes.toml")


@dataclass
class Recipe:
    type: str
    provider: str
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str = ""
    success_codes: list = field(default_factory=list)
    success_match: str = ""
    fail_codes: list = field(default_factory=list)
    fail_match: str = ""
    write: bool = False
    pair_type: str = ""


@dataclass
class Validation:
    type: str
    value: str
    status: str
    provider: str = ""
    detail: str = ""
    evidence: str = ""


def load_recipes(path: Path | None = None) -> dict[str, Recipe]:
    target = path or RECIPES_FILE
    try:
        with open(target, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        if path:
            raise ValueError(f"could not read the recipes file {target}: {exc}") from exc
        return {}
    recipes: dict[str, Recipe] = {}
    for row in data.get("recipe", []):
        if not isinstance(row, dict) or "type" not in row or "url" not in row:
            continue
        recipe = Recipe(
            type=row["type"],
            provider=row.get("provider", ""),
            method=row.get("method", "GET"),
            url=row["url"],
            headers=dict(row.get("headers", {})),
            body=row.get("body", ""),
            success_codes=list(row.get("success_codes", [])),
            success_match=row.get("success_match", ""),
            fail_codes=list(row.get("fail_codes", [])),
            fail_match=row.get("fail_match", ""),
            write=bool(row.get("write", False)),
            pair_type=row.get("pair_type", ""),
        )
        recipes[recipe.type] = recipe
    return recipes


def _render(template: str, value: str, value2: str = "") -> str:
    return template.replace("{value}", value).replace("{value2}", value2)


class Validator:
    def __init__(self, recipes: dict[str, Recipe] | None = None, tier: str = "read",
                 timeout: float = 15.0, client: httpx.Client | None = None, egress=None,
                 session=None):
        self.recipes = recipes if recipes is not None else load_recipes()
        self.tier = tier
        self.timeout = timeout
        self.client = client
        self.egress = egress
        self.session = session

    def _recipe_for(self, secret_type: str) -> Recipe | None:
        """A write variant wins over the read recipe when the tier allows it."""
        if self.tier in ("write", "full"):
            variant = self.recipes.get(f"{secret_type}_write")
            if variant is not None:
                return variant
        return self.recipes.get(secret_type)

    def validate(self, secret_type: str, value: str, source: str = "",
                 value2: str = "") -> Validation:
        recipe = self._recipe_for(secret_type)
        if recipe is None:
            return Validation(secret_type, value, "unknown", detail="no recipe for this type")
        if recipe.pair_type and not value2:
            return Validation(secret_type, value, "unknown", provider=recipe.provider,
                              detail=f"needs a paired {recipe.pair_type} value")
        if recipe.write and self.tier not in ("write", "full"):
            return Validation(secret_type, value, "skipped", provider=recipe.provider,
                              detail="write recipe held back at the current tier")

        url = _render(recipe.url, value, value2)
        headers = {key: _render(val, value, value2) for key, val in recipe.headers.items()}
        body = _render(recipe.body, value, value2) or None
        if any(ch in url for ch in ("\r", "\n", "\x00")) or \
                any(ch in header for header in headers.values() for ch in ("\r", "\n", "\x00")):
            return Validation(secret_type, value, "unknown", provider=recipe.provider,
                              detail="value carries control characters; request not sent")
        proxy = self.egress.get() if self.egress else None

        try:
            if self.session is not None:
                response = self.session.request(recipe.method, url, headers=headers,
                                                content=body, follow_redirects=False)
            elif self.client is not None:
                response = self.client.request(recipe.method, url, headers=headers, content=body)
            else:
                with httpx.Client(timeout=self.timeout, follow_redirects=False, proxy=proxy) as client:
                    response = client.request(recipe.method, url, headers=headers, content=body)
        except Exception as exc:  # network or provider failure
            if self.egress and proxy:
                self.egress.mark_failed(proxy)
            return Validation(secret_type, value, "unknown", provider=recipe.provider,
                              detail=f"request failed: {type(exc).__name__}")

        if response is None:
            return Validation(secret_type, value, "unknown", provider=recipe.provider,
                              detail="no response")

        text = response.text or ""
        status = response.status_code
        evidence = text[:400].replace("\n", " ")

        # A failure signal always wins, then a success needs a positive marker
        # that agrees with the status. A 4xx is never treated as success, and a
        # bare 200 only verifies when the recipe opted into status-codes and
        # defined no body marker to check.
        if recipe.fail_match and recipe.fail_match in text:
            return Validation(secret_type, value, "unverified", provider=recipe.provider,
                              detail=f"HTTP {status}", evidence=evidence)
        if recipe.fail_codes and status in recipe.fail_codes:
            return Validation(secret_type, value, "unverified", provider=recipe.provider,
                              detail=f"HTTP {status}", evidence=evidence)
        status_ok = status < 400 and (not recipe.success_codes or status in recipe.success_codes)
        if recipe.success_match:
            if recipe.success_match in text and status_ok:
                return Validation(secret_type, value, "verified", provider=recipe.provider,
                                  detail=f"HTTP {status}", evidence=evidence)
            return Validation(secret_type, value, "unknown", provider=recipe.provider,
                              detail=f"HTTP {status} without a confirming marker", evidence=evidence)
        if recipe.success_codes and status in recipe.success_codes and status < 400:
            return Validation(secret_type, value, "verified", provider=recipe.provider,
                              detail=f"HTTP {status}", evidence=evidence)
        return Validation(secret_type, value, "unknown", provider=recipe.provider,
                          detail=f"HTTP {status}", evidence=evidence)
