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
    with open(target, "rb") as handle:
        data = tomllib.load(handle)
    recipes: dict[str, Recipe] = {}
    for row in data.get("recipe", []):
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
        proxy = self.egress.get() if self.egress else None

        try:
            if self.session is not None:
                response = self.session.request(recipe.method, url, headers=headers, content=body)
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

        if recipe.success_match and recipe.success_match in text:
            return Validation(secret_type, value, "verified", provider=recipe.provider,
                              detail=f"HTTP {status}", evidence=evidence)
        if recipe.fail_match and recipe.fail_match in text:
            return Validation(secret_type, value, "unverified", provider=recipe.provider,
                              detail=f"HTTP {status}", evidence=evidence)
        if recipe.success_codes and status in recipe.success_codes:
            if recipe.success_match:
                return Validation(secret_type, value, "unknown", provider=recipe.provider,
                                  detail=f"HTTP {status} without expected marker", evidence=evidence)
            return Validation(secret_type, value, "verified", provider=recipe.provider,
                              detail=f"HTTP {status}", evidence=evidence)
        if recipe.fail_codes and status in recipe.fail_codes:
            return Validation(secret_type, value, "unverified", provider=recipe.provider,
                              detail=f"HTTP {status}", evidence=evidence)
        return Validation(secret_type, value, "unknown", provider=recipe.provider,
                          detail=f"HTTP {status}", evidence=evidence)
