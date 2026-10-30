"""Turn verified lab chains into model-facing lessons.

A free model is useful for explanation and recall, but it is not allowed to
declare a lab solved. This module gives the model one verified chain at a time
and stores the resulting concise playbook as a skill. Every agent can retrieve
that skill on the next run, so the model's effective memory grows even when
the underlying weights do not change.
"""

from __future__ import annotations

from .config import load_config
from .providers import ProviderBus


def _prompt(slug: str, recipe: dict) -> list[dict]:
    steps = recipe.get("steps") or []
    lines = []
    for step in steps:
        kind = step.get("kind")
        if kind == "http":
            lines.append(f"- HTTP {step.get('method', 'GET')} {step.get('path', '')}")
        elif kind == "login":
            lines.append(f"- login as {step.get('username')}")
        elif kind == "upload":
            lines.append(f"- upload {step.get('filename')} to {step.get('path')}")
        elif kind == "jwt_tamper":
            lines.append(f"- change JWT claim {step.get('claim')} to {step.get('value')}")
        elif kind == "php_serial_tamper":
            lines.append("- flip the serialized admin boolean")
        elif kind == "submit":
            lines.append("- submit the captured answer")
        elif kind == "verify":
            lines.append("- verify the Academy banner")
        elif kind == "record":
            lines.append("- record evidence and the lesson")
    return [
        {"role": "system", "content": (
            "You are a security training analyst. Explain a verified lab chain "
            "in at most 180 words. State the exact input, the parser or trust "
            "boundary, and the proof. Do not invent steps or claim anything "
            "beyond the supplied chain.")},
        {"role": "user", "content": (
            f"Lab: {recipe.get('title')}\nSlug: {slug}\n"
            f"Verified steps:\n" + "\n".join(lines) +
            f"\nOriginal lesson:\n{recipe.get('lesson', '')}\n"
            "Write a reusable playbook for a smaller model: what to observe, "
            "what to send, what proves success, and one mistake to avoid.")},
    ]


def study_recipe(index, slug: str, recipe: dict) -> dict:
    messages = _prompt(slug, recipe)
    text, provider, model, error = "", "", "", ""
    try:
        completion = ProviderBus(load_config(), timeout=60.0).complete(
            "sentinel", messages, timeout=60.0)
        text = (completion.text or "").strip()
        provider, model = completion.provider, completion.model
        error = completion.error or ""
    except Exception as exc:  # noqa: BLE001 - a dead provider is a recorded result
        error = f"{type(exc).__name__}: {exc}"
    verified = str(recipe.get("lesson") or "").strip()
    if not verified and not text:
        raise ValueError("no model text and no recipe lesson")
    name = f"model-lab-{slug}"[:110]
    skill = index.upsert_skill(
        name=name,
        title=f"Model playbook: {recipe.get('title', slug)}",
        description=(text.splitlines()[0][:180] if text else
                     f"Verified chain for {slug}"),
        body=(f"# Model playbook: {recipe.get('title', slug)}\n\n"
              f"Source: verified recipe `{slug}`\n\n"
              f"## Verified chain (authoritative)\n\n{verified}\n\n"
              f"## Model explanation (advisory)\n\n"
              f"{text or 'No model text; use the verified chain above.'}\n"),
        tags=["model-training", "lab", slug],
        source=f"training:{slug}")
    return {"slug": slug, "provider": provider, "model": model,
            "error": error, "skill": skill,
            "used_model": bool(text)}


def study_all(index, recipes: dict, limit: int = 20) -> dict:
    items, errors = [], []
    for slug, recipe in list(recipes.items())[:max(1, min(int(limit or 20), 50))]:
        try:
            items.append(study_recipe(index, slug, recipe))
        except Exception as exc:  # noqa: BLE001 - one lab must not stop the batch
            errors.append({"slug": slug, "error": str(exc)[:200]})
    return {"items": items, "errors": errors,
            "note": ("Model playbooks are retrieval memory, not proof. The lab "
                     "is still solved only by the verified recipe.")}
