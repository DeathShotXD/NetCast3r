"""Design tokens.

One source of truth for the NetCast3r palette, stages, states, and glyphs.
The terminal console, the HTML dashboard template, and the report writers all
read from here so a colour can never drift between surfaces.

Every hex value was measured out of assets/NetCast3r-Logo.png and
assets/NetCast3r-Banner.png. See docs/DESIGN.md for the rules on when each
one is allowed to appear.
"""

from __future__ import annotations

import re

# -- Palette -----------------------------------------------------------------

VOID = "#000000"
VOID_SOFT = "#010101"
ACID = "#C8F81A"
ACID_HOT = "#F5F87D"
ACID_DIM = "#B1E61B"
ACID_DEEP = "#6CA52E"
ACID_ABYSS = "#172603"
VIOLET = "#9F23DD"
VIOLET_DEEP = "#4C2377"
VIOLET_ABYSS = "#160334"
BONE = "#F5E9DC"
BONE_DIM = "#FDF7E8"
INDIGO = "#281550"
INDIGO_DEEP = "#170F3F"
SLATE = "#2C2C4A"
GOLD = "#EFE4B1"
BONE_DUST = "#A89591"
ASH = "#9698A2"

PALETTE: dict[str, str] = {
    "void": VOID, "void_soft": VOID_SOFT, "acid": ACID, "acid_hot": ACID_HOT,
    "acid_dim": ACID_DIM, "acid_deep": ACID_DEEP, "acid_abyss": ACID_ABYSS,
    "violet": VIOLET, "violet_deep": VIOLET_DEEP, "violet_abyss": VIOLET_ABYSS,
    "bone": BONE, "bone_dim": BONE_DIM, "indigo": INDIGO,
    "indigo_deep": INDIGO_DEEP, "slate": SLATE, "gold": GOLD,
    "bone_dust": BONE_DUST, "ash": ASH,
}

# -- Operational states ------------------------------------------------------

# The validation ladder. Same four words the artwork prints on the banner.
STATES: dict[str, str] = {
    "confirmed": ACID,
    "corroborated": GOLD,
    "inferred": VIOLET,
    "unresolved": SLATE,
    "rejected": VIOLET_DEEP,
    "live": ACID,
    "safe": ASH,
    "unknown": SLATE,
}

SEVERITIES: dict[str, str] = {
    "critical": ACID,
    "high": ACID_HOT,
    "medium": GOLD,
    "low": BONE_DUST,
    "info": ASH,
    "none": ASH,
}

# -- Pipeline ----------------------------------------------------------------

# Six stages, in order, exactly as the banner lays them out.
STAGES: list[dict[str, str]] = [
    {"key": "crawl", "label": "CRAWL", "detail": "Target & Endpoints", "glyph": "@", "agent": "recon"},
    {"key": "readjs", "label": "READ JS", "detail": "Map Logic & Weak Spots", "glyph": "<>", "agent": "exegete"},
    {"key": "hunt", "label": "HUNT", "detail": "Secrets & Credentials", "glyph": "*", "agent": "prospector"},
    {"key": "validate", "label": "VALIDATE", "detail": "Check Access & Impact", "glyph": "^", "agent": "assayer"},
    {"key": "escalate", "label": "ESCALATE", "detail": "Find Highest Provable", "glyph": "^^", "agent": "chainer"},
    {"key": "report", "label": "REPORT", "detail": "Ready for Submission", "glyph": "#", "agent": "scribe"},
]

# Which pipeline stage each agent belongs to, so a log line lights its stage.
AGENT_STAGE: dict[str, str] = {
    "recon": "crawl",
    "exegete": "readjs",
    "prospector": "hunt",
    "classifier": "hunt",
    "assayer": "validate",
    "chainer": "escalate",
    "scribe": "report",
    "sentinel": "validate",
    "run": "crawl",
}

# Terminal colour per agent. Families share a colour so the log reads in bands.
AGENT_COLORS: dict[str, str] = {
    "recon": ACID_DIM,
    "exegete": VIOLET,
    "prospector": ACID,
    "classifier": ACID_HOT,
    "assayer": GOLD,
    "chainer": VIOLET,
    "scribe": BONE,
    "sentinel": ACID,
    "run": BONE_DUST,
}

# -- Glyphs ------------------------------------------------------------------
# The type system. > navigation, // list, [*] live, <> code.

PROMPT = ">_"
LIST_MARK = "//"
LIVE_MARK = "[*]"
CHEVRON = ">"
RULE = "-" * 40
SEPARATOR = " / "

# Terminal-only decor, drawn with box characters.
T_BOX = {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|"}


# -- ANSI --------------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

_ANSI = re.compile(r"\033\[[0-9;]*m")


def _rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return (int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16))


def fg(color: str) -> str:
    r, g, b = _rgb(color)
    return f"\033[38;2;{r};{g};{b}m"


def bg(color: str) -> str:
    r, g, b = _rgb(color)
    return f"\033[48;2;{r};{g};{b}m"


def paint(text: str, color: str, *, bold: bool = False, color_on: bool = True) -> str:
    """Wrap text in a truecolor foreground. Returns plain text when off."""
    if not color_on:
        return text
    prefix = fg(color) + (BOLD if bold else "")
    return f"{prefix}{text}{RESET}"


def strip(text: str) -> str:
    """Remove escape sequences so a value can be measured or logged."""
    return _ANSI.sub("", text)


def visible_len(text: str) -> int:
    return len(strip(text))


def pad(text: str, width: int) -> str:
    """Pad to a display width, accounting for escape sequences."""
    return text + " " * max(width - visible_len(text), 0)


def state_color(status: str) -> str:
    return STATES.get(str(status or "").lower().strip(), SLATE)


def severity_color(severity: str) -> str:
    return SEVERITIES.get(str(severity or "").lower().strip(), ASH)


def agent_color(agent: str) -> str:
    return AGENT_COLORS.get(str(agent or "").lower().strip(), BONE_DUST)


def stage_index(agent: str) -> int:
    key = AGENT_STAGE.get(str(agent or "").lower().strip())
    for index, stage in enumerate(STAGES):
        if stage["key"] == key:
            return index
    return -1


def mask(value: str, keep: int = 6) -> str:
    """The masked credential shape the artwork uses: sk_live_••••••••."""
    text = str(value or "")
    if len(text) <= 12:
        return text[:2] + "*" * max(len(text) - 2, 0)
    return f"{text[:keep]}...{text[-4:]}"


def css_vars() -> str:
    """The palette as CSS custom properties, for the HTML dashboard.

    Python keeps the underscore names, CSS gets the hyphenated ones.
    """
    return "\n".join(
        f"  --{name.replace('_', '-')}: {hexv};" for name, hexv in PALETTE.items()
    )
