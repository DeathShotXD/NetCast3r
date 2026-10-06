"""Live console and dashboard.

One surface for a running job: the identity header, the six stage rail, the
counters, the agent log, the reasoning stream, and the findings as they land.
It uses rich when it is available and falls back to plain painted text when it
is not, so the same design survives a minimal install.

Colour, glyph, stage, and state rules all come from netcast3r.theme.
"""

from __future__ import annotations

import threading
import time

from . import theme as T

# Counter labels in the order the artwork prints them.
KPIS: list[tuple[str, str]] = [
    ("pages", "PAGES"),
    ("js_files", "JS"),
    ("endpoints", "ENDS"),
    ("candidates", "CAND"),
    ("verified", "VER"),
    ("findings", "FIND"),
]

_LOG_WIDTH = 14
_FINDING_WIDTH = 6


def _rich_available() -> bool:
    try:
        import rich  # noqa: F401
    except Exception:
        return False
    return True


class Console:
    def __init__(self, show_reasoning: bool = True, color: bool = True):
        self.show_reasoning = show_reasoning
        self.color = color
        self.events: list[dict] = []
        self._rich = None
        if color and _rich_available():
            try:
                from rich.console import Console as RichConsole
                self._rich = RichConsole()
            except Exception:
                self._rich = None

    # -- plumbing -----------------------------------------------------------

    def _c(self, text: str, role: str, bold: bool = False) -> str:
        return T.paint(text, role, bold=bold, color_on=self.color)

    def _record(self, event: dict) -> None:
        """Keep a structured copy of every event for the HTML dashboard."""
        self.events.append(event)

    def _emit(self, text: str) -> None:
        if self._rich is not None:
            self._rich.print(text)
        else:
            print(text)

    # -- events -------------------------------------------------------------

    def header(self, target: str) -> None:
        self._record({"kind": "header", "agent": "run", "text": target or "-"})
        name = self._c("NETCAST3R", T.ACID, bold=True)
        prompt = self._c(T.PROMPT, T.VIOLET)
        where = self._c("target=", T.ASH) + self._c(target or "-", T.BONE)
        self._emit(f" {name}  {prompt}  {where}")
        self._emit(" " + self._c(T.RULE, T.VIOLET_DEEP))

    def line(self, agent: str, text: str) -> None:
        self._record({"kind": "line", "agent": agent, "text": text})
        label = T.paint(f"[{agent}]", T.agent_color(agent), color_on=self.color)
        self._emit(f"  {T.pad(label, 13)}{text}")

    def reasoning(self, agent: str, text: str) -> None:
        if not self.show_reasoning:
            return
        for piece in text.splitlines():
            piece = piece.strip()
            if piece:
                self._record({"kind": "reason", "agent": agent, "text": piece})
                dot = T.paint("..", T.VIOLET_DEEP, color_on=self.color)
                tag = T.paint(agent, T.agent_color(agent), color_on=self.color)
                self._emit(f"    {dot} {tag}: {T.paint(piece, T.ASH, color_on=self.color)}")

    def finding(self, status: str, secret_type: str, value: str, detail: str) -> None:
        self._record({"kind": "finding", "status": status, "type": secret_type,
                      "value": value, "detail": detail})
        state = str(status or "").lower()
        label = T.paint(f"[{state}]", T.state_color(state), bold=True, color_on=self.color)
        kind = T.paint(secret_type, T.BONE, color_on=self.color)
        shown = self._c(T.mask(value), T.ACID_DIM)
        note = T.paint(detail or "", T.ASH, color_on=self.color)
        self._emit(f"  {label} {kind} {shown}  {note}")

    def counts(self, **values) -> None:
        """Counter updates. The plain console has nowhere to show them."""

    def summary(self, data: dict) -> None:
        self._record({"kind": "summary", "agent": "run", "text": "run complete",
                      "data": dict(data)})
        self._emit("")
        self._emit(" " + self._c("SUMMARY", T.BONE, bold=True))
        self._emit(" " + self._c(T.RULE, T.VIOLET_DEEP))
        for key, value in data.items():
            label = T.paint(f"  {key:<18}", T.BONE_DUST, color_on=self.color)
            numeric = value if isinstance(value, (int, float)) else 0
            role = T.ACID if numeric else (T.BONE if value else T.ASH)
            self._emit(f"{label}{self._c(str(value), role)}")


class Progress:
    """A small progress line for a loop with a known size."""

    def __init__(self, console: Console, total: int, label: str = "working"):
        self.console = console
        self.total = max(total, 1)
        self.label = label
        self.done = 0
        self._step = max(self.total // 10, 1)
        self._bar = None
        self._task = None
        if console._rich is not None:
            try:
                from rich.progress import Progress as RichProgress
                self._bar = RichProgress(console=console._rich)
                self._task = self._bar.add_task(label, total=self.total)
                self._bar.start()
            except Exception:
                self._bar = None

    def advance(self, step: int = 1) -> None:
        self.done += step
        if self._bar is not None:
            self._bar.update(self._task, completed=min(self.done, self.total))
            return
        if self.done % self._step == 0 or self.done >= self.total:
            percent = int(self.done * 100 / self.total)
            bar = self._bar_text(percent)
            self.console._emit(f"    {bar} {self.label} {self.done}/{self.total} ({percent}%)")

    def _bar_text(self, percent: int) -> str:
        width = 24
        fill = max(0, min(width, int(width * percent / 100)))
        block = "=" * fill + "-" * (width - fill)
        return T.paint("[", T.VIOLET_DEEP) + T.paint(block, T.ACID) + T.paint("]", T.VIOLET_DEEP)

    def close(self) -> None:
        if self._bar is not None:
            self._bar.update(self._task, completed=self.total)
            self._bar.stop()


class Dashboard(Console):
    """The live surface.

    Holds the stage rail, the counters, the agent log, and the findings, and
    repaints them as one panel while the run is going. Falls back to the plain
    console when rich is unavailable.
    """

    is_dashboard = True

    def __init__(self, show_reasoning: bool = True, max_lines: int = 14):
        super().__init__(show_reasoning=show_reasoning, color=True)
        self._lines: list[str] = []
        self._max = max_lines
        self._findings: list[tuple[str, str, str, str]] = []
        self._counts: dict[str, int] = {}
        self._stage = 0
        self._target = ""
        self._note = "starting"
        self._started = time.time()
        self._finished = False
        self._lock = threading.Lock()
        self._live = None
        if self._rich is not None:
            try:
                from rich.live import Live
                self._live = Live(self._render(), console=self._rich,
                                  refresh_per_second=8, transient=False)
            except Exception:
                self._live = None

    # -- events -------------------------------------------------------------

    def header(self, target: str) -> None:
        with self._lock:
            self._target = target or "-"
            self._started = time.time()
            self._note = "recon"
        if self._live is None:
            super().header(target)
            return
        self._record({"kind": "header", "agent": "run", "text": self._target})
        self._refresh()

    def line(self, agent: str, text: str) -> None:
        with self._lock:
            label = T.paint(f"[{agent}]", T.agent_color(agent))
            self._lines.append(f" {T.pad(label, 13)}{text}")
            self._lines = self._lines[-self._max:]
            index = T.stage_index(agent)
            if index >= 0:
                self._stage = index
            self._note = str(agent)
        if self._live is None:
            Console.line(self, agent, text)
            return
        self._record({"kind": "line", "agent": agent, "text": text})
        self._refresh()

    def reasoning(self, agent: str, text: str) -> None:
        if not self.show_reasoning:
            return
        if self._live is None:
            Console.reasoning(self, agent, text)
            return
        for piece in text.splitlines():
            piece = piece.strip()
            if not piece:
                continue
            with self._lock:
                dot = T.paint("   ..", T.VIOLET_DEEP)
                tag = T.paint(agent, T.agent_color(agent))
                self._lines.append(f"{dot} {tag}: {T.paint(piece, T.ASH)}")
                self._lines = self._lines[-self._max:]
            self._record({"kind": "reason", "agent": agent, "text": piece})
        self._refresh()

    def finding(self, status: str, secret_type: str, value: str, detail: str) -> None:
        with self._lock:
            self._findings.append((status, secret_type, value, detail))
            self._findings = self._findings[-_FINDING_WIDTH:]
        if self._live is None:
            Console.finding(self, status, secret_type, value, detail)
            return
        self._record({"kind": "finding", "status": status, "type": secret_type,
                      "value": value, "detail": detail})
        self._refresh()

    def counts(self, **values) -> None:
        with self._lock:
            for key, value in values.items():
                if isinstance(value, (int, float)):
                    self._counts[key] = int(value)
        if self._live is None:
            return
        self._refresh()

    def summary(self, data: dict) -> None:
        with self._lock:
            for key, value in data.items():
                if isinstance(value, (int, float)):
                    self._counts[key] = int(value)
            self._finished = True
            self._note = "done"
        if self._live is None:
            Console.summary(self, data)
            return
        self._record({"kind": "summary", "agent": "run", "text": "run complete",
                      "data": dict(data)})
        self._refresh()

    # -- render -------------------------------------------------------------

    def _stage_rail(self) -> str:
        parts = []
        total = len(T.STAGES)
        for index, stage in enumerate(T.STAGES):
            if self._finished or index < self._stage:
                role = T.BONE_DUST
            elif index == self._stage:
                role = T.ACID
            else:
                role = T.VIOLET_DEEP
            parts.append(T.paint(f" {stage['label']} ", role,
                                 bold=index == self._stage and not self._finished,
                                 color_on=self.color))
            if index < total - 1:
                parts.append(T.paint(f" {T.CHEVRON} ", T.VIOLET_DEEP, color_on=self.color))
        return "".join(parts)

    def _kpi_row(self) -> str:
        parts = ["  "]
        for key, label in KPIS:
            value = int(self._counts.get(key, 0))
            parts.append(T.paint(f"{label} ", T.BONE_DUST, color_on=self.color))
            parts.append(T.paint(str(value), T.ACID if value else T.ASH, bold=value > 0,
                                 color_on=self.color))
            parts.append(T.paint("   ", T.VIOLET_DEEP, color_on=self.color))
        return "".join(parts)

    def _finding_rows(self) -> list[str]:
        rows = []
        for status, secret_type, value, detail in self._findings:
            state = str(status or "").lower()
            label = T.paint(f"[{state}]", T.state_color(state), bold=True, color_on=self.color)
            kind = T.paint(secret_type, T.BONE, color_on=self.color)
            shown = self._c(T.mask(value), T.ACID_DIM)
            note = T.paint(detail or "", T.ASH, color_on=self.color)
            rows.append(f"  {label} {kind} {shown}  {note}")
        return rows

    def _header_line(self) -> str:
        elapsed = int(time.time() - self._started)
        parts = [
            T.paint(" NETCAST3R ", T.ACID, bold=True, color_on=self.color),
            T.paint(T.PROMPT, T.VIOLET, color_on=self.color),
            T.paint("  target=", T.ASH, color_on=self.color),
            T.paint(self._target, T.BONE, color_on=self.color),
            T.paint("   ", T.VIOLET_DEEP, color_on=self.color),
            T.paint(self._note, T.GOLD, color_on=self.color),
            T.paint(f"   {elapsed // 60:02d}:{elapsed % 60:02d}", T.BONE_DUST,
                    color_on=self.color),
        ]
        return "".join(parts)

    def _render(self):
        from rich.panel import Panel
        from rich.text import Text

        width = getattr(self._rich, "width", None) or 78
        with self._lock:
            log_text = "\n".join(self._lines) if self._lines else (
                T.paint("  waiting for the first event", T.ASH, color_on=self.color))
            rows = self._finding_rows()
            body = [
                self._header_line(),
                T.paint(" " + "-" * max(width - 4, 20), T.VIOLET_DEEP, color_on=self.color),
                "  " + self._stage_rail(),
                self._kpi_row(),
                "",
                log_text,
            ]
            if rows:
                body.append("")
                body.append(T.paint("  FINDINGS", T.ACID, bold=True, color_on=self.color))
                body.extend(rows)

        # Assembled as ANSI, then decoded once. Rich markup never sees the
        # bracketed agent tags, and the plain fallback paints the same string.
        text = Text.from_ansi("\n".join(body))
        return Panel(text, border_style=T.VIOLET_DEEP, padding=(0, 1))

    def _refresh(self) -> None:
        if self._live is None:
            return
        self._live.update(self._render())

    def start(self) -> None:
        if self._live is not None:
            self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.stop()
