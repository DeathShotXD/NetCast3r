"""Live console.

A small status surface for a running job: one line per agent, the reasoning
stream as it arrives, findings as they land, and a closing summary. It uses
rich when it is available and falls back to plain text otherwise.
"""

from __future__ import annotations


class Console:
    def __init__(self, show_reasoning: bool = True, color: bool = True):
        self.show_reasoning = show_reasoning
        self._rich = None
        if color:
            try:
                from rich.console import Console as RichConsole
                self._rich = RichConsole()
            except Exception:
                self._rich = None

    def _emit(self, text: str) -> None:
        if self._rich is not None:
            self._rich.print(text)
        else:
            print(text)

    def header(self, target: str) -> None:
        self._emit(f"netcast3r  target={target}")

    def line(self, agent: str, text: str) -> None:
        self._emit(f"  [{agent}] {text}")

    def reasoning(self, agent: str, text: str) -> None:
        if not self.show_reasoning:
            return
        for piece in text.splitlines():
            piece = piece.strip()
            if piece:
                self._emit(f"    .. {agent}: {piece}")

    def finding(self, status: str, secret_type: str, value: str, detail: str) -> None:
        shown = value if len(value) <= 12 else f"{value[:6]}...{value[-4:]}"
        self._emit(f"  [{status}] {secret_type} {shown}  {detail}")

    def summary(self, data: dict) -> None:
        self._emit("")
        for key, value in data.items():
            self._emit(f"  {key:<18} {value}")


class Progress:
    """A small progress line for a loop with a known size."""

    def __init__(self, console: Console, total: int, label: str = "working"):
        self.console = console
        self.total = max(total, 1)
        self.label = label
        self.done = 0
        self._step = max(self.total // 10, 1)
        self._bar = None
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
            self.console._emit(f"    {self.label} {self.done}/{self.total} ({percent}%)")

    def close(self) -> None:
        if self._bar is not None:
            self._bar.update(self._task, completed=self.total)
            self._bar.stop()
