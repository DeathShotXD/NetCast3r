"""Live console.

A small status surface for a running job: one line per agent, the reasoning
stream as it arrives, findings as they land, and a closing summary. It uses
rich when it is available and falls back to plain text otherwise.
"""

from __future__ import annotations


class Console:
    def __init__(self, show_reasoning: bool = True):
        self.show_reasoning = show_reasoning
        self._rich = None
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
