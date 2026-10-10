"""Live event bus.

Stages, findings, and log lines are published here as runs execute. Every
subscriber gets its own bounded queue, so a slow reader can never stall a run;
when a queue overflows the oldest log lines are dropped and a single lagged
marker is sent instead.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class Event:
    type: str
    run_id: str = ""
    agent: str = ""
    stage: str = ""
    level: str = "info"
    progress: dict | None = None
    payload: dict = field(default_factory=dict)
    seq: int = 0
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.seq,
            "seq": self.seq,
            "ts": self.ts,
            "run_id": self.run_id,
            "type": self.type,
            "agent": self.agent,
            "stage": self.stage,
            "level": self.level,
            "progress": self.progress,
            "payload": self.payload,
        }

    def sse(self) -> str:
        data = json.dumps(self.to_dict(), default=str)
        return f"id: {self.seq}\nevent: message\ndata: {data}\n\n"


class EventBus:
    def __init__(self, capacity: int = 10000, queue_size: int = 1000):
        self.capacity = capacity
        self.queue_size = queue_size
        self._ring: deque[Event] = deque(maxlen=capacity)
        self._subs: set[queue.Queue] = set()
        self._lock = threading.Lock()
        self._seq = 0

    def publish(self, event: Event) -> Event:
        with self._lock:
            self._seq += 1
            event.seq = self._seq
            self._ring.append(event)
            subs = list(self._subs)
        for sub in subs:
            try:
                sub.put_nowait(event)
            except queue.Full:
                self._shed(sub)
        return event

    def _shed(self, sub: queue.Queue) -> None:
        """Drop the oldest log line or reasoning piece, or collapse progress."""
        try:
            dropped = sub.get_nowait()
            while dropped.type in ("log", "reasoning", "fetch") and not sub.empty():
                dropped = sub.get_nowait()
            kept = dropped.to_dict()
            kept["type"] = "lagged"
            kept["payload"] = {"dropped_from": dropped.seq}
            sub.put_nowait(kept)
        except queue.Empty:
            pass
        except queue.Full:
            pass

    def subscribe(self, since: int | None = None) -> queue.Queue:
        sub: queue.Queue = queue.Queue(maxsize=self.queue_size)
        if since is not None:
            for event in self.backlog(since):
                try:
                    sub.put_nowait(event)
                except queue.Full:
                    break
        with self._lock:
            self._subs.add(sub)
        return sub

    def unsubscribe(self, sub: queue.Queue) -> None:
        with self._lock:
            self._subs.discard(sub)

    def backlog(self, since: int | None = None) -> list[Event]:
        with self._lock:
            events = list(self._ring)
        if since is None:
            return []
        return [event for event in events if event.seq > since]

    def stream(self, sub: queue.Queue, heartbeat: float = 15.0):
        """Yield SSE frames for one subscriber until it disconnects."""
        try:
            while True:
                try:
                    event = sub.get(timeout=heartbeat)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                if isinstance(event, dict):
                    yield "event: message\ndata: " + json.dumps(event, default=str) + "\n\n"
                else:
                    yield event.sse()
        finally:
            self.unsubscribe(sub)
