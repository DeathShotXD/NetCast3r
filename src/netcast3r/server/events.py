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
                try:
                    sub.put_nowait(event)
                except queue.Full:
                    pass
        return event

    def _shed(self, sub: queue.Queue) -> None:
        """Free room by dropping the oldest log/reasoning/fetch lines only.

        A finding or a stage change must survive backpressure, so the drain
        stops at the first event that is not chatter. If the queue holds only
        chatter-free events, the oldest is still dropped so a stalled reader
        does not wedge the run, and one lagged marker records the gap.
        """
        dropped = None
        while sub.queue:
            head = sub.queue[0]
            if head.type in ("log", "reasoning", "fetch"):
                try:
                    dropped = sub.get_nowait()
                except queue.Empty:
                    break
            else:
                break
        if dropped is None:
            try:
                dropped = sub.get_nowait()
            except queue.Empty:
                return
        try:
            sub.put_nowait(Event(type="lagged", run_id=dropped.run_id,
                                 payload={"dropped_from": dropped.seq}))
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

    def stream(self, sub: queue.Queue, heartbeat: float = 15.0, run_id: str | None = None,
               since: int = 0):
        """Yield SSE frames for one subscriber until it disconnects.

        When ``run_id`` is given, only events for that run are forwarded; the
        bus is shared, so a per-run screen must not see another run's events.
        ``since`` drops live events at or below a replay boundary so a
        reconnecting client never sees the same event twice.
        """
        try:
            while True:
                try:
                    event = sub.get(timeout=heartbeat)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                if run_id is not None:
                    owner = None
                    if isinstance(event, dict):
                        owner = event.get("run_id")
                    else:
                        owner = getattr(event, "run_id", None)
                        if owner is None:
                            inner = getattr(event, "event", None)
                            if isinstance(inner, dict):
                                owner = inner.get("run_id")
                    if owner != run_id:
                        continue
                if since and not (not isinstance(event, dict)
                                  and getattr(event, "type", "") == "replay"):
                    seq = event.get("seq") if isinstance(event, dict) else getattr(event, "seq", 0)
                    if isinstance(seq, int) and 0 < seq <= since:
                        continue
                if isinstance(event, dict):
                    yield "event: message\ndata: " + json.dumps(event, default=str) + "\n\n"
                else:
                    yield event.sse()
        finally:
            self.unsubscribe(sub)
