"""Event pipeline regressions: replay window, counters, shed safety, frames.

These pin the fixes made after the engine-room audit: stale counters on
reload, replay truncation of long runs, the subscribe/read race, a shed path
that could crash on replay items, and reasoning deltas joined with newlines.
"""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.server.events import Event, EventBus
from netcast3r.server.index import Index
from netcast3r.server.jobs import JobManager, _ReasonCoalescer
from netcast3r.server.keys import KeyStore
from netcast3r.server.runner import EventConsole


class IndexWindowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "netcast3r.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def _seed(self, count: int) -> None:
        for seq in range(1, count + 1):
            self.index.add_event("run_x", {"seq": seq, "ts": float(seq), "type": "log",
                                           "payload": {"text": f"line {seq}"}})

    def test_a_fresh_read_returns_the_tail_not_the_head(self):
        self._seed(1200)
        rows = self.index.list_events("run_x")
        self.assertEqual(len(rows), 1000)
        self.assertEqual(rows[0]["seq"], 201)
        self.assertEqual(rows[-1]["seq"], 1200)

    def test_since_pages_forward_in_order(self):
        self._seed(1200)
        rows = self.index.list_events("run_x", since=1150)
        self.assertEqual([row["seq"] for row in rows], list(range(1151, 1201)))

    def test_progress_counters_survive_replay(self):
        self.index.add_event("run_x", {"seq": 1, "ts": 1.0, "type": "stage.progress",
                                       "payload": {}, "progress": {"crawled": 42}})
        rows = self.index.list_events("run_x")
        self.assertEqual(rows[0]["progress"], {"crawled": 42})
        self.assertEqual(rows[0]["payload"], {})


class EventShedRegressionTests(unittest.TestCase):
    class _ReplayLike:
        type = "replay"
        seq = 3

    def test_shedding_a_replay_like_item_never_raises(self):
        bus = EventBus(queue_size=2)
        sub = bus.subscribe()
        sub.put_nowait(self._ReplayLike())
        sub.put_nowait(Event(type="log", seq=4))
        bus.publish(Event(type="log"))  # fills, sheds, retries - must not raise
        self.assertTrue(sub.qsize() <= 2)

    def test_a_flood_with_a_replay_like_head_does_not_crash_the_publisher(self):
        bus = EventBus(queue_size=1)
        sub = bus.subscribe()
        sub.put_nowait(self._ReplayLike())
        event = bus.publish(Event(type="finding.created", seq=0))
        self.assertEqual(event.type, "finding.created")


class ReasonCoalescerTests(unittest.TestCase):
    def test_deltas_reassemble_words_without_newlines(self):
        seen = []
        coalescer = _ReasonCoalescer(lambda event: seen.append(event))
        for piece in ("Hel", "lo wo", "rld"):
            coalescer.add(Event(type="reasoning", agent="exegete", payload={"text": piece}))
        coalescer.flush()
        self.assertEqual([event.payload["text"] for event in seen], ["Hello world"])

    def test_embedded_newlines_survive(self):
        seen = []
        coalescer = _ReasonCoalescer(lambda event: seen.append(event))
        coalescer.add(Event(type="reasoning", agent="scribe", payload={"text": "one\ntwo "}))
        coalescer.add(Event(type="reasoning", agent="scribe", payload={"text": "three"}))
        coalescer.flush()
        self.assertEqual(seen[0].payload["text"], "one\ntwo three")

    def test_the_console_forwards_chunks_verbatim(self):
        seen = []
        console = EventConsole(emit=seen.append, run_id="run_x")
        console.reasoning("exegete", "a frag")
        console.reasoning("exegete", "ment")
        self.assertEqual([event.payload["text"] for event in seen], ["a frag", "ment"])


class EventFramesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        base = Path(self.tmp.name)
        self.index = Index(base / "netcast3r.db")
        self.bus = EventBus()
        self.keys = KeyStore(base)
        self.jobs = JobManager(self.index, self.bus, lambda *a: {}, workers=1)

    def tearDown(self):
        self.jobs.shutdown()
        self.index.close()
        self.tmp.cleanup()

    def _persist(self, run_id: str, event: Event) -> Event:
        self.bus.publish(event)
        self.index.add_event(run_id, event.to_dict())
        return event

    def _seqs(self, frames) -> list[int]:
        seqs = []
        for frame in frames:
            for line in str(frame).splitlines():
                if line.startswith("id: "):
                    seqs.append(int(line[4:]))
                    break
        return seqs

    def _take_seqs(self, gen, count: int) -> list[int]:
        import itertools
        return self._seqs(itertools.islice(gen, count))

    def test_replay_precedes_live_and_catches_the_read_window(self):
        from netcast3r.server import Server
        server = Server(self.index, self.bus, self.jobs, self.keys)
        for seq in range(1, 6):
            self._persist("run_x", Event(type="log", run_id="run_x", payload={"text": str(seq)}))
        original = self.index.list_events
        state = {"injected": False}

        def hook(run_id, since=0, limit=1000):
            if not state["injected"]:
                state["injected"] = True
                # Published after the subscription opened but before the read
                # landed; only the live queue can carry it, and it must.
                self.bus.publish(Event(type="log", run_id="run_x", payload={"text": "6"}))
            return original(run_id, since=since, limit=limit)

        self.index.list_events = hook
        try:
            gen = server._event_frames("run_x", None)
            self.assertEqual(self._take_seqs(gen, 6), [1, 2, 3, 4, 5, 6])
            # The queued copy of a persisted event is not re-sent after replay.
            self._persist("run_x", Event(type="log", run_id="run_x", payload={"text": "7"}))
            self.assertEqual(self._take_seqs(gen, 1), [7])
        finally:
            gen.close()
            self.index.list_events = original

    def test_an_event_on_the_bus_still_reaches_live_viewers_only_once(self):
        from netcast3r.server import Server
        server = Server(self.index, self.bus, self.jobs, self.keys)
        first = self._persist("run_y", Event(type="log", run_id="run_y"))
        gen = server._event_frames("run_y", None)
        self.assertEqual(self._take_seqs(gen, 1), [first.seq])
        gen.close()


class AppReloadTests(unittest.TestCase):
    def test_a_rebuilt_bundle_is_picked_up_without_a_restart(self):
        from netcast3r.server import Server
        tmp = TemporaryDirectory()
        base = Path(tmp.name)
        app = base / "index.html"
        app.write_text("<html>one</html>", encoding="utf-8")
        index = Index(base / "netcast3r.db")
        jobs = JobManager(index, EventBus(), lambda *a: {}, workers=1)
        server = Server(index, jobs.bus, jobs, KeyStore(base), static_dir=base)
        self.assertIn("one", server._app() or "")
        app.write_text("<html>two</html>", encoding="utf-8")
        self.assertIn("two", server._app() or "")
        jobs.shutdown()
        index.close()
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
