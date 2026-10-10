import json
import queue
import re
import tempfile
import time
import unittest
from pathlib import Path

from netcast3r.agents import _first_json
from netcast3r.config import ProviderConfig, default_config
from netcast3r.knowledge import Knowledge
from netcast3r.providers import ProviderBus
from netcast3r.secrets import Extractor, Pattern, load_patterns
from netcast3r.server.events import Event, EventBus


class RedosTests(unittest.TestCase):
    def test_the_full_catalog_scans_a_hostile_blob_in_bounds(self):
        patterns = load_patterns()
        blob = ("meraki cohere okta private_ai sumo jfrog atlassian "
                + "a" * 200_000)
        extractor = Extractor(patterns=patterns)
        started = time.monotonic()
        extractor.scan(blob, source="blob.js")
        self.assertLess(time.monotonic() - started, 8.0)


class FirstJsonTests(unittest.TestCase):
    def test_a_fenced_block_is_read(self):
        self.assertEqual(_first_json('```json\n{"a": 1}\n```'), {"a": 1})

    def test_the_first_of_two_objects_wins(self):
        self.assertEqual(_first_json('{"a": 1} and {"b": 2}'), {"a": 1})

    def test_prose_braces_do_not_swallow_the_value(self):
        self.assertEqual(_first_json('note {not json} then {"ok": true}'), {"ok": True})

    def test_an_array_is_returned(self):
        self.assertEqual(_first_json("here:\n[1, 2, 3]"), [1, 2, 3])

    def test_no_json_is_none(self):
        self.assertIsNone(_first_json("no structure here"))


class ScanCapTests(unittest.TestCase):
    def test_the_tail_is_still_scanned(self):
        pattern = Pattern(id="x", type="x", regex=re.compile(r"SECRET[0-9]+"))
        extractor = Extractor(patterns=[pattern], max_scan=40)
        text = "a" * 500 + " SECRET12345"
        found = extractor.scan(text)
        self.assertTrue(any(s.value == "SECRET12345" for s in found))


class KnowledgeTests(unittest.TestCase):
    def test_a_raw_secret_is_not_written_to_disk(self):
        workdir = Path(tempfile.mkdtemp())
        knowledge = Knowledge(store_path=workdir / "classifications.json")
        knowledge.remember_classification("SUPERSECRETVALUE", {"type": "aws", "confidence": 0.9})
        raw = (workdir / "classifications.json").read_text()
        self.assertNotIn("SUPERSECRETVALUE", raw)
        self.assertEqual(knowledge.classification("SUPERSECRETVALUE")["type"], "aws")


class ProviderCandidateTests(unittest.TestCase):
    def test_a_keyless_loopback_provider_is_offered(self):
        config = default_config()
        config.providers = [ProviderConfig(name="local", base_url="http://127.0.0.1:8000/v1",
                                           models=["m"], priority=1)]
        bus = ProviderBus(config)
        names = [provider.name for provider, _, _ in bus._candidates("exegete")]
        self.assertIn("local", names)

    def test_a_keyless_remote_provider_is_skipped(self):
        config = default_config()
        config.providers = [ProviderConfig(name="remote", base_url="https://api.example.com/v1",
                                           models=["m"], priority=1)]
        bus = ProviderBus(config)
        names = [provider.name for provider, _, _ in bus._candidates("exegete")]
        self.assertNotIn("remote", names)


class EventShedTests(unittest.TestCase):
    def test_a_finding_survives_backpressure(self):
        bus = EventBus(queue_size=4)
        sub = bus.subscribe()
        sub.put_nowait(Event(type="log", seq=1))
        sub.put_nowait(Event(type="log", seq=2))
        sub.put_nowait(Event(type="finding.created", seq=3))
        sub.put_nowait(Event(type="log", seq=4))
        bus._shed(sub)
        types = [event.type for event in list(sub.queue)]
        self.assertIn("finding.created", types)


if __name__ == "__main__":
    unittest.main()
