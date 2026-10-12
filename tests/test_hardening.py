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
from netcast3r.scope import ScopeManager
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

    def test_a_dead_model_is_retired_after_two_strikes(self):
        config = default_config()
        config.providers = [ProviderConfig(name="p", base_url="https://api.example.com/v1",
                                           api_key="k", models=["m1", "m2"], priority=1)]
        bus = ProviderBus(config)
        bus._strike("p", "m1")
        models = [model for _, model, _ in bus._candidates("exegete")]
        self.assertIn("m1", models)
        bus._strike("p", "m1")
        models = [model for _, model, _ in bus._candidates("exegete")]
        self.assertNotIn("m1", models)
        self.assertIn("m2", models)

    def test_a_404_retires_a_model_at_once(self):
        config = default_config()
        config.providers = [ProviderConfig(name="p", base_url="https://api.example.com/v1",
                                           api_key="k", models=["m1"], priority=1)]
        bus = ProviderBus(config)
        bus._strike("p", "m1", fatal=True)
        models = [model for _, model, _ in bus._candidates("exegete")]
        self.assertNotIn("m1", models)


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


class PatternGroupTests(unittest.TestCase):
    def test_group_defaults_to_the_first_capture(self):
        workdir = Path(tempfile.mkdtemp())
        path = workdir / "patterns.toml"
        path.write_text(
            "[[pattern]]\n"
            "id = \"t\"\n"
            "type = \"t\"\n"
            "regex = \"KEY=([A-Z0-9]{8})\"\n"
        )
        patterns = load_patterns(path)
        self.assertEqual(patterns[0].group, 1)
        found = Extractor(patterns=patterns).scan("prefix KEY=ABCD1234 suffix")
        self.assertEqual([s.value for s in found], ["ABCD1234"])


class ScopeTests(unittest.TestCase):
    def test_a_bang_entry_is_an_exclusion(self):
        scope = ScopeManager(in_scope=["example.com", "!admin.example.com"])
        self.assertTrue(scope.is_in_scope("https://www.example.com/"))
        self.assertFalse(scope.is_in_scope("https://admin.example.com/"))

    def test_url_prefix_blocks_path_traversal(self):
        scope = ScopeManager(in_scope=["https://example.com/app"])
        self.assertTrue(scope.is_in_scope("https://example.com/app/x"))
        self.assertFalse(scope.is_in_scope("https://example.com/app/../../admin"))


if __name__ == "__main__":
    unittest.main()
