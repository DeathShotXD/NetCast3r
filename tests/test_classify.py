import tempfile
import unittest
from pathlib import Path

from netcast3r.config import default_config
from netcast3r.knowledge import Knowledge
from netcast3r.orchestrator import Orchestrator
from netcast3r.scope import ScopeManager
from netcast3r.secrets import Extractor, Secret
from netcast3r.store import Store
from netcast3r.validate import Recipe, Validator


class FakeBus:
    def _candidates(self, agent):
        return [("fake", object())]

    def chat_stream(self, agent, messages, on_chunk=None):
        return ('{"items":[{"value":"AIzaSyTESTVALUE123","type":"google_api",'
                '"provider":"Google","is_secret":true,"confidence":0.9}]}')


class ClassifierTests(unittest.TestCase):
    def _orchestrator(self, workdir):
        config = default_config()
        config.run.action_tier = "read"
        scope = ScopeManager(in_scope=["example.com"])
        store = Store(workdir / "netcast3r.db")
        recipe = Recipe(type="google_api", provider="Google", method="GET",
                        url="https://example.test/?key={value}", success_codes=[200])
        validator = Validator(recipes={"google_api": recipe}, tier="read")
        orch = Orchestrator(config, scope, store, bus=FakeBus(), use_agents=True,
                            validator=validator, extractor=Extractor(patterns=[]))
        orch.knowledge = Knowledge(store_path=workdir / "classifications.json")
        return orch

    def test_classifier_retypes_a_generic_candidate(self):
        workdir = Path(tempfile.mkdtemp())
        orch = self._orchestrator(workdir)
        candidates = [Secret(type="generic", value="AIzaSyTESTVALUE123", pattern_id="generic")]
        out = orch._classify(candidates)
        self.assertEqual(out[0].type, "google_api")
        self.assertGreaterEqual(out[0].confidence, 0.9)
        self.assertTrue((workdir / "classifications.json").exists())

    def test_safe_check_blocks_ssrf_targets(self):
        self.assertFalse(Orchestrator._safe_check("http://example.com"))
        self.assertFalse(Orchestrator._safe_check("https://127.0.0.1/x"))
        self.assertFalse(Orchestrator._safe_check("https://169.254.169.254/latest"))
        self.assertFalse(Orchestrator._safe_check("https://10.0.0.5/x"))
        self.assertFalse(Orchestrator._safe_check("https://metadata.google.internal/x"))
        self.assertTrue(Orchestrator._safe_check("https://api.example.com/v1"))


if __name__ == "__main__":
    unittest.main()
