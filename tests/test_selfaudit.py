import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import selfaudit
from netcast3r.server.index import Index


class SelfAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.index = Index(self.base / "netcast3r.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_database_is_created_0600(self):
        mode = self.base.joinpath("netcast3r.db").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_audit_flags_world_readable_state(self):
        os.chmod(self.base / "netcast3r.db", 0o644)
        (self.base / "control-plane.json").write_text("{}")
        os.chmod(self.base / "control-plane.json", 0o644)
        result = selfaudit.audit(self.base)
        titles = [item["title"] for item in result["findings"]]
        self.assertTrue(any("index database" in title for title in titles))
        self.assertTrue(any("control-plane" in title for title in titles))
        self.assertLess(result["score"], 100)

    def test_audit_clean_after_chmod(self):
        os.chmod(self.base, 0o700)
        os.chmod(self.base / "netcast3r.db", 0o600)
        result = selfaudit.audit(self.base)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["grade"], "A")

    def test_diagnostics_reports_integrity_and_counts(self):
        result = selfaudit.diagnostics(self.index, self.base, routes=5, tools=115)
        self.assertEqual(result["integrity"], "ok")
        self.assertTrue(result["ok"])
        self.assertEqual(result["counts"]["findings"], 0)
        self.assertEqual(result["routes"], 5)
        self.assertEqual(result["tools"], 115)


class ExpertiseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.tmp.name) / "netcast3r.db")

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def test_lessons_build_a_technology_profile(self):
        self.index.add_lesson("WP plugin path", "The plugin exposes a backup file.",
                              outcome="success", tags=["wordpress", "php"])
        self.index.add_lesson("WP REST users", "The users route enumerates accounts.",
                              outcome="success", tags=["wordpress", "api"])
        self.index.add_lesson("WP login lockout", "The login path did not rate limit.",
                              outcome="failure", tags=["wordpress", "auth"])
        profile = {item["tech"]: item for item in self.index.list_expertise()}
        self.assertGreaterEqual(profile["wordpress"]["exposures"], 3)
        self.assertEqual(profile["wordpress"]["successes"], 2)
        self.assertEqual(profile["wordpress"]["failures"], 1)
        self.assertEqual(profile["wordpress"]["confidence"], 0.67)
        self.assertEqual(profile["wordpress"]["level"], "novice")
        self.assertIn("php", profile)

    def test_non_technology_tags_are_ignored(self):
        self.index.add_lesson("A note", "Nothing technical.", tags=["random-tag"])
        self.assertEqual(self.index.list_expertise(), [])


if __name__ == "__main__":
    unittest.main()
