import os
import unittest

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import offsec


class OffsecTests(unittest.TestCase):
    def test_framework_map_is_candid(self):
        items = offsec.frameworks()
        self.assertGreaterEqual(len(items), 15)
        ids = [item["id"] for item in items]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(any(item["coverage"] == "gap" for item in items))
        found = offsec.search(query="bloodhound")
        self.assertEqual(found["items"][0]["id"], "bloodhound")
        summary = offsec.summary()
        self.assertEqual(summary["total"], len(items))
        self.assertGreater(summary["coverage"]["gap"], 0)

    def test_boot2root_plan_has_phases_and_gaps(self):
        plan = offsec.boot2root_plan(
            "linux", ["http", "ssh"], goal="prove root")
        phases = [item["phase"] for item in plan["phases"]]
        self.assertIn("enumerate", phases)
        self.assertIn("web-access", phases)
        self.assertIn("privilege-escalation", phases)
        self.assertIn("cleanup", phases)
        self.assertTrue(any("gap" in item for item in plan["phases"]))
        ad = offsec.boot2root_plan("windows", ["ldap", "smb"])
        self.assertTrue(ad["ad"])
        self.assertIn("directory", [item["phase"] for item in ad["phases"]])


if __name__ == "__main__":
    unittest.main()
