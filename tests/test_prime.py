import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import prime
from netcast3r.server import build_server


class PrimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.prime = prime.Prime(self.index)

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def mission(self, title="M", autonomy="autonomous", status="active",
                target="http://127.0.0.1:9/", **kwargs):
        return self.index.create_mission(
            title, target, status=status, autonomy=autonomy,
            scope=["127.0.0.1"], **kwargs)

    def test_manual_missions_are_never_ranked_above_autonomous(self):
        auto = self.mission("auto", autonomy="autonomous")
        manual = self.mission("manual", autonomy="manual")
        rows = {row["mission_id"]: row for row in self.prime.portfolio()}
        self.assertIn(auto["id"], rows)
        self.assertIn(manual["id"], rows)
        self.assertGreater(rows[auto["id"]]["score"], rows[manual["id"]]["score"])

    def test_inactive_and_training_missions_are_excluded(self):
        self.mission("archived", status="archived")
        self.mission("done", status="done")
        self.mission("paused", status="paused")
        training = self.index.create_mission(
            "Training", "https://portswigger.net/", status="active",
            autonomy="autonomous")
        rows = self.prime.portfolio()
        self.assertEqual(rows, [])
        self.assertNotIn(training["id"], [row["mission_id"] for row in rows])

    def test_open_leads_and_findings_raise_the_score(self):
        base = self.mission("plain")
        rich = self.mission("rich")
        self.index.create_hypothesis("A real lead", target="http://127.0.0.1:9/",
                                     mission_id=rich["id"])
        rows = {row["mission_id"]: row for row in self.prime.portfolio()}
        self.assertGreater(rows[rich["id"]]["score"], rows[base["id"]]["score"])
        self.assertEqual(rows[rich["id"]]["open_hypotheses"], 1)

    def test_pending_approvals_push_a_mission_down(self):
        blocked = self.mission("blocked")
        clean = self.mission("clean")
        self.index.create_approval(blocked["id"], "http_probe", risk="high",
                                   reason="needs a human")
        rows = {row["mission_id"]: row for row in self.prime.portfolio()}
        self.assertLess(rows[blocked["id"]]["score"], rows[clean["id"]]["score"])
        without = self.prime.score({**rows[blocked["id"]],
                                    "pending_approvals": 0})
        self.assertEqual(rows[blocked["id"]]["score"], without - 30)

    def test_next_objective_prefers_an_open_hypothesis(self):
        mission = self.mission("leads")
        self.index.create_hypothesis("IDOR on order lookup",
                                     target="http://127.0.0.1:9/",
                                     mission_id=mission["id"])
        signals = self.prime._signals(mission)
        objective = self.prime.next_objective(signals)
        self.assertEqual(objective["kind"], "hypothesis")
        self.assertIn("IDOR on order lookup", objective["goal"])
        self.assertEqual(self.prime.mode_for(signals, objective), "swarm")

    def test_mode_escalates_hunt_then_autopilot(self):
        mission = self.mission("fresh")
        signals = self.prime._signals(mission)
        objective = self.prime.next_objective(signals)
        self.assertEqual(self.prime.mode_for(signals, objective), "hunt")
        signals["run_count"] = 3
        self.assertEqual(self.prime.mode_for(signals, objective), "autopilot")

    def test_model_advice_can_reorder_but_not_add_mission(self):
        first = self.mission("first")
        second = self.mission("second")
        calls = {"n": 0}

        def complete(role, messages):
            calls["n"] += 1
            self.assertEqual(role, "prime")
            order = {"thought": "second has a lead",
                     "order": [{"mission_id": second["id"], "why": "lead"},
                               {"mission_id": "msn_invented", "why": "ghost"}]}
            return {"text": json.dumps(order)}

        advisor = prime.Prime(self.index, complete=complete, use_model=True)
        decision = advisor.decide(limit=5, use_model=True)
        self.assertEqual(decision["source"], "model")
        self.assertEqual(decision["ranked"][0]["mission_id"], second["id"])
        ids = {row["mission_id"] for row in decision["ranked"]}
        self.assertNotIn("msn_invented", ids)
        self.assertIn(first["id"], ids)  # kept, appended after the model's picks
        self.assertEqual(calls["n"], 1)

    def test_a_broken_model_falls_back_to_deterministic(self):
        self.mission("only")

        def complete(role, messages):
            raise RuntimeError("provider down")

        advisor = prime.Prime(self.index, complete=complete, use_model=True)
        decision = advisor.decide(limit=5)
        self.assertEqual(decision["source"], "deterministic")
        self.assertTrue(decision["ranked"])

    def test_prime_creates_no_finding(self):
        self.mission("clean")
        self.prime.decide(limit=5)
        counts = self.index.totals()
        self.assertEqual(counts.get("findings", 0), 0)


if __name__ == "__main__":
    unittest.main()
