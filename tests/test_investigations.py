import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import investigations
from netcast3r.server import build_server


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Lead evidence", "example.com", status="active",
            autonomy="autonomous", scope=["example.com"])
        self.hypothesis = self.index.create_hypothesis(
            "Test SSRF through the image fetcher",
            target="https://example.com/fetch",
            mission_id=self.mission["id"], technique="ssrf",
            rationale="the endpoint accepts a remote image URL",
            expected="a callback from the server proves it fetched the URL")

    def tearDown(self):
        if getattr(self.server, "director", None) is not None:
            self.server.director.shutdown()
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def test_evidence_collects_notes_calls_and_runs(self):
        self.index.add_agent_note(
            self.mission["id"], "swarm.observation", "SSRF callback seen",
            "The server fetched the image URL and called the OAST host.")
        run = self.index.create_run("example.com", {"mode": "swarm"})
        self.index.add_mission_run(self.mission["id"], run["id"])
        self.index.add_tool_call(
            "http_request", risk="medium", status="ok", actor="agent:swarm",
            mission_id=self.mission["id"], run_id=run["id"],
            args={"target": "https://example.com/fetch?url=https://oast.test"},
            result={"status": 200})
        result = investigations.evidence(self.index, self.hypothesis["id"])
        self.assertEqual(result["hypothesis"]["id"], self.hypothesis["id"])
        self.assertEqual(result["progress"], "evidence recorded, no verdict")
        self.assertEqual(result["counts"]["notes"], 1)
        self.assertEqual(result["counts"]["tool_calls"], 1)
        self.assertEqual(result["counts"]["runs"], 1)
        self.assertTrue(result["notes"][0]["matched_terms"])
        self.assertIn("not a finding", result["note"])

    def test_a_path_scoped_lead_ignores_unrelated_redirect_evidence(self):
        lead = self.index.create_hypothesis(
            "Open redirect on the callback", 
            target="https://example.com/api/callback?redirect=https://example.com/x",
            mission_id=self.mission["id"], technique="open-redirect",
            rationale="recorded 301", expected="Location header")
        self.index.add_agent_note(
            self.mission["id"], "swarm.observation", "Root redirects to www",
            "GET https://example.com/ returned 301 to https://www.example.com/.")
        self.index.add_agent_note(
            self.mission["id"], "swarm.observation", "Callback reflects redirect",
            "GET /api/callback?redirect=https://example.com/x returned 301 "
            "with a Location header.")
        result = investigations.evidence(self.index, lead["id"])
        self.assertEqual(result["path_hint"], "api/callback")
        self.assertEqual(result["counts"]["notes"], 1)
        self.assertIn("Callback reflects", result["notes"][0]["title"])

    def test_the_evidence_brief_is_markdown(self):
        record = investigations.evidence(self.index, self.hypothesis["id"])
        text = investigations.render_markdown(record)
        self.assertIn(self.hypothesis["title"], text)
        self.assertIn("What would prove it", text)
        self.assertIn("not a finding", text.lower())

    def test_evidence_chain_shape_on_finding_detail(self):
        run = self.index.create_run("example.com", {"mode": "swarm"})
        self.index.add_mission_run(self.mission["id"], run["id"])
        self.index.add_tool_call(
            "http_request", risk="medium", status="ok", actor="agent:swarm",
            mission_id=self.mission["id"], run_id=run["id"],
            args={"target": "https://example.com/fetch?url=https://oast.test",
                  "method": "GET"},
            result={"status": 200, "body": '{"ok":true}', "url": "https://example.com/fetch"},
        )
        self.index.patch_hypothesis(self.hypothesis["id"], status="supported",
                                    test={"steps": [{"path": "/fetch", "method": "GET"}]},
                                    result={"ok": True, "passed": 1})
        finding = self.index.create_finding(
            title="SSRF in fetcher", severity="high", run_id=run["id"],
            impact="Server-side request to attacker URL enables internal network access.",
            evidence="Recorded callback from server-side fetch to OAST host during retest.",
            tags=[self.hypothesis["id"], "confirmed"],
            hypothesis_id=self.hypothesis["id"])
        detail = investigations.finding_detail(self.index, finding["id"])
        self.assertIsNotNone(detail)
        chain = detail.get("evidence_chain") or []
        self.assertTrue(chain)
        kinds = {item["kind"] for item in chain}
        self.assertIn("tool_call", kinds)
        tool_items = [item for item in chain if item["kind"] == "tool_call"]
        self.assertIn("response", tool_items[0])
        self.assertIn("body_sample", tool_items[0]["response"])
        self.assertIn("publish_gate", detail)

    def test_candidate_detail_includes_poc_steps_in_chain(self):
        candidate = self.index.create_candidate(
            self.mission["id"], "IDOR on invoice API", severity="high",
            evidence={"steps": [{
                "target": "https://example.com/api/invoice/1",
                "observation": {"status": 200, "body": '{"owner":"victim"}'},
            }]})
        detail = investigations.candidate_detail(self.index, candidate["id"])
        self.assertEqual(detail["id"], candidate["id"])
        steps = [item for item in detail["evidence_chain"] if item["kind"] == "poc_step"]
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["response"]["status"], 200)

    def test_a_refuted_lead_says_refuted(self):
        self.index.patch_hypothesis(self.hypothesis["id"], status="refuted",
                                    test="callback never arrived",
                                    result="refuted")
        result = investigations.evidence(self.index, self.hypothesis["id"])
        self.assertEqual(result["progress"], "refuted by the recorded evidence")

    def test_unknown_hypothesis_is_refused(self):
        with self.assertRaises(ValueError):
            investigations.evidence(self.index, "hyp_missing")

    def test_a_recorded_observation_becomes_a_visible_lead(self):
        note = self.index.add_agent_note(
            self.mission["id"], "swarm.observation",
            "Open redirect on /api/auth/callback",
            "GET https://example.com/api/auth/callback?redirect=https://example.com/test "
            "returned a 301 Location to the external host.")
        result = investigations.sync_from_notes(self.index, self.mission["id"])
        self.assertEqual(result["counts"]["created"], 1)
        lead = result["created"][0]
        self.assertEqual(lead["technique"], "open-redirect")
        self.assertIn("example.com/api/auth/callback", lead["target"])
        self.assertIn(note["id"], lead["rationale"])
        again = investigations.sync_from_notes(self.index, self.mission["id"])
        self.assertEqual(again["counts"]["created"], 0)
        self.assertTrue(any("already exists" in item["reason"]
                            for item in again["skipped"]))

    def test_a_generic_observation_does_not_become_a_lead(self):
        self.index.add_agent_note(
            self.mission["id"], "swarm.observation", "Scope checked",
            "The target is inside the mission scope and the request is ready.")
        result = investigations.sync_from_notes(self.index, self.mission["id"])
        self.assertEqual(result["counts"]["created"], 0)

    def test_evidence_route(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        response = self.server.route(
            "GET", f"/api/v1/hypotheses/{self.hypothesis['id']}/evidence",
            {}, headers, b"")
        self.assertEqual(response.status, 200)
        payload = json.loads(response.body.decode())
        self.assertEqual(payload["counts"]["notes"], 0)
        self.assertIn("untested", payload["progress"])

    def test_evidence_markdown_route(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        response = self.server.route(
            "GET", f"/api/v1/hypotheses/{self.hypothesis['id']}/evidence.md",
            {}, headers, b"")
        self.assertEqual(response.status, 200)
        self.assertIn("text/markdown", response.content_type)
        self.assertIn(self.hypothesis["title"], response.body.decode())

    def test_leads_sync_route(self):
        self.index.add_agent_note(
            self.mission["id"], "swarm.observation",
            "SSRF callback observed",
            "The server fetched https://example.com/fetch?url=https://oast.test "
            "and the callback arrived.")
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        response = self.server.route(
            "POST", f"/api/v1/missions/{self.mission['id']}/leads/sync",
            {}, headers, json.dumps({"limit": 3}).encode())
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body.decode())["counts"]["created"], 1)

    def test_hypothesis_verify_requires_steps(self):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token,
                   "content-type": "application/json"}
        response = self.server.route(
            "POST", f"/api/v1/hypotheses/{self.hypothesis['id']}/verify",
            {}, headers, b"{}")
        self.assertEqual(response.status, 400)
        detail = json.loads(response.body.decode())
        self.assertIn("steps", (detail.get("title") or "").lower())


if __name__ == "__main__":
    unittest.main()