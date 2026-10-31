import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import campaign, graph, kb, target
from netcast3r.server import build_server


class MemoryHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        self.index = self.server.index
        self.mission = self.index.create_mission(
            "Acme", "https://acme.example/", status="active",
            scope=["acme.example"])
        self.run = self.index.create_run("https://acme.example/",
                                         {"mode": "hunt"})
        self.index.add_mission_run(self.mission["id"], self.run["id"])

    def tearDown(self):
        self.server.jobs.shutdown(wait=False)
        self.index.close()

    def add_probe(self, headers=None):
        self.index.add_tool_call(
            "http_probe", risk="low", status="ok", actor="agent:swarm",
            mission_id=self.mission["id"], run_id=self.run["id"],
            args={"target": "https://acme.example/"},
            result={"status": 200, "headers": headers or {
                "server": "nginx/1.25.3", "cf-ray": "abc",
                "x-powered-by": "Express"}})


class KnowledgeBaseTests(MemoryHarness):
    def test_record_search_and_digest(self):
        kb.record(self.index, "global", "technology", "nginx", title="nginx",
                  body="seen everywhere")
        kb.record(self.index, self.mission["id"], "pattern", "admin", title="admin panel")
        rows = kb.search(self.index, query="nginx")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "technology")
        digest = kb.digest(self.index, self.mission["id"], limit=10)
        kinds = {row["kind"] for row in digest}
        self.assertIn("technology", kinds)
        self.assertIn("pattern", kinds)

    def test_upsert_is_idempotent_and_hits_order_the_digest(self):
        kb.record(self.index, "global", "technology", "nginx", title="nginx")
        kb.record(self.index, "global", "technology", "nginx", title="nginx v2")
        rows = kb.search(self.index, scope="global", kind="technology")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["title"], "nginx v2")
        second = kb.record(self.index, "global", "technology", "apache",
                           title="apache")
        self.index.bump_kb_hit(second["id"])
        digest = kb.digest(self.index, self.mission["id"], limit=5)
        self.assertEqual(digest[0]["title"], "apache")
        self.assertEqual(kb.stats(self.index)["total"], 2)

    def test_learn_from_mission_writes_global_knowledge(self):
        self.add_probe()
        hyp = self.index.create_hypothesis(
            "IDOR on /api/orders/7", target="https://acme.example/api/orders/7",
            mission_id=self.mission["id"], technique="idor",
            expected="user B reads user A")
        self.index.patch_hypothesis(hyp["id"], status="refuted")
        graph.rebuild(self.index, self.mission["id"])
        counts = kb.learn_from_mission(self.index, self.mission["id"])
        self.assertGreaterEqual(counts["endpoint"], 1)
        self.assertEqual(counts["dead-end"], 1)
        entries = self.index.list_kb_entries(scope="global")
        kinds = {entry["kind"] for entry in entries}
        self.assertIn("endpoint", kinds)
        self.assertIn("dead-end", kinds)
        # Idempotent: a second pass does not duplicate.
        before = len(entries)
        kb.learn_from_mission(self.index, self.mission["id"])
        self.assertEqual(len(self.index.list_kb_entries(scope="global")), before)

    def test_endpoint_patterns_are_host_agnostic(self):
        self.index.create_hypothesis(
            "order shape", target="https://acme.example/api/orders/42",
            mission_id=self.mission["id"])
        graph.rebuild(self.index, self.mission["id"])
        kb.learn_from_mission(self.index, self.mission["id"])
        keys = [entry["key"] for entry in
                self.index.list_kb_entries(scope="global", kind="endpoint")]
        self.assertIn("/api/orders/{n}", keys)


class TargetProfileTests(MemoryHarness):
    def test_profile_reads_real_headers_and_never_invents(self):
        self.add_probe()
        profile = target.build_profile(self.index, self.mission["id"])
        self.assertEqual(profile["host"], "acme.example")
        self.assertIn("nginx", profile["tech"])
        self.assertIn("express", profile["tech"])
        self.assertEqual(profile["waf"]["vendor"], "cloudflare")
        # No IP was observed, so none is claimed.
        self.assertEqual(profile["ip"], "")
        self.assertEqual(profile["network"], {})

    def test_profile_feeds_technology_nodes_onto_the_graph(self):
        self.add_probe()
        target.build_profile(self.index, self.mission["id"])
        tech = self.index.list_graph_nodes(self.mission["id"], kind="technology")
        self.assertTrue(tech)
        edges = self.index.list_graph_edges(self.mission["id"], kind="runs")
        self.assertTrue(edges)
        self.assertEqual(edges[0]["evidence"]["source"], "target_profile")


class CampaignTests(MemoryHarness):
    def test_stages_progress_with_evidence(self):
        self.assertEqual(campaign.stage_of(self.index, self.mission["id"])["stage"],
                         "recon")
        target.build_profile(self.index, self.mission["id"])
        self.assertEqual(campaign.stage_of(self.index, self.mission["id"])["stage"],
                         "surface")
        self.index.create_hypothesis("a lead", target="https://acme.example/x",
                                     mission_id=self.mission["id"])
        graph.rebuild(self.index, self.mission["id"])
        stage = campaign.stage_of(self.index, self.mission["id"])
        self.assertEqual(stage["stage"], "exploit")
        self.assertEqual(stage["mode"], "swarm")
        self.assertEqual(stage["open_leads"], 1)

    def test_a_verified_path_moves_to_chain_and_a_finding_to_report(self):
        self.index.create_hypothesis("a lead", target="https://acme.example/x",
                                     mission_id=self.mission["id"])
        graph.rebuild(self.index, self.mission["id"])
        self.index.upsert_graph_path(self.mission["id"], "verified chain",
                                     steps=[{"kind": "test"}], state="verified")
        self.assertEqual(campaign.stage_of(self.index, self.mission["id"])["stage"],
                         "chain")
        self.index.add_findings(self.run["id"], [{
            "title": "Real bug", "severity": "high", "source": "run"}])
        self.assertEqual(campaign.stage_of(self.index, self.mission["id"])["stage"],
                         "report")

    def test_advance_persists_and_keeps_a_history(self):
        campaign.advance(self.index, self.mission["id"])
        target.build_profile(self.index, self.mission["id"])
        result = campaign.advance(self.index, self.mission["id"])
        self.assertEqual(result["stage"], "surface")
        stored = self.index.get_campaign(self.mission["id"])
        self.assertEqual(stored["stage"], "surface")
        self.assertGreaterEqual(len(stored["stages"]), 1)


class DirectionTests(MemoryHarness):
    def test_directions_queue_consume_and_parse_mentions(self):
        from netcast3r.server import _parse_mentions

        mentions = _parse_mentions("look at @lead:hyp_abc and @finding:fnd_1")
        self.assertEqual(mentions, [{"kind": "hypothesis", "id": "hyp_abc"},
                                    {"kind": "finding", "id": "fnd_1"}])
        self.index.create_direction(self.mission["id"], "focus the order API",
                                    mentions=mentions)
        queued = self.index.list_directions(self.mission["id"], status="queued")
        self.assertEqual(len(queued), 1)
        consumed = self.index.consume_directions(self.mission["id"], limit=3,
                                                 run_id="run_x")
        self.assertEqual(len(consumed), 1)
        self.assertEqual(consumed[0]["mentions"][0]["id"], "hyp_abc")
        self.assertEqual(self.index.list_directions(self.mission["id"],
                                                    status="queued"), [])
        self.assertEqual(len(self.index.list_directions(self.mission["id"],
                                                        status="consumed")), 1)


class MemorySurfaceTests(MemoryHarness):
    def call(self, method, path, body=None, query=None):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, query or {}, headers, payload)

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def test_kb_profile_campaign_and_direction_routes(self):
        write = self.call("POST", "/api/v1/kb", {
            "kind": "technology", "key": "nginx", "title": "nginx"})
        self.assertEqual(write.status, 201)
        listing = self.call("GET", "/api/v1/kb", None, {"scope": "global"})
        self.assertEqual(listing.status, 200)
        self.assertTrue(self.data(listing)["items"])

        self.add_probe()
        profile = self.call("POST", f"/api/v1/missions/{self.mission['id']}/profile")
        self.assertEqual(profile.status, 200)
        self.assertIn("nginx", self.data(profile)["tech"])

        campaign_route = self.call(
            "GET", f"/api/v1/missions/{self.mission['id']}/campaign")
        self.assertEqual(campaign_route.status, 200)
        self.assertIn("stage", self.data(campaign_route))

        direction = self.call(
            "POST", f"/api/v1/missions/{self.mission['id']}/directions",
            {"body": "chase the order API"})
        self.assertEqual(direction.status, 201)
        listed = self.call(
            "GET", f"/api/v1/missions/{self.mission['id']}/directions")
        self.assertEqual(len(self.data(listed)["items"]), 1)

    def test_the_memory_tools_are_catalogued(self):
        from netcast3r.mcp.tools import _TOOL_MAP, catalog

        names = [tool["name"] for tool in catalog()]
        for name in ("kb_search", "kb_write", "kb_digest", "kb_stats", "kb_learn",
                     "target_profile", "campaign_status", "direction_add",
                     "directions_list"):
            self.assertIn(name, _TOOL_MAP)
            self.assertIn(name, names)

    def test_finding_trend_and_route(self):
        self.index.add_findings(self.run["id"], [
            {"title": "A", "severity": "high", "source": "run"},
            {"title": "B", "severity": "critical", "source": "run"}])
        trend = self.index.finding_trend(7)
        self.assertEqual(len(trend), 7)
        self.assertEqual(trend[-1]["total"], 2)
        self.assertEqual(trend[-1]["critical"], 1)
        self.assertEqual(trend[-1]["high"], 1)
        response = self.call("GET", "/api/v1/metrics/trend", None, {"days": "7"})
        self.assertEqual(response.status, 200)
        self.assertEqual(len(self.data(response)["items"]), 7)


if __name__ == "__main__":
    unittest.main()
