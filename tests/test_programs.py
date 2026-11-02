import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import programs
from netcast3r.server import build_server
from netcast3r.server.index import Index


class ProgramParseTests(unittest.TestCase):
    def test_csv_export_is_split_into_in_and_out_of_scope(self):
        brief = programs.parse(
            "identifier,asset_type,eligible_for_submission,max_severity\n"
            "example.com,url,true,critical\n"
            "api.example.com,url,true,high\n"
            "old.example.com,url,false,\n",
            filename="hackerone_example.csv")
        self.assertEqual(brief.platform, "hackerone")
        self.assertEqual(brief.in_scope, ["example.com", "api.example.com"])
        self.assertEqual(brief.out_of_scope, ["old.example.com"])
        self.assertEqual(brief.assets[0]["severity"], "critical")
        self.assertEqual(brief.handle, "hackerone_example")

    def test_markdown_brief_keeps_sections_and_rules(self):
        brief = programs.parse(
            "# Example\n\n"
            "## In scope\n"
            "- https://app.example.com\n"
            "- *.api.example.com\n"
            "## Out of scope\n"
            "- staging.example.com\n"
            "- !admin.example.com\n"
            "## Rules\n"
            "- No automated scanning of checkout.\n",
            filename="brief.md")
        self.assertEqual(brief.in_scope,
                         ["https://app.example.com/", "*.api.example.com"])
        self.assertEqual(brief.out_of_scope,
                         ["staging.example.com", "admin.example.com"])
        self.assertEqual(brief.rules, ["No automated scanning of checkout."])

    def test_json_export_is_walked_without_inventing_targets(self):
        payload = {
            "program": {"name": "Example", "handle": "example"},
            "assets": [
                {"identifier": "https://app.example.com", "type": "url"},
                {"identifier": "legacy.example.com", "eligible": False},
                {"identifier": "not a host", "type": "url"},
            ],
            "out_of_scope": ["staging.example.com"],
        }
        brief = programs.parse(json.dumps(payload), filename="scope.json")
        self.assertEqual(brief.in_scope, ["https://app.example.com/"])
        self.assertEqual(brief.out_of_scope,
                         ["legacy.example.com", "staging.example.com"])

    def test_non_assets_are_rejected(self):
        self.assertEqual(programs.clean_asset("not a host"), "")
        self.assertEqual(programs.clean_asset("user@example.com"), "")
        self.assertEqual(programs.clean_asset("foo"), "")
        self.assertEqual(programs.clean_asset("example.com/path"), "example.com/path")
        with self.assertRaises(programs.ProgramBriefError):
            programs.parse("just some prose with no assets")


class ProgramApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.index = Index(self.tmp / "index.db")
        self.mission = self.index.create_mission(
            "Program", "example.com", status="active", autonomy="autonomous",
            scope=["example.com"])

    def tearDown(self):
        self.index.close()

    def test_apply_adds_exclusions_and_covered_assets_but_not_expansion(self):
        brief = (
            "In scope\n"
            "- api.example.com\n"
            "- other.example.net\n"
            "Out of scope\n"
            "- staging.example.com\n")
        result = programs.apply(self.index, self.mission["id"], brief)
        self.assertTrue(result["diff"]["would_expand"])
        self.assertEqual(result["applied"]["added"], 2)
        mission = self.index.get_mission(self.mission["id"])
        self.assertIn("api.example.com", mission["scope"])
        self.assertIn("!staging.example.com", mission["scope"])
        self.assertNotIn("other.example.net", mission["scope"])
        self.assertEqual(result["diff"]["requires_allow_expand"],
                         ["other.example.net"])
        notes = self.index.list_agent_notes(self.mission["id"])
        self.assertTrue(any(note["kind"] == "program.ingest" for note in notes))
        history = self.index.list_program_imports(self.mission["id"])
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["in_scope"],
                         ["api.example.com", "other.example.net"])
        self.assertEqual(history[0]["out_of_scope"], ["staging.example.com"])
        self.assertEqual(history[0]["diff"]["requires_allow_expand"],
                         ["other.example.net"])

    def test_apply_with_allow_expand_authorises_the_new_asset(self):
        result = programs.apply(
            self.index, self.mission["id"],
            "In scope\n- other.example.net\n", allow_expand=True)
        self.assertIn("other.example.net", result["applied"]["scope"])
        mission = self.index.get_mission(self.mission["id"])
        self.assertIn("other.example.net", mission["scope"])

    def test_preview_is_read_only(self):
        before = self.index.get_mission(self.mission["id"])["scope"]
        programs.preview(self.index, self.mission["id"],
                         "In scope\n- api.example.com\n")
        after = self.index.get_mission(self.mission["id"])["scope"]
        self.assertEqual(before, after)

    def test_unknown_mission_is_refused(self):
        with self.assertRaises(programs.ProgramBriefError):
            programs.preview(self.index, "msn_missing", "example.com")


class ProgramRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = build_server(results_dir=str(self.tmp / "results"),
                                   base=self.tmp, recover=False)
        mission = self.server.index.create_mission(
            "Program routes", "example.com", status="active",
            autonomy="autonomous", scope=["example.com"])
        self.mission_id = mission["id"]

    def tearDown(self):
        if getattr(self.server, "director", None) is not None:
            self.server.director.shutdown()
        self.server.jobs.shutdown(wait=False)
        self.server.index.close()

    def call(self, method, path, body=None):
        headers = {"host": "127.0.0.1:7857",
                   "x-netcast3r-token": self.server.token}
        payload = json.dumps(body).encode() if body is not None else b""
        return self.server.route(method, path, {}, headers, payload)

    @staticmethod
    def data(response):
        return json.loads(response.body.decode()) if response.body else None

    def test_preview_and_import_routes(self):
        body = {"brief": "In scope\n- api.example.com\nOut of scope\n- old.example.com\n"}
        preview = self.call("POST", f"/api/v1/missions/{self.mission_id}/program/preview",
                            body)
        self.assertEqual(preview.status, 200)
        self.assertEqual(self.data(preview)["diff"]["add_in_scope"],
                         ["api.example.com"])
        applied = self.call("POST", f"/api/v1/missions/{self.mission_id}/program",
                            body)
        self.assertEqual(applied.status, 200)
        self.assertEqual(self.data(applied)["applied"]["added"], 2)
        mission = self.server.index.get_mission(self.mission_id)
        self.assertIn("!old.example.com", mission["scope"])
        history = self.call(
            "GET", f"/api/v1/missions/{self.mission_id}/program/imports")
        self.assertEqual(history.status, 200)
        self.assertEqual(len(self.data(history)["items"]), 1)

    def test_bad_brief_is_a_problem_document(self):
        response = self.call(
            "POST", f"/api/v1/missions/{self.mission_id}/program/preview",
            {"brief": "nothing usable here"})
        self.assertEqual(response.status, 400)

    def test_formats_route(self):
        response = self.call("GET", "/api/v1/programs/formats")
        self.assertEqual(response.status, 200)
        self.assertIn("hackerone", self.data(response)["platforms"])


if __name__ == "__main__":
    unittest.main()
