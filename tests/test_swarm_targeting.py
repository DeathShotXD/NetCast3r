"""Targeting quality: hostname-as-path fix and deterministic high-value probes."""

import json
import unittest

from netcast3r import swarm
from netcast3r.autopilot import _normalize_target


class FakeRegistry:
    def call(self, name, args, actor=""):
        return {"ok": True}, False

    def names(self):
        return []


def mission():
    return {"id": "msn_target", "title": "Target", "target": "https://bca.example/",
            "objective": "prove a lead", "scope": ["bca.example"], "status": "active"}


def mesh():
    return swarm.Swarm(FakeRegistry(), lambda role, messages, exclude=None: {
        "text": "{}", "provider": "p", "model": "m"}, mission(), max_steps=1)


class TargetNormalisationTests(unittest.TestCase):
    def test_hostname_appended_as_path_is_promoted(self):
        self.assertEqual(
            _normalize_target("https://bca.example/webmail.bca.example"),
            "https://webmail.bca.example/")

    def test_normal_paths_and_hosts_are_untouched(self):
        for value in ("https://bca.example/login",
                      "https://bca.example/api/v1/thing",
                      "bca.example/login"):
            self.assertEqual(_normalize_target(value), value)


class PortalProbeTests(unittest.TestCase):
    def test_git_objective_probes_the_real_vcs_path(self):
        move = mesh()._portal_evidence_move({
            "goal": "recover .git source", "target": "https://bca.example/",
            "hypothesis": ".git exposure"})
        self.assertEqual(move["action"], "http_request")
        self.assertTrue(move["args"]["target"].endswith("/.git/HEAD"))

    def test_git_index_objective_targets_index(self):
        move = mesh()._portal_evidence_move({
            "goal": "fetch .git/index", "target": "https://bca.example/"})
        self.assertTrue(move["args"]["target"].endswith("/.git/index"))

    def test_sqli_objective_is_a_post_with_a_bypass_payload(self):
        move = mesh()._portal_evidence_move({
            "goal": "SQLi auth bypass on login",
            "target": "https://bca.example/login",
            "hypothesis": "an injection in the login parameter bypasses auth"})
        self.assertEqual(move["args"]["method"], "POST")
        self.assertIn("OR '1'='1", move["args"]["form"]["username"])

    def test_reset_objective_sends_a_canary_forwarded_host(self):
        move = mesh()._portal_evidence_move({
            "goal": "password reset host header poisoning",
            "target": "https://bca.example/"})
        self.assertEqual(move["args"]["method"], "POST")
        self.assertEqual(move["args"]["headers"]["X-Forwarded-Host"],
                         "nc3r-canary.example")

    def test_oauth_objective_probes_redirect_uri(self):
        move = mesh()._portal_evidence_move({
            "goal": "OAuth redirect_uri parser differential",
            "target": "https://bca.example/"})
        self.assertIn("redirect_uri=", move["args"]["target"])
        self.assertIn("nc3r-canary.example", move["args"]["target"])


if __name__ == "__main__":
    unittest.main()
