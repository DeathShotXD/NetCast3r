import unittest

from netcast3r.scope import ScopeManager, parse_rule


class ScopeRuleTests(unittest.TestCase):
    def test_suffix_matches_host_and_subdomains(self):
        rule = parse_rule("example.com")
        self.assertTrue(rule.matches("example.com"))
        self.assertTrue(rule.matches("api.example.com"))
        self.assertTrue(rule.matches("a.b.example.com"))
        self.assertFalse(rule.matches("example.net"))
        self.assertFalse(rule.matches("notexample.com"))

    def test_wildcard_matches_subdomains_only(self):
        rule = parse_rule("*.example.com")
        self.assertTrue(rule.matches("api.example.com"))
        self.assertFalse(rule.matches("example.com"))

    def test_url_prefix_matches_host_and_path(self):
        rule = parse_rule("https://example.com/app")
        self.assertTrue(rule.matches("example.com", "/app/v1"))
        self.assertFalse(rule.matches("example.com", "/other"))
        self.assertFalse(rule.matches("other.com", "/app"))

    def test_network_rule(self):
        rule = parse_rule("10.0.0.0/24")
        self.assertTrue(rule.matches("10.0.0.7"))
        self.assertFalse(rule.matches("10.0.1.7"))

    def test_regex_rule(self):
        rule = parse_rule(r"re:^api\.")
        self.assertTrue(rule.matches("api.example.com"))
        self.assertFalse(rule.matches("www.example.com"))

    def test_blank_and_comment_lines_ignored(self):
        self.assertIsNone(parse_rule(""))
        self.assertIsNone(parse_rule("   "))
        self.assertIsNone(parse_rule("# a note"))


class ScopeManagerTests(unittest.TestCase):
    def test_out_of_scope_wins(self):
        manager = ScopeManager(in_scope=["example.com"], out_of_scope=["admin.example.com"])
        self.assertTrue(manager.is_in_scope("https://api.example.com/"))
        self.assertFalse(manager.is_in_scope("https://admin.example.com/"))
        self.assertEqual(manager.classify("https://admin.example.com/"), "out")

    def test_unknown_host(self):
        manager = ScopeManager(in_scope=["example.com"])
        self.assertEqual(manager.classify("https://other.net/"), "unknown")
        self.assertFalse(manager.is_in_scope("https://other.net/"))

    def test_empty_scope_allows_all(self):
        manager = ScopeManager()
        self.assertTrue(manager.is_in_scope("https://anything.net/"))

    def test_seed_becomes_suffix_rule(self):
        manager = ScopeManager()
        manager.add_seed("https://target.com")
        self.assertTrue(manager.is_in_scope("https://sub.target.com/"))


if __name__ == "__main__":
    unittest.main()
