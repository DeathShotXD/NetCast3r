import unittest

from netcast3r import leads


class ClassifyTests(unittest.TestCase):
    def test_keyword_classes(self):
        self.assertEqual(leads.classify("Blind SQL injection in id"), "sql")
        self.assertEqual(leads.classify("Reflected XSS in q"), "xss")
        self.assertEqual(leads.classify("Server-side request forgery"), "ssrf")
        self.assertEqual(leads.classify("IDOR on /orders"), "idor")
        self.assertEqual(leads.classify("Open redirect via next"), "open_redirect")
        self.assertEqual(leads.classify("Something unusual"), "unknown")


class SignatureTests(unittest.TestCase):
    def test_ids_collapse(self):
        self.assertEqual(leads.normalize_path("https://a.test/users/123"),
                         "/users/{id}")
        self.assertEqual(leads.normalize_path("https://a.test/orders/1/items"),
                         "/orders/{id}/items")

    def test_same_bug_same_signature(self):
        a = leads.signature(title="IDOR on order", target="https://a.test/orders/1")
        b = leads.signature(title="IDOR on order 2", target="https://a.test/orders/2")
        self.assertEqual(a, b)

    def test_different_class_differs(self):
        a = leads.signature(title="SQL injection in id", target="https://a.test/p?id=1")
        b = leads.signature(title="XSS in id", target="https://a.test/p?id=1")
        self.assertNotEqual(a, b)

    def test_query_parameter_used(self):
        sig = leads.signature(title="bug", target="https://a.test/search?q=1")
        self.assertIn("|q|", sig)


class DedupeTests(unittest.TestCase):
    def test_groups_duplicates(self):
        items = [
            {"id": "h1", "title": "IDOR on order",
             "target": "https://a.test/orders/1", "technique": "idor"},
            {"id": "h2", "title": "IDOR on order",
             "target": "https://a.test/orders/2", "technique": "idor"},
            {"id": "h3", "title": "SQL injection in id",
             "target": "https://a.test/p?id=1", "technique": "sqli"},
        ]
        result = leads.dedupe(items)
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["unique"], 2)
        self.assertEqual(result["duplicate_count"], 1)
        self.assertEqual(result["groups"][0]["ids"], ["h1", "h2"])

    def test_no_duplicates(self):
        result = leads.dedupe([{"title": "a", "target": "https://a.test/1"}])
        self.assertEqual(result["duplicate_count"], 0)
        self.assertEqual(result["groups"], [])

    def test_summary(self):
        self.assertIn("sql", leads.summary()["classes"])


if __name__ == "__main__":
    unittest.main()
