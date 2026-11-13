import json
import unittest

from netcast3r import graphql


class IntrospectionTests(unittest.TestCase):
    def test_enabled_schema(self):
        text = json.dumps({"data": {"__schema": {
            "queryType": {"name": "Query"},
            "types": [{"name": "User"}, {"name": "Query"}]}}})
        result = graphql.analyze_introspection({"status": 200, "text": text,
                                                "headers": {}})
        self.assertTrue(result["enabled"])
        self.assertEqual(result["type_count"], 2)
        self.assertEqual(result["query_type"], "Query")

    def test_disabled_reports_error(self):
        text = json.dumps({"errors": [{"message": "Introspection is disabled"}]})
        result = graphql.analyze_introspection({"status": 200, "text": text,
                                                "headers": {}})
        self.assertFalse(result["enabled"])
        self.assertIn("disabled", result["error"])

    def test_non_json(self):
        result = graphql.analyze_introspection({"status": 200, "text": "<html>",
                                                "headers": {}})
        self.assertFalse(result["enabled"])


class SuggestionTests(unittest.TestCase):
    def test_did_you_mean(self):
        text = ('{"errors":[{"message":"Cannot query field \\"zzz\\". '
                'Did you mean \\"users\\", \\"user\\", or \\"usage\\"?"}]}')
        found = graphql.suggestions(text)
        self.assertIn("users", found)
        self.assertIn("user", found)
        self.assertIn("usage", found)

    def test_no_suggestions(self):
        self.assertEqual(graphql.suggestions("bad request"), [])


class ProbeTests(unittest.TestCase):
    def _fetch(self):
        def fetch(url, method, body, headers):
            if url == "https://app.example.com/graphiql":
                return {"status": 200, "text": "<console>", "headers": {}}
            if url.split("?")[0].endswith("/graphql"):
                if method == "GET":
                    return {"status": 200,
                            "text": json.dumps({"data": {"__typename": "Query"}}),
                            "headers": {}}
                payload = json.loads(body) if body else None
                if isinstance(payload, list):
                    return {"status": 200, "text": json.dumps(
                        [{"data": {"__typename": "Query"}},
                         {"data": {"__typename": "Query"}}]), "headers": {}}
                query = str((payload or {}).get("query", ""))
                if "__schema" in query:
                    return {"status": 200, "text": json.dumps({"data": {
                        "__schema": {"queryType": {"name": "Query"},
                                     "types": [{"name": "User"}]}}}),
                        "headers": {}}
                if "no_such_field" in query:
                    return {"status": 200, "text": json.dumps({"errors": [{
                        "message": 'Cannot query field "zzz". Did you mean "users", or "usage"?'}]}),
                        "headers": {}}
            return {"status": 404, "text": "", "headers": {}}
        return fetch

    def test_probe_finds_surface(self):
        result = graphql.probe("https://app.example.com/graphql",
                               fetch=self._fetch())
        ids = {row["id"] for row in result["findings"]}
        for expected in ("introspection_enabled", "field_suggestions",
                         "batching_enabled", "get_queries", "console_exposed"):
            self.assertIn(expected, ids)
        self.assertEqual(result["results"]["console_paths"], ["/graphiql"])

    def test_probe_finds_nothing_on_a_plain_endpoint(self):
        result = graphql.probe("https://app.example.com/graphql",
                               fetch=lambda url, method, body, headers:
                               {"status": 404, "text": "", "headers": {}},
                               test_console=False)
        ids = {row["id"] for row in result["findings"]}
        self.assertIn("introspection_disabled", ids)
        self.assertNotIn("batching_enabled", ids)


class SummaryTests(unittest.TestCase):
    def test_summary(self):
        self.assertIn("introspection", graphql.summary()["checks"])


if __name__ == "__main__":
    unittest.main()
