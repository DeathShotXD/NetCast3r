import os
import unittest

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import pathdiff


class VariantTests(unittest.TestCase):
    def test_variants_cover_encoding_case_and_slashes(self):
        variants = pathdiff.build_variants("/api/mobile/services/addons")
        labels = [item["label"] for item in variants]
        paths = [item["path"] for item in variants]
        self.assertEqual(labels[0], "baseline")
        self.assertIn("encode_last_first", labels)
        self.assertIn("encode_last_all", labels)
        self.assertIn("uppercase", labels)
        self.assertIn("trailing_slash", labels)
        self.assertIn("/api/mobile/services/%61ddons", paths)
        self.assertEqual(len(paths), len(set(paths)))

    def test_limit_and_query_are_preserved(self):
        variants = pathdiff.build_variants("/api/services/domains?x=1", limit=4)
        self.assertLessEqual(len(variants), 4)
        for item in variants:
            self.assertTrue(item["path"].endswith("?x=1"))

    def test_unicode_and_encoding_variants(self):
        variants = pathdiff.build_variants("/api/services/domains")
        labels = [item["label"] for item in variants]
        paths = [item["path"] for item in variants]
        self.assertEqual(paths[0], "/api/services/domains")
        self.assertIn("fullwidth_last", labels)
        self.assertIn("unicode_slash", labels)
        self.assertIn("double_encode_slash", labels)
        self.assertIn("unicode_dot_segment", labels)
        self.assertIn("/api/services/domains".replace("/", "%252f"), paths)
        fullwidth = next(item for item in variants if item["label"] == "fullwidth_last")
        for char in fullwidth["path"].rsplit("/", 1)[-1]:
            self.assertGreater(ord(char), 0xFF00)

    def test_nfkc_folds_fullwidth_back(self):
        variants = pathdiff.build_variants("/api/\uff41dmin")
        nfkc = next((item for item in variants if item["label"] == "nfkc"), None)
        self.assertIsNotNone(nfkc)
        self.assertEqual(nfkc["path"], "/api/admin")

    def test_target_for_keeps_scheme_host_and_query(self):
        url = pathdiff.target_for("https://snapdeploy.dev/api/services/domains?x=1",
                                  "/api/services/%64omains?x=1")
        self.assertEqual(url, "https://snapdeploy.dev/api/services/%64omains?x=1")


class CompareTests(unittest.TestCase):
    def _base(self, status=403, body='{"error":"INSUFFICIENT_SCOPE"}'):
        return {"status": status, "body": body, "bytes": len(body),
                "body_hash": pathdiff._digest(body)}

    def test_encoded_validation_error_is_labeled_check_skipped(self):
        baseline = self._base(403)
        rows = [
            {"label": "baseline", "path": "/api/services/addons",
             "status": 403, "body": baseline["body"]},
            {"label": "encode_last_first", "path": "/api/services/%61ddons",
             "status": 400, "body": '{"error":"Invalid input"}'},
        ]
        result = pathdiff.compare(baseline, rows)
        self.assertEqual(result["summary"]["suspicious"], 1)
        self.assertEqual(result["suspicious"][0]["delta"], "check_skipped")

    def test_encoded_success_is_labeled_auth_bypass(self):
        baseline = self._base(403)
        rows = [{"label": "x", "path": "/x", "status": 200, "body": "ok"}]
        result = pathdiff.compare(baseline, rows)
        self.assertEqual(result["suspicious"][0]["delta"], "auth_bypass")

    def test_server_error_is_suspicious(self):
        baseline = self._base(200, "ok")
        rows = [{"label": "x", "path": "/x", "status": 500, "body": "trace"}]
        result = pathdiff.compare(baseline, rows)
        self.assertEqual(result["suspicious"][0]["delta"], "server_error")

    def test_generic_router_error_is_not_a_handler_hit(self):
        baseline = self._base(403)
        rows = [{"label": "x", "path": "/x", "status": 400,
                 "body": '{"error":"The request could not be understood by the server."}'}]
        result = pathdiff.compare(baseline, rows)
        self.assertEqual(result["suspicious"], [])
        self.assertEqual(result["variants"][0]["delta"], "routing_error")

    def test_same_status_and_body_is_not_suspicious(self):
        baseline = self._base(200, "ok")
        rows = [{"label": "x", "path": "/x", "status": 200, "body": "ok"}]
        result = pathdiff.compare(baseline, rows)
        self.assertEqual(result["suspicious"], [])


if __name__ == "__main__":
    unittest.main()
