import json
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

import httpx

from netcast3r import threatintel

CVE = "CVE-2025-12345"
NVD = {
    "vulnerabilities": [{
        "cve": {
            "id": CVE, "published": "2025-01-01T00:00:00", "lastModified": "2025-01-02T00:00:00",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "A test RCE in Example 1.0."}],
            "metrics": {"cvssMetricV31": [{"source": "nvd", "cvssData": {
                "baseScore": 9.8, "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
            "references": [{"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]}],
        }
    }]
}
KEV = {
    "catalogVersion": "2025.01.01", "dateReleased": "2025-01-01",
    "vulnerabilities": [{
        "cveID": CVE, "vendorProject": "Example", "product": "Example",
        "vulnerabilityName": "Example RCE", "shortDescription": "RCE",
        "requiredAction": "Patch", "dueDate": "2025-02-01",
        "knownRansomwareCampaignUse": "Known",
    }],
}
REPOS = {"items": [{
    "full_name": "researcher/poc", "html_url": "https://github.com/researcher/poc",
    "description": "PoC", "stargazers_count": 42, "updated_at": "2025-01-03",
    "topics": ["cve"], "default_branch": "main",
}]}
README = "## PoC\n\n```bash\ncurl -s http://target/evil\n```\n"


def handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    path = request.url.path
    if host == "services.nvd.nist.gov":
        return httpx.Response(200, json=NVD)
    if host == "www.cisa.gov":
        return httpx.Response(200, json=KEV)
    if host == "api.github.com" and "/search/repositories" in path:
        return httpx.Response(200, json=REPOS)
    if host == "api.github.com" and "/advisories" in path:
        return httpx.Response(200, json=[{
            "ghsa_id": "GHSA-xxxx", "summary": "Example", "severity": "critical",
            "cvss": {"score": 9.8}, "html_url": "https://github.com/advisories/GHSA-xxxx",
            "published_at": "2025-01-01",
        }])
    if host == "raw.githubusercontent.com":
        return httpx.Response(200, text=README)
    if host == "sploitus.com":
        return httpx.Response(200, text='<a href="/exploits/abc">Example RCE</a>')
    return httpx.Response(404, text="not found")


TRANSPORT = httpx.MockTransport(handler)


class ThreatIntelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.object(threatintel, "_cache_get", return_value=None)
        self.addCleanup(patcher.stop)
        patcher.start()
        patcher = mock.patch.object(threatintel, "_cache_put", return_value=None)
        self.addCleanup(patcher.stop)
        patcher.start()

    def tearDown(self):
        self.tmp.cleanup()

    def test_nvd_parse(self):
        result = threatintel.nvd_cve(CVE, transport=TRANSPORT)
        self.assertEqual(result["cve"], CVE)
        self.assertIn("RCE", result["description"])
        self.assertEqual(result["best_score"]["score"], 9.8)
        self.assertEqual(result["best_score"]["severity"], "CRITICAL")
        self.assertIn("CWE-78", result["cwe"])

    def test_kev_lookup(self):
        result = threatintel.kev_lookup(CVE, transport=TRANSPORT, base=self.tmp.name)
        self.assertTrue(result["known_exploited"])
        self.assertEqual(result["entry"]["vendor"], "Example")

    def test_github_pocs(self):
        repos = threatintel.github_pocs(CVE, transport=TRANSPORT)
        self.assertEqual(repos[0]["repo"], "researcher/poc")
        self.assertEqual(repos[0]["stars"], 42)

    def test_search_combines_sources(self):
        result = threatintel.search(CVE, transport=TRANSPORT)
        self.assertEqual(result["cve"], CVE)
        self.assertEqual(result["nvd"]["cve"], CVE)
        self.assertTrue(result["kev"]["known_exploited"])
        self.assertEqual(result["advisories"][0]["severity"], "critical")
        self.assertEqual(result["sploitus"][0]["url"],
                         "https://sploitus.com/exploits/abc")
        self.assertEqual(result["errors"], [])

    def test_reproduction_plan_is_non_executing_and_cited(self):
        plan = threatintel.reproduction_plan(CVE, target="example.com",
                                             transport=TRANSPORT, base=self.tmp.name)
        self.assertEqual(plan["cve"], CVE)
        self.assertEqual(plan["target"], "example.com")
        self.assertTrue(plan["known_exploited"])
        self.assertIn("curl", plan["code_blocks"][0])
        self.assertFalse(plan["destructive_payload_detected"])
        self.assertIn("authorized target", plan["safety"])
        self.assertIn("nvd.nist.gov", plan["source"])

    def test_destructive_payload_is_flagged(self):
        def destructive_handler(request):
            if request.url.host == "raw.githubusercontent.com":
                return httpx.Response(200, text="```bash\nrm -rf /\n```")
            return handler(request)
        plan = threatintel.reproduction_plan(
            CVE, transport=httpx.MockTransport(destructive_handler), base=self.tmp.name)
        self.assertTrue(plan["destructive_payload_detected"])

    def test_invalid_cve_is_rejected(self):
        with self.assertRaises(ValueError):
            threatintel.nvd_cve("not-a-cve", transport=TRANSPORT)


if __name__ == "__main__":
    unittest.main()
