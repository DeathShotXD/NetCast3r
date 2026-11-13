import unittest
from unittest import mock

from netcast3r import dnsposture, dnsq


def rec(name, rtype, data, fields=None):
    number = dnsq.QTYPES[rtype]
    return dnsq.Record(name, number, 1, 60, data, fields or {})


def msg(records, rcode=0):
    return dnsq.Message(ident=1, flags=0, rcode=rcode, answers=list(records))


def txt(name, text):
    return rec(name, "TXT", text, {"text": text, "strings": [text]})


class SpfTests(unittest.TestCase):
    def test_hard_fail_policy(self):
        parsed = dnsposture.parse_spf("v=spf1 include:_spf.google.com -all")
        self.assertTrue(parsed["hard_fail"])
        self.assertFalse(parsed["allow_all"])
        self.assertEqual(parsed["includes"], ["_spf.google.com"])

    def test_allow_all(self):
        parsed = dnsposture.parse_spf("v=spf1 +all")
        self.assertTrue(parsed["allow_all"])
        self.assertFalse(parsed["hard_fail"])

    def test_lookup_limit(self):
        terms = " ".join(f"include:s{i}.example" for i in range(11))
        parsed = dnsposture.parse_spf(f"v=spf1 {terms} ~all")
        self.assertTrue(parsed["lookup_limit_exceeded"])
        self.assertEqual(parsed["lookups"], 11)


class DmarcTests(unittest.TestCase):
    def test_monitor_only(self):
        parsed = dnsposture.parse_dmarc("v=DMARC1; p=none; rua=mailto:x@y")
        self.assertTrue(parsed["monitor_only"])
        self.assertFalse(parsed["enforcing"])
        self.assertEqual(parsed["rua"], "mailto:x@y")

    def test_enforcing(self):
        parsed = dnsposture.parse_dmarc("v=DMARC1; p=reject; sp=quarantine")
        self.assertTrue(parsed["enforcing"])
        self.assertEqual(parsed["subdomain_policy"], "quarantine")


class PostureTests(unittest.TestCase):
    def _query(self, table):
        def q(name, rtype):
            return table.get((name, rtype), msg([]))
        return q

    def test_weak_posture_reports_findings(self):
        table = {
            ("example.com", "NS"): msg([rec("example.com", "NS", "ns1.example.com")]),
            ("example.com", "MX"): msg([rec("example.com", "MX", "10 mx1.example.com",
                                            {"preference": 10, "exchange": "mx1.example.com"})]),
            ("example.com", "SOA"): msg([rec("example.com", "SOA", "ns1 hostmaster",
                                             {"mname": "ns1.example.com"})]),
            ("example.com", "CAA"): msg([]),
            ("example.com", "TXT"): msg([txt("example.com", "v=spf1 +all")]),
        }
        result = dnsposture.posture("example.com", query=self._query(table))
        ids = {row["id"] for row in result["findings"]}
        self.assertIn("spf_allow_all", ids)
        self.assertIn("dmarc_missing", ids)
        self.assertIn("caa_missing", ids)
        self.assertNotIn("spf_missing", ids)
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_strong_posture_has_no_findings(self):
        table = {
            ("example.com", "NS"): msg([rec("example.com", "NS", "ns1.example.com")]),
            ("example.com", "MX"): msg([rec("example.com", "MX", "10 mx1",
                                            {"preference": 10, "exchange": "mx1.example.com"})]),
            ("example.com", "SOA"): msg([rec("example.com", "SOA", "ns1 hostmaster", {})]),
            ("example.com", "CAA"): msg([rec("example.com", "CAA", '0 issue "ca.example"',
                                             {"flags": 0, "tag": "issue",
                                              "value": "ca.example"})]),
            ("example.com", "TXT"): msg([txt("example.com", "v=spf1 -all")]),
            ("_dmarc.example.com", "TXT"): msg([
                txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com")]),
        }
        result = dnsposture.posture("example.com", query=self._query(table))
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["mail"]["dmarc"]["enforcing"])

    def test_multiple_spf_records(self):
        table = {
            ("example.com", "TXT"): msg([txt("example.com", "v=spf1 -all"),
                                         txt("example.com", "v=spf1 include:x ~all")]),
        }
        result = dnsposture.posture("example.com", query=self._query(table))
        ids = {row["id"] for row in result["findings"]}
        self.assertIn("spf_multiple", ids)

    def test_dkim_selector_found(self):
        table = {
            ("google._domainkey.example.com", "TXT"): msg([
                txt("google._domainkey.example.com", "v=DKIM1; p=MIIBIjANBg")]),
        }
        result = dnsposture.posture("example.com", query=self._query(table),
                                    dkim_selectors=["google", "default"])
        self.assertEqual(result["mail"]["dkim"][0]["selector"], "google")

    def test_zone_transfer_open(self):
        table = {
            ("example.com", "NS"): msg([rec("example.com", "NS", "ns1.example.com")]),
        }
        axfr = mock.Mock(return_value={"nameserver": "ns1.example.com", "open": True,
                                       "count": 42, "rcode": 0})
        result = dnsposture.posture("example.com", query=self._query(table),
                                    zone_transfer=True, axfr_fn=axfr)
        ids = {row["id"] for row in result["findings"]}
        self.assertIn("zone_transfer_open", ids)
        self.assertTrue(result["zone_transfer"]["open"])

    def test_dns_error_is_recorded(self):
        def broken(name, rtype):
            raise dnsq.DnsError("timeout")

        result = dnsposture.posture("example.com", query=broken)
        self.assertTrue(result["errors"])
        self.assertIn("spf_missing", {row["id"] for row in result["findings"]})

    def test_summary(self):
        self.assertIn("dmarc", dnsposture.summary()["checks"])
        self.assertFalse(dnsposture.summary()["zone_transfer_default"])


if __name__ == "__main__":
    unittest.main()
