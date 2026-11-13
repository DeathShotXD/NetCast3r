import socket
import struct
import unittest
from unittest import mock

from netcast3r import dnsq


def _pack_rr(name, rtype, rdata, ttl=60):
    return (dnsq.encode_name(name)
            + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata)


def _pack_message(ident, flags, questions, answers=(), authority=(), additional=()):
    header = struct.pack("!HHHHHH", ident, flags, len(questions),
                         len(answers), len(authority), len(additional))
    body = b"".join(questions) + b"".join(answers) + b"".join(authority) + b"".join(additional)
    return header + body


def _question(name, qtype=1):
    return dnsq.encode_name(name) + struct.pack("!HH", qtype, 1)


class EncodeTests(unittest.TestCase):
    def test_encode_name_labels_and_root(self):
        self.assertEqual(dnsq.encode_name("a.b.com"), b"\x01a\x01b\x03com\x00")
        self.assertEqual(dnsq.encode_name(""), b"\x00")
        self.assertEqual(dnsq.encode_name("example.com."), b"\x07example\x03com\x00")

    def test_build_query_header_and_question(self):
        data = dnsq.build_query("example.com", "MX", ident=0x1234)
        ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        self.assertEqual(ident, 0x1234)
        self.assertEqual((qd, an, ns, ar), (1, 0, 0, 0))
        self.assertTrue(flags & 0x0100)
        self.assertEqual(data[12:], _question("example.com", 15))

    def test_unknown_type_is_refused(self):
        with self.assertRaises(dnsq.DnsError):
            dnsq.build_query("example.com", "NOPE")

    def test_label_bytes_use_idna_for_unicode(self):
        raw = dnsq.encode_name("b\u00fccher.example")
        self.assertEqual(raw, b"\x0dxn--bcher-kva\x07example\x00")


class ParseTests(unittest.TestCase):
    def test_parse_a_and_cname(self):
        rd = socket.inet_aton("203.0.113.9")
        data = _pack_message(
            0x0001, 0x8180, [_question("www.example.com")],
            answers=[
                _pack_rr("www.example.com", 5, dnsq.encode_name("edge.cdn.example")),
                _pack_rr("edge.cdn.example", 1, rd),
            ])
        message = dnsq.parse_message(data)
        self.assertEqual(message.rcode, 0)
        self.assertEqual(message.rcode_name, "NOERROR")
        self.assertEqual(message.records("CNAME")[0].data, "edge.cdn.example")
        self.assertEqual(message.records("A")[0].data, "203.0.113.9")

    def test_compression_pointer_is_followed(self):
        pointer = b"\xc0\x0c"
        data = _pack_message(
            0x0002, 0x8180, [_question("a.example.com")],
            answers=[pointer + struct.pack("!HHIH", 1, 1, 60, 4)
                     + socket.inet_aton("10.0.0.1")])
        message = dnsq.parse_message(data)
        self.assertEqual(message.answers[0].name, "a.example.com")

    def test_compression_loop_is_refused(self):
        # A pointer that points at itself must not spin.
        loop = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 2) + b"\xc0\x0c"
        header = struct.pack("!HHHHHH", 3, 0x8180, 0, 1, 0, 0)
        with self.assertRaises(dnsq.DnsError):
            dnsq.parse_message(header + loop)

    def test_txt_mx_caa_soa_decode(self):
        txt = b"\x0bv=spf1 -all"
        mx = struct.pack("!H", 10) + dnsq.encode_name("mx1.example.com")
        caa = bytes([0, 5]) + b"issue" + b"letsencrypt.org"
        soa = (dnsq.encode_name("ns1.example.com")
               + dnsq.encode_name("hostmaster.example.com")
               + struct.pack("!IIIII", 2026010101, 7200, 3600, 1209600, 300))
        data = _pack_message(
            0x0004, 0x8180, [_question("example.com")],
            answers=[
                _pack_rr("example.com", 16, txt),
                _pack_rr("example.com", 15, mx),
                _pack_rr("example.com", 257, caa),
                _pack_rr("example.com", 6, soa),
            ])
        message = dnsq.parse_message(data)
        self.assertEqual(message.records("TXT")[0].fields["text"], "v=spf1 -all")
        self.assertEqual(message.records("MX")[0].fields["exchange"], "mx1.example.com")
        self.assertEqual(message.records("CAA")[0].fields["tag"], "issue")
        self.assertEqual(message.records("CAA")[0].fields["value"], "letsencrypt.org")
        self.assertEqual(message.records("SOA")[0].fields["serial"], 2026010101)

    def test_nxdomain_is_a_rcode_not_an_error(self):
        data = _pack_message(0x0005, 0x8183, [_question("gone.example.com")])
        message = dnsq.parse_message(data)
        self.assertEqual(message.rcode, 3)
        self.assertEqual(message.rcode_name, "NXDOMAIN")

    def test_truncated_flag(self):
        data = _pack_message(0x0006, 0x8380, [_question("example.com")])
        self.assertTrue(dnsq.parse_message(data).truncated)

    def test_short_message_is_refused(self):
        with self.assertRaises(dnsq.DnsError):
            dnsq.parse_message(b"\x00\x01\x02")


class ResolveChainTests(unittest.TestCase):
    def test_chain_follows_cname_to_addresses(self):
        def fake_query(name, qtype="A", **kwargs):
            if name == "www.example.com" and qtype == "CNAME":
                return dnsq.parse_message(_pack_message(
                    1, 0x8180, [_question(name)],
                    answers=[_pack_rr(name, 5, dnsq.encode_name("app.herokuapp.com"))]))
            if name == "app.herokuapp.com" and qtype == "CNAME":
                return dnsq.parse_message(_pack_message(2, 0x8180, [_question(name)]))
            if name == "app.herokuapp.com" and qtype == "A":
                return dnsq.parse_message(_pack_message(
                    3, 0x8180, [_question(name)],
                    answers=[_pack_rr(name, 1, socket.inet_aton("1.2.3.4"))]))
            return dnsq.parse_message(_pack_message(4, 0x8180, [_question(name)]))

        with mock.patch.object(dnsq, "query", side_effect=fake_query):
            chain = dnsq.resolve_chain("www.example.com", nameserver="127.0.0.1")
        self.assertEqual(chain["chain"], ["app.herokuapp.com"])
        self.assertEqual(chain["cname"], "app.herokuapp.com")
        self.assertIn("1.2.3.4", chain["addresses"])
        self.assertFalse(chain["nxdomain"])

    def test_chain_reports_nxdomain(self):
        def fake_query(name, qtype="A", **kwargs):
            rcode = 3 if qtype == "CNAME" else 3
            return dnsq.parse_message(_pack_message(
                1, 0x8180 | rcode, [_question(name)]))

        with mock.patch.object(dnsq, "query", side_effect=fake_query):
            chain = dnsq.resolve_chain("gone.example.com", nameserver="127.0.0.1")
        self.assertTrue(chain["nxdomain"])
        self.assertEqual(chain["addresses"], [])


class SystemResolverTests(unittest.TestCase):
    def test_no_nameserver_raises(self):
        with mock.patch.object(dnsq, "system_nameservers", return_value=[]):
            with self.assertRaises(dnsq.DnsError):
                dnsq.query("example.com")

    def test_udp_query_returns_none_on_timeout(self):
        with mock.patch.object(socket, "socket") as sock_factory:
            sock = sock_factory.return_value
            sock.recvfrom.side_effect = socket.timeout()
            self.assertIsNone(dnsq._udp_query(b"\x00\x01", "127.0.0.1", 0.1))
            sock.close.assert_called()


if __name__ == "__main__":
    unittest.main()
