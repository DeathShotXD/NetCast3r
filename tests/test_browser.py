import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import httpx

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import browser, tempmail
from netcast3r.mcp.tools import (
    TOOLS,
    ToolError,
    _browser_scope,
    audit_args,
)


class BrowserUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_state_for_unknown_profile_is_stopped(self):
        state = browser.state("missing", base=self.tmp)
        self.assertFalse(state["running"])
        self.assertEqual(state["profile"], "missing")

    def test_profile_names_are_restricted(self):
        with self.assertRaises(browser.BrowserError):
            browser.state("../escape", base=self.tmp)

    def test_launch_without_a_binary_is_a_clean_error(self):
        with mock.patch.object(browser, "find_chromium",
                               side_effect=browser.BrowserError("Chromium not found")):
            with self.assertRaises(browser.BrowserError):
                browser.launch("demo", "about:blank", base=self.tmp)

    def test_scope_gate_refuses_an_unlisted_target(self):
        with self.assertRaises(ToolError) as caught:
            _browser_scope(mock.Mock(), "https://example.com/", "", None)
        self.assertEqual(caught.exception.code, "scope_denied")

    def test_identity_purpose_only_allows_known_providers(self):
        _browser_scope(mock.Mock(), "https://github.com/login", "", None,
                       purpose="identity")
        with self.assertRaises(ToolError):
            _browser_scope(mock.Mock(), "https://attacker.example/login", "", None,
                           purpose="identity")

    def test_browser_type_text_is_redacted_from_the_audit(self):
        clean = audit_args("browser_type", {"profile": "p", "text": "hunter2",
                                            "ref": "e1"})
        self.assertEqual(clean["text"], "[redacted]")
        self.assertEqual(clean["ref"], "e1")
        other = audit_args("http_request", {"target": "https://example.com"})
        self.assertEqual(other["target"], "https://example.com")

    def test_catalogue_exposes_the_browser_surface(self):
        names = {tool.name for tool in TOOLS}
        self.assertIn("browser_open", names)
        self.assertIn("browser_capture", names)
        self.assertEqual(len(TOOLS), 93)


class GuerrillaMailTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_create_list_and_read_with_a_mock_transport(self):
        def handler(request: httpx.Request) -> httpx.Response:
            function = request.url.params.get("f")
            if function == "get_email_address":
                return httpx.Response(200, json={
                    "email_addr": "seed@guerrillamailblock.com",
                    "sid_token": "sid-1"})
            if function == "set_email_user":
                local = request.url.params.get("email_user")
                return httpx.Response(200, json={
                    "email_addr": f"{local}@guerrillamailblock.com"})
            if function == "get_email_list":
                return httpx.Response(200, json={"list": [{
                    "mail_id": "42", "mail_from": "noreply@target.test",
                    "mail_subject": "Verify your email",
                    "mail_excerpt": "click the link", "mail_timestamp": "1793235000",
                    "mail_read": "0"}]})
            if function == "fetch_email":
                return httpx.Response(200, json={
                    "mail_id": "42", "mail_from": "noreply@target.test",
                    "mail_subject": "Verify your email",
                    "mail_body": '<a href="https://target.test/verify?t=abc">verify</a>',
                    "mail_timestamp": "1793235000"})
            return httpx.Response(404, json={})

        client = tempmail.GuerrillaClient(
            transport=httpx.MockTransport(handler))
        box = client.create(base=self.tmp)
        self.assertEqual(box.provider, "guerrillamail")
        self.assertTrue(box.address.endswith("@guerrillamailblock.com"))
        rows = client.messages(box)
        self.assertEqual(rows[0]["subject"], "Verify your email")
        message = client.read(box, "42")
        self.assertIn("https://target.test/verify?t=abc", message["links"])
        self.assertEqual(tempmail.client_for(box).__class__,
                         tempmail.GuerrillaClient)

    def test_unknown_provider_falls_back_to_mail_tm(self):
        with mock.patch.object(tempmail.MailClient, "create",
                               return_value=tempmail.Mailbox(
                                   id="1", address="a@b.test", password="p",
                                   token="t")) as create:
            box = tempmail.create_mailbox(provider="not-a-provider")
        self.assertEqual(box.address, "a@b.test")
        create.assert_called_once()


if __name__ == "__main__":
    unittest.main()
