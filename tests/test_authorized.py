import os
import unittest

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.mcp.tools import _TOOL_MAP, ToolContext, ToolRegistry


class _Plane:
    kind = "local"
    url = ""

    def request(self, method, path, query=None, body=None):
        return {}


def _registry(policy="supervised", authorized=False):
    return ToolRegistry(ToolContext(plane=_Plane(), policy=policy,
                                    mission_id="msn_x", authorized=authorized))


class AuthorizedExecutionTests(unittest.TestCase):
    """The domain is the authorization: an active autonomous mission runs its
    in-scope chain without a per-call human step-up, and the call is audited."""

    def test_authorized_context_clears_a_high_risk_step(self):
        tool = _TOOL_MAP["missions_delete"]
        registry = _registry(policy="full", authorized=True)
        marker = registry._policy_check(tool, {})
        self.assertEqual(marker, "authorized:autonomous")

    def test_a_supervised_context_still_needs_an_approval(self):
        tool = _TOOL_MAP["missions_delete"]
        with self.assertRaises(Exception) as ctx:
            _registry(policy="supervised")._policy_check(tool, {})
        self.assertEqual(getattr(ctx.exception, "code", ""), "approval_required")

    def test_a_full_context_still_needs_confirm_without_authorization(self):
        tool = _TOOL_MAP["missions_delete"]
        with self.assertRaises(Exception) as ctx:
            _registry(policy="full", authorized=False)._policy_check(tool, {})
        self.assertEqual(getattr(ctx.exception, "code", ""), "confirm_required")

    def test_authorization_never_covers_operator_only_tools(self):
        operator_tools = [name for name, tool in _TOOL_MAP.items()
                          if getattr(tool, "operator_only", False)]
        self.assertTrue(operator_tools)
        registry = _registry(policy="full", authorized=True)
        for name in operator_tools:
            with self.assertRaises(Exception) as ctx:
                registry._policy_check(_TOOL_MAP[name], {})
            self.assertEqual(getattr(ctx.exception, "code", ""), "policy_denied")

    def test_low_risk_is_unaffected(self):
        tool = _TOOL_MAP["http_probe"]
        self.assertEqual(_registry(authorized=True)._policy_check(tool, {}), "")
        self.assertEqual(_registry()._policy_check(tool, {}), "")


if __name__ == "__main__":
    unittest.main()
