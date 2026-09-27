"""Bundled knowledge.

Validation hints per credential type, escalation steps per provider, and the
public documentation links the agents read before they reason about a finding.
Nothing here touches a target; it only reads public references and local notes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx


VALIDATION_HINTS: dict[str, str] = {
    "aws": "sts:GetCallerIdentity confirms the pair. Enumerate permissions with an "
           "identity enumeration pass before you claim impact.",
    "slack": "auth.test confirms the token. Check scopes for read and write reach.",
    "stripe_live": "Retrieve the account or a resource list. Live keys expose charges "
                   "and customer metadata.",
    "sendgrid": "The scopes endpoint confirms the key and lists granted scopes.",
    "google_api": "Try a geocode request. REQUEST_DENIED means the key is dead or "
                  "restricted.",
    "shodan": "The api-info endpoint confirms the key and returns the plan.",
    "jwt": "Decode the claims, check the algorithm, then test whether the service "
           "still trusts the token.",
    "private_key": "Test the key against the matching host or service it was issued "
                   "for. Do not reuse it anywhere else.",
    "gitlab": "The token maps to a user; project listing reveals reach.",
    "generic": "Confirm the value is really a credential and not a placeholder "
               "before you spend time on it.",
}


ESCALATION: dict[str, list[str]] = {
    "aws": [
        "aws sts get-caller-identity --output json",
        "aws iam list-attached-user-policies --user-name <user> --output json",
        "aws s3 ls",
        "aws secretsmanager list-secrets --output json",
    ],
    "slack": [
        "POST auth.test",
        "POST users.list",
        "POST conversations.list",
        "POST team.info",
    ],
    "stripe_live": [
        "GET /v1/account",
        "GET /v1/charges?limit=3",
        "GET /v1/customers?limit=3",
        "GET /v1/balance",
    ],
    "sendgrid": [
        "GET /v3/scopes",
        "GET /v3/api_keys",
        "GET /v3/senders",
    ],
    "google_api": [
        "GET geocode for a known address",
        "Enumerate enabled services for the key",
        "Check quota and billing impact",
    ],
    "github": [
        "GET /user",
        "GET /user/repos",
        "Check scope headers on the response",
    ],
}


DOCS: dict[str, str] = {
    "aws": "https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html",
    "slack": "https://api.slack.com/methods/auth.test",
    "stripe_live": "https://docs.stripe.com/api/authentication",
    "sendgrid": "https://www.twilio.com/docs/sendgrid/api-reference",
    "google_api": "https://developers.google.com/maps/get-started",
    "github": "https://docs.github.com/en/rest/users/users",
    "shodan": "https://developer.shodan.io/api",
}


@dataclass
class Knowledge:
    fetched: dict[str, str] = field(default_factory=dict)
    timeout: float = 15.0

    def hint(self, secret_type: str) -> str:
        return VALIDATION_HINTS.get(secret_type, "")

    def escalation(self, secret_type: str) -> list[str]:
        return ESCALATION.get(secret_type, [])

    def docs(self, secret_type: str) -> str:
        return DOCS.get(secret_type, "")

    def fetch(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            return ""
        if url in self.fetched:
            return self.fetched[url]
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(url, headers={"User-Agent": "netcast3r-docs"})
                text = response.text[:20000]
        except Exception:
            text = ""
        self.fetched[url] = text
        return text

    def context_for(self, secret_type: str, provider: str = "") -> str:
        parts = []
        hint = self.hint(secret_type)
        if hint:
            parts.append(f"note: {hint}")
        steps = self.escalation(secret_type)
        if steps:
            parts.append("steps: " + " | ".join(steps))
        link = self.docs(secret_type)
        if link:
            parts.append(f"docs: {link}")
        return "\n".join(parts)
