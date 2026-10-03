"""Agents.

Each agent owns one job, a role prompt, and an optional model route. Agents
read from the evidence store and write back to it. When no provider is
reachable an agent returns nothing and the caller falls back to the
deterministic path, so a run always produces a result.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .knowledge import Knowledge
from .providers import Chunk, ProviderBus


def _first_json(text: str):
    match = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


@dataclass
class AgentResult:
    agent: str
    text: str = ""
    data: object = None
    reasoning: str = ""
    used_model: bool = False


class Agent:
    name = "agent"
    role = ""

    def __init__(self, bus: ProviderBus | None, knowledge: Knowledge | None = None):
        self.bus = bus
        self.knowledge = knowledge or Knowledge()

    def available(self) -> bool:
        if self.bus is None:
            return False
        return any(True for _ in self.bus._candidates(self.name))

    def ask(self, task: str, content: str, on_reasoning=None) -> AgentResult:
        if not self.available():
            return AgentResult(agent=self.name, used_model=False)
        messages = [
            {"role": "system", "content": self.role},
            {"role": "user", "content": f"{task}\n\n{content}"},
        ]
        reasoning: list[str] = []

        def collect(chunk: Chunk):
            if chunk.kind == "reasoning":
                reasoning.append(chunk.text)
                if on_reasoning:
                    on_reasoning(chunk.text)

        text = self.bus.chat_stream(self.name, messages, on_chunk=collect)
        return AgentResult(agent=self.name, text=text, data=_first_json(text),
                           reasoning="".join(reasoning), used_model=bool(text))


class Exegete(Agent):
    name = "exegete"
    role = (
        "You read JavaScript like a code reviewer. You reconstruct what each "
        "function does, trace the data flow, and name the weak points that an "
        "attacker could act on. Answer with compact JSON only."
    )

    def analyze(self, url: str, code: str, on_reasoning=None) -> AgentResult:
        task = (
            "Read this JavaScript and return JSON: "
            '{"endpoints":[{"path":"","method":"","note":""}],'
            '"loopholes":[{"detail":"","severity":"","evidence":""}],'
            '"flows":[""]}. Keep every list short and specific.'
        )
        content = f"file: {url}\n\n{code[:16000]}"
        return self.ask(task, content, on_reasoning=on_reasoning)


class Prospector(Agent):
    name = "prospector"
    role = (
        "You triage candidate credentials. You decide which ones are real, what "
        "service they belong to, and which deserve validation first. Answer with "
        "compact JSON only."
    )

    def triage(self, candidates: list[dict], on_reasoning=None) -> AgentResult:
        task = (
            "Rank these candidates. Return JSON: "
            '{"items":[{"type":"","value":"","provider":"","priority":1,'
            '"reason":""}]}. Highest priority first.'
        )
        return self.ask(task, json.dumps(candidates)[:16000], on_reasoning=on_reasoning)


class Classifier(Agent):
    name = "classifier"
    role = (
        "You are a credential classifier. You look at strings pulled from "
        "client JavaScript and decide whether each is a real credential, name "
        "the service and the credential type, and rate your confidence. You "
        "never invent a secret that is not in the input. Answer with compact JSON only."
    )

    def classify(self, items: list[dict], on_reasoning=None) -> AgentResult:
        task = (
            "Classify each item. Return JSON: "
            '{"items":[{"value":"","type":"","provider":"","is_secret":true,'
            '"confidence":0.0,"validate":"","reason":""}]}. '
            "Use a short lowercase snake_case type that matches common provider "
            "names when you recognise one. Set is_secret to false for values that "
            "are clearly placeholders, status words, or public identifiers."
        )
        return self.ask(task, json.dumps(items)[:16000], on_reasoning=on_reasoning)


class Assayer(Agent):
    name = "assayer"
    role = (
        "You confirm whether a credential is alive and what it can reach. You "
        "answer with the exact read-only request that proves it. Answer with "
        "compact JSON only."
    )

    def plan(self, secret_type: str, provider: str, on_reasoning=None) -> AgentResult:
        task = (
            "Given the credential type and the notes, return JSON: "
            '{"method":"GET","url":"","headers":{},"success_marker":"","note":""}. '
            "Read-only requests only."
        )
        content = f"type: {secret_type}\nprovider: {provider}\n{self.knowledge.context_for(secret_type, provider)}"
        return self.ask(task, content, on_reasoning=on_reasoning)


class Chainer(Agent):
    name = "chainer"
    role = (
        "You take a live credential and map the shortest path to the highest "
        "provable impact. You sequence the steps and stop at proof. Answer with "
        "compact JSON only."
    )

    def escalate(self, secret_type: str, detail: str, on_reasoning=None) -> AgentResult:
        task = (
            "Return JSON: "
            '{"impact":"","severity":"","steps":[{"command":"","expect":""}],'
            '"notes":""}. Read-only steps unless the tier allows writes.'
        )
        content = f"type: {secret_type}\nresult: {detail}\n{self.knowledge.context_for(secret_type)}"
        return self.ask(task, content, on_reasoning=on_reasoning)


class Scribe(Agent):
    name = "scribe"
    role = (
        "You write the finding the way a senior operator would: plain, direct, "
        "and easy to reproduce. No filler, no hype."
    )

    def write(self, finding: dict, on_reasoning=None) -> AgentResult:
        task = (
            "Write the finding as short markdown with these parts: title, impact, "
            "proof, reproduction, remediation. Keep it human."
        )
        return self.ask(task, json.dumps(finding)[:16000], on_reasoning=on_reasoning)


@dataclass
class Roster:
    bus: ProviderBus | None = None
    knowledge: Knowledge = field(default_factory=Knowledge)

    def __post_init__(self):
        self.exegete = Exegete(self.bus, self.knowledge)
        self.prospector = Prospector(self.bus, self.knowledge)
        self.classifier = Classifier(self.bus, self.knowledge)
        self.assayer = Assayer(self.bus, self.knowledge)
        self.chainer = Chainer(self.bus, self.knowledge)
        self.scribe = Scribe(self.bus, self.knowledge)
