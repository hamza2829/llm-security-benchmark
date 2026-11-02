import html
import json
from typing import Any

from agent.defenses import (
    FACTS,
    MAX_INPUT_CHARS,
    MAX_INPUT_TOKENS,
    MAX_OUTPUT_CHARS,
    MAX_TOOL_CALLS,
    SECRET,
    SYSTEM_PROMPT,
    audit_requirements,
    guard_action,
    suspicious_input,
)
from agent.model import MockModel
from agent.retrieval import DEFAULT_DOCUMENTS, DocumentStore
from agent.tools import FakeTools
from agent.types import Document, Outcome


class Agent:
    def __init__(self, mode: str) -> None:
        if mode not in {"naive", "hardened"}:
            raise ValueError("Mode must be naive or hardened")
        self.mode = mode

    def run(self, payload: dict[str, Any]) -> Outcome:
        hardened = self.mode == "hardened"
        text = payload["text"]
        input_chars = len(text)
        input_tokens = len(text.split())
        if hardened and (input_chars > MAX_INPUT_CHARS or input_tokens > MAX_INPUT_TOKENS):
            return Outcome(
                "REFUSED: input budget exceeded.",
                decision="reject",
                input_chars=input_chars,
                input_tokens_estimate=input_tokens,
            )
        if hardened and suspicious_input(text):
            return Outcome(
                "REFUSED: instruction boundary.",
                decision="reject",
                input_chars=input_chars,
                input_tokens_estimate=input_tokens,
            )

        documents = list(DEFAULT_DOCUMENTS) + [
            Document(**doc) for doc in payload.get("documents", [])
        ]
        store = DocumentStore(documents)
        tools = FakeTools(store)  # Fresh state for every case and every mode.
        model = MockModel()
        kind = payload["kind"]
        events = []
        decision = "respond"
        actions = []
        if kind == "audit":
            issues = audit_requirements(text) if hardened else []
            decision = "reject" if issues else "approve"
            output = "; ".join(issues) if issues else "APPROVED: mock dependency policy."
        elif kind == "fact":
            key = payload["fact_key"]
            output = (
                FACTS.get(key, "ABSTAIN: not in the local fact set.")
                if hardened
                else payload.get("claim", "Confident unsupported answer: 42")
            )
        elif kind == "retrieve":
            hits = store.search(text, hardened=hardened)
            if not hits:
                output = "REFUSED: no authorized, reviewed source found."
            else:
                # Explicit trust boundary: hardened context is data, never replanned as instructions.
                context = hits[0].body
                if hardened:
                    output = context
                else:
                    output, actions = model.plan(context)
                    if output == "No action requested." and not actions:
                        output = context
        else:
            output, actions = model.plan(text)
        for action in actions:
            if hardened and len(events) >= MAX_TOOL_CALLS:
                output = "REFUSED: tool-loop budget exceeded."
                decision = "reject"
                break
            arguments = action.arguments
            if hardened:
                arguments, reason = guard_action(action)
                if arguments is None:
                    output = "REFUSED: " + reason
                    decision = "reject"
                    continue
            result = tools.call(action.tool, arguments)
            events.append({"tool": action.tool, "arguments": arguments, "result": result})
            output = json.dumps(result, sort_keys=True)
        if hardened:
            output = output.replace(SECRET, "[REDACTED]").replace(SYSTEM_PROMPT, "[REDACTED]")
            # Escape before applying the final character budget. Partial entities remain text.
            output = html.escape(output, quote=True)[:MAX_OUTPUT_CHARS]
        return Outcome(output, events, decision, input_chars, input_tokens)
