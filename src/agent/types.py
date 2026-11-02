from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Document:
    id: str
    body: str
    tenant: str = "acme"
    trust: str = "reviewed"
    source: str = "internal"


@dataclass(frozen=True)
class Action:
    tool: str
    arguments: dict[str, Any]


@dataclass
class Outcome:
    output: str
    events: list[dict[str, Any]] = field(default_factory=list)
    decision: str = "respond"
    input_chars: int = 0
    input_tokens_estimate: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
