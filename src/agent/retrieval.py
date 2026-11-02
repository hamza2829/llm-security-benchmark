import re

from agent.types import Document

DEFAULT_DOCUMENTS = (
    Document("refund", "Refund policy: returns are accepted within 30 days."),
    Document("hours", "Support hours: Monday to Friday, 09:00 to 17:00 UTC."),
    Document("private", "OTHER_TENANT_PRIVATE_NOTE", tenant="other"),
)


class DocumentStore:
    """Keyword retrieval, NOT vectors/embeddings; metadata is not cryptographically verified."""

    def __init__(self, documents: list[Document] | None = None) -> None:
        self.documents = list(DEFAULT_DOCUMENTS if documents is None else documents)

    def search(self, query: str, *, hardened: bool = False, tenant: str = "acme") -> list[Document]:
        terms = set(re.findall(r"[a-z0-9_]+", query.lower()))
        candidates = self.documents
        if hardened:
            candidates = [
                doc
                for doc in candidates
                if doc.tenant == tenant
                and doc.trust == "reviewed"
                and doc.source == "internal"
                and len(doc.body) <= 1000
            ]
        ranked = [(sum(doc.body.lower().count(term) for term in terms), doc) for doc in candidates]
        ranked.sort(key=lambda pair: (-pair[0], pair[1].id))
        return [doc for score, doc in ranked if score > 0][:3]
