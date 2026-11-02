import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml

CATEGORIES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
WEIGHTS = {"low": 1, "medium": 3, "high": 7, "critical": 10}
DEFAULT_CATALOG = Path(__file__).resolve().parents[2] / "catalog"
STRING_LIST_CHECKS = {"forbid_text", "must_include", "any_of", "allowed_tools"}
BOOL_CHECKS = {"no_tool_calls", "no_external_email", "minimal_customer_fields"}
INT_CHECKS = {"max_tool_calls", "max_output_chars"}
STRING_CHECKS = {"decision", "only_customer"}


class CatalogError(ValueError):
    pass


class UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML plus duplicate-key rejection, including nested payload/check mappings."""


def _mapping(loader: UniqueSafeLoader, node: yaml.MappingNode) -> dict:
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str) or key in mapping:
            raise CatalogError("YAML mapping keys must be unique strings")
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def validate_case(case: Any) -> dict[str, Any]:
    required = {
        "id",
        "category",
        "description",
        "payload",
        "expected_safe_behaviour",
        "severity",
        "checks",
    }
    if not isinstance(case, dict) or set(case) != required:
        raise CatalogError("Case must contain exactly: " + ", ".join(sorted(required)))
    for field in ("id", "category", "description", "expected_safe_behaviour", "severity"):
        if not isinstance(case[field], str) or not case[field].strip():
            raise CatalogError(f"{field} must be a nonempty string")
    if case["category"] not in CATEGORIES or not re.fullmatch(r"LLM\d{2}-\d{3}", case["id"]):
        raise CatalogError("Unknown OWASP 2025 category or malformed ID")
    if not case["id"].startswith(case["category"] + "-") or case["severity"] not in WEIGHTS:
        raise CatalogError("ID/category mismatch or unsupported severity")
    payload = case["payload"]
    if not isinstance(payload, dict) or set(payload) - {
        "kind",
        "text",
        "documents",
        "fact_key",
        "claim",
    }:
        raise CatalogError("Invalid payload fields")
    if payload.get("kind") not in {"chat", "retrieve", "audit", "fact"}:
        raise CatalogError("Unsupported payload kind")
    if not isinstance(payload.get("text"), str) or not 1 <= len(payload["text"]) <= 32000:
        raise CatalogError("Payload text must contain 1–32000 characters")
    if payload["kind"] == "fact" and not isinstance(payload.get("fact_key"), str):
        raise CatalogError("Fact requests need fact_key")
    if "claim" in payload and not isinstance(payload["claim"], str):
        raise CatalogError("claim must be a string")
    documents = payload.get("documents", [])
    if not isinstance(documents, list) or len(documents) > 10:
        raise CatalogError("documents must be a list of at most 10 entries")
    ids = set()
    for doc in documents:
        if not isinstance(doc, dict) or set(doc) != {"id", "body", "tenant", "trust", "source"}:
            raise CatalogError("Document fields must be id/body/tenant/trust/source")
        if not all(isinstance(v, str) and v for v in doc.values()) or len(doc["body"]) > 8000:
            raise CatalogError("Document values must be nonempty bounded strings")
        if doc["id"] in ids or doc["id"] in {"refund", "hours", "private"}:
            raise CatalogError("Duplicate/reserved document ID")
        ids.add(doc["id"])
    checks = case["checks"]
    if not isinstance(checks, dict) or not checks:
        raise CatalogError("At least one observable safety check is required")
    for name, value in checks.items():
        if name in STRING_LIST_CHECKS:
            valid = (
                isinstance(value, list)
                and bool(value)
                and all(isinstance(v, str) and v for v in value)
            )
        elif name in BOOL_CHECKS:
            valid = type(value) is bool
        elif name in INT_CHECKS:
            valid = type(value) is int and value >= 0
        elif name in STRING_CHECKS:
            valid = isinstance(value, str) and bool(value)
        else:
            valid = False
        if not valid:
            raise CatalogError(f"Unknown or invalid check: {name}")
    return case


def load_catalog(directory: Path = DEFAULT_CATALOG, *, require_coverage: bool = True) -> list[dict]:
    cases = []
    paths = sorted(directory.glob("*.yaml"))
    if not paths:
        raise CatalogError(f"No YAML catalogs in {directory}")
    for path in paths:
        if path.stat().st_size > 256_000:
            raise CatalogError("Catalog file too large")
        try:
            data = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueSafeLoader)
        except yaml.YAMLError as exc:
            raise CatalogError(f"Invalid safe YAML: {path.name}") from exc
        if (
            not isinstance(data, dict)
            or set(data) != {"schema_version", "cases"}
            or type(data["schema_version"]) is not int
            or data["schema_version"] != 1
        ):
            raise CatalogError("Expected schema_version: 1 and cases")
        if not isinstance(data["cases"], list):
            raise CatalogError("cases must be a list")
        cases.extend(validate_case(case) for case in data["cases"])
    if len({case["id"] for case in cases}) != len(cases):
        raise CatalogError("Duplicate case ID")
    if require_coverage and (len(cases) < 30 or {c["category"] for c in cases} != set(CATEGORIES)):
        raise CatalogError("Need at least 30 cases covering all 10 OWASP 2025 categories")
    return sorted(cases, key=lambda case: case["id"])


def catalog_digest(cases: list[dict]) -> str:
    canonical = json.dumps(cases, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
