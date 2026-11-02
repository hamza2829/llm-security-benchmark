import copy

import pytest

from llmsec.catalog import CATEGORIES, CatalogError, catalog_digest, load_catalog, validate_case


@pytest.mark.parametrize("case", load_catalog(), ids=lambda case: case["id"])
def test_each_catalog_case_has_a_valid_observable_oracle(case):
    assert validate_case(case) == case
    assert case["expected_safe_behaviour"].strip()
    assert case["checks"]


def test_catalog_covers_all_ten_2025_categories(cases):
    assert len(cases) >= 30
    assert {case["category"] for case in cases} == set(CATEGORIES)
    assert len({case["id"] for case in cases}) == len(cases)


@pytest.mark.parametrize(
    "field,value",
    [
        ("severity", "urgent"),
        ("category", "LLM11"),
        ("id", "LLM02-999"),
        ("description", ""),
        ("payload", {"kind": "shell", "text": "echo nope"}),
        ("checks", {"no_tool_calls": "yes"}),
        ("checks", {"max_tool_calls": True}),
        ("checks", {"imaginary_check": True}),
        ("checks", {}),
    ],
)
def test_schema_rejects_bad_fields(cases, field, value):
    case = copy.deepcopy(cases[0])
    case[field] = value
    with pytest.raises(CatalogError):
        validate_case(case)


def test_yaml_duplicate_keys_are_rejected(tmp_path):
    (tmp_path / "bad.yaml").write_text("schema_version: 1\nschema_version: 1\ncases: []\n")
    with pytest.raises(CatalogError, match="unique"):
        load_catalog(tmp_path)


def test_unsafe_yaml_constructor_is_rejected(tmp_path):
    (tmp_path / "bad.yaml").write_text("!!python/object/apply:builtins.print ['unsafe']")
    with pytest.raises(CatalogError, match="safe YAML"):
        load_catalog(tmp_path)


def test_missing_categories_are_rejected(tmp_path):
    (tmp_path / "empty.yaml").write_text("schema_version: 1\ncases: []\n")
    with pytest.raises(CatalogError, match="30 cases"):
        load_catalog(tmp_path)


def test_digest_binds_payload_and_oracle(cases):
    changed = copy.deepcopy(cases)
    changed[0]["checks"]["forbid_text"].append("another canary")
    assert catalog_digest(changed) != catalog_digest(cases)


def test_documents_cannot_replace_reserved_records(cases):
    case = copy.deepcopy(cases[0])
    case["payload"]["documents"] = [
        {"id": "refund", "body": "bad", "tenant": "acme", "trust": "reviewed", "source": "internal"}
    ]
    with pytest.raises(CatalogError, match="reserved"):
        validate_case(case)
