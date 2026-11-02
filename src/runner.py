import json
from pathlib import Path

from agent import Agent
from agent.types import Outcome
from llmsec.catalog import CATEGORIES, WEIGHTS, catalog_digest
from llmsec.evaluation import evaluate

SCORING_VERSION = 1


def summarize(rows: list[dict]) -> dict:
    modes = {}
    for mode in ("naive", "hardened"):
        selected = [row for row in rows if row["mode"] == mode]
        total_weight = sum(WEIGHTS[row["severity"]] for row in selected)
        safe_weight = sum(WEIGHTS[row["severity"]] for row in selected if row["passed"])
        modes[mode] = {
            "passed": sum(row["passed"] for row in selected),
            "failed": sum(not row["passed"] for row in selected),
            "total": len(selected),
            "safe_weight": safe_weight,
            "total_weight": total_weight,
            "weighted_score": round(100 * safe_weight / total_weight, 6) if total_weight else 0.0,
            "categories": {
                category: {
                    "passed": sum(row["passed"] for row in selected if row["category"] == category),
                    "failed": sum(
                        not row["passed"] for row in selected if row["category"] == category
                    ),
                }
                for category in CATEGORIES
            },
        }
    return modes


def run_benchmark(cases: list[dict]) -> dict:
    rows = []
    for mode in ("naive", "hardened"):
        for case in cases:
            # Unexpected implementation errors abort execution; they never count as safe refusals.
            outcome = Agent(mode).run(case["payload"])
            failures = evaluate(case["checks"], outcome)
            rows.append(
                {
                    "id": case["id"],
                    "mode": mode,
                    "category": case["category"],
                    "severity": case["severity"],
                    "passed": not failures,
                    "failures": failures,
                    "outcome": outcome.to_dict(),
                }
            )
    return {
        "schema_version": 1,
        "scoring_version": SCORING_VERSION,
        "catalog_sha256": catalog_digest(cases),
        "case_count": len(cases),
        "coverage": {
            category: sum(c["category"] == category for c in cases) for category in CATEGORIES
        },
        "summary": summarize(rows),
        "results": rows,
    }


def validate_results(data: dict, cases: list[dict]) -> dict:
    if data.get("schema_version") != 1 or data.get("scoring_version") != SCORING_VERSION:
        raise ValueError("Unsupported result/scoring schema")
    if data.get("catalog_sha256") != catalog_digest(cases) or data.get("case_count") != len(cases):
        raise ValueError("Results do not match this catalog")
    indexed = {case["id"]: case for case in cases}
    rows = data.get("results")
    if not isinstance(rows, list) or len(rows) != 2 * len(cases):
        raise ValueError("Incomplete result set")
    seen = set()
    for row in rows:
        key = (row["mode"], row["id"])
        if row["mode"] not in {"naive", "hardened"} or row["id"] not in indexed or key in seen:
            raise ValueError("Invalid/duplicate result identity")
        seen.add(key)
        case = indexed[row["id"]]
        if row["category"] != case["category"] or row["severity"] != case["severity"]:
            raise ValueError("Result metadata mismatch")
        failures = evaluate(case["checks"], Outcome(**row["outcome"]))
        if (
            type(row["passed"]) is not bool
            or row["passed"] != (not failures)
            or row["failures"] != failures
        ):
            raise ValueError("Outcome and safety judgment disagree")
    if data.get("summary") != summarize(rows):
        raise ValueError("Stored scores disagree with executed outcomes")
    expected_coverage = {
        category: sum(c["category"] == category for c in cases) for category in CATEGORIES
    }
    if data.get("coverage") != expected_coverage:
        raise ValueError("Coverage mismatch")
    return data


def write_results(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
