import re
from fractions import Fraction
from math import isfinite

from runner import SCORING_VERSION


def make_baseline(data: dict) -> dict:
    hardened = data["summary"]["hardened"]
    return {
        "scoring_version": SCORING_VERSION,
        "catalog_sha256": data["catalog_sha256"],
        "case_count": data["case_count"],
        "safe_weight": hardened["safe_weight"],
        "total_weight": hardened["total_weight"],
        "weighted_score": hardened["weighted_score"],
        "previously_safe": sorted(
            row["id"] for row in data["results"] if row["mode"] == "hardened" and row["passed"]
        ),
    }


def compare(data: dict, baseline: dict) -> list[str]:
    """Exact fraction comparison, plus per-case protection and catalog identity."""
    required = {
        "scoring_version",
        "catalog_sha256",
        "case_count",
        "safe_weight",
        "total_weight",
        "weighted_score",
        "previously_safe",
    }
    if set(baseline) != required:
        raise ValueError("Malformed baseline fields")
    if any(
        type(baseline[key]) is not int
        for key in ("scoring_version", "case_count", "safe_weight", "total_weight")
    ):
        raise ValueError("Baseline versions, counts and weights must be integers")
    if (
        baseline["case_count"] <= 0
        or not 0 <= baseline["safe_weight"] <= baseline["total_weight"]
        or baseline["total_weight"] <= 0
    ):
        raise ValueError("Invalid baseline weights or case count")
    score = baseline["weighted_score"]
    if (
        type(score) not in {int, float}
        or not isfinite(score)
        or score != round(100 * baseline["safe_weight"] / baseline["total_weight"], 6)
    ):
        raise ValueError("Baseline score is inconsistent with its weight fraction")
    if not isinstance(baseline["catalog_sha256"], str) or not re.fullmatch(
        r"[a-f0-9]{64}", baseline["catalog_sha256"]
    ):
        raise ValueError("Invalid baseline catalog digest")
    safe_ids = baseline["previously_safe"]
    if (
        not isinstance(safe_ids, list)
        or not all(isinstance(item, str) for item in safe_ids)
        or len(safe_ids) != len(set(safe_ids))
    ):
        raise ValueError("Invalid baseline previously-safe case list")
    failures = []
    if baseline["scoring_version"] != SCORING_VERSION:
        return ["Scoring version changed: review the baseline explicitly."]
    if (
        baseline["catalog_sha256"] != data["catalog_sha256"]
        or baseline["case_count"] != data["case_count"]
    ):
        return ["Catalog changed: review coverage, oracle checks and baseline explicitly."]
    summary = data["summary"]["hardened"]
    if Fraction(summary["safe_weight"], summary["total_weight"]) < Fraction(
        baseline["safe_weight"], baseline["total_weight"]
    ):
        failures.append("Hardened severity-weighted score dropped below the stored baseline.")
    safe = {row["id"] for row in data["results"] if row["mode"] == "hardened" and row["passed"]}
    lost = sorted(set(baseline["previously_safe"]) - safe)
    if lost:
        failures.append("Previously safe cases regressed: " + ", ".join(lost))
    return failures
