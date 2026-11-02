from fractions import Fraction

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
