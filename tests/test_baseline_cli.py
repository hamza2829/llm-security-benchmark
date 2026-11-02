import copy
import json
from pathlib import Path

import pytest

from llmsec.__main__ import main
from llmsec.baseline import compare, make_baseline
from llmsec.reporting import read_json
from runner import summarize, write_results


def regressed(benchmark):
    data = copy.deepcopy(benchmark)
    row = next(
        row for row in data["results"] if row["mode"] == "hardened" and row["id"] == "LLM02-001"
    )
    row["outcome"]["output"] = "SYNTHETIC_CANARY_ORCHID_47"
    row["failures"] = ["Forbidden content exposed: SYNTHETIC_CANARY_ORCHID_47"]
    row["passed"] = False
    data["summary"] = summarize(data["results"])
    return data


def test_unchanged_results_pass_baseline(benchmark):
    assert not compare(benchmark, make_baseline(benchmark))


def test_score_drop_fails_baseline(benchmark):
    failures = compare(regressed(benchmark), make_baseline(benchmark))
    assert any("score dropped" in failure for failure in failures)
    assert any("LLM02-001" in failure for failure in failures)


def test_catalog_change_requires_explicit_review(benchmark):
    baseline = make_baseline(benchmark)
    baseline["catalog_sha256"] = "0" * 64
    assert "Catalog changed" in compare(benchmark, baseline)[0]


def test_scoring_version_change_is_not_silently_accepted(benchmark):
    baseline = make_baseline(benchmark)
    baseline["scoring_version"] = 999
    assert "Scoring version" in compare(benchmark, baseline)[0]


@pytest.mark.parametrize(
    "field,value",
    [
        ("total_weight", 0),
        ("safe_weight", -1),
        ("weighted_score", 100),
        ("weighted_score", float("nan")),
    ],
)
def test_malformed_baseline_weights_and_scores_are_rejected(benchmark, field, value):
    baseline = make_baseline(benchmark)
    baseline[field] = value
    with pytest.raises(ValueError, match="baseline|Baseline"):
        compare(benchmark, baseline)


def test_cli_returns_operational_error_for_a_malformed_baseline(tmp_path, benchmark):
    results, baseline_path = tmp_path / "results.json", tmp_path / "baseline.json"
    baseline = make_baseline(benchmark)
    baseline["total_weight"] = 0
    write_results(benchmark, results)
    write_results(baseline, baseline_path)
    assert main(["compare", "--results", str(results), "--baseline", str(baseline_path)]) == 2


def test_equal_aggregate_score_cannot_hide_a_per_case_regression(benchmark):
    baseline = make_baseline(benchmark)
    data = regressed(benchmark)
    data["summary"]["hardened"] = benchmark["summary"]["hardened"]
    assert any("Previously safe" in failure for failure in compare(data, baseline))


def test_checked_in_baseline_matches_measured_results(benchmark):
    assert make_baseline(benchmark) == read_json(Path("baseline.json"))


def test_run_command_writes_results_and_reports(tmp_path):
    results = tmp_path / "results.json"
    assert main(["run", "--results", str(results), "--output", str(tmp_path)]) == 0
    assert len(json.loads(results.read_text())["results"]) >= 60
    assert (tmp_path / "report.html").exists()


def test_report_command_regenerates_from_saved_evidence(tmp_path, benchmark):
    results = tmp_path / "results.json"
    write_results(benchmark, results)
    assert main(["report", "--results", str(results), "--output", str(tmp_path)]) == 0
    assert (tmp_path / "report.md").exists()


def test_compare_command_returns_one_for_an_actual_regression(tmp_path, benchmark):
    results, baseline = tmp_path / "results.json", tmp_path / "baseline.json"
    write_results(regressed(benchmark), results)
    write_results(make_baseline(benchmark), baseline)
    assert main(["compare", "--results", str(results), "--baseline", str(baseline)]) == 1


def test_compare_command_returns_zero_for_unchanged_results(tmp_path, benchmark):
    results, baseline = tmp_path / "results.json", tmp_path / "baseline.json"
    write_results(benchmark, results)
    write_results(make_baseline(benchmark), baseline)
    assert main(["compare", "--results", str(results), "--baseline", str(baseline)]) == 0


@pytest.mark.parametrize("command", ["report", "compare"])
def test_missing_result_file_is_an_operational_error(tmp_path, command):
    assert main([command, "--results", str(tmp_path / "missing.json")]) == 2


def test_invalid_catalog_is_an_operational_error(tmp_path):
    assert main(["run", "--catalog", str(tmp_path)]) == 2
