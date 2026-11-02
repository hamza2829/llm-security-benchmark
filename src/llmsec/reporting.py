import html
import json
import re
from pathlib import Path

from llmsec.catalog import CATEGORIES


def md(value: object) -> str:
    escaped = html.escape(str(value), quote=True).replace("\n", " ")
    return re.sub(r"([\\`*{}\[\]()#+.!_|>~-])", r"\\\1", escaped)


def markdown_report(data: dict, cases: list[dict]) -> str:
    lines = [
        "# Local mock-agent security evaluation",
        "",
        "Synthetic, deterministic control simulation. Not an LLM evaluation, audit, or security product.",
        "",
        f"Catalog SHA-256: `{data['catalog_sha256']}`",
        "",
        "Score = 100 × safe severity weight / total severity weight. Weights: low=1, medium=3, high=7, critical=10. Higher is safer on this catalog only.",
        "",
        "## Results",
        "",
        "| Mode | Passed | Failed | Weighted score |",
        "|---|---:|---:|---:|",
    ]
    for mode, result in data["summary"].items():
        lines.append(
            f"| {mode} | {result['passed']}/{result['total']} | {result['failed']} | {result['weighted_score']:.2f}% ({result['safe_weight']}/{result['total_weight']}) |"
        )
    lines += [
        "",
        "## Coverage and category pass/fail",
        "",
        "| OWASP 2025 category | Cases | Naive pass / fail | Hardened pass / fail |",
        "|---|---:|---:|---:|",
    ]
    for category, title in CATEGORIES.items():
        naive = data["summary"]["naive"]["categories"][category]
        hard = data["summary"]["hardened"]["categories"][category]
        lines.append(
            f"| {category} {title} | {data['coverage'][category]} | {naive['passed']} / {naive['failed']} | {hard['passed']} / {hard['failed']} |"
        )
    lines += ["", "## Hardened failures (retained)", ""]
    failed = [row for row in data["results"] if row["mode"] == "hardened" and not row["passed"]]
    for row in failed:
        lines.append(f"- **{row['id']} ({row['severity']})**: {md('; '.join(row['failures']))}")
    if not failed:
        lines.append(
            "No failures observed on this catalog; this is not a general security guarantee."
        )
    indexed = {case["id"]: case for case in cases}
    lines += [
        "",
        "## Case evidence",
        "",
        "| Case | Mode | Severity | Result | Expected safe behaviour | Output / finding |",
        "|---|---|---|---|---|---|",
    ]
    for row in data["results"]:
        evidence = row["outcome"]["output"] + (
            " / " + "; ".join(row["failures"]) if row["failures"] else ""
        )
        lines.append(
            f"| {row['id']} | {row['mode']} | {row['severity']} | {'PASS' if row['passed'] else 'FAIL'} | {md(indexed[row['id']]['expected_safe_behaviour'])} | {md(evidence)} |"
        )
    lines += [
        "",
        "## Interpretation and limits",
        "",
        "Cases use a documented mock command grammar, not natural-language LLM inference. Supply-chain checks are fake offline policy examples; no packages are installed from payloads. Poisoning is simulated at document ingestion, not model training. LLM08 uses keyword retrieval, not a vector database. The fact set is tiny. Limits count characters/whitespace tokens, not provider tokens or money. A higher score does not establish real-world security. See README and docs/catalog-review.md.",
        "",
    ]
    return "\n".join(lines)


def html_report(data: dict, cases: list[dict]) -> str:
    def table(headers: list[str], rows: list[list[object]]) -> str:
        head = "".join('<th scope="col">' + html.escape(h) + "</th>" for h in headers)
        body = "".join(
            "<tr>"
            + "".join("<td>" + html.escape(str(cell), quote=True) + "</td>" for cell in row)
            + "</tr>"
            for row in rows
        )
        return (
            '<div class="scroll"><table><thead><tr>'
            + head
            + "</tr></thead><tbody>"
            + body
            + "</tbody></table></div>"
        )

    totals = table(
        ["Mode", "Passed / total", "Failed", "Weighted score"],
        [
            [
                mode,
                f"{result['passed']} / {result['total']}",
                result["failed"],
                f"{result['weighted_score']:.2f}%",
            ]
            for mode, result in data["summary"].items()
        ],
    )
    coverage_rows = []
    for category, title in CATEGORIES.items():
        naive = data["summary"]["naive"]["categories"][category]
        hard = data["summary"]["hardened"]["categories"][category]
        coverage_rows.append(
            [
                category + " " + title,
                data["coverage"][category],
                f"{naive['passed']} / {naive['failed']}",
                f"{hard['passed']} / {hard['failed']}",
            ]
        )
    coverage = table(
        ["OWASP 2025 category", "Cases", "Naive pass / fail", "Hardened pass / fail"], coverage_rows
    )
    failures = table(
        ["Retained hardened failure", "Severity", "Finding"],
        [
            [row["id"], row["severity"], "; ".join(row["failures"])]
            for row in data["results"]
            if row["mode"] == "hardened" and not row["passed"]
        ],
    )
    indexed = {case["id"]: case for case in cases}
    evidence = []
    for row in data["results"]:
        label = f"{row['id']} / {row['mode']} / {'PASS' if row['passed'] else 'FAIL'}"
        content = json.dumps(
            {
                "description": indexed[row["id"]]["description"],
                "expected_safe_behaviour": indexed[row["id"]]["expected_safe_behaviour"],
                "outcome": row["outcome"],
                "findings": row["failures"],
            },
            indent=2,
        )
        evidence.append(
            "<details><summary>"
            + html.escape(label)
            + "</summary><pre>"
            + html.escape(content, quote=True)
            + "</pre></details>"
        )
    digest = html.escape(data["catalog_sha256"])
    return (
        """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Local mock-agent security evaluation</title>
<style>body{max-width:1120px;margin:48px auto;padding:0 24px;background:#f4f6fa;color:#18243b;font:15px/1.6 system-ui}h1{font-size:34px;line-height:1.2}h2{margin-top:36px}.eyebrow{color:#147566;font-weight:700;letter-spacing:.12em;font-size:12px}.notice{border-left:4px solid #147566;padding:12px 18px;background:#e5f2ee}.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;background:white}td,th{text-align:left;padding:12px 16px;border:1px solid #dde3ec}th{background:#18243b;color:white}details{margin:10px 0;border:1px solid #d9dfea;border-radius:8px;padding:12px 18px;background:white}summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere}code{overflow-wrap:anywhere}</style>
</head><body><p class="eyebrow">OWASP LLM APPLICATIONS / 2025</p><h1>Local mock-agent security evaluation</h1><p class="notice">Synthetic, deterministic control simulation. Not a real LLM evaluation, security audit, or security product. No provider API calls.</p><h2>Results</h2>"""
        + totals
        + "<p>Score = 100 × safe severity weight / total severity weight. Weights: low=1, medium=3, high=7, critical=10. Higher is safer only on this catalog.</p><h2>Coverage and category pass/fail</h2>"
        + coverage
        + "<h2>Hardened failures retained</h2>"
        + failures
        + "<h2>Case evidence and tool traces</h2>"
        + "".join(evidence)
        + "<h2>Limits</h2><p>The command interpreter is not an LLM. Supply-chain and poisoning cases are local simulations. Retrieval uses keywords, not embeddings. The fact set is tiny; character/whitespace budgets do not model provider billing. No real data, packages, tools, or messages are sent anywhere.</p><p>Catalog SHA-256: <code>"
        + digest
        + "</code></p></body></html>\n"
    )


def write_reports(data: dict, cases: list[dict], directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "report.md").write_text(markdown_report(data, cases), encoding="utf-8")
    (directory / "report.html").write_text(html_report(data, cases), encoding="utf-8")


def read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return data
