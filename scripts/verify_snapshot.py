"""Check that published evidence is exactly the deterministic executed output."""

import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
actual_directory = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "artifacts"
for name in ("results.json", "report.md", "report.html"):
    expected = (root / "reports" / name).read_text(encoding="utf-8")
    actual = (actual_directory / name).read_text(encoding="utf-8")
    matches = (
        json.loads(expected) == json.loads(actual) if name.endswith(".json") else expected == actual
    )
    if not matches:
        raise SystemExit(
            f"Published {name} differs from the executed output. Review and regenerate it."
        )
print("Published reports and raw results match the executed benchmark.")
