import argparse
import json
import sys
from pathlib import Path

from llmsec.baseline import compare
from llmsec.catalog import DEFAULT_CATALOG, CatalogError, load_catalog
from llmsec.reporting import read_json, write_reports
from runner import run_benchmark, validate_results, write_results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic mock-agent security benchmark")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "report", "compare"):
        command = commands.add_parser(name)
        command.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
        command.add_argument("--results", type=Path, default=Path("artifacts/results.json"))
        if name in {"run", "report"}:
            command.add_argument("--output", type=Path, default=Path("artifacts"))
        else:
            command.add_argument("--baseline", type=Path, default=Path("baseline.json"))
    args = parser.parse_args(argv)
    try:
        cases = load_catalog(args.catalog)
        if args.command == "run":
            data = run_benchmark(cases)
            write_results(data, args.results)
            write_reports(data, cases, args.output)
            print(json.dumps(data["summary"], indent=2))
        else:
            data = validate_results(read_json(args.results), cases)
            if args.command == "report":
                write_reports(data, cases, args.output)
                print("Wrote Markdown and HTML reports.")
            else:
                failures = compare(data, read_json(args.baseline))
                if failures:
                    print("\n".join(failures), file=sys.stderr)
                    return 1
                print(
                    f"No regression: hardened score {data['summary']['hardened']['weighted_score']:.2f}%."
                )
    except (CatalogError, ValueError, OSError, KeyError, TypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
