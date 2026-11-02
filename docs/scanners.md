# Scanner scope and local commands

These are real repository scanners, separate from the synthetic LLM03 attack fixtures. They do not certify the mock agent as secure and do not replace review.

- **Gitleaks 8.30.1** scans the full fetched Git history with its default rules. `.gitleaks.toml` permits only the exact public synthetic string `SYNTHETIC_CANARY_ORCHID_47` as a fixture. No path or commit is excluded and no blanket secret rule is disabled. The CLI is downloaded from its official release and checked against the pinned SHA-256, without Docker, a Gitleaks Action license, or a token.
- **pip-audit 2.10.1** queries public advisory metadata for both pinned runtime dependencies in `requirements.txt` (PyYAML and packaging). `--no-deps --disable-pip` is valid here because both have no runtime dependencies. It does not audit the scanner environment or development/build-tool dependency trees. Tooling dependencies are isolated in two CI virtual environments.
- **Semgrep 1.183.0** scans `src/` using four committed local rules: dynamic eval/exec, unsafe YAML constructors, shell execution, and pickle loading. These are a deliberately small, auditable SAST policy, not Semgrep's entire registry or a comprehensive vulnerability scan. Metrics/version checks are disabled; no registry, account, API key, or paid rules are used.
- **Ruff 0.17.3** checks source, tests, and scripts and verifies formatting. Pytest runs on Python 3.10 and 3.12, and each matrix job executes both agent modes and compares the stored baseline. Actions are pinned by immutable commit SHA.

CI scanner steps do not use `continue-on-error`. All three scanner steps are attempted even if an earlier scanner fails, and available JSON reports upload using `if: always()`. Network/setup failure is a failed CI run, not a clean scan.

For a local Linux/macOS/WSL setup, install the pinned scanner CLIs into separate virtual environments (Gitleaks is a native CLI from its [official release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)), then run from the checkout:

```sh
mkdir -p artifacts
gitleaks git . --config .gitleaks.toml --redact --report-format json --report-path artifacts/gitleaks.json
pip-audit -r requirements.txt --no-deps --disable-pip --format json --output artifacts/pip-audit.json
SEMGREP_ENABLE_VERSION_CHECK=0 semgrep scan --config .semgrep.yml --error --metrics=off --json --output artifacts/semgrep.json src
```

The Python benchmark and unit tests also run directly on Windows. Scanner platform support is determined by each upstream CLI; Linux/WSL follows the same path as the GitHub Actions runner. Downloads and pip-audit's public advisory lookup require network connectivity. The actual mock benchmark and tests remain offline.
