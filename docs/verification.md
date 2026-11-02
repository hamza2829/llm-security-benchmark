# Verification record

Python 3.11.0 local environment, 2 November 2026. All counts below are from executed reports.

- First executed benchmark: 40 cases × 2 modes = **80 evaluations**. Naive **0 passed / 40 failed**, hardened **31 passed / 9 failed**. Severity weights: naive **0/313**, hardened **248/313 = 79.233227%**. These are observed benchmark findings, not suppressed tests.
- First pytest run: **124 passed, 1 failed**. `test_markdown_does_not_emit_raw_attack_html` wrongly rejected the inert substring `javascript:alert` even when its parentheses and markup were escaped. The assertion now checks the unescaped executable form `javascript:alert(1)` alongside raw-tag checks. No benchmark case or oracle was weakened.
- Ruff initially found one unused import, automatically removed; formatting was applied.

- One local rerun from a different execution context had **114 passes and 11 fixture setup errors**: Windows denied access to the shared pytest temp directory. Using a workspace-local `--basetemp` resolved this environment problem without product changes.
- Local run before final baseline validation: **125 passed, 0 failed, 0 errors, 0 skipped** in Python 3.11.0. Ruff check and format check passed. Benchmark remained **31/40 hardened, 9 findings, 79.233227%**. Baseline comparison returned 0. Reports were generated from executed outcomes, not hand-entered scores.

## CI setup PR and final correction

[CI setup PR #1](https://github.com/hamza2829/llm-security-benchmark/pull/1) was merged on 2 November 2026 after [its CI run](https://github.com/hamza2829/llm-security-benchmark/actions/runs/41449965182) passed: 125 tests on Python 3.10, 125 on 3.12, and all three security scanners. The [initial main-branch merge run](https://github.com/hamza2829/llm-security-benchmark/actions/runs/41450356553) also passed. No CI runs failed during this build.

Final review then identified that malformed baseline weights could raise a division-by-zero traceback, and inconsistent score metadata could contradict its weight fraction. Added validation and five negative tests, without changing any catalog case, severity, oracle, measured score, or baseline. Local verification passed **130 tests** with 0 failures/errors/skips. An actual `python -m llmsec compare` invocation against a deliberately regressed temporary result returned **exit code 1**, naming the score drop and previously safe case LLM02-001. The committed baseline and published results were unchanged by that probe.

## Final verified source

[CI run 41450902484](https://github.com/hamza2829/llm-security-benchmark/actions/runs/41450902484) **completed successfully** for source commit `5437cc40d2af1d010a3a314f2d0248fd471e6520`. Later README/docs-only commits save these results without altering the tested application, tests, catalog, or workflow.

| Environment | Tests | Passed | Failed | Errors | Skipped |
|---|---:|---:|---:|---:|---:|
| Local Python 3.11 | 130 | 130 | 0 | 0 | 0 |
| CI Python 3.10 | 130 | 130 | 0 | 0 | 0 |
| CI Python 3.12 | 130 | 130 | 0 | 0 | 0 |

These are 130 distinct pytest cases, exercised in three environments; the two CI matrix jobs total 260 test executions. The 40 catalog attacks are separate from the pytest count and produce 80 case-mode evaluations per benchmark run. Both CI versions reproduced the committed `reports/results.json` exactly: naive **0/40, weighted 0/313 = 0%**; hardened **31/40, weighted 248/313 = 79.233227%, 9 failed safety checks/cases**. The nine failed case IDs are preserved in the report and [CI evidence summary](ci-results.json).

| Scanner | Real result | Scope |
|---|---|---|
| Gitleaks 8.30.1 | 0 findings | Full fetched Git history; one exact public synthetic-canary exception |
| pip-audit 2.10.1 | 0 known vulnerabilities | 2 pinned runtime packages, PyYAML and packaging |
| Semgrep 1.183.0 | 0 findings, 0 errors | 14 source files, 4 committed local security rules |

Original pytest XML and scanner JSON were downloaded from the final successful run into [ci-evidence](ci-evidence/); [ci-results.json](ci-results.json) was calculated from those files. Full Markdown/HTML/raw benchmark artifacts are available for each Python version in the [successful CI run](https://github.com/hamza2829/llm-security-benchmark/actions/runs/41450902484#artifacts). Report snapshots and baseline checks passed on both versions. The local native Gitleaks scan also reported 0 findings.

These results verify the specified mock implementation and scanner scopes. They are not a security audit, a real-LLM benchmark result, or a production-security claim. Initial local test failures/setup errors remain recorded above.
