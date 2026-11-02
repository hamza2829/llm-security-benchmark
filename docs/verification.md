# Verification record

Python 3.11.0 local environment, 2 November 2026. CI results will be appended after execution.

- First executed benchmark: 40 cases × 2 modes = **80 evaluations**. Naive **0 passed / 40 failed**, hardened **31 passed / 9 failed**. Severity weights: naive **0/313**, hardened **248/313 = 79.233227%**. These are observed benchmark findings, not suppressed tests.
- First pytest run: **124 passed, 1 failed**. `test_markdown_does_not_emit_raw_attack_html` wrongly rejected the inert substring `javascript:alert` even when its parentheses and markup were escaped. The assertion now checks the unescaped executable form `javascript:alert(1)` alongside raw-tag checks. No benchmark case or oracle was weakened.
- Ruff initially found one unused import, automatically removed; formatting was applied.

- One local rerun from a different execution context had **114 passes and 11 fixture setup errors**: Windows denied access to the shared pytest temp directory. Using a workspace-local `--basetemp` resolved this environment problem without product changes.
- Final local run: **125 passed, 0 failed, 0 errors, 0 skipped** in Python 3.11.0. Ruff check and format check passed. Benchmark remained **31/40 hardened, 9 findings, 79.233227%**. Baseline comparison returned 0. Reports were generated from executed outcomes, not hand-entered scores.

Scanner results, CI run, and the CI setup PR merge are pending.
