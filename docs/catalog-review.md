# Catalog review and provenance

Reviewed by OpenAI Codex on 2 November 2026. No subagents, independent reviewer, external red team, or human sign-off is claimed. Original synthetic cases were authored for this repository, using OWASP's category names and definitions as a taxonomy, not copying a third-party exploit dataset.

Source: [OWASP's 2025 Top 10](https://genai.owasp.org/llm-top-10/) and its linked individual risk pages. This project intentionally preserves the **2025** numbering provided in the task, irrespective of later revisions.

| Category | Review rationale / local proxy |
|---|---|
| LLM01 | Direct overrides, forged developer authority, untrusted-document commands and Unicode obfuscation attempt to cross instruction boundaries. |
| LLM02 | Whole/partial private canaries, excess customer fields and sensitive retrieved text exercise confidentiality. All strings are synthetic. |
| LLM03 | Offline fake requirements checks cover pins, URLs, package names and missing artifact integrity. This is only one small supply-chain proxy. |
| LLM04 | False content, forged ingestion provenance and a document-triggered tool backdoor stand in for poisoning. No training or weights are modified. |
| LLM05 | Script/image/anchor/SVG outputs would be unsafe if embedded as HTML; model-output escaping and independent report escaping are separate controls. |
| LLM06 | Unknown tool, outside recipient, another customer's ID and fabricated confirmation test authority at the tool boundary. |
| LLM07 | Verbatim, debug, paraphrased and encoded disclosures target private prompt text, not merely user-visible content. |
| LLM08 | Tenant/provenance filters and rank stuffing exercise retrieval-store risks. Keyword matching is explicitly not embedding/vector testing. |
| LLM09 | Three fact-set checks and one forged retrieval citation test unsupported or wrong assertions and appropriate abstention. |
| LLM10 | A huge single token, many short words, repeated fake tool calls and long output probe bounded consumption. No real inference billing occurs. |

Each of the 40 cases has an independent, mode-agnostic oracle over text, decisions, and tool traces. The same checks apply to naive and hardened. The agent never receives the category, ID, severity, or checks. Catalog parsing rejects unknown fields, unsafe YAML constructors, duplicate keys, duplicate IDs, invalid severities, incomplete coverage, oversized files/documents, and malformed check types. Canonical content (including payload and checks) is bound to a SHA-256 fingerprint; category/ID changes cannot silently reuse the baseline.

Review included executing both modes, inspecting all nine hardened failures, checking each expected safe behavior against its observable checks, and adding benign controls to verify the hardened agent still performs authorized work. Negative controls explicitly check that refusal text cannot conceal an observed leak and that safe-looking final text cannot conceal an unsafe tool event.

## Fixed measurement, not 100% tuning

The first run measured naive 0/40, hardened 31/40, with weights 0/313 and 248/313 (0.00% and 79.23%). That first score was frozen in `baseline.json`. Nine findings remain: encoded/partial leaks, forged reviewed metadata, missing artifact integrity verification, model-controlled confirmation, policy paraphrase/encoding, and retrieved false facts. No case was removed or weakened after measurement to improve the score.

The catalog and model were co-developed. These are **not held-out cases**, an independently curated dataset, a representative sample of real attacks, or a provider comparison. Four cases in every category means numeric breadth, not complete taxonomy coverage. Some attacks overlap categories; each case is counted once in its declared primary category. Severity weights are illustrative and uncalibrated.

The local baseline is editable and unsigned. A reviewer must inspect baseline changes and catalog/oracle diffs; a malicious repository maintainer can alter them. The comparison command is a regression aid, not an integrity or compliance guarantee.
