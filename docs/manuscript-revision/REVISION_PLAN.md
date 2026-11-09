# PP-NSMF Manuscript — Phase A: Inventory and Audit

Prepared for NDPC International Journal of Data Privacy & Protection, 3rd Edition 2026 submission.
Scope: **Phase A only** — inventory and audit. No manuscript, CSV, log, script, or evidence file was modified.
All new working files are in `docs/manuscript-revision/` (this revision workspace).

---

## 1. Source files located

| Artefact | Path | Status |
|---|---|---|
| Manuscript (DOCX) | `PP-NSMF_NDPC_manuscript.docx` | Found, repo root. Only one manuscript file exists — treated as "the latest corrected manuscript." |
| Corrected metrics CSV | `evidence-backup/reports/aggregate-metrics-v2.csv` | Found, 29 data rows. Treated as authoritative per `metric-scope-resolution-completion.md`. |
| Historical metrics CSV | `evidence-backup/reports/aggregate-metrics.csv` | Found, superseded (combined-scope denominator); kept as historical only, not used for claims. |
| Consolidated run CSV | `evidence-backup/reports/consolidated-runs.csv` | Found, 29 rows, run-level detail. |
| Run log | `evidence-backup/protocol/experiment-run-log.csv` | Found, 31 lines (30 data rows incl. 1 FAILED + 1 retry for S4-R1). |
| Checksum manifest | `evidence-backup/SHA256SUMS.txt` | Found, 243 entries. Independently re-verified: **243/243 OK**, 0 failures. |
| Validation reports | `evidence-backup/reports/S*-R*.validation.json`, `S*-summary.md` | Found, complete set for all 29 compliant runs. |
| Transformation/validation scripts | `scripts/*.py` | Found: `transform_telemetry.py`, `validate_results.py`, `metrics.py`, `linkability.py`, `generate_metrics_csv.py`, plus test suites. |
| Supporting docs | `docs/*.md` | Found: experiment protocol, topology audit, IP addressing, transformation changelog, linkability report, metric-scope validation/proposal/completion, manuscript results package, pre-writing audit. |
| Footnotes (Chicago-style) | `word/footnotes.xml` inside the DOCX | Found: 11 real Word footnotes (not manually typed numbers — this is good practice already in place). |
| Journal call-for-papers flyer | Two attached images (`ndpc 1.jpeg`, `ndpc 2.jpeg`) | Read. Used as the source of truth for journal requirements (Section 7 below). |

**Extraction method note:** `python-docx` is not installed in this environment and no package install was requested, so the DOCX was parsed directly via `zipfile` + `xml.etree.ElementTree` against the OOXML `word/document.xml` and `word/footnotes.xml` parts. This is a faithful, lossless text extraction (confirmed against paragraph/footnote structure) and does not require modifying or re-saving the DOCX. Extracted text saved to:
- `docs/manuscript-revision/manuscript-extracted-raw.txt` (body text, 86 paragraphs)
- `docs/manuscript-revision/footnotes-extracted-raw.txt` (11 footnotes)

---

## 2. Current manuscript structure and word counts

The manuscript **already follows the required structure** from the master prompt almost exactly: Title → Abstract → Keywords → 1. Introduction → 2. Literature Review and Conceptual Background (2.1–2.4) → 3. PP-NSMF Framework and Research Methodology (3.1–3.3) → 4. Results (4.1–4.5) → 5. Discussion (5.1–5.3) → 6. Limitations and Future Research → 7. Conclusion. No section is missing.

| Section | Word count | Requirement | Status |
|---|---|---|---|
| Abstract | 273 | 250–300 | **Compliant** |
| Main text (Intro → Conclusion) | ~3,583 | 3,500–4,000 | **Compliant** |
| Keywords | 1 line, 7 terms | concise, relevant | Compliant |
| Introduction | 547 | — | — |
| Literature Review | 965 | — | — |
| Methodology | 570 | — | — |
| Results | 711 | — | — |
| Discussion | 439 | — | — |
| Limitations | 192 | — | — |
| Conclusion | 159 | — | — |

**This is good news: the manuscript does not need word-count surgery.** Phase C should focus on precision, synthesis and correctness rather than cutting or padding content.

### Formatting (checked directly in the OOXML, not just visually)
- Font: **Times New Roman** confirmed as the only font used in document text runs (`word/document.xml`), consistent with the 12pt body-text requirement (`w:sz 24` half-points = 12pt appears in styles).
- Line spacing: `w:line="360" w:lineRule="auto"` in both `styles.xml` and `document.xml` → 360/240 = **1.5 line spacing**, confirmed already applied.
- Footnotes: genuine Word footnotes via `footnoteReference`/`word/footnotes.xml`, not manually typed numbers — already compliant with the "do not manually type footnote numbers" instruction.
- A full per-style, per-run font/size audit (e.g., confirming headings vs body consistently) is deferred to Phase D as specified in the workflow.

---

## 3. Numeric claims cross-checked against `aggregate-metrics-v2.csv`

I recomputed every headline figure directly from the CSV (29 rows) rather than trusting the manuscript prose. Results:

**Confirmed exact matches:**
- C2 scenario-mean reductions: S1 95.46%, S2 85.78%, S3 95.26%, S4 87.78%, S5 96.34%, S6 98.30% — ✅ matches manuscript §4.1 and abstract exactly.
- C3 scenario-mean reductions: S1 99.23%, S2 98.94%, S3 98.95%, S4 98.88%, S5 99.18%, S6 98.47% — ✅ matches exactly.
- Record counts (C0→C2): S1 17→5, S2 17.25→12, S3 7→5, S4 22→15, S5 6.2→4, S6 2.4→1 — ✅ matches §4.3 exactly.
- Observed-event counts per scenario (§4.5: HTTP/DNS/scan/auth/beacon/bulk counts) — ✅ all match CSV columns exactly.
- S4 alerts = 5/run; S3/S5/S6 = 0 alerts (no rule loaded) — ✅ matches §4.5 and the run log.
- Checksum audit: 243 entries — ✅ independently re-ran `sha256sum -c`: **243 OK, 0 failures**, matching §3.2 exactly.
- Compliant dataset = 29 runs (5+4+5+5+5+5) with legacy S2/R1 and failed S4/R1 attempt excluded — ✅ confirmed against the run log (31 lines = header + 30 data rows, one of which is the excluded FAILED S4/R1 row) and the evidence-backup exclusion folders.
- Transformation versions (2.0.0 / 2.1.0 / 2.2.0) and validator version 1.1.0 — ✅ confirmed directly in `scripts/validate_results.py` (`VALIDATOR_VERSION = "1.1.0"`) and the transformation changelog.

**One discrepancy found — flagging per your instruction to stop rather than silently resolve:**

> §4.2 of the manuscript states: *"C1 byte-volume reduction was negative in every compliant run, ranging from −0.14% to −2.28%."*

This exact figure also appears in your master prompt's own "Section 7: Verified Experimental Facts" and in `docs/manuscript-results-package.md`. However, **−0.14% and −2.28% are the S6 and S4 *scenario means*, not the true per-run extremes.** When I compute the min/max across all 29 individual run rows in the CSV directly:

- True per-run range: **−0.09% (S6-R5) to −2.29% (S4-R2)**.
- Scenario-mean range: **−0.14% (S6 mean) to −2.28% (S4 mean)** — this is what the manuscript actually reports, mislabeled as a per-run range.

The difference is small (0.05–0.01 percentage points) but the sentence explicitly says "in every compliant run," which implies run-level extremes rather than scenario-mean extremes. This is exactly the "label means correctly, preserve distinctions between per-run values and scenario means" issue your instructions ask me to guard against.

**I need your decision before Phase C touches this sentence:**
1. Keep reporting the scenario-mean range, but reword to "scenario-mean reduction ranged from −0.14% to −2.28%" (accurate to existing framing, minimal change), or
2. Switch to the true per-run extremes, "−0.09% to −2.29%" (more literally matches "every compliant run").

Both are defensible; I won't pick one silently since it touches a headline abstract-adjacent figure.

---

## 4. Footnote and citation audit

The DOCX contains 11 Chicago-style footnotes, formatted correctly (full note on first citation, shortened form on repeat — e.g., footnote 10 "Cooper et al., ... sections 6–7" correctly shortens footnote 1). Footnotes cited: RFC 6973 (×3), Nigeria Data Protection Act 2023 (×2), and five network-security/privacy research papers (van Dijkhuizen & van der Ham 2018; Pan et al. 2020; Mohammady et al. 2021; Fiore & Palmieri; Manocchio et al. 2024).

**Verification status: blocked.** I attempted to independently verify each DOI and bibliographic detail via `web_search` and `web_fetch` (both the RFC, the Act, and all five DOIs). Every call returned a `502` server error, including a plain test query — this is a tool-side outage, not a judgment call on my part, so I did not fabricate or assume verification succeeded.

**A second, more pressing issue:** you separately pasted a "corrected sources.txt" with footnote text that **differs from what's actually embedded in the DOCX** in three places:

| Footnote | DOCX (current manuscript) | Your pasted "corrected sources.txt" | Conflict |
|---|---|---|---|
| 4 — van Dijkhuizen & van der Ham | DOI `10.1145/3186333` | DOI `10.1145/3182660` | Different DOI for the same citation |
| 5 — Pan et al. | DOI `10.1109/JLT.2020.3005909` | DOI `10.1109/JLT.2020.3007491` | Different DOI for the same citation |
| 7 — Fiore & Palmieri | "Information Sciences 690 **(2025)**: 121559, https://doi.org/10.1016/j.ins.2024.121559" | "Information Sciences 690 **(2024)**: 121559," same DOI | Year in the DOCX text (2025) doesn't even match the year embedded in its own DOI (2024) — an internal inconsistency already present in the current manuscript, independent of your correction |

I cannot adjudicate which DOI is correct for footnotes 4 and 5 without working web access — I will not guess. This needs either (a) a retry once search/fetch recover, or (b) your direct confirmation of the correct DOI, ideally by checking the publisher page or CrossRef yourself. The footnote-7 year fix (2025→2024 to match its own DOI) looks safe to apply regardless, since it resolves a self-contradiction in the current text rather than relying on an unverified external source.

I've saved your pasted version to `docs/manuscript-revision/corrected-sources-received.txt` for reference; it has not been applied anywhere.

---

## 5. Style, integrity and prose scan

- **One formatting artefact found:** end of §2.4 (Research Gap and Contribution) reads: *"...configurable privacy–utility trade-offs.**–** These contributions provide important foundations..."* — a stray en-dash sitting between two sentences, almost certainly a leftover from an edit. Flagged for removal in Phase C.
- **Hedging language check:** scanned for unqualified "proves/ensures/guarantees/anonymous/fully compliant" per your style rules. The manuscript already uses these terms carefully and only in negated/qualified form (e.g., "do not prove," "not anonymised," "not a formal proof of anonymity"). **No violations found** — the existing author voice already matches the caution your instructions require. This is a strength to preserve, not a problem to fix.
- **Outcome-conflation check:** the manuscript already explicitly distinguishes byte-volume reduction, identifier exposure, pseudonym linkability, aggregation, investigation utility, and detection effectiveness as separate properties (clearest in §4.4, §4.5, §5.1, and the limitations section). This aligns with Section 5 of your master prompt and does not need structural rework.
- **No fabricated experimental details detected** — every concrete claim I spot-checked (scenario descriptions, run counts, versions, checksum totals) traces to an evidence file.

---

## 6. Journal requirement gaps (flagging per your instruction, not guessing)

From the two flyer images, the following are **explicitly stated** and already satisfied or trackable: theme, focus areas, abstract word count, main word count, Chicago footnotes, Times New Roman 12pt, 1.5 spacing, English language, manuscript types, key dates, submission email (`research@ndpc.gov.ng`) and required subject line (`Submission - Third Edition NDPC International Journal of Data Privacy & Protection`).

**Not addressed by the flyer, and not assumed either way:**
- Whether a separate bibliography/reference list is required in addition to footnotes.
- Whether an author biography or declarations (conflict of interest, originality statement) must accompany the submission.
- Any required file-naming convention for the manuscript file itself.

These are flagged as open questions for you to confirm with NDPC or from any fuller guidelines document, if one exists beyond the flyer.

---

## 7. What Phase A deliberately did not touch

- The manuscript DOCX, CSV, logs, scripts, and evidence-backup files are all unmodified (verified: only new files were created, all under `docs/manuscript-revision/`).
- No rewriting of Introduction/Literature Review/Methodology/Results/Discussion/Limitations/Conclusion has occurred yet — that is Phase C.
- No claim-by-claim source-to-text mapping (Phase B) has been produced yet.

## 8. Proposed next step (Phase B)

Pending your review of the two items above (§3 C1-range decision, §4 DOI conflict), Phase B will:
- Map every major claim in the manuscript to its supporting evidence file or footnote.
- Produce the claim-and-source audit table.
- Surface any remaining unsupported or weakly-synthesized claims before any prose is rewritten.

**I am stopping here per your Phase A instructions and awaiting your review before proceeding to Phase B.**
