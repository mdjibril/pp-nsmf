# PP-NSMF Manuscript — Phase D: Final Quality Assurance Report

Scope: Phase D only — verification of the working draft produced in Phase C
(`docs/manuscript-revision/manuscript-working-draft.docx`). No new prose edits were made in this
phase; this is a check-and-report pass. Where an issue was found, it is reported, not silently fixed.

---

## 1. Word counts (recalculated directly from the working draft's OOXML)

| Element | Count | Requirement | Status |
|---|---|---|---|
| Abstract | 273 words | 250–300 | **Pass** |
| Main text (Introduction through Conclusion) | 3,654 words | 3,500–4,000 | **Pass** |
| Total document (incl. abstract, keywords) | 3,955 words | — | — |

Per-section breakdown (for transparency, no individual-section requirement applies):

| Section | Words |
|---|---|
| 1. Introduction | 537 |
| 2. Literature Review and Conceptual Background | 965 |
| 3. PP-NSMF Framework and Research Methodology | 570 |
| 4. Results | 728 |
| 5. Discussion | 439 |
| 6. Limitations and Future Research | 219 |
| 7. Conclusion | 196 |

Paragraph count: 86 (unchanged from the original manuscript throughout Phases C). Approximately 346
words of headroom remain below the main-text ceiling if any further addition becomes necessary.

---

## 2. Exhaustive numerical verification against `aggregate-metrics-v2.csv` and `consolidated-runs.csv`

Every number that appears in the manuscript's Abstract, Results, Discussion, and Conclusion was
recomputed independently from the two authoritative CSVs (not spot-checked — every scenario, every
metric cited in the text).

### 2.1 C1/C2/C3 byte-volume reductions (all six scenarios, recomputed from `aggregate-metrics-v2.csv`)

| Scenario | n | C1 mean (manuscript) | C1 mean (recomputed) | C2 mean | C3 mean |
|---|---|---|---|---|---|
| S1 | 5 | — | −1.92 | 95.46 ✅ | 99.23 ✅ |
| S2 | 4 | — | −1.29 | 85.78 ✅ | 98.94 ✅ |
| S3 | 5 | — | −0.38 | 95.26 ✅ | 98.95 ✅ |
| S4 | 5 | −2.28 ✅ | −2.28 | 87.78 ✅ | 98.88 ✅ |
| S5 | 5 | — | −0.29 | 96.34 ✅ | 99.18 ✅ |
| S6 | 5 | −0.14 ✅ | −0.14 | 98.30 ✅ | 98.47 ✅ |

All 12 scenario-mean figures cited in the manuscript (6 × C2, 6 × C3) match the CSV exactly. The two
scenario-mean C1 figures explicitly cited in §4.2 (S6 = −0.14%, S4 = −2.28%) also match exactly.

**C1 per-run range (the figure corrected in Phase C):** recomputed across all 29 individual rows —
true minimum is −0.09% (S6-R5), true maximum is −2.29% (S4-R2). The working draft's §4.2 now states
*"Scenario-mean C1 reduction ranged from −0.14% (S6) to −2.28% (S4); across all 29 individual runs,
per-run values ranged from −0.09% to −2.29%"* — **this matches the recomputed values exactly.**

### 2.2 Record counts and C3 windows (recomputed from `consolidated-runs.csv`)

| Scenario | C0 mean (manuscript / recomputed) | C2 mean (manuscript / recomputed) | C3 windows |
|---|---|---|---|
| S1 | 17 / 17.00 ✅ | 5 / 5.00 ✅ | 1 (all 5 runs) ✅ |
| S2 | 17.25 / 17.25 ✅ | 12 / 12.00 ✅ | 1 (all 4 runs) ✅ |
| S3 | 7 / 7.00 ✅ | 5 / 5.00 ✅ | 1 (all 5 runs) ✅ |
| S4 | 22 / 22.00 ✅ | 15 / 15.00 ✅ | 1 (all 5 runs) ✅ |
| S5 | 6.2 / 6.20 ✅ | 4 / 4.00 ✅ | 1 (all 5 runs) ✅ |
| S6 | 2.4 / 2.40 ✅ | 1 / 1.00 ✅ | 1 (all 5 runs) ✅ |

All record-count figures match exactly.

### 2.3 Observed-event counts (§4.5, recomputed from `consolidated-runs.csv` first row per scenario)

| Scenario | Manuscript claim | CSV value | Status |
|---|---|---|---|
| S1 | 5 HTTP requests, 5 Suricata HTTP events | `http_requests=5`, `suricata_http_events=5` | ✅ |
| S2 | 6 DNS queries, 12 Suricata DNS events | `dns_queries=6`, `suricata_dns_events=12` | ✅ |
| S3 | 5 scan connections, 5 flow events | `scan_connections=5`, `suricata_flow_events=5` | ✅ |
| S4 | 5 auth attempts, 5 HTTP events | `auth_401=5`, `observed_suricata_events=5` | ✅ |
| S5 | 4 periodic connections, 4 flow events | `beacon_connections=4`, `suricata_flow_events=4` | ✅ |
| S6 | 1 bulk connection, 65,536-byte payload | `bulk_connections=1`, `bulk_orig_bytes=65536` | ✅ |
| S4 | 5 alerts/run (configured rule) | `alerts=5` | ✅ |
| S3, S5, S6 | 0 alerts (no rule loaded) | `alerts=0` for all three | ✅ |

### 2.4 Checksum and dataset-size claims

- "243 checksum entries with no failures" (§3.2): re-ran `sha256sum -c evidence-backup/SHA256SUMS.txt`
  independently in this phase — **243 OK, 0 failures.** Matches exactly.
- "29 successful runs" (Abstract, §3.2, Conclusion): recounted from both CSVs — **29 rows in each,
  confirmed** (5+4+5+5+5+5).
- Transformation versions (2.0.0 / 2.1.0 / 2.2.0) and validator 1.1.0 (§3.2): confirmed directly
  against `scripts/validate_results.py` (`VALIDATOR_VERSION = "1.1.0"`) and `consolidated-runs.csv`
  `transformation_version` column. Matches.

**Result: zero numerical discrepancies remain in the working draft.** The one discrepancy found in
Phase A (§4.2 C1 range) was corrected in Phase C per your confirmed instruction, and this phase
independently re-derived the same figures from the raw CSV to confirm the fix is numerically correct,
not just differently worded.

---

## 3. Citation and footnote verification status

### 3.1 Tool availability — retried again this phase

`web_search` and `web_fetch` (including the CrossRef API as an alternate host) were retried at the
start of Phase D. **All calls returned 502 errors**, consistent with every prior attempt in Phases A
and B. This is now confirmed across three separate attempts in this session as a persistent
environment-level outage, not a transient or per-URL issue. I am not able to independently verify any
DOI, RFC content, or journal metadata against a live source in this environment.

### 3.2 Footnote structural check (independent of content verification)

Re-extracted all 11 footnotes directly from the working draft's `word/footnotes.xml`:

- Sequential numbering 1–11, no gaps or duplicates.
- Shortened-note convention correctly applied: FN2 and FN10 both correctly shorten FN1 (Cooper et
  al.); FN11 correctly shortens FN3 (Nigeria Data Protection Act); FN9 correctly aggregates three
  already-cited sources (Mohammady, Fiore & Palmieri, Manocchio) using short-form author-title.
- All footnotes are genuine Word footnote objects (`w:footnoteReference` / `word/footnotes.xml`), not
  manually typed numbers in body text — confirmed again in this phase.
- **Footnote 7 year fix persisted correctly**: re-extraction confirms it now reads "Information
  Sciences 690 (2024): 121559, https://doi.org/10.1016/j.ins.2024.121559" — in-text year and DOI year
  are now consistent.

### 3.3 Outstanding citation items (unchanged from Phase B, still pending your action)

| Footnote | Issue | Status |
|---|---|---|
| FN4 (van Dijkhuizen & van der Ham) | DOI conflict: DOCX has `10.1145/3186333`; your corrected-sources list has `10.1145/3182660` | **Unresolved** — left as original DOCX value; awaiting your web verification |
| FN5 (Pan et al.) | DOI conflict: DOCX has `10.1109/JLT.2020.3005909`; your corrected-sources list has `10.1109/JLT.2020.3007491` | **Unresolved** — left as original DOCX value; awaiting your web verification |
| Literature Review sentences 3.4, 3.6, 3.9 (per `CLAIM_AND_CITATION_AUDIT.md` §3) | Specific factual claims attributed to Pan et al., Mohammady et al., and the Manocchio et al. paper that could not be checked against the source text | **Unresolved** — awaiting your manual review |

No new citation issues were found in this phase beyond what Phase B already identified.

---

## 4. Research question / objectives / methods / results / conclusion alignment

| Element | Text | Alignment check |
|---|---|---|
| Research question (Introduction) | "How can network security monitoring telemetry be transformed through pseudonymisation, data minimisation and temporal aggregation to reduce exposure of identifying information while retaining selected security-monitoring observations in resource-constrained organisational environments?" | — |
| Objective 1 | Implement a repeatable four-stage pipeline | Addressed in Methodology §3.1 (C0–C3 defined, GNS3/Zeek/Suricata/Python implementation described) |
| Objective 2 | Measure byte-volume changes and validate identifier-handling across six scenarios | Addressed in Results §4.1–§4.5 |
| Objective 3 | Identify limitations and trade-offs for further evaluation | Addressed in full in §6 |
| Conclusion opening (post-Phase-C edit) | "This study asked how network security monitoring telemetry can be transformed through pseudonymisation, data minimisation and temporal aggregation to reduce the exposure of identifying information while retaining selected security-monitoring observations. The implemented PP-NSMF pipeline answers this question for the six scenarios tested..." | Directly mirrors the RQ's own phrasing before presenting supporting numbers — **confirmed aligned** |

No contradictions found between what the Introduction promises, what the Methodology implements, what
the Results report, and what the Conclusion claims. The Conclusion does not introduce any claim,
citation, or evidence not already established earlier in the paper (checked by reading the Conclusion
against the full claim audit from Phase B — every sentence in the Conclusion traces to an earlier
section).

---

## 5. Headings, punctuation, terminology, and page-layout audit

### 5.1 Heading hierarchy (checked directly in OOXML `pStyle` values, not just visual inspection)

- Title: `Heading1` style, bold, 12pt (consistent with body font size per the journal's flat
  font-size convention; distinguished by boldness and position, not size).
- Top-level sections (1–7, Abstract): `Heading2` style, bold, 12pt — **consistently applied, no
  exceptions found** across all 9 top-level headings checked.
- Subsections (2.1–2.4, 3.1–3.3, 4.1–4.5, 5.1–5.3): `Heading3` style, bold, 12pt — **consistently
  applied, no exceptions found** across all 12 subsections checked.
- One minor inconsistency: the "Keywords:" line carries no paragraph style (plain body formatting),
  while "Abstract" immediately above it uses `Heading2`. This is a cosmetic/presentational choice —
  the CFP flyer does not specify keyword formatting — and is noted but not corrected, since it is a
  defensible editorial choice rather than an error. Flagging for your preference.

### 5.2 Terminology consistency

- British spelling used consistently throughout own prose: "organisation" (16×), "minimisation"
  (23×), "pseudonymisation" (31×), "behaviour" (3×), "analyse" (2×) — zero American-spelling
  variants of these terms in the authors' own sentences.
- One instance of "Anonymization" (American spelling) appears inside the verbatim title of the
  Mohammady et al. paper ("A Multi-view Approach to Preserve Privacy and Utility in Network Trace
  Anonymization"), which is correctly quoted as published and should not be altered to match the
  surrounding British convention — **this is correct practice, not an inconsistency.**
- C0/C1/C2/C3 stage labels: 40 mentions, 100% consistent formatting, no variant forms ("Condition 1,"
  "Stage 1," etc.) found anywhere.
- S1–S6 scenario labels: 49 mentions, consistent formatting throughout.
- Percentage formatting: 26 uses of the "%" symbol, zero instances of "percent" spelled out —
  consistent.
- En-dash used consistently for numeric ranges (e.g., "85.78%–98.30%"); zero instances of a
  plain hyphen used for a numeric range.
- Oxford comma: consistently omitted in "X, Y and Z" lists (15/15 instances) — internally uniform.

### 5.3 Punctuation and formatting artefacts

- No stray dashes, double-spaces, or mixed straight/curly quotation marks found (document uses no
  direct quotations in body text at all, consistent with the instruction not to fabricate quoted
  material).
- Apostrophes are consistently straight (ASCII `'`) throughout; not mixed with curly apostrophes.
- The stray en-dash artefact identified in Phase A (§2.4) was confirmed removed and did not
  reappear.

### 5.4 Page layout / font verification (re-confirmed from OOXML, not just Phase A's reading)

- Font: Times New Roman confirmed as the only font family in all document text runs.
- Font size: 24 half-points (= 12pt) used uniformly across the entire document, including headings.
- Line spacing: `w:line="360" w:lineRule="auto"` (360/240 = 1.5) confirmed in both `styles.xml` and
  every paragraph's direct formatting in `document.xml`.
- Zip and XML integrity: `zipfile.testzip()` reports no errors; both `word/document.xml` and
  `word/footnotes.xml` parse as well-formed XML.

---

## 6. Confirmation that no source data or evidence files were modified

| File/location | Check performed | Result |
|---|---|---|
| `PP-NSMF_NDPC_manuscript.docx` (original, repo root) | SHA-256 checksum compared against the value recorded at the start of Phase C | **Identical** (`13432d6d661c27391b06d2edb07d4e22983c70c4665593f0525f14dbf5d8c617`) — confirmed untouched |
| `evidence-backup/SHA256SUMS.txt` manifest (243 entries covering all raw/transformed run evidence) | Re-ran `sha256sum -c` | **243 OK, 0 failures** — identical to Phase A and Phase B results |
| `evidence-backup/reports/aggregate-metrics-v2.csv`, `consolidated-runs.csv` | Used read-only in this phase for recomputation; no write operations performed | Unmodified |
| `scripts/*.py` | Read-only inspection only (`validate_results.py`, `transform_telemetry.py`, `metrics.py`) | Unmodified |
| All edits this session | Confined to `docs/manuscript-revision/manuscript-working-draft.docx` and its companion `.md`/`.txt` files in the revision workspace | No file outside `docs/manuscript-revision/` was written in Phases C or D |

(Note: this repository is not under git version control, so no `git status`/`git diff` was available
as a cross-check; checksum comparison was used instead, which is an equally reliable integrity check
for this purpose.)

---

## 7. Outstanding issues carried into Phase E (not resolved, by design)

These require your input and were not silently resolved, consistent with the master prompt's
instruction to flag rather than guess:

1. **FN4 DOI** (van Dijkhuizen & van der Ham) — two candidate values, unverified.
2. **FN5 DOI** (Pan et al.) — two candidate values, unverified.
3. **Literature Review claims 3.4, 3.6, 3.9** — specific factual claims about cited papers' methods
   and findings that could not be checked against source text in this environment.
4. **Bibliography / author-biography / file-naming requirements** — not specified in the two CFP
   flyer images; unknown whether NDPC requires anything beyond the manuscript file itself.
5. **Keywords line formatting** (§5.1 above) — minor, optional, cosmetic; flagged for your preference
   only, does not block submission.

None of these affect the numerical integrity, structural compliance, or word-count compliance of the
manuscript, which are all confirmed passing in this phase.

---

## 8. Summary verdict

| Check | Status |
|---|---|
| Abstract word count (250–300) | ✅ Pass (273) |
| Main text word count (3,500–4,000) | ✅ Pass (3,654) |
| Every numerical claim traced to CSV | ✅ Pass (zero discrepancies) |
| Checksum integrity (243 evidence files) | ✅ Pass (243/243 OK) |
| RQ → objectives → methods → results → conclusion alignment | ✅ Pass |
| Heading hierarchy consistency | ✅ Pass |
| Terminology/spelling/punctuation consistency | ✅ Pass (one correct verbatim-title exception, documented) |
| Font / spacing / footnote-object formatting | ✅ Pass |
| Original manuscript and evidence files unmodified | ✅ Pass |
| All citations independently verified against live sources | ❌ **Blocked** — tool outage persisted across all three phases |
| Three Literature Review claims verified against source text | ❌ **Blocked** — same tool outage |

The manuscript is ready for Phase E packaging with the five outstanding items above carried forward
as explicitly flagged limitations, not silently resolved.
