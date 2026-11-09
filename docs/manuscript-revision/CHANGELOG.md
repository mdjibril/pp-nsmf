# PP-NSMF Manuscript Revision — Change Log

All substantive edits to the manuscript are recorded here as they are made. The original
`PP-NSMF_NDPC_manuscript.docx` in the repository root is never modified; all edits are applied to
`docs/manuscript-revision/manuscript-working-draft.docx`, created as a byte-for-byte copy of the
original with only the specific paragraph/footnote runs listed below changed (verified: identical
paragraph count, valid zip/XML structure, no other text altered).

---

## Entry 1 — C1 pseudonymisation-overhead range (Methodology/Results §4.2)

**Date:** this session. **Author decision basis:** user confirmed "report both mean and per-run range."

**Problem:** The sentence "C1 byte-volume reduction was negative in every compliant run, ranging from
−0.14% to −2.28%" used scenario-mean values (S6 mean = −0.14%, S4 mean = −2.28%) while the phrase
"in every compliant run, ranging from" implied per-run extremes. The true per-run range across all 29
runs is −0.09% (S6-R5) to −2.29% (S4-R2). Identified in Phase A audit, confirmed again in Phase B
claim audit (§5.4), resolved by explicit user choice before editing.

**Before:**
> C1 byte-volume reduction was negative in every compliant run, ranging from −0.14% to −2.28%.

**After:**
> C1 byte-volume reduction was negative in every compliant run. Scenario-mean C1 reduction ranged
> from −0.14% (S6) to −2.28% (S4); across all 29 individual runs, per-run values ranged from −0.09%
> to −2.29%.

**Evidence basis:** recomputed directly from `evidence-backup/reports/aggregate-metrics-v2.csv`,
column `suricata_c1_reduction_pct`, all 29 rows. Scenario means cross-checked against
`docs/manuscript-results-package.md` Table 2b.

**Net word-count effect:** +17 words to the main text (3,884 → 3,901 total document words). Still
within the 3,500–4,000 main-text requirement.

---

## Entry 2 — Footnote 7 year self-contradiction

**Date:** this session. **Author decision basis:** flagged in Phase B as safe to fix regardless of
web-verification status, since it resolves a contradiction already present in the current manuscript
(the in-text year did not match the year embedded in its own DOI string).

**Before:** `Information Sciences 690 (2025): 121559, https://doi.org/10.1016/j.ins.2024.121559.`

**After:** `Information Sciences 690 (2024): 121559, https://doi.org/10.1016/j.ins.2024.121559.`

**Status:** This fixes only the internal (2025-vs-2024) inconsistency. It does **not** constitute
independent verification of the Fiore & Palmieri citation's accuracy — `web_search`/`web_fetch` remain
unavailable (502 errors reconfirmed in Phase B). The DOI string itself is unchanged and still
unverified against CrossRef/publisher records.

**Not yet applied (awaiting user confirmation per Phase B §8–9):**
- Footnote 4 (van Dijkhuizen & van der Ham) DOI conflict: DOCX has `10.1145/3186333`; a user-supplied
  "corrected sources" list has `10.1145/3182660`. Left unchanged pending verification.
- Footnote 5 (Pan et al.) DOI conflict: DOCX has `10.1109/JLT.2020.3005909`; user-supplied list has
  `10.1109/JLT.2020.3007491`. Left unchanged pending verification.

---

## Entry 3 — Stray en-dash artefact (§2.4, Research Gap and Contribution)

**Date:** this session.

**Before:** "...configurable privacy–utility trade-offs.**–** These contributions provide important
foundations..." (a stray en-dash directly between two sentences, with no grammatical function).

**After:** "...configurable privacy–utility trade-offs. These contributions provide important
foundations..."

**Evidence basis:** identified as a formatting artefact in Phase A (§5 of `REVISION_PLAN.md`); no
content was removed, only the stray character.

---

## Entry 4 — Introduction opening sentence (generic "important component" framing)

**Date:** this session (Phase C).

**Problem:** The Introduction opened with "Network security monitoring is an important component
of organisational cybersecurity," an empty importance-statement the style guidance explicitly asks
to avoid (it asserts significance without evidence rather than stating what the records actually do).

**Before:**
> Network security monitoring is an important component of organisational cybersecurity. Network
> logs and traffic-analysis records can help administrators identify suspicious connections,
> investigate incidents, understand protocol behaviour and reconstruct events. However, the same
> records may contain source and destination IP addresses, hostnames, queried domains, timestamps,
> connection identifiers and other information that permits activities to be linked across time.

**After:**
> Network logs and traffic-analysis records allow administrators to identify suspicious connections,
> investigate incidents, understand protocol behaviour and reconstruct events. The same records may
> also contain source and destination IP addresses, hostnames, queried domains, timestamps,
> connection identifiers and other information that permits activities to be linked across time.

**Rationale:** removes the unsupported importance claim; opens directly on the concrete capability
and the concrete privacy exposure, which is what the paragraph is actually about. No factual content
was added or removed, only the framing sentence.

---

## Entry 5 — Limitations: added missing S3/S5/S6 no-alert-rule point

**Date:** this session (Phase C).

**Problem:** The master prompt's required Limitations content explicitly lists "No alert rules for
S3, S5 and S6, so their flow observations are not detection-performance results" as a limitation that
must be retained. This fact was present in Results §4.5 but was not restated in the Limitations
section itself, where a reader scanning limitations specifically would expect to find it.

**Before:**
> ...The S4 alert result is limited to configured rule firing on known HTTP-401 responses.

**After:**
> ...The S4 alert result is limited to configured rule firing on known HTTP-401 responses. S3, S5
> and S6 had no alert rules configured, so their flow observations are not detection-performance
> results and should not be read as evidence of absent threats.

**Evidence basis:** `docs/manuscript-results-package.md` Table 6; `experiments/scenarios.yaml`
(S3/S5/S6 have no `suricata_rules` field, unlike S4).

---

## Entry 6 — Conclusion: answer the research question before restating headline numbers

**Date:** this session (Phase C).

**Problem:** The master prompt requires the Conclusion to "answer the research question directly"
before summarising numerical findings. The existing Conclusion opened directly with "This study
presented and experimentally evaluated PP-NSMF..." followed immediately by the C2/C3 percentages,
without first stating, in plain terms, what the answer to the stated research question actually is.

**Before:**
> This study presented and experimentally evaluated PP-NSMF, a framework that applies
> pseudonymisation, data minimisation and temporal aggregation to network security telemetry.
> Across 29 compliant runs from six synthetic traffic scenarios, the corrected source-matched
> Suricata results showed C2 byte-volume reductions of 85.78%–98.30% and C3 reductions of
> 98.47%–99.23%. Pseudonymisation alone increased byte volume in every run, demonstrating that
> identifier protection and storage reduction are different objectives.

**After:**
> This study asked how network security monitoring telemetry can be transformed through
> pseudonymisation, data minimisation and temporal aggregation to reduce the exposure of identifying
> information while retaining selected security-monitoring observations. The implemented PP-NSMF
> pipeline answers this question for the six scenarios tested: staged transformation substantially
> reduced telemetry byte volume at C2 and C3, while pseudonymisation alone did not. Across 29
> compliant runs from six synthetic traffic scenarios, the corrected source-matched Suricata results
> showed C2 byte-volume reductions of 85.78%–98.30% and C3 reductions of 98.47%–99.23%.
> Pseudonymisation alone increased byte volume in every run, demonstrating that identifier protection
> and storage reduction are different objectives.

**Rationale:** adds a direct, plain-language answer to the stated research question as the opening
move of the Conclusion, before the numbers that support it. No new evidence, citations, or claims
were introduced — this only restates, in answer form, points already established in the Introduction
and Results.

**Net word-count effect of Entries 4–6:** +54 words to the main text (3,901 → 3,955 total document
words; main text alone 3,600 → 3,654). Still within the 3,500–4,000 main-text requirement, with
approximately 346 words of headroom remaining.

---

## Phase C verification performed

- Checked the full working draft for generic transitions, unqualified absolutes ("proves,"
  "ensures," "guarantees," "anonymous," "fully compliant"), and "all/every Nigerian organisations"
  overclaims: **zero matches**, confirming the manuscript's existing hedged style meets the required
  standard and needed no further correction on this front.
- Compared every Results paragraph against every Discussion paragraph for textual similarity
  (sequence-matching ratio): **no pair exceeded 0.35 similarity**, confirming Discussion interprets
  rather than repeats Results.
- Scanned for vague "importance" filler sentences elsewhere in the document: one match, assessed as
  a specific, evidence-grounded claim (not filler) and left unchanged.
- Checked repeated paragraph-openers across the document: all repeats are natural restatements in
  structurally distinct sections (Abstract vs. Introduction vs. Limitations vs. Conclusion), not
  formulaic repetition within a section.
- Re-ran zip integrity (`testzip`) and XML well-formedness checks on `word/document.xml` and
  `word/footnotes.xml` after all Phase C edits: both pass. Paragraph count unchanged (86). Footnote
  element count unchanged (13, including the two structural separator entries).
- Re-confirmed `PP-NSMF_NDPC_manuscript.docx` checksum is identical to its Phase A/B value,
  confirming it remains untouched.
- Final word counts: Abstract 273 (requirement 250–300, compliant); main text 3,654 (requirement
  3,500–4,000, compliant).

---

## Pending decisions (not yet actioned)

- Footnote 4 / Footnote 5 DOI conflicts (Entry 2, above) — awaiting user web-verification.
- Literature Review claims 3.4, 3.6, 3.9 (per `CLAIM_AND_CITATION_AUDIT.md` §3) — awaiting user's
  manual review against source papers.
- Bibliography / author-biography / file-naming requirements beyond the CFP flyer — unresolved, not
  blocking current edits.

## Verification performed after this batch of edits

- `zipfile.testzip()` on the working draft: no errors.
- `word/document.xml` and `word/footnotes.xml` both re-parse as well-formed XML.
- Paragraph count unchanged (86), confirming no paragraph was accidentally split, merged, or deleted.
- Total document word count: 3,901 (was 3,884). Abstract word count unaffected (edits were in §2.4 and
  §4.2 of the main body, not the abstract).
- The three target strings were each matched **exactly once** (enforced via Python `assert`) before
  replacement, so no unintended duplicate text elsewhere in the document was altered.
- Original `PP-NSMF_NDPC_manuscript.docx` re-read after edits and confirmed byte-identical to its
  pre-edit state (untouched).

---

## Phase D — Final QA (no prose edits)

Phase D was a verification-only pass; no manuscript text was changed. Full findings are in
`FINAL_QA_REPORT.md`. Summary: every numerical claim in the working draft was independently
recomputed from `aggregate-metrics-v2.csv` and `consolidated-runs.csv` with zero discrepancies;
word counts reconfirmed compliant (abstract 273, main text 3,654); checksum audit re-run (243/243
OK); heading hierarchy, terminology, punctuation and footnote structure all confirmed consistent;
original manuscript reconfirmed untouched. Web-based citation verification remained blocked by a
persistent tool outage (502 errors), reconfirmed for a third time in this phase.

---

## Phase E — Packaging

**Date:** this session.

`docs/manuscript-revision/manuscript-working-draft.docx` (the file edited and verified across
Phases C and D) was copied, unmodified, to `docs/manuscript-revision/final_manuscript.docx` as the
packaged deliverable. No further prose changes were made during packaging. Verified after copying:

- SHA-256 of `final_manuscript.docx` is identical to `manuscript-working-draft.docx`
  (`3bd3f0910a8d11695fa77dd665e5c6198eb843348f32f759b82579b8afe26b08`), confirming an exact copy.
- Zip integrity check (`testzip`) passes; all required OOXML parts present
  (`[Content_Types].xml`, `_rels/.rels`, `word/document.xml`, `word/footnotes.xml`, `word/styles.xml`).
- Paragraph count (86) and footnote element count (13) unchanged from the Phase D-verified state.
- `PP-NSMF_NDPC_manuscript.docx` (original, repository root) reconfirmed byte-identical to its
  Phase A checksum (`13432d6d661c27391b06d2edb07d4e22983c70c4665593f0525f14dbf5d8c617`) — still
  untouched.

### Outstanding items carried forward into the delivered package (not resolved by this revision)

These remain exactly as left in Phases B–D, per the master prompt's instruction to flag rather than
guess when verification is not possible:

1. Footnote 4 DOI (van Dijkhuizen & van der Ham) — two candidate values exist; unverified against a
   live source. Current `final_manuscript.docx` retains the original DOCX's value
   (`10.1145/3186333`) unchanged.
2. Footnote 5 DOI (Pan et al.) — two candidate values exist; unverified. Current
   `final_manuscript.docx` retains the original DOCX's value (`10.1109/JLT.2020.3005909`) unchanged.
3. Literature Review sentences 3.4, 3.6, 3.9 — specific factual claims about cited sources that
   could not be checked against source text in this environment; unchanged from the original.
4. Bibliography, author-biography, and file-naming-convention requirements — not specified in the
   two CFP flyer images provided; status unknown, not addressed in this package.
5. "Keywords:" paragraph formatting (no bold/heading style, unlike "Abstract" above it) — cosmetic,
   optional, left as the original author's formatting choice.

None of these five items affect the word-count compliance, numerical accuracy, or structural
integrity of the delivered manuscript, all of which were independently verified in Phase D.
