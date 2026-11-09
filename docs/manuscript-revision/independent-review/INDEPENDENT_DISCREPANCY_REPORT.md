# Independent Final Review — Discrepancy Report

**Subject:** `docs/manuscript-revision/final_manuscript.docx`
**Compared against:** `PP-NSMF_NDPC_manuscript.docx` (original), `evidence-backup/reports/aggregate-metrics-v2.csv`,
`evidence-backup/reports/consolidated-runs.csv`, `evidence-backup/protocol/experiment-run-log.csv`,
`evidence-backup/SHA256SUMS.txt`, `scripts/*.py`, `experiments/scenarios.yaml`, `corrected sources.txt`, the two NDPC
CFP flyer images.

**Method note:** This review was conducted independently of the Phase A–E work recorded in
`REVISION_PLAN.md`, `CLAIM_AND_CITATION_AUDIT.md`, `FINAL_QA_REPORT.md` and `CHANGELOG.md`. Rather than
reading those documents' conclusions and confirming them, I re-extracted the manuscript text directly
from the OOXML, re-diffed it paragraph-by-paragraph against the original DOCX, and recomputed every
number from the raw CSVs and footnote XML from scratch in this session. Where my own prior-phase
conclusions are referenced below for context, they were independently re-derived, not assumed correct.
One finding below (Item 2) contradicts an explicit "Verified"/"correctly worded" judgment made in my own
earlier `CLAIM_AND_CITATION_AUDIT.md` (§5.4) and `FINAL_QA_REPORT.md` — flagged accordingly.

Automated checks (word counts, checksum verification, numeric recomputation, XML structure checks) are
reported as what they are: mechanical verifications of specific, falsifiable facts. No automated tool used
in this review establishes, and this report does not claim, that the manuscript is free of plagiarism, that
any part of it was or was not written using generative AI, or that it complies with the Nigeria Data
Protection Act or any other regulatory regime. Those are determinations outside the scope of what a text
diff, a checksum, or a CSV comparison can establish.

---

## 1. Numerical claims vs experimental evidence

Every numerical claim in the manuscript was traced to `aggregate-metrics-v2.csv`, `consolidated-runs.csv`,
or `experiment-run-log.csv` and recomputed independently in this session (not copied from prior reports).

| Claim (location) | Manuscript value | Recomputed value | Label |
|---|---|---|---|
| C2 scenario means, all six scenarios (§4.1, para 53) | 95.46 / 85.78 / 95.26 / 87.78 / 96.34 / 98.30 | Identical, recomputed from `suricata_c2_reduction_pct` | **Verified** |
| C3 scenario means, all six scenarios (§4.1, para 53) | 99.23 / 98.94 / 98.95 / 98.88 / 99.18 / 98.47 | Identical, recomputed from `suricata_c3_reduction_pct` | **Verified** |
| C1 scenario-mean range "−0.14% (S6) to −2.28% (S4)" and per-run range "−0.09% to −2.29%" (§4.2, para 57) | As stated | Recomputed across all 29 rows: scenario means match exactly; true per-run min/max = −0.09 / −2.29, matches exactly | **Verified** |
| Record counts C0→C2 per scenario (§4.3, para 60) | 17→5 (S1), 17.25→12 (S2), 7→5 (S3), 22→15 (S4), 6.2→4 (S5), 2.4→1 (S6) | Identical, recomputed from `consolidated-runs.csv` | **Verified** |
| One C3 window per run, all 29 runs (§4.3) | "Each compliant run produced one C3 aggregation window" | `c3_windows` column = `1` for all 29 rows, confirmed | **Verified** |
| Observed-event counts per scenario (§4.5, para 67) | S1 5/5, S2 6/12, S3 5/5, S4 5/5, S5 4/4, S6 1×65,536 bytes | Identical, recomputed from `consolidated-runs.csv` | **Verified** |
| S4 = 5 alerts/run from configured rule; S3/S5/S6 = 0 alerts, no rule (§4.5, para 68) | As stated | `alerts` column: S4=5 for all 5 rows; S3/S5/S6=0 for all rows; `scenarios.yaml` shows `suricata_rules` set only for S4 | **Verified** |
| 243 checksum entries, no failures (§3.2, para 44) | As stated | Re-ran `sha256sum -c evidence-backup/SHA256SUMS.txt` fresh in this session: 243 OK, 0 failures | **Verified** |
| 29 compliant runs total (Abstract, §3.2, Conclusion) | As stated | Recounted from three independent sources: `aggregate-metrics-v2.csv` (29 rows), `consolidated-runs.csv` (29 rows), `experiment-run-log.csv` (29 `COMPLETED`/no-FAILED-duplicate rows after excluding the one FAILED S4/R1 first attempt) | **Verified** |
| Single HMAC key ID across all compliant runs (§3.2, para 44) | As stated | `hmac_key_id` column: single unique value `e04d6b0475fd` across all 29 rows | **Verified** |
| Transformation versions 2.0.0 (S1, compliant S2) / 2.1.0 (S3) / 2.2.0 (S4–S6); validator 1.1.0 | As stated | Confirmed exactly from `transformation_version`/`validator_version` columns, grouped by scenario | **Verified** |
| Pseudonym token length vs IPv4 (§4.2, para 57–58) | "HMAC-derived pseudonym tokens were longer than the original IPv4 addresses" | `scripts/transform_telemetry.py` `token()`: `"h_" + digest[:16]` = 18 characters; max IPv4 literal = 15 characters. Confirmed from source code directly | **Verified** |
| Reduction formula and baseline file (§3.3, para 46–48) | `100 × (1 − Transformed/Raw)`, denominator = raw `suricata/eve.json` | Exact match to `scripts/metrics.py` `_reduction_pct()` and `compute_source_metrics()` | **Verified** |
| Zeek and Suricata never combined into one percentage (§3.1, para 34) | As stated | Confirmed from `scripts/generate_metrics_csv.py`: Suricata and Zeek metrics computed via fully separate code paths; only `legacy_combined_*` columns mix them, and those are explicitly excluded from the manuscript's reported figures | **Verified** |

### 1.1 — MAJOR: Abstract and Conclusion state the C2/C3 range without the "scenario-mean" qualifier that Results §4.1 uses

**Location:** Abstract (para 2): *"Source-matched Suricata byte-volume reductions at C2 ranged from
85.78% to 98.30% across scenarios, while C3 reductions ranged from 98.47% to 99.23%."* Conclusion (para
84): *"the corrected source-matched Suricata results showed C2 byte-volume reductions of 85.78%–98.30%
and C3 reductions of 98.47%–99.23%."*

**Problem:** These figures are the range of the six **scenario means** (confirmed against §4.1, para 53,
which explicitly says "**Mean** C2 reduction was 95.46% for S1..."). However, the Abstract and Conclusion
state them as a bare range without the word "mean" or "scenario" doing the same disambiguating work that
§4.1 does. The Conclusion sentence even places this figure immediately after "across 29 compliant runs,"
which invites the reader to interpret 85.78%–98.30% as the range observed *across all 29 runs*, not across
six scenario means.

I recomputed the **true per-run range across all 29 individual rows**, independent of the six scenario
means:

- True per-run C2 range: **85.69%** (S2-R2) to **98.91%** (S6-R4) — wider than the stated 85.78–98.30.
- True per-run C3 range: **98.11%** (S6-R1) to **99.39%** (S5-R1) — wider than the stated 98.47–99.23.

This is the same category of ambiguity that was already identified and fixed for the C1 figure in §4.2
(scenario-mean vs. per-run range), but the fix was not extended to the C2/C3 figures carried in the
Abstract and Conclusion. My own prior-phase documents (`CLAIM_AND_CITATION_AUDIT.md` §7.7,
`FINAL_QA_REPORT.md` §2.1) explicitly characterised the Conclusion's C2/C3 wording as "correctly worded...
across scenario means" and treated it as resolved. On this independent re-examination, I do not think that
conclusion was adequately scrutinised: the sentence is numerically correct (the scenario means are exactly
85.78–98.30 and 98.47–99.23) but is **ambiguously worded** in a way that a careful reader could reasonably
misread as a per-run range, which is exactly the failure mode the master prompt's "preserve distinctions
between per-run values and scenario means" instruction warns against.

**Recommendation (not yet applied):** Add "scenario-mean" (or equivalent) before the C2/C3 figures in the
Abstract and Conclusion, matching the disambiguation already used for C1 in §4.2, e.g.: *"Source-matched
Suricata scenario-mean byte-volume reductions at C2 ranged from 85.78% to 98.30%..."* This is a wording
clarification only; no numeric value needs to change.

**Label: Major.** The underlying numbers are accurate and traceable (no fabrication), but the phrasing
creates a genuine risk of the reader inferring a narrower per-run range than the data actually show,
which is a substantive precision issue the journal's "scholarly rigour" requirement is intended to catch.

### 1.2 — Minor/Verified: S2 scenario traffic count (6 DNS queries) vs. the scenario configuration file

**Location:** Abstract, §3.2 (para 43), §4.5 (para 67).

`experiments/scenarios.yaml` (S2 definition) specifies `queries: 3` (three A-record queries). The
manuscript, the CSVs, and the per-run evidence reports (`S2-summary.md`, `S2-R2.md` through `S2-R5.md`)
all consistently state **6** queries (three A + three AAAA). I traced this to the actual run evidence
(`S2-summary.md`: "R2–R5 are consistent: 6 DNS queries (3 A + 3 AAAA)") — the executed traffic generator
evidently issued both record types per cycle, doubling the count relative to the scenario config file's
stated plan.

**Assessment:** The manuscript accurately reports what was actually observed and measured (6 queries),
which is the correct evidentiary standard — it should describe what happened, not what was originally
planned in a config file. This is not a manuscript error. It is noted here only because an independent
reviewer encountering `scenarios.yaml` in isolation could flag an apparent conflict; the resolution is that
the config file reflects the original experiment design and the manuscript/evidence reports reflect actual
execution. **Label: Verified** (manuscript is correct; config-file/evidence drift is a pre-existing
documentation quirk outside the manuscript itself, not a manuscript defect).

---

## 2. New or altered claims not supported by the original research

The final manuscript differs from the original `PP-NSMF_NDPC_manuscript.docx` in exactly **5 paragraphs**
and **1 footnote** (confirmed by a full paragraph-indexed diff across all 86 paragraphs and all 13
footnote entries — no other text differs). Each is assessed below for whether it introduces any claim,
number, or citation not already present in and supported by the original manuscript/evidence.

| # | Location | Nature of change | New claim introduced? |
|---|---|---|---|
| 1 | Para 8 (Introduction opening) | Removed an unsupported generic "is an important component" framing sentence; no new factual content added | No — pure deletion/rephrasing of framing, zero new facts |
| 2 | Para 29 (§2.4) | Removed a stray en-dash character between two sentences | No — punctuation-only |
| 3 | Para 57 (§4.2) | Added the true per-run C1 range (−0.09% to −2.29%) alongside the existing scenario-mean range | **New number added**, but independently verified in §1 above as numerically exact against the CSV — supported, not fabricated |
| 4 | Para 81 (§6 Limitations) | Added one sentence: "S3, S5 and S6 had no alert rules configured, so their flow observations are not detection-performance results and should not be read as evidence of absent threats." | **New sentence**, but it restates a fact already established and supported in §4.5 (para 68) of the same manuscript — not a new, independent claim, just a required cross-reference |
| 5 | Para 84 (Conclusion opening) | Added two new sentences restating the research question and stating that the pipeline "answers this question for the six scenarios tested" | **New framing language**, but every factual element in it (pseudonymisation vs. minimisation/aggregation effects) is already established in §4.1–4.2 and §5.1 of the same manuscript — no new evidence or citation introduced |
| 6 | Footnote 7 | Year changed from "2025" to "2024" | Corrects an internal self-contradiction (text year vs. DOI year); does not introduce a new unverified claim — the DOI string itself (which contains "2024") is unchanged | 

**Finding: no fabricated evidence, invented data, new citations, or unsupported empirical claims were
introduced in any of the six changes.** All additions either (a) restate facts already present and
sourced elsewhere in the same document, or (b) add numbers directly and exactly traceable to the CSV.
**Label: Verified** for all six changes as a set.

---

## 3. Citations — missing, inaccurate, unverifiable, or unrelated

### 3.1 Footnote-by-footnote conflict check against `corrected sources.txt`

Re-diffed all 11 footnotes against the file you provided, character-by-character (not relying on the
Phase B/D summary). Confirmed:

| Footnote | Status | Label |
|---|---|---|
| FN1 (RFC 6973) | Identical in both versions | **Verified** |
| FN2 (RFC 6973 shortened) | Identical | **Verified** |
| FN3 (NDPA 2023) | Identical | **Verified** |
| FN4 (van Dijkhuizen & van der Ham) | **DOI conflict**: current manuscript has `10.1145/3186333`; your corrected-sources list has `10.1145/3182660`. Everything else (authors, title, journal, volume, issue, year, article number) is identical between both versions | **Critical — unresolved** |
| FN5 (Pan et al.) | **DOI conflict**: current manuscript has `10.1109/JLT.2020.3005909`; your corrected-sources list has `10.1109/JLT.2020.3007491`. Everything else identical | **Critical — unresolved** |
| FN6 (Mohammady et al.) | Identical (DOI `10.1145/3439732` unchanged in both versions) | **Verified** |
| FN7 (Fiore & Palmieri) | Identical after the Phase C year fix (both now read "2024", matching the DOI's own year) | **Verified** |
| FN8 (Manocchio et al.) | Identical (DOI `10.1016/j.compeleceng.2024.109465` unchanged in both versions) | **Verified** |
| FN9 (combined short-form citation) | Identical | **Verified** |
| FN10 (RFC 6973 shortened, §6–7) | Identical | **Verified** |
| FN11 (NDPA 2023 shortened) | Identical | **Verified** |

**I attempted to re-verify FN4 and FN5 against a live source in this session** (`web_search`, `web_fetch`
against `doi.org`, and `api.crossref.org` as an alternate host). All attempts returned 502 errors,
consistent with every prior attempt across Phases A, B, and D. This is a persistent tool-level outage in
this environment, not a one-off failure, and I cannot independently confirm either DOI's correctness.
**I am not asserting that either version is correct** — both remain unverified by me. The manuscript
currently retains its original DOI values for FN4/FN5 (the "corrected sources.txt" values were never
applied), which is the conservative choice pending verification, but "conservative" here means "not yet
contradicted," not "confirmed accurate."

**Label: Critical** for FN4 and FN5 — these cannot be confirmed as accurate, and an incorrect DOI
attached to a real, correctly-titled paper is a reportable citation-accuracy defect regardless of which
version is ultimately correct. This must be resolved (by you, with database/publisher access, or once web
tools recover) before submission, since the CFP flyer requires that "all sources, quotations and citations
are appropriately acknowledged" and inaccurate identifiers undermine that.

### 3.2 Specific factual claims attributed to sources (content, not just identifier, accuracy)

Three sentences in the Literature Review make specific, falsifiable claims about what a cited paper found
or did, beyond just citing its existence:

| # | Location | Claim | Verification status |
|---|---|---|---|
| 1 | Para 17 (§2.1, FN5) | "They proposed a privacy-preserving system using homomorphic encryption, compression, integrity verification and anomaly analysis over encrypted telemetry, and evaluated the implementation in an IP-over-elastic-optical-network testbed." | **Unverifiable in this session** — web tools unavailable; this is a specific, technical, falsifiable description that I cannot confirm against the source text itself |
| 2 | Para 20 (§2.2, FN6) | "They observed that conventional approaches, including prefix-preserving IP address pseudonymisation, may remain vulnerable to adversaries with prior knowledge of network flows or may require sanitisation that reduces analytical utility... Experiments using real network traces showed lower information leakage than the comparison approach while maintaining comparable utility." | **Unverifiable in this session** — same limitation |
| 3 | Para 25 (§2.3, FN8) | "A 2024 study in Computers & Electrical Engineering proposed a configurable approach that permits different anonymity levels for different traffic classes and examines the trade-off between privacy preservation and the utility of data used by machine-learning-based network intrusion-detection systems." | **Unverifiable in this session** — same limitation |

**Label: Major, unresolved** for all three. These are not citation-identifier problems (the DOIs for FN6
and FN8 are unconflicted) — they are claims about *paper content* that only the paper's actual text can
confirm or refute. Given that the master prompt explicitly prohibits manufacturing "quotations, findings,
page numbers, publication details" and requires flagging anything unverifiable rather than guessing, these
three sentences should be checked against the source papers (by you, or by me once web access is restored)
before submission. I am not asserting these are wrong — only that I have not been able to confirm they are
right, and specificity of this kind carries real misattribution risk if unconfirmed.

### 3.3 Citations unrelated to their attached claim

I checked whether any footnote is attached to a claim it does not plausibly support (e.g., a citation to
RFC 6973 attached to a claim about Nigerian law). Reviewed all 11 footnote anchor points directly in the
OOXML (see Section 7 below for method): **all 11 footnotes are anchored to sentences that are topically
and substantively consistent with what each source is cited for** (RFC 6973 citations attach to
general privacy-engineering/correlation claims; NDPA 2023 citations attach to Nigerian statutory-context
claims; each named-author footnote attaches to a sentence specifically discussing that author's work).
**Label: Verified.**

---

## 4. Remaining textual overlap requiring contextual review

I ran an independent similarity scan (not reusing the Phase C script, rewritten fresh this session):

- **Results vs. Discussion, paragraph-by-paragraph:** maximum similarity ratio found was 0.417, between
  two section **headings** ("4.3 Record counts and aggregation" vs. "5.3 Relevance to Nigerian
  organisations") rather than body content — a false positive caused by shared short heading vocabulary,
  not real duplication. Body-paragraph-to-body-paragraph similarity is materially lower throughout.
- **Abstract vs. Conclusion:** similarity ratio 0.144 — low; the Conclusion does not read as a copy-paste
  of the Abstract (confirmed by direct reading: the Conclusion adds the direct research-question answer
  the Abstract does not contain, and omits abstract-only content like the word "practical challenge").
- **Exact-match sentence duplication (8+ words) anywhere in the document:** zero instances found.

**Label: Verified — no textual overlap found that requires contextual review or deletion.** The repeated
phrases that do exist across sections (e.g., "pseudonymisation, data minimisation and temporal
aggregation" appearing in the Abstract, Introduction, and Conclusion) are short technical-term phrases
naming the method under study, not substantive sentence-level repetition, and should not be
mechanically deleted — removing them would harm clarity, not similarity scores, since they name the
object of study and recur appropriately across any paper's Abstract/Intro/Conclusion.

---

## 5. Abstract and main-text word counts

Recomputed independently in this session using a freshly written counting script (not the Phase D script):

| Element | Count | Requirement | Label |
|---|---|---|---|
| Abstract (para 2 only) | 273 words | 250–300 | **Verified** |
| Main text (Introduction §1 through Conclusion §7, paras 7–85) | 3,654 words | 3,500–4,000 | **Verified** |

Both figures match the Phase D report exactly, now independently re-derived with a different script,
which is a meaningful cross-check (agreement between two independently written counting methods).

---

## 6. Compliance with stated NDPC formatting requirements

Re-read both CFP flyer images directly in this session (not from memory of Phase A). Checked each stated
requirement against the OOXML directly:

| Requirement (from flyer) | Manuscript status | Label |
|---|---|---|
| Original, unpublished, not under consideration elsewhere | Cannot be verified by file inspection — this is a factual assertion about the author's submission history, not something a document audit can confirm | **Not verifiable by this review** |
| Abstract 250–300 words | 273 words | **Verified** |
| Main text 3,500–4,000 words, excluding abstract/footnotes | 3,654 words | **Verified** |
| "Appropriate research methodology and scholarly rigour, where applicable" | Methodology section names tools, versions, exclusion criteria, and formula; independently verified against code in Section 1 above | **Verified** |
| "References must be presented using Chicago Style footnotes **only**" | All 11 references are genuine Word footnote objects (confirmed via `word/footnoteReference` + `word/footnotes.xml`, not manually typed numbers); no separate bibliography/reference list section found anywhere in the 86 paragraphs (confirmed by text search for "bibliography," "reference list," "works cited" — zero matches) | **Verified** |
| Times New Roman, 12-point font | Confirmed directly from OOXML: `Times New Roman` is the only font family in every run across `document.xml` and `footnotes.xml`; font size is uniformly `24` half-points (= 12pt) | **Verified** |
| 1.5 line spacing | Confirmed directly from OOXML: `w:line="360" w:lineRule="auto"` throughout (360/240 = 1.5) | **Verified** |
| Manuscript type: falls under "Research articles / Empirical studies" | The paper is an implemented-and-evaluated experimental study; this classification is reasonable | **Verified (reasonable classification)** |
| Language: English | Confirmed | **Verified** |
| "Well-written, properly edited and professionally presented" | Subjective; addressed throughout Phases C/D and this review's style checks; no major prose defects found in this pass | **Verified (to the extent checkable)** |
| "All sources, quotations and citations are appropriately acknowledged" | No direct quotations appear anywhere in body text (confirmed: zero curly or straight quotation-mark pairs in body text in Section 7 below), so no quotation-attribution risk exists; all named-author claims carry a footnote — but see Section 3.2 above for the content-accuracy caveat on three of those footnotes | **Major caveat — see §3.2** |
| "Clearly state the research question, methodology, findings and conclusions" | Confirmed present and aligned (see Section 7 below) | **Verified** |

**Unresolved / not addressed by the flyer alone:**

- The flyer does not state whether a separate bibliography is required, forbidden, or optional in
  addition to Chicago footnotes. The phrase "Chicago Style footnotes **only**" is the strongest signal
  available, and I am reading it as "do not also provide a separate bibliography," which is consistent
  with the manuscript's current state (footnotes only, no bibliography). This interpretation is
  reasonable but not explicitly confirmed by the flyer text, which never uses the word "bibliography."
  **Label: Minor — interpretation risk, not a defect**, since the current document already follows the
  more literal reading of the stated rule.
- No author-biography, declaration-of-originality, or conflict-of-interest section appears in the
  manuscript. The flyer does not explicitly require one in the submission file itself (it only states the
  originality requirement as a condition, with the subject-line and email instructions suggesting
  originality may be asserted through the submission process rather than embedded text). **Label: Minor —
  unresolved, flag for the author to confirm against any fuller submission portal instructions not
  visible in the two flyer images.**
- File-naming convention: the flyer specifies only the **email subject line** format ("Submission - Third
  Edition NDPC International Journal of Data Privacy & Protection"), not a file-naming convention for the
  attachment itself. **Label: Minor — no manuscript defect, but the final file name should be confirmed
  against the subject-line convention before sending.**

---

## 7. Research question / objectives / methodology / results / discussion / conclusion consistency

Checked for internal contradiction across the full logical chain, re-reading each section fresh.

| Check | Finding | Label |
|---|---|---|
| RQ (Introduction, para 12) vs. Conclusion opening (para 84) | Conclusion's added opening sentence restates the RQ nearly verbatim before answering it; no drift in wording or scope | **Verified** |
| Three stated objectives (para 13) vs. actual Methodology/Results content | Objective 1 (repeatable pipeline) → §3.1; Objective 2 (byte-volume + identifier validation across 6 scenarios) → §4.1–4.4; Objective 3 (limitations/trade-offs) → §6. All three are addressed, none orphaned | **Verified** |
| Claimed contribution ("auditable proof of concept," not a cryptographic primitive, not comprehensive privacy, not a compliance framework, not a general IDS) vs. actual claims made throughout | Checked every section for violation of this boundary: Discussion §5.2 explicitly states investigation utility is unmeasured; §5.3 explicitly states no legal analysis was performed; §4.4 explicitly states validation does not prove anonymity; §4.5/§6 explicitly state no general detection-effectiveness claim is made. No section crosses the stated boundary | **Verified** |
| Methodology's defined terms (C0–C3, byte-volume reduction formula) used consistently in Results/Discussion/Conclusion | All instances of "C1," "C2," "C3," and "reduction" checked for consistent meaning across sections — no redefinition or drift found | **Verified** |
| Discussion claims vs. Results evidence | Spot-checked each Discussion subsection's claims against the specific Results paragraphs they interpret (e.g., §5.1's "pseudonymisation changed representation but increased byte volume" directly traces to §4.2's findings) — no Discussion claim introduces evidence absent from Results | **Verified** |
| Limitations list vs. what Results/Discussion actually measured | Cross-checked the Limitations bullets (synthetic workloads; 29 runs with 4 for DNS; validator scope; no investigation-utility measurement; no labelled-ground-truth detection evaluation; S4 alert scope; S3/S5/S6 no-alert-rule caveat; Zeek exclusion) against Methodology/Results — all eight limitations are factually grounded, none overstate or understate what was actually done | **Verified** |
| The Major finding in Section 1.1 above (Abstract/Conclusion C2/C3 wording) | This is the one place where a figure is not mislabeled in substance but is ambiguously worded relative to its own Results section — already logged above, not duplicated here | Cross-referenced |

**No new internal contradictions found beyond the Section 1.1 wording issue.**

---

## 8. Disclosures and declarations requiring policy verification

| Item | Status |
|---|---|
| Statement of originality / not under consideration elsewhere | Required by the flyer as a condition of submission; not a text block found inside the manuscript body. Typically asserted via cover letter or submission-portal checkbox rather than in-manuscript text — but the flyer images provided do not show a submission portal, only an email address, so I cannot confirm what form this declaration should take. **Flag for author verification.** |
| Author identity / affiliation | No author name, institutional affiliation, or contact details appear anywhere in the manuscript body or document properties (`docProps/core.xml` is absent from the DOCX package entirely). This is consistent with a blind/anonymised peer-review process, which the flyer's description of an "editorial assessment" and "peer-review process" suggests but does not explicitly mandate as blind. **Flag for author verification** — confirm whether NDPC expects author details on a separate cover sheet, in the email body, or omitted entirely from the manuscript file as currently done. |
| Generative-AI-assistance disclosure | The flyer images provided do not mention AI-assistance disclosure policy at all. I am not able to determine NDPC's position on this from the available source material. **This review does not assert that the manuscript was or was not written with AI assistance**, and no such claim should be made in any submission correspondence without the author's direct knowledge of how the manuscript was produced. **Flag — policy unknown, unresolved by available sources.** |
| Data/evidence availability statement | The flyer does not mention a data-availability requirement. The manuscript does not currently include one. Given the paper's emphasis on auditability (checksum evidence, versioned transformations), the author may wish to consider whether a brief evidence-availability statement strengthens the submission, but this is a discretionary improvement, not a flagged compliance gap, since the flyer does not require it. **Label: Minor, optional.** |

**None of these four items can be resolved from the two CFP flyer images alone.** I am not treating
silence in the flyer as either a requirement or a non-requirement — each is reported as genuinely unknown.

---

## 9. Summary table

| # | Issue | Label | Section/Evidence |
|---|---|---|---|
| 1 | All scenario-mean and per-run numerical claims (C1/C2/C3, record counts, event counts, alerts, checksums, versions, HMAC keys) | **Verified** | §1, cross-checked against 3 independent CSV/log sources and source code |
| 2 | Abstract/Conclusion state C2 (85.78–98.30%) and C3 (98.47–99.23%) ranges without the "scenario-mean" qualifier used in §4.1, creating a plausible misreading as a per-run range when the true per-run range is wider (C2: 85.69–98.91%; C3: 98.11–99.39%) | **Major** | §1.1 — Abstract para 2, Conclusion para 84, vs. Results para 53 |
| 3 | S2 traffic count (6 queries) differs from `scenarios.yaml`'s planned 3 queries, but matches actual run evidence exactly | **Verified** (manuscript correct; no action needed) | §1.2 |
| 4 | The six paragraph/footnote changes made in Phases C–E introduce no fabricated evidence or unsupported new claims | **Verified** | §2 |
| 5 | FN4 DOI conflict (`10.1145/3186333` vs. `10.1145/3182660`), unresolved — web tools still down (502, reconfirmed this session) | **Critical** | §3.1 |
| 6 | FN5 DOI conflict (`10.1109/JLT.2020.3005909` vs. `10.1109/JLT.2020.3007491`), unresolved — same tool outage | **Critical** | §3.1 |
| 7 | FN7 year self-contradiction | **Verified** (already fixed in Phase C; confirmed consistent now) | §3.1 |
| 8 | Three Literature Review sentences (paras 17, 20, 25) make specific factual claims about cited papers' methods/findings that remain unverifiable against source text | **Major** | §3.2 |
| 9 | No footnote found anchored to an unrelated or mismatched claim | **Verified** | §3.3 |
| 10 | No problematic textual overlap/repetition found anywhere in the document | **Verified** | §4 |
| 11 | Abstract 273 words, main text 3,654 words | **Verified** | §5 |
| 12 | Font/spacing/footnote-mechanism/no-bibliography formatting requirements | **Verified** | §6 |
| 13 | Bibliography-vs-footnotes-only interpretation | **Minor** (reasonable interpretation already followed) | §6 |
| 14 | Author-biography / originality-declaration / file-naming conventions beyond the flyer | **Minor**, unresolved — outside what the two flyer images specify | §6, §8 |
| 15 | RQ → objectives → methodology → results → discussion → conclusion alignment | **Verified** | §7 |
| 16 | AI-assistance disclosure policy | **Unresolved**, policy unknown from available sources — not claimed either way | §8 |

---

## 10. Recommended next actions (scoped to scholarly accuracy, originality, clarity, and compliance only)

1. **Reword the Abstract and Conclusion's C2/C3 range sentences** to explicitly say "scenario-mean"
   (or equivalent), matching the disambiguation already applied to the C1 figure in §4.2. This is a
   wording change only — no numbers require correction.
2. **Resolve the FN4 and FN5 DOI conflicts** before submission — either confirm one of the two existing
   candidate values via a source you trust, or mark both footnotes for independent verification once
   `web_search`/`web_fetch` recover in this environment.
3. **Verify the three flagged Literature Review sentences** (paras 17, 20, 25) against the Pan et al.,
   Mohammady et al., and Manocchio et al. source papers directly, since their specific technical claims
   cannot be confirmed from this environment.
4. **Confirm with NDPC (or fuller submission guidelines, if available)** whether an author biography,
   originality declaration, or specific file-naming convention is expected beyond what the two CFP flyer
   images specify.
5. No change is recommended for word counts, formatting, footnote mechanics, RQ/conclusion alignment, or
   the six Phase C–E prose edits — all independently confirmed compliant and supported in this review.

I have not made any of the above changes in this pass, as instructed. Awaiting direction on which items to
action.
