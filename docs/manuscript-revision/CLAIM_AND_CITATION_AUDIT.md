# PP-NSMF Manuscript — Phase B: Claim-and-Source Audit

Scope: Phase B only — structural/evidence review. No manuscript prose has been rewritten.
Every major factual, numeric, and citation-bearing claim in the current manuscript is mapped below to its
supporting evidence file, script, or footnote, with a verification verdict. No source data, scripts, or the
manuscript itself were modified while producing this audit.

Verdict key: **V** = independently verified against primary evidence/code. **U** = unverifiable in this
environment (web tools unavailable). **F** = flagged discrepancy needing a decision. **OK-interp** = defensible
interpretive/discussion claim, not a raw fact (assessed for reasonableness, not "verified" in the data sense).

---

## 1. Abstract

| # | Claim | Evidence source | Verdict |
|---|---|---|---|
| 1.1 | PP-NSMF combines pseudonymisation, data minimisation, temporal aggregation in a controlled network environment | `docs/experiment-protocol.md` §4; `scripts/transform_telemetry.py` | V |
| 1.2 | Implemented using GNS3, Zeek, Suricata, Python | `docs/topology-audit.md` §1.1–1.5; `scripts/*.py` | V |
| 1.3 | Six synthetic traffic scenarios (HTTP, DNS, TCP scan, auth failures, periodic TCP, bulk transfer) | `experiments/scenarios.yaml` (S1–S6) | V |
| 1.4 | Compliant dataset = 29 runs, 5 per scenario except DNS (4) | `evidence-backup/reports/aggregate-metrics-v2.csv` (29 rows); `evidence-backup/protocol/experiment-run-log.csv` | V |
| 1.5 | Four stages C0–C3 as defined | `docs/metric-scope-validation.md` §2; `scripts/transform_telemetry.py` header comment | V |
| 1.6 | C2 reduction 85.78%–98.30% across scenarios; C3 reduction 98.47%–99.23% | Recomputed directly from CSV: C2 min 85.78 (S2), max 98.30 (S6); C3 min 98.47 (S6), max 99.23 (S1) | V |
| 1.7 | Pseudonymisation alone increased volume in every run because pseudonyms longer than IPv4 | Recomputed: all 29 `suricata_c1_reduction_pct` values negative (−0.09 to −2.29); token = `"h_" + 16 hex chars` = 18 chars vs IPv4 ≤ 15 chars (`scripts/transform_telemetry.py` `token()`) | V |
| 1.8 | Validation: no raw identifiers, consistent pseudonym mappings, all 29 runs | `docs/manuscript-results-package.md` §6 ("29/29 runs had no raw identifiers"; "ok" in 29/29 runs) | V |
| 1.9 | "Do not establish complete privacy, regulatory compliance, investigation utility or general intrusion-detection effectiveness" | Consistent with `docs/pre-writing-audit.md` §7 (investigation utility and detection effectiveness explicitly "not measured") | OK-interp, well-grounded |

**Abstract word count:** 273 words. Requirement: 250–300. **Compliant.**

No abstract-level issues found beyond the C1-range labelling question carried from Phase A (see §4.2 below, same underlying issue repeated in the abstract's framing — the abstract itself does not state a numeric C1 range, so it is not directly affected, but §4.2's wording feeds the Conclusion).

---

## 2. Introduction

| # | Claim | Evidence source | Verdict |
|---|---|---|---|
| 2.1 | Network telemetry can reveal relationships/patterns even without content (metadata argument) | Footnote 2 (RFC 6973, correlation/surveillance/stored-data compromise sections) | U (RFC content not independently refetchable this session, but RFC 6973 is a real, well-known IETF document whose subject matter — correlation, surveillance, data minimisation — is publicly well established; low risk) |
| 2.2 | Nigeria Data Protection Act 2023 provides national statutory context; NDPC is the regulator | Footnote 3 | U (could not refetch `ndpc.gov.ng` URL this session; however the Act and NDPC's existence are independently well known and match the journal's own publisher, so this is a low-risk citation) |
| 2.3 | "This study does not provide a legal compliance assessment" | Self-referential methodological scope statement, consistent with §5.3 and §6 | V (internally consistent) |
| 2.4 | Pseudonymisation may preserve linkability; can increase storage size when tokens longer than identifiers | Matches C1 negative-reduction finding (§4.2) | V |
| 2.5 | Research question (verbatim) | Matches master-prompt-specified RQ exactly, word for word | V |
| 2.6 | Three objectives stated | Consistent with Methodology §3.1–3.3 and Results structure | V |

No fabricated claims found in the Introduction. One stylistic note: the Introduction's second paragraph leans on RFC 6973 for a general metadata-privacy argument that is standard and uncontroversial in the privacy-engineering literature; this is a reasonable use of the citation and not a case of over-claiming.

---

## 3. Literature Review (Section 2)

This is the section most exposed to citation-accuracy risk, since every paragraph attributes specific findings to named authors.

| # | Claim | Footnote | Verdict |
|---|---|---|---|
| 3.1 | Van Dijkhuizen & van der Ham, "A Survey of Network Traffic Anonymisation Techniques and Implementations," *ACM Computing Surveys* 51(3), 2018, article 52 | FN4 | **F** — DOI conflict unresolved (see §8 below). Title/author/venue/year plausible and internally consistent with known literature in this subfield, but exact DOI not independently confirmed this session. |
| 3.2 | "Their review examines available techniques and implementations and highlights the importance of evaluating how anonymisation methods affect the information retained" | FN4 | U — plausible characterisation of a survey paper by that title, but the specific claim content was not verified against the source text (could not fetch). |
| 3.3 | Pan et al., "Privacy-Preserving Multilayer In-Band Network Telemetry and Data Analytics," *Journal of Lightwave Technology* 38(21), 2020: 5855–66 | FN5 | **F** — DOI conflict unresolved (see §8). |
| 3.4 | "Proposed a privacy-preserving system using homomorphic encryption, compression, integrity verification and anomaly analysis... IP-over-elastic-optical-network testbed" | FN5 | U — specific technical description (homomorphic encryption + EON testbed) not independently verified against the paper. This is a precise, falsifiable claim — if the DOI/source cannot be confirmed, this sentence carries real fabrication risk and should be treated cautiously in Phase C. |
| 3.5 | Mohammady et al., "A Multi-view Approach to Preserve Privacy and Utility in Network Trace Anonymization," *ACM Transactions on Privacy and Security* 24(3), 2021 | FN6 | U — DOI `10.1145/3439732` unchanged between manuscript and your corrected-sources list (no conflict), but not independently refetched this session. |
| 3.6 | "They observed that conventional approaches, including prefix-preserving IP address pseudonymisation, may remain vulnerable to adversaries with prior knowledge of network flows..." | FN6 | U — specific claim content not independently verified. |
| 3.7 | Fiore & Palmieri, "A Distance-Based Network Activity Correlation Framework for Defeating Anonymization Overlays," *Information Sciences* 690, 121559 | FN7 | **F** — internal year inconsistency already in the DOCX (text says "2025", DOI string says "2024"); your corrected-sources list says "2024" throughout, which resolves the self-contradiction. DOI itself (`10.1016/j.ins.2024.121559`) is unchanged between both versions — **no DOI conflict here**, only the in-text year. |
| 3.8 | Manocchio et al., "A Configurable Anonymisation Approach for Network Flow Data: Balancing Utility and Privacy," *Computers & Electrical Engineering* 118(B), 2024: 109465 | FN8 | U — unchanged between both source versions (no conflict), not independently refetched. |
| 3.9 | "A 2024 study in Computers & Electrical Engineering proposed a configurable approach that permits different anonymity levels for different traffic classes..." | FN8 | U — specific claim content not independently verified. |
| 3.10 | Combined footnote 9 citing three sources together for the "research gap" paragraph | FN9 | V (internally consistent — correctly aggregates sources already cited individually) |

**Assessment:** The Literature Review's prose does not read as generic listing — it already does what your master prompt asks for (comparing assumptions/approaches/limitations rather than summarising title-by-title), which is a structural strength. The risk here is narrower and sharper than "bad synthesis": it is **unverified specific factual content** (claims 3.4 and 3.6 in particular are detailed enough that if the underlying paper doesn't say exactly that, it would constitute a misattribution). This is squarely a "flag for manual verification" situation per your instructions, not something I will resolve by guessing.

---

## 4. Methodology (Section 3)

| # | Claim | Evidence source | Verdict |
|---|---|---|---|
| 4.1 | C0/C1/C2/C3 stage definitions | `scripts/transform_telemetry.py` header docstring; `docs/metric-scope-validation.md` §2 | V |
| 4.2 | GNS3 virtual network with client/server/attacker/monitor nodes | `docs/topology-audit.md` §1.1–1.4; `PP-NSMF.gns3` | V |
| 4.3 | `suricata/eve.json` as the sole raw baseline; Zeek processed separately, not combined | `docs/metric-scope-validation.md` §1–2, §5 ("the two sources are not additive") | V |
| 4.4 | Six scenarios as described (S1 HTTP ×5, S2 DNS 3A+3AAAA, S3 scan 5 ports, S4 auth ×5, S5 periodic ×4, S6 bulk 65,536 bytes) | `experiments/scenarios.yaml`; `scripts/traffic_generator.py` (`generate_http` default 5, `generate_dns`, `generate_tcp_connect_scan` ports list, `generate_auth_failures` default 5, `generate_periodic_beacon` count=4, `generate_bulk_transfer` bytes=65536) | V — exact match between manuscript prose and actual generator code defaults |
| 4.5 | Each scenario repeated 5×, except S2 (4 compliant) | `aggregate-metrics-v2.csv` row counts per scenario | V |
| 4.6 | Legacy S2/R1 excluded: different HMAC key, legacy script, unclean capture boundary | `docs/manuscript-results-package.md` §1; `docs/topology-audit.md` §3 item 6; `evidence-backup/S2-R1-zeek/`, `S2-R1-suricata/` (present, excluded from CSV) | V |
| 4.7 | First S4/R1 attempt excluded: raw-identifier leak in nested flow field; corrected and retried | `evidence-backup/protocol/experiment-run-log.csv` (FAILED row then PASS retry for S4,R1); `docs/transformation-changelog.md` §2.2.0 | V |
| 4.8 | Resulting compliant dataset = 29 successful runs | Recounted directly: 5+4+5+5+5+5 = 29, matches CSV row count | V |
| 4.9 | SHA-256 checksum audit, 243 entries, no failures | Independently re-ran `sha256sum -c evidence-backup/SHA256SUMS.txt`: **243 OK, 0 failures** (wc -l also confirms 243 lines) | V |
| 4.10 | Transformation versions: 2.0.0 (S1, compliant S2), 2.1.0 (S3), 2.2.0 (S4–S6); validator 1.1.0 | `docs/transformation-changelog.md`; `scripts/validate_results.py` line 20 `VALIDATOR_VERSION = "1.1.0"`; `consolidated-runs.csv` `transformation_version` column | V |
| 4.11 | Compliant runs share one HMAC key identifier | `docs/manuscript-results-package.md` §1 ("HMAC key ID e04d6b0475fd (single key, all compliant runs)") | V |
| 4.12 | Reduction formula: `100 × (1 − Transformed/Raw)`, denominator = raw `eve.json`, numerator = C1/C2/C3 output size | `scripts/metrics.py` `compute_source_metrics`; `docs/metric-scope-resolution-completion.md` "Exact metric definitions safe for the paper" | V |
| 4.13 | Byte sizes measured as file sizes | `docs/metric-scope-resolution-completion.md` ("Byte counts use file size (st_size)") | V |
| 4.14 | Zeek byte-size changes excluded from minimisation claims because of header rewriting | `docs/metric-scope-validation.md` §5 | V |
| 4.15 | Validation checks raw-identifier absence + pseudonym mapping consistency/injectivity, limited scope, not a formal anonymity proof | `docs/linkability-validation-report.md` §2, §7; `scripts/linkability.py` | V |
| 4.16 | Experiment descriptive; no labelled ground truth; no precision/recall/FPR/FNR computed; S4 evaluated for rule firing only | `docs/pre-writing-audit.md` §7–8; `docs/experiment-protocol.md` §6 | V |

**Methodology section is the most thoroughly evidence-backed section of the manuscript.** Every checkable claim traces exactly to code or evidence. No discrepancies found here beyond the ones already carried from Phase A.

---

## 5. Results (Section 4)

| # | Claim | Evidence source | Verdict |
|---|---|---|---|
| 5.1 | C2 means: 95.46/85.78/95.26/87.78/96.34/98.30 (S1–S6) | Recomputed from CSV directly | V — exact match |
| 5.2 | C3 means: 99.23/98.94/98.95/98.88/99.18/98.47 (S1–S6) | Recomputed from CSV directly | V — exact match |
| 5.3 | "Largest reported C2 reduction... S6, at 98.30%... S2 had the lowest, at 85.78%" | Recomputed: confirmed min/max across the six scenario means | V |
| 5.4 | §4.2: "C1 byte-volume reduction was negative in every compliant run, ranging from −0.14% to −2.28%" | Recomputed per-run: true per-run range is **−0.09% to −2.29%**; −0.14/−2.28 are the **S6/S4 scenario means** | **F — carried forward from Phase A, unresolved.** See §9 below for the specific wording decision still needed. |
| 5.5 | Pseudonym tokens longer than IPv4 addresses, causing negative C1 | `scripts/transform_telemetry.py` `token()`: `"h_" + 16 hex chars` = 18 chars; max IPv4 = 15 chars (confirmed by direct computation) | V |
| 5.6 | §4.3 record counts: C0→C2 as 17→5 (S1), 17.25→12 (S2), 7→5 (S3), 22→15 (S4), 6.2→4 (S5), 2.4→1 (S6); one C3 window per run | `consolidated-runs.csv`; recomputed `c3_windows` column across all 29 rows = constant `{'1'}` | V |
| 5.7 | "Fractional scenario means... reflect variation in raw source events... e.g., additional Suricata statistics event" | `docs/manuscript-results-package.md` §9 note ("driven by Suricata's periodic stats-event emission timing") | V |
| 5.8 | §4.4: all 29 runs pass raw-identifier absence and pseudonym-linkability checks; C3 and some Zeek C2 marked not-applicable | `docs/manuscript-results-package.md` §6; `docs/linkability-validation-report.md` §2 | V |
| 5.9 | §4.5 observed-event counts per scenario (S1: 5/5, S2: 6/12, S3: 5/5, S4: 5/5, S5: 4/4, S6: 1 w/ 65,536 bytes) | `docs/manuscript-results-package.md` Table 5; CSV columns (`http_requests`, `suricata_http_events`, `zeek_queries`, `suricata_dns_events`, etc.) | V |
| 5.10 | S4: 5 alerts/run from configured HTTP-401 rule (sid 1000001); not general detection effectiveness | `docs/manuscript-results-package.md` Table 6; `experiments/scenarios.yaml` S4 `suricata_rules` field | V |
| 5.11 | S3/S5/S6 run without alert rules → flow observations, not detection results | `docs/manuscript-results-package.md` Table 6 (`-S /dev/null`, 0 alerts) | V |

**Only one unresolved issue in Results: the C1 range framing (5.4), already flagged in Phase A.** No new numeric discrepancies found in this section beyond that one.

---

## 6. Discussion (Section 5)

This section is interpretive by design. I assessed each claim for whether it stays within the evidentiary bounds established in Results/Methodology, rather than treating it as a "verifiable fact."

| # | Claim | Assessment |
|---|---|---|
| 6.1 | §5.1: pseudonymisation/minimisation/aggregation have different volume effects at different stages | OK-interp — directly supported by 5.1–5.5 above |
| 6.2 | §5.1: RFC 6973 recommendation re: identifiers/correlation/purpose-limitation, applied to HMAC token linkability | OK-interp — standard, appropriately qualified ("tokens remain linkable within the relevant scope") |
| 6.3 | §5.2: minimisation policy recommendations for security teams | OK-interp — reasonable practitioner guidance, explicitly framed as a suggestion ("the results suggest"), not a proven conclusion |
| 6.4 | §5.2: "the experiment did not test whether an analyst could reconstruct incidents... cannot yet claim... preserves adequate investigation utility" | V — consistent with `docs/pre-writing-audit.md` §7 (investigation utility explicitly unmeasured) |
| 6.5 | §5.3: framework "may be relevant" to Nigerian organisations, explicitly "not a turnkey compliance solution" | OK-interp — appropriately hedged, matches your Section 5/10 style requirements (no "all Nigerian organisations" overclaim) |
| 6.6 | §5.3: NDPA 2023 provides statutory context; study did not perform legal analysis, assess lawful bases, or test governance controls | V — consistent with Introduction §3 and matches footnote 11 scope |

**No overclaiming found in Discussion.** This section already honours the requested distinction between evidence and interpretation.

---

## 7. Limitations, Future Research, and Conclusion (Sections 6–7)

| # | Claim | Evidence source | Verdict |
|---|---|---|---|
| 7.1 | Synthetic workloads, controlled virtual network | `docs/topology-audit.md`; `scripts/traffic_generator.py` (all traffic generated via scripted `docker_exec` calls, no production traffic) | V |
| 7.2 | 5 repetitions per scenario except S2 (4) | Matches §4.5 above | V |
| 7.3 | Validator checked defined field/value set only, not comprehensive re-identification/adversarial analysis | `docs/linkability-validation-report.md` §7 "Remaining limitations" | V |
| 7.4 | Investigation utility and general detection effectiveness not measured | `docs/pre-writing-audit.md` §7 | V |
| 7.5 | S4 alert result limited to configured rule firing on known HTTP-401 | Matches 5.10 above | V |
| 7.6 | Zeek byte comparisons excluded due to header rewrite | Matches 4.14 above | V |
| 7.7 | Conclusion recaps C2 (85.78–98.30%) and C3 (98.47–99.23%) reductions | Matches 5.1–5.2 (scenario-mean ranges, correctly labelled as ranges across scenarios here, not per-run) | V — note the Conclusion's phrasing ("C2 byte-volume reductions of 85.78%–98.30%") is actually worded correctly as a range *across scenario means*, unlike §4.2's C1 sentence which claims a per-run range. This confirms the C1 sentence in §4.2 is the one outlier needing a wording fix, not a pattern repeated elsewhere. |
| 7.8 | Conclusion: pseudonymisation increased volume in every run; validation reported no leakage, consistent mappings in all 29 runs, within defined scope | Matches 5.4–5.8 | V (except inherits the same C1 per-run/mean ambiguity noted in 5.4, since "in every run" + "pseudonymisation alone increased byte volume" is true at the per-run level even though the specific numbers aren't restated here) |

No fabricated future-work claims (e.g., no claim that adversarial testing or analyst-task evaluation has already been done).

---

## 8. Footnote/DOI conflict — status update

Retried `web_fetch` (doi.org and api.crossref.org) and `web_search` at the start of this phase. **All calls still return 502 errors**, including a plain unrelated test query, confirming this is a continued tool-side outage rather than a per-URL issue. I am not able to adjudicate the DOI conflict for footnotes 4 and 5 this session.

**Carrying forward exactly as flagged in Phase A:**
- FN4 (van Dijkhuizen & van der Ham): DOCX has `10.1145/3186333`; your corrected list has `10.1145/3182660`.
- FN5 (Pan et al.): DOCX has `10.1109/JLT.2020.3005909`; your corrected list has `10.1109/JLT.2020.3007491`.
- FN7 (Fiore & Palmieri): DOCX text says "(2025)" against its own DOI year "2024"; your corrected list says "(2024)" — **this one fix is safe to apply in Phase C regardless of web access**, since it resolves a self-contradiction already present in the current manuscript rather than depending on unverified external data.

**Recommendation:** Phase C will apply the FN7 year fix immediately. For FN4/FN5, Phase C will hold the DOCX's current DOIs unless you confirm which value is correct, since over-writing one unverified DOI with another unverified DOI doesn't reduce risk — it just changes which wrong-or-right value is in the paper. If you have a way to confirm (e.g., you sourced the "corrected sources.txt" from a database lookup you trust), tell me and I'll apply it directly in Phase C.

---

## 9. Decisions still needed before Phase C touches prose

1. **C1 range wording (§4.2).** Choose: (a) reword as "scenario-mean reduction ranged from −0.14% to −2.28%", or (b) replace with true per-run extremes "−0.09% to −2.29%". Both are factually defensible; Phase C will not silently pick one.
2. **FN4/FN5 DOIs.** Confirm which DOI is correct, or authorise leaving the DOCX's current values unchanged pending independent verification.
3. **Literature Review specific claims (3.4, 3.6, 3.9).** These are detailed enough that I'd flag them for your manual check against the actual papers if you have access to them (e.g., via your institution's library or personal copies), since I cannot fetch them this session. Phase C can proceed with the existing prose as-is (it is well-written and appropriately hedged) without waiting on this, but the underlying factual accuracy of these three sentences remains unconfirmed by me.
4. **Bibliography/author-bio/file-naming requirements.** Still unknown from the flyer alone (carried from Phase A §6). Confirm if you have fuller NDPC guidelines beyond the two images.

None of these block starting Phase C's lower-risk work (the FN7 year fix, the stray-dash artefact removal in §2.4, and section-by-section prose tightening that doesn't depend on the open numeric/citation questions). I'll proceed into Phase C on that basis unless you'd rather resolve items 1–2 first.
