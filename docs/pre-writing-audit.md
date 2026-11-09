# PP-NSMF Pre-Writing Audit

Audit date: 2026-10-21. Scope: verify evidence integrity and prepare the
manuscript's Results section. No experiments were run and no raw evidence was
modified during this audit.

## 1. Checksum verification

`evidence-backup/SHA256SUMS.txt` was re-verified with `sha256sum -c`:

- **243 entries, 243 OK, 0 failures** (no missing, mismatched, or failed files).

## 2. Reports read

- `evidence-backup/reports/EVIDENCE-FREEZE-S1-S4.md`
- `evidence-backup/reports/S1-summary.md` … `S6-summary.md` (six scenario summaries)

## 3. Compliant dataset (29 successful runs)

Confirmed from the run log (`experiment-run-log.csv`, **30 data rows**) and the
`reports/*.validation.json` files:

| Scenario | Runs | Count |
|----------|------|-------|
| S1 | R1–R5 | 5 |
| S2 | R2–R5 | 4 |
| S3 | R1–R5 | 5 |
| S4 | R1–R5 | 5 |
| S5 | R1–R5 | 5 |
| S6 | R1–R5 | 5 |
| **Total** | | **29** |

**Excluded from compliant numeric comparison:**

- **Legacy S2/R1** — preserved under `S2-R1-zeek/` and `S2-R1-suricata/`
  (16 checksummed files). Used a replacement HMAC key, a legacy transform
  script, an unclean capture boundary, and untransformed Zeek logs. It appears
  in no run-log row, no `*.validation.json`, and no `aggregate-metrics.csv` row.
- **S4/R1 first attempt** — recorded in the run log as `S4,R1,FAILED`
  ("validation failed", nested flow-IP leak) and preserved at
  `failed-runs/S4-R1/`. The compliant S4/R1 is the successful retry.

## 4. Consolidated run-level CSV

Produced at `evidence-backup/reports/consolidated-runs.csv` (**29 data rows**),
one row per compliant run. Columns: scenario, run_id, transformation_version,
validator_version, hmac_key_id, c0/c1/c2 records, c3 windows, c0/c1/c2/c3 bytes,
c2/c3 reduction %, observed Zeek/Suricata events, scenario-specific observed
counts, validation status, and documented deviation. Values are sourced from the
run log and the per-run `*.validation.json` files only (no invented values;
missing fields are left blank).

## 5. Per-scenario statistics (mean [min–max])

| Scenario | n | C0 records | C2 records | C0 bytes | C2 bytes | C3 bytes | C2 red% | C3 red% |
|----------|---|-----------|-----------|----------|----------|----------|---------|---------|
| S1 | 5 | 17.0 | 5.0 | 36438.6 [36149–36558] | 1065 | 180 | 97.08 [97.05–97.09] | 99.51 [99.50–99.51] |
| S2 | 4 | 17.25 [17–18] | 12.0 | 32183.5 [31720–33107] | 3144 | 236 | 90.23 [90.09–90.50] | 99.27 [99.26–99.29] |
| S3 | 5 | 7.0 | 5.0 | 27738.6 [27399–27941] | 878 | 194 | 96.84 [96.80–96.86] | 99.30 [99.29–99.31] |
| S4 | 5 | 22.0 | 15.0 | 42327.0 [42012–42510] | 3405 | 313 | 91.96 [91.90–91.99] | 99.26 [99.25–99.26] |
| S5 | 5 | 6.2 [6–7] | 4.0 | 29136.0 [26865–37746] | 700 | 157 | 97.55 [97.39–98.15] | 99.45 [99.42–99.58] |
| S6 | 5 | 2.4 [2–3] | 1.0 | 18693.2 [14212–25414] | 177 | 159 | 98.98 [98.75–99.30] | 99.08 [98.88–99.37] |

Run-level values are preserved in the consolidated CSV alongside these summary
statistics.

**Missing / incomparable metrics:**

- Alert counts exist only for S4 (5 per run). S3/S5/S6 record `alert_count = 0`
  (no rule loaded); S1/S2 have no alert field at all (different pipeline). Alert
  counts are therefore not comparable across scenarios.
- Observed-event types differ by design: HTTP requests (S1), DNS queries (S2),
  scan connections (S3), 401/auth (S4), beacon connections (S5), bulk bytes (S6).
  Counts are **not** interchangeable.
- `bulk_orig_bytes` (65536) is S6-only; `bytes_toserver` (Suricata wire bytes,
  68778) is not in the run log and must be read from `*.validation.json`.
- C1 reduction percentage is not reported anywhere (C1 byte counts exist, but no
  C1 reduction column).

## 6. C0/C2/C3 definitions and the reduction denominator

Definitions are in `scripts/transform_telemetry.py` and
`scripts/validate_results.py` (`compute_metrics`):

- **C0** = raw telemetry (preserved). Byte count = sum of **all** raw file sizes
  (Zeek + Suricata).
- **C1** = pseudonymised (HMAC-SHA256), field-identical.
- **C2** = minimised (explicit field selection) + pseudonymised.
- **C3** = aggregated from C2 into 60-second windows.

**Reduction percentages use byte counts (file sizes), not record counts:**
`c2_reduction_pct = 100 * (1 - c2_bytes / raw_bytes)`, and likewise for C3.
`raw_bytes` is the combined Zeek+Suricata raw total.

**Inconsistencies flagged (not silently reconciled):**

1. **Numerator/denominator scope mismatch.** `c2_bytes`/`c3_bytes` are
   Suricata-only transformed file sizes, but `raw_bytes` (the C0 denominator) is
   the combined Zeek+Suricata total. The Zeek C1/C2 transformed outputs are not
   included in any byte metric. The reported reduction is therefore
   "Suricata-pipeline byte reduction relative to combined raw telemetry", not a
   symmetric C2-vs-C0 comparison.
2. **`c0_records` is Suricata-only, `c0_bytes` is combined.** In the run log,
   `c0_records` = Suricata `source_events` (eve.json line count), while
   `c0_bytes` = all raw files. The "C0" label has two different scopes.
3. **C1 reduction is not reported.** `c1_bytes` is computed but no
   `c1_reduction_pct` is emitted.

The manuscript must state the exact denominator (combined raw bytes) and the
Suricata-only numerator, or recompute with a consistent denominator before
quoting reduction figures. Do not describe these percentages as record-count or
"data-volume" reductions without that qualification.

## 7. Outcome distinctions the manuscript must preserve

The evidence supports six distinct outcomes that must not be conflated:

1. **Telemetry-volume reduction** — measured (C2/C3 byte reduction, §6).
2. **Identifier exposure** — measured (privacy checks confirm raw IPs/domain are
   absent from C1/C2/C3 and Zeek C1/C2).
3. **Pseudonym linkability** — measured (`linkability.assess`; overall "ok"
   means injective, consistent pseudonyms — linkable, not anonymised).
4. **Aggregation** — measured (C3 60-second windows).
5. **Investigation utility** — **not measured.** No metric quantifies whether an
   analyst can still answer detection/investigation questions after
   transformation; only structural properties (field retention, linkability,
   aggregation) are validated. The paper must not equate volume reduction with
   preserved investigation utility.
6. **Detection effectiveness** — **not established.** S4 demonstrates rule
   firing only (§8); no scenario has labelled ground truth or FP/FN measurement.

## 8. S4 alerts vs no-detection scenarios

- **S4**: 5 alerts per run, `alert_count = 5` (verified in all five
  `*.validation.json`). These are **configured HTTP-401 rule firing**
  (`test-auth-401.rules`, sid 1000001, loaded only for S4), not a
  detection-effectiveness result.
- **S3, S5, S6**: `alert_count = 0` in every run (Suricata ran with `-S /dev/null`,
  flows only). These have **no detection-effectiveness result**.

## 9. Two documentation discrepancies (corrections proposed)

1. **S4/R1 FAILED run-log path fields.** The `S4,R1,FAILED` row's
   `raw_zeek_path`/`raw_suricata_path` point to `raw-runs/S4-R1/` (the retry),
   not the archived failed evidence. The SHA-256 values in that row correctly
   identify the archived files (verified).
   *Correction (documentation-only, no evidence/history change):* add a note or
   update those two path fields to `failed-runs/S4-R1/raw/zeek` and
   `failed-runs/S4-R1/raw/suricata`, leaving the hashes untouched.

2. **Stale `S2-summary.md` manifest count.** It cites "SHA256SUMS.txt (48
   entries)". The manifest is now 243 entries (S1–S6).
   *Correction:* update the prose to "243 entries, all verified" (or a
   version-stable wording such as "all entries verified at audit time").

Related note: `S4-summary.md` cites "173 entries / 20 rows", which were correct
at the S1–S4 freeze but are now stale (243 entries / 30 rows) after S5–S6. The
freeze report's manifest pin (`68a0c154…`) is a point-in-time snapshot and is
expected to differ from the current manifest; this is not an error.

## 10. Recommended tables for the Results section

- **Table 1 — Scenario overview:** scenario, traffic type, generator node,
  destination, protocol/port, whether a Suricata alert rule was loaded
  (S4 only), and validation outcome.
- **Table 2 — Per-run results:** the consolidated CSV (`consolidated-runs.csv`)
  rendered as a table (or a per-scenario sub-table), preserving run-level values.
- **Table 3 — Per-scenario summary statistics:** n, mean and range for C0/C2/C3
  bytes and C2/C3 reduction percentages (§5), with the reduction-denominator
  caveat (§6) stated in the caption.
- **Table 4 — Outcome matrix:** rows = the six outcomes (§7), columns = scenarios,
  cells = measured / not measured / not applicable. This makes explicit that
  investigation utility and detection effectiveness are not measured.

## Unresolved issues

- Reduction percentages mix Suricata-only numerators with a combined raw
  denominator (§6) — must be defined precisely or recomputed before quoting.
- `c0_records` vs `c0_bytes` scope mismatch (§6).
- "Investigation utility" has no metric (§7).
- Two documentation discrepancies remain uncorrected (§9); corrections are
  documentation-only and do not alter evidence or historical run results.
