# Metric Scope Validation — Old vs Corrected Formula

This report validates the corrected source-specific metrics proposed in
`docs/metric-scope-resolution-proposal.md` against preserved evidence only.
No raw, transformed, or historical report was modified.

## 1. Reconciliation of the old formula

The stored `raw_bytes`, `c2_bytes`, `c3_bytes`, `c2_reduction_pct`, and
`c3_reduction_pct` in all 29 `*.validation.json` files were independently
recomputed from the preserved files. **Every stored value matched**:

- `raw_bytes` = sum of all files under `raw-runs/<run>/` (Zeek + Suricata combined).
- `c2_bytes` = `suricata/C2-minimised-pseudonymised.jsonl` size.
- `c3_bytes` = `suricata/C3-aggregated-60s.jsonl` size.

So the old numbers are arithmetically correct but use a **scope-mismatched
denominator** (combined raw) against a **Suricata-only numerator**.

## 2. Supporting source files (traceability)

| Metric | Source file(s) |
|--------|----------------|
| Suricata raw baseline | `raw-runs/<run>/suricata/eve.json` |
| Suricata C1 | `transformed-runs/<run>/suricata/C1-pseudonymised.jsonl` |
| Suricata C2 | `transformed-runs/<run>/suricata/C2-minimised-pseudonymised.jsonl` |
| Suricata C3 | `transformed-runs/<run>/suricata/C3-aggregated-60s.jsonl` |
| Zeek raw baseline | `raw-runs/<run>/zeek/{dns,conn,http}.log` (transformed subset only) |
| Zeek C1 / C2 | `transformed-runs/<run>/zeek/{dns,conn,http}.log.C1/.C2` |

Excluded from every baseline: Suricata `fast.log`/`stats.log`/`suricata.log` and
Zeek `files.log`/`packet_filter.log`/`reporter.log` (none are transformed).

## 3. Old vs corrected percentages (representative runs)

| Run | Old raw (combined) | Suricata eve.json | Old C2% | New C2% | Old C3% | New C3% | New C1% |
|-----|--------------------|-------------------|---------|---------|---------|---------|---------|
| S1-R1 | 36544 | 23438 | 97.09 | 95.46 | 99.51 | 99.23 | −1.92 |
| S2-R2 | 31949 | 21977 | 90.16 | 85.69 | 99.26 | 98.93 | −1.34 |
| S3-R1 | 27399 | 18528 | 96.80 | 95.26 | 99.29 | 98.95 | −0.38 |
| S4-R1 | 42494 | 27945 | 91.99 | 87.82 | 99.26 | 98.88 | −2.27 |
| S5-R1 | 37746 | 25740 | 98.15 | 97.28 | 99.58 | 99.39 | −0.22 |
| S6-R1 | 14212 | 8406 | 98.75 | 97.89 | 98.88 | 98.11 | −0.17 |

The old combined-scope percentages **overstate** the reduction because the
denominator includes untransformed Zeek and Suricata auxiliary files. The
corrected Suricata-only reduction is 0.9–4.5 percentage points lower.

## 4. Corrected per-scenario mean [min–max] (all 29 runs)

Suricata pipeline (canonical C0→C1→C2→C3):

| Scenario | n | C1 red% | C2 red% | C3 red% |
|----------|---|---------|---------|---------|
| S1 | 5 | −1.92 | 95.46 | 99.23 |
| S2 | 4 | −1.29 [−1.34–−1.12] | 85.78 [85.69–86.01] | 98.94 [98.93–98.95] |
| S3 | 5 | −0.38 | 95.26 | 98.95 |
| S4 | 5 | −2.28 [−2.29–−2.27] | 87.78 [87.70–87.82] | 98.88 [98.87–98.88] |
| S5 | 5 | −0.29 [−0.31–−0.22] | 96.34 [96.10–97.28] | 99.18 [99.13–99.39] |
| S6 | 5 | −0.14 [−0.17–−0.09] | 98.30 [97.89–98.91] | 98.47 [98.11–99.02] |

Zeek pipeline (secondary, header-rewrite caveat — see §5):

| Scenario | n | C1 red% | C2 red% |
|----------|---|---------|---------|
| S1 | 5 | −1.47 | 26.95 [26.90–26.99] |
| S2 | 4 | 2.85 [2.58–2.94] | 30.15 [30.09–30.18] |
| S3 | 5 | 4.22 | 24.77 [24.75–24.77] |
| S4 | 5 | −0.18 | 26.97 [26.95–26.99] |
| S5 | 5 | 6.10 [6.09–6.10] | 24.98 [24.95–25.00] |
| S6 | 5 | 16.05 [16.04–16.09] | 27.38 [27.36–27.44] |

## 5. Interpretation and caveats

- **Suricata C1 is negative in every run** (−0.1% to −2.3%): HMAC pseudonyms
  are longer than IPv4 addresses, so pseudonymisation *adds* a small amount of
  volume rather than reducing it. This is correct and expected, and it
  contradicts any framing of C1 as a "volume reduction" step.
- **Suricata C2/C3 are clean** comparisons: `eve.json → C1 → C2 → C3` is a
  one-to-one JSONL stream with no header rewrite.
- **Zeek byte reductions are not a pure data-minimisation measure.**
  `zeek_pseudonymise` rewrites the log header to a minimal two-line
  `#fields`/`#types` header, so Zeek C1/C2 byte changes mix header
  simplification with identifier pseudonymisation/minimisation. The apparent
  "reduction" of 2.6–16% for C1 and ~25–30% for C2 is dominated by the header
  rewrite for low-row-count runs. Zeek results should be reported with this
  caveat or excluded from volume-reduction claims.
- **The two sources are not additive.** Zeek and Suricata emit different,
  non-overlapping representations of the same traffic; there is no valid
  combined baseline.

## 6. File anomalies (not silently treated as zero)

- **24 empty files**: `suricata/fast.log` is 0 bytes in all S1/S2/S3/S5/S6 runs
  (no alerts). S4's `fast.log` is non-empty (alert lines). These empty files are
  auxiliary and are excluded from every baseline.
- **No missing transformed files** for any of the 29 runs.
- **No malformed JSONL** detected in the transformed Suricata C1/C2/C3 outputs.

## 7. Edge-case behaviour (tested)

`compute_source_metrics` returns `None` (undefined) for a reduction percentage
when the baseline is missing or ≤ 0 bytes, and `None` for any missing stage file.
It never fabricates a 0 or a partial value. These behaviours are covered by
regression tests in `scripts/test_metrics.py`.
