# PP-NSMF Source-Scoped Telemetry-Volume Summary (v2)

Corrected scope (Suricata and Zeek reported separately). See
`docs/metric-scope-resolution-proposal.md` and
`docs/metric-scope-validation.md`. All values are recomputed from
preserved evidence; historical combined-scope values remain in
`aggregate-metrics.csv` and are retained under `legacy_combined_*` columns
in `aggregate-metrics-v2.csv`.

Negative percentages mean the stage is *larger* than its baseline
(HMAC pseudonyms are longer than IPv4 addresses), not a reduction.

## Suricata pipeline (canonical C0→C1→C2→C3)

| Scenario | n | C1 red% | C2 red% | C3 red% |
|----------|---|---------|---------|---------|
| S1 | 5 | -1.92 [-1.92–-1.92] | 95.46 [95.46–95.46] | 99.23 [99.23–99.23] |
| S2 | 4 | -1.29 [-1.34–-1.12] | 85.78 [85.69–86.01] | 98.94 [98.93–98.95] |
| S3 | 5 | -0.38 [-0.38–-0.38] | 95.26 [95.26–95.26] | 98.95 [98.95–98.95] |
| S4 | 5 | -2.28 [-2.29–-2.27] | 87.78 [87.70–87.82] | 98.88 [98.87–98.88] |
| S5 | 5 | -0.29 [-0.31–-0.22] | 96.34 [96.10–97.28] | 99.18 [99.13–99.39] |
| S6 | 5 | -0.14 [-0.17–-0.09] | 98.30 [97.89–98.91] | 98.47 [98.11–99.02] |

## Zeek pipeline (secondary; header-rewrite caveat applies)

| Scenario | n | C1 red% | C2 red% |
|----------|---|---------|---------|
| S1 | 5 | -1.47 [-1.47–-1.47] | 26.95 [26.90–26.99] |
| S2 | 4 | 2.85 [2.58–2.94] | 30.15 [30.09–30.18] |
| S3 | 5 | 4.22 [4.22–4.22] | 24.77 [24.75–24.77] |
| S4 | 5 | -0.18 [-0.18–-0.18] | 26.97 [26.95–26.99] |
| S5 | 5 | 6.10 [6.09–6.10] | 24.98 [24.95–25.00] |
| S6 | 5 | 16.05 [16.04–16.09] | 27.38 [27.36–27.44] |

## Notes

- C2/C3 reductions for Suricata are clean byte-volume reductions
  (`eve.json` vs `C2`/`C3` JSONL).
- C1 is negative for Suricata in every run (pseudonymisation overhead).
- Zeek byte reductions mix header simplification with minimisation and
  are therefore not a pure data-reduction measure; interpret with care.
- Byte-volume reduction is not a privacy-risk reduction; identifier
  exposure, linkability, and aggregation are separate measures.
- Record-count metrics (source_events, c1/c2 records, c3 windows) are
  reported separately in the run log and are not part of these byte
  percentages.

