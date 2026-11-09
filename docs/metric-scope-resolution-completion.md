# Metric Scope Resolution — Completion Report

## Outcome

The telemetry-reduction metric scope mismatch is resolved with **Option C
(separate source-specific metrics)**. The historical combined-scope values are
retained under `legacy_combined_*` columns and the corrected Suricata/Zeek
values are added as new columns. No evidence was modified.

## Modified / new files

- `docs/metric-scope-resolution-proposal.md` (new) — options A/B/C, chosen method, formulas, limitations.
- `docs/metric-scope-validation.md` (new) — old-vs-new audit, file traceability, test outcomes.
- `scripts/metrics.py` (new) — `compute_source_metrics` (corrected source-specific formulas).
- `scripts/test_metrics.py` (new) — 7 regression tests (zero/missing baseline, missing stage, untransformed-log exclusion).
- `scripts/generate_metrics_csv.py` (modified) — emits corrected columns into a new versioned output; no longer overwrites `aggregate-metrics.csv`.
- `evidence-backup/reports/aggregate-metrics-v2.csv` (new) — 29-run corrected results.
- `evidence-backup/reports/source-scoped-summary-v2.md` (new) — per-scenario means/ranges.
- `docs/metric-scope-artifacts.sha256` (new) — SHA-256 of the new deliverables.

## Unchanged evidence (verified)

- `evidence-backup/SHA256SUMS.txt` — **243 entries, all 243 OK** (0 failures), byte-for-byte unchanged.
- Raw captures, transformed outputs, `*.validation.json`, `experiment-run-log.csv` (30 rows), and historical `aggregate-metrics.csv` are untouched.
- 29-run compliant dataset intact; legacy S2/R1 and the failed S4/R1 attempt remain excluded.

## Checksum status

- Evidence manifest: 243/243 OK.
- New-artifact manifest: `docs/metric-scope-artifacts.sha256` (7 files), added without modifying the evidence manifest.

## Tests

- `scripts/test_linkability.py`: 7/7 OK (existing).
- `scripts/test_metrics.py`: 7/7 OK (new; covers zero-byte baseline, missing source, missing stage, untransformed-log exclusion, Suricata/Zeek values).

## Key numerical result (scope correction)

The old combined-scope reduction over-stated Suricata reduction by ~0.9–4.5
percentage points. Corrected Suricata C2/C3 (mean, per scenario):

| Scenario | Old C2% | New C2% | New C3% |
|----------|---------|---------|---------|
| S1 | 97.08 | 95.46 | 99.23 |
| S2 | 90.23 | 85.78 | 98.94 |
| S3 | 96.84 | 95.26 | 98.95 |
| S4 | 91.96 | 87.78 | 98.88 |
| S5 | 97.55 | 96.34 | 99.18 |
| S6 | 98.98 | 98.30 | 98.47 |

Suricata **C1 reduction is negative in every run** (HMAC pseudonyms are longer
than IPv4 addresses), so pseudonymisation adds volume, not reduces it.

## Exact metric definitions safe for the paper

- `suricata_c2_reduction_pct = 100 × (1 − suricata_c2_bytes / suricata_raw_bytes)`
- `suricata_c3_reduction_pct = 100 × (1 − suricata_c3_bytes / suricata_raw_bytes)`
- `suricata_raw_bytes` = size of `suricata/eve.json` (the only Suricata file the
  transformation reads).
- `suricata_c2_bytes` = size of `suricata/C2-minimised-pseudonymised.jsonl`.
- `suricata_c3_bytes` = size of `suricata/C3-aggregated-60s.jsonl`.
- Byte counts use file size (`st_size`); percentages are byte-volume reductions.
- These are **telemetry-volume reductions only**, not privacy-risk, identifier-
  exposure, linkability, or detection measures.

## Unresolved limitations

- Zeek byte reductions are **not** a pure data-minimisation measure: the Zeek
  transform rewrites the log header, so Zeek C1/C2 byte changes mix header
  simplification with pseudonymisation/minimisation. Report Zeek with this
  caveat or exclude it from volume-reduction claims.
- Record-count reduction is a separate metric (available in the run log as
  `source_events`/`c1_records`/`c2_records`/`c3_windows`) and is not folded into
  these byte percentages.
- No C1 reduction was previously reported; the corrected C1 is now provided but
  is negative (pseudonymisation overhead) for Suricata.
- `c0_records` remains a Suricata-only event count and is kept separate from all
  byte metrics.
