# PP-NSMF Evidence Freeze Report — S1–S4

Frozen on 2026-10-21. This report pins the state of all completed S1–S4
evidence. The evidence described here must not be overwritten, deleted, or
regenerated.

## Freeze status: FROZEN

## Checksum verification

- `evidence-backup/SHA256SUMS.txt`: **173 entries**, all verified **PASS**
  (0 failures). No raw evidence was overwritten, deleted, or regenerated.
- Manifest pin: `68a0c15446a662366487e8802cfeaca0c8c380fb1c36fade8fe39154ffb72b16`

Entry breakdown:

| Set | Entries |
|-----|---------|
| S1 (R1–R5, 9 files each) | 45 |
| S2 (R2–R5, 8 files each) | 32 |
| S3 (R1–R5, 7 files each) | 35 |
| S4 (R1–R5, 9 files each) | 45 |
| Legacy S2/R1 (preserved) | 16 |

## Run log

`evidence-backup/protocol/experiment-run-log.csv` — **20 data rows**, pin
`20dcfd975ba9c5d7e6c23ee2f0902006fa2eea68b2be36e1a83c2e63af1d51a5`.

S4 rows confirm the failed attempt, the successful retry, and R2–R5:

- `S4,R1,FAILED` (20:37:14) — first attempt, preserved.
- `S4,R1,COMPLETED` (20:39:06) — successful retry.
- `S4,R2..R5,COMPLETED` — passed.

S1 (R1–R5), S2 (R2–R5), and S3 (R1–R5) are recorded as COMPLETED. No S2/R1 row
exists (legacy, excluded).

## Legacy S2/R1 exclusion

Legacy S2/R1 exists only under `evidence-backup/S2-R1-zeek/` and
`evidence-backup/S2-R1-suricata/` (16 checksummed files, preserved). It used a
replacement HMAC key, a legacy transform script, an unclean capture boundary,
and untransformed Zeek logs, so it is **excluded** from the compliant numeric
comparison: it appears in no run-log row, no `*.validation.json`, and no
`aggregate-metrics.csv` row.

## Versions and key

- Transformation: **2.0.0** (S1, S2), **2.1.0** (S3), **2.2.0** (S4).
- Validator: **1.1.0**.
- HMAC key ID: **e04d6b0475fd** (single key across S1–S4; the legacy S2/R1 used
  a different replacement key).

## C0–C3 definitions

- **C0**: raw telemetry (preserved, never rewritten).
- **C1**: pseudonymised (HMAC-SHA256), field-identical except identifiers.
- **C2**: minimised (explicit field selection) and pseudonymised.
- **C3**: aggregated into 60-second windows from C2.

## Terminology

- HMAC pseudonymisation is **linkable pseudonymisation**, not anonymisation.
- Rule firing is **not** detection effectiveness (no labelled ground truth or
  false-positive/negative measurement).

## Discrepancies noted (no evidence modified)

1. The `S4,R1,FAILED` run-log row's `raw_zeek_path`/`raw_suricata_path` fields
   still point to `raw-runs/S4-R1/`, which now holds the retry. The failed
   attempt's evidence is preserved at `failed-runs/S4-R1/raw/`; the SHA-256
   values in that row correctly identify the archived failed evidence (verified).
2. `S2-summary.md` still cites "SHA256SUMS.txt (48 entries)"; the manifest has
   since grown to 173 entries. This is a stale prose count, not a data issue.
