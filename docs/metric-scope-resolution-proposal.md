# Metric Scope Resolution Proposal — Telemetry-Volume Reduction

Status: proposal. No metric code has been changed by this document. This
proposal resolves the scope mismatch identified in `docs/pre-writing-audit.md`.

## 1. What the current implementation actually does

`scripts/validate_results.py::compute_metrics` and
`scripts/experiment_controller.py` currently compute:

- `raw_bytes` (labelled `c0_bytes` in the run log) = sum of **all** file sizes
  under `raw-runs/<run>/` — i.e. Zeek logs **and** Suricata logs **combined**.
- `c1_bytes` = size of `suricata/C1-pseudonymised.jsonl` only.
- `c2_bytes` = size of `suricata/C2-minimised-pseudonymised.jsonl` only.
- `c3_bytes` = size of `suricata/C3-aggregated-60s.jsonl` only.
- `c2_reduction_pct = 100 × (1 − c2_bytes / raw_bytes)` (and likewise for C3).

**This mixes scopes:** the denominator is combined Zeek+Suricata, but the
numerator is Suricata-only. There is no C1 reduction, and `c0_records`
(Suricata-only) uses a different scope from `c0_bytes` (combined).

## 2. Traced source scope

Inspection of `scripts/transform_telemetry.py` establishes the actual
transformation sources:

- **Suricata pipeline** (`transform_suricata`) reads **only** `suricata/eve.json`
  and emits `suricata/C1-pseudonymised.jsonl`,
  `suricata/C2-minimised-pseudonymised.jsonl`, and
  `suricata/C3-aggregated-60s.jsonl`. The other Suricata files (`fast.log`,
  `stats.log`, `suricata.log`) are **auxiliary and are not transformed**.
- **Zeek pipeline** (`transform_zeek`) reads **only** `zeek/dns.log`,
  `zeek/conn.log`, and `zeek/http.log` and emits `<name>.C1` and `<name>.C2`.
  The files `files.log`, `packet_filter.log`, and `reporter.log` are
  **not transformed**. Zeek has **no C3**.

Confirmed for representative runs (S1-R1, S2-R2, S3-R1, S4-R1, S5-R1, S6-R1):
every run's transformed Suricata outputs are 1:1 with `eve.json`, and every
run's transformed Zeek outputs are 1:1 with the subset `{dns,conn,http}.log`.

## 3. Why the combined baseline is not defensible

Zeek and Suricata are two independent monitors that observe the same traffic but
emit **different, non-overlapping event representations** (Zeek connection/DNS/
HTTP logs vs Suricata EVE JSON). Summing their byte counts does not produce a
valid single source stream; it double-counts the same traffic as two unrelated
representations and mixes in auxiliary files (`stats.log`, `suricata.log`,
`packet_filter.log`, `reporter.log`, `files.log`) that the transformation never
reads. The original "C1/C2/C3" files are Suricata outputs, so the correct
baseline for that chain is the Suricata source, not the combined total.

## 4. Options considered

### Option A — Suricata-only matched scope

- Raw baseline: `suricata/eve.json` only.
- Stages: `C1-pseudonymised.jsonl`, `C2-minimised-pseudonymised.jsonl`,
  `C3-aggregated-60s.jsonl`.
- Unit: bytes (file size), identical JSONL structure, no header rewrite.
- Formula: `100 × (1 − Ck_bytes / eve_bytes)` for k ∈ {1,2,3}.
- Supported: **yes, cleanly** — `eve.json → C1 → C2 → C3` is a one-to-one source
  stream. C1 is field-identical to eve.json (values pseudonymised); C2 drops
  stats events and selects fields; C3 aggregates C2 into 60-second windows.
- Limitation: `eve.json` includes Suricata `stats` events, which C2 drops, so C2
  and C3 reductions fold "stats-event removal + field minimisation" together.
  This is acceptable and should be stated.
- Scenarios/runs: all 29 compliant runs (every run has `eve.json`).

### Option B — Zeek-only matched scope

- Raw baseline: sum of `zeek/dns.log + zeek/conn.log + zeek/http.log` (only the
  logs actually transformed; excludes `files.log`, `packet_filter.log`,
  `reporter.log`).
- Stages: `<name>.C1` and `<name>.C2` (summed per stage); **no C3**.
- Unit: bytes.
- Formula: `100 × (1 − Ck_bytes / zeek_raw_bytes)` for k ∈ {1,2}.
- Supported: partially. The byte comparison is **contaminated** because
  `zeek_pseudonymise` rewrites the log header to a minimal two-line
  `#fields/#types` header (dropping `#separator`, `#set_separator`,
  `#unset_field`, `#empty_field`, `#path`, `#open`, `#close`). So a Zeek C1/C2
  byte change reflects both header simplification **and** identifier
  pseudonymisation/minimisation, not data reduction alone.
- Limitation: not a pure data-minimisation measure; must be reported with the
  header-rewrite caveat.

### Option C — Separate source-specific metrics (chosen)

Report Suricata and Zeek independently, because their transformation paths,
event structures, and retained fields differ. Do not sum them.

- Suricata reduction: as Option A (clean, the canonical C0→C1→C2→C3 chain).
- Zeek reduction: as Option B, reported separately and clearly labelled, with
  the header-rewrite limitation stated.

This is the most defensible approach supported by preserved data: it reports
every metric against the exact source stream that was transformed, never mixes
scopes, and never double-counts.

## 5. Chosen method and formulas

**Suricata (primary):**

- `suricata_raw_bytes` = size(`raw-runs/<run>/suricata/eve.json`)
- `suricata_c1_bytes` = size(`transformed-runs/<run>/suricata/C1-pseudonymised.jsonl`)
- `suricata_c2_bytes` = size(`transformed-runs/<run>/suricata/C2-minimised-pseudonymised.jsonl`)
- `suricata_c3_bytes` = size(`transformed-runs/<run>/suricata/C3-aggregated-60s.jsonl`)
- `suricata_c1_reduction_pct = 100 × (1 − c1/raw)` (undefined if raw == 0)
- `suricata_c2_reduction_pct = 100 × (1 − c2/raw)`
- `suricata_c3_reduction_pct = 100 × (1 − c3/raw)`

**Zeek (secondary, only where the transformed logs exist):**

- `zeek_raw_bytes` = Σ size(`raw-runs/<run>/zeek/{dns,conn,http}.log` that exist)
- `zeek_c1_bytes` = Σ size(`transformed-runs/<run>/zeek/{dns,conn,http}.log.C1` that exist)
- `zeek_c2_bytes` = Σ size(`transformed-runs/<run>/zeek/{dns,conn,http}.log.C2` that exist)
- `zeek_c1_reduction_pct = 100 × (1 − c1/raw)` (undefined if raw == 0)
- `zeek_c2_reduction_pct = 100 × (1 − c2/raw)`
- Zeek has no C3 (not produced by the pipeline).

If a baseline is zero bytes or the source file is missing, the percentage is
marked **undefined** (empty/`null`), never 0 and never fabricated.

## 6. Metric distinctions (must not be conflated)

1. **Byte-volume reduction** — the source-specific formulas above (file sizes).
2. **Record-count reduction** — separate; already present as `source_events`,
   `c1_records`, `c2_records`, `c3_windows` (Suricata) in the run log and
   transformation metadata. Computed from record counts, **not** bytes.
3. **Field reduction** — a documented field inventory (C2 retains an explicit
   field-selection policy; see `suricata_c2` in `transform_telemetry.py`); not a
   byte number.
4. **Identifier exposure** — the validation `check_privacy` scan for raw
   IPs/domain in transformed outputs.
5. **Linkability** — the `linkability.assess` mapping-consistency checks.
6. **Aggregation** — the C3 60-second windowing behaviour.

Byte-volume reduction is **not** a direct privacy-risk reduction measure; it is
a telemetry-size reduction only.

## 7. C1 inclusion

C1 is included for Suricata because a clean, field-identical, same-structure
baseline (`eve.json`) and preserved C1 output exist. Note that Suricata C1 is
**larger** than `eve.json` in every run (HMAC tokens are longer than IPv4
addresses), so `suricata_c1_reduction_pct` is negative — this is a correct,
expected observation (pseudonymisation adds identifier-length overhead).

Zeek C1 is included but labelled with the header-rewrite caveat.

## 8. Reporting rules

- Report per-run values first; never pool all scenarios into one percentage.
- Report mean and range only within a scenario (and only for comparable metrics).
- Preserve individual run values alongside summaries.
- Keep `c0_records` (Suricata source-event count) strictly separate from byte
  metrics.
- Label every recalculated metric as derived from preserved evidence, and
  retain the historical combined-scope values as `_legacy_combined` columns so
  the old numbers are not silently replaced.

## 9. What will not change

- Raw captures, transformed outputs, validation reports, run history, and
  `SHA256SUMS.txt` are untouched.
- The 29-run compliant dataset and the legacy S2/R1 + failed S4/R1 exclusions
  are unchanged.
- The transformation pipeline is not modified; only metric *reporting* is
  corrected.
