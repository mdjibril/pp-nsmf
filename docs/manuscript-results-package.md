# PP-NSMF Manuscript-Ready Results Package

Prepared 2026-10-21 for the paper
*"Privacy-Preserving Network Security Monitoring: A Framework for Balancing
Cybersecurity and Data Protection in Nigerian Organisations."*

This package converts the corrected, validated results into an auditable basis
for the Results and Discussion sections. It adds no new experiments and does not
modify evidence. Corrected byte-volume claims use `aggregate-metrics-v2.csv` and
the source-scoped definitions in `docs/metric-scope-resolution-*.md`; the
historical `aggregate-metrics.csv` is preserved unchanged as historical analysis.

## 1. Dataset freeze

Compliant dataset = **29 successful runs**, one row per run, no duplicates:

| Scenario | Compliant runs | n |
|----------|----------------|---|
| S1 | R1–R5 | 5 |
| S2 | R2–R5 | 4 |
| S3 | R1–R5 | 5 |
| S4 | R1–R5 | 5 |
| S5 | R1–R5 | 5 |
| S6 | R1–R5 | 5 |

**Excluded from compliant numerical comparison** (evidence retained):

- **Legacy S2/R1** — replacement HMAC key, legacy transform script, unclean
  capture boundary, untransformed Zeek logs. Preserved under
  `evidence-backup/S2-R1-zeek/` and `evidence-backup/S2-R1-suricata/`.
- **Failed first attempt of S4/R1** — nested `flow.src_ip`/`flow.dest_ip` leak in
  C1; fixed in transform 2.2.0. Preserved under `evidence-backup/failed-runs/S4-R1/`.

Versions: transformation **2.0.0** (S1, S2), **2.1.0** (S3), **2.2.0** (S4–S6);
validator **1.1.0**; HMAC key ID **e04d6b0475fd** (single key, all compliant runs).

## 2. Validated metric definitions

The reduction metric is source-specific (Zeek and Suricata are never combined):

`reduction_pct = 100 × (1 − transformed_bytes / same_source_raw_bytes)`

- **C0** raw baseline = `suricata/eve.json` only (the sole Suricata file the
  pipeline transforms). Suricata `fast.log`, `stats.log`, `suricata.log` and all
  Zeek auxiliary logs are **not** part of any baseline.
- **C1** = pseudonymised (HMAC-SHA256), field-identical to C0 except identifiers.
- **C2** = minimised (explicit field selection) + pseudonymised.
- **C3** = C2 aggregated into 60-second windows.
- Byte counts are file sizes (`st_size`); percentages are **byte-volume
  reductions only**.

Definitions were confirmed directly against `scripts/metrics.py`,
`scripts/transform_telemetry.py`, and `scripts/validate_results.py`. No field or
formula differs from the specification in `docs/metric-scope-resolution-proposal.md`.

## 3. Table 1 — Experimental design and compliant runs

| Scenario | Workload | Traffic-generation method | Repetitions | Compliant n | Configuration note |
|----------|----------|---------------------------|-------------|-------------|--------------------|
| S1 | 5 HTTP GET → 200 OK | busybox `nc` HTTP responder (`http_responder.sh`), client GETs | R1–R5 | 5 | tcp 80; no alert rule |
| S2 | 6 DNS queries (3 A + 3 AAAA) | DNS responder (`dns_responder.py`), client queries | R2–R5 | 4 | udp 53; no alert rule; R1 legacy |
| S3 | 5-port TCP connect scan | payload-free `bash /dev/tcp` connect (1 s timeout) | R1–R5 | 5 | ports 21,22,80,443,8080; `-S /dev/null` |
| S4 | 5 invalid Basic-auth requests | auth responder at `:8080/login` | R1–R5 | 5 | HTTP-401 rule sid 1000001 loaded |
| S5 | 4 periodic payload-free TCP connects (3 s) | `generate_periodic_beacon` | R1–R5 | 5 | tcp 80; `-S /dev/null` |
| S6 | 65,536-byte NUL bulk transfer | `generate_bulk_transfer` + `bulk_receiver.sh` | R1–R5 | 5 | tcp 9999; `-S /dev/null` |

All client/server traffic is synthetic, non-sensitive, and confined to the lab
(10.10.10.10 client, 10.10.10.20 server, 10.10.10.30 attacker, 10.10.10.40 DNS).

## 4. Table 2 — Suricata telemetry byte-volume results

Baseline = `suricata/eve.json` (bytes). Mean [min–max] over compliant runs.

| Scenario | n | C0 raw | C1 bytes | C2 bytes | C3 bytes | C1 red% | C2 red% | C3 red% |
|----------|---|--------|----------|----------|----------|---------|---------|---------|
| S1 | 5 | 23439 [23435–23444] | 23889 [23885–23894] | 1065 | 180 | −1.92 | 95.46 | 99.23 |
| S2 | 4 | 22105 [21977–22475] | 22388 [22271–22727] | 3144 | 236 | −1.29 [−1.34–−1.12] | 85.78 [85.69–86.01] | 98.94 [98.93–98.95] |
| S3 | 5 | 18525 [18523–18528] | 18595 [18593–18598] | 878 | 194 | −0.38 | 95.26 | 98.95 |
| S4 | 5 | 27870 [27692–27958] | 28505 [28327–28593] | 3405 | 313 | −2.28 [−2.29–−2.27] | 87.78 [87.70–87.82] | 98.88 [98.87–98.88] |
| S5 | 5 | 19503 [17943–25740] | 19559 [17999–25796] | 700 | 157 | −0.29 [−0.31–−0.22] | 96.34 [96.10–97.28] | 99.18 [99.13–99.39] |
| S6 | 5 | 11526 [8406–16207] | 11540 [8420–16221] | 177 | 159 | −0.14 [−0.17–−0.09] | 98.30 [97.89–98.91] | 98.47 [98.11–99.02] |

Notes: a single value means constant across runs (sd = 0). C2 and C3 are
byte-identical across repetitions within each scenario; raw/C1 variation is
timestamp/UID content only. The large raw-byte (and hence reduction) spread in
S5 and S6 is driven by Suricata's periodic `stats`-event emission timing
(S5-R1 and S6-R4/R5 carry one extra `stats` event), not by workload differences.
**C1 is negative in every run** because HMAC
pseudonym tokens (18 chars) are longer than IPv4 addresses (≤15 chars), so
pseudonymisation *adds* volume rather than reducing it. C2 reduction is
minimisation + pseudonymisation; C3 reduction is minimisation + pseudonymisation
+ 60-second aggregation.

### Table 2b — Per-run spread and stability (source-matched Suricata)

Bytes are reported as mean [min–max]; reduction percentages as mean [min–max]
with population SD in parentheses. A single value means constant across runs
(SD = 0).

| Scenario | n | C0 raw (B) | C1 (B) | C2 (B) | C3 (B) | C2 red% | C3 red% |
|----------|---|------------|--------|--------|--------|---------|---------|
| S1 | 5 | 23439 [23435–23444] | 23889 [23885–23894] | 1065 | 180 | 95.46 (0.00) | 99.23 (0.00) |
| S2 | 4 | 22105 [21977–22475] | 22388 [22271–22727] | 3144 | 236 | 85.78 [85.69–86.01] (0.14) | 98.94 [98.93–98.95] (0.01) |
| S3 | 5 | 18525 [18523–18528] | 18595 [18593–18598] | 878 | 194 | 95.26 (0.00) | 98.95 (0.00) |
| S4 | 5 | 27870 [27692–27958] | 28505 [28327–28593] | 3405 | 313 | 87.78 [87.70–87.82] (0.05) | 98.88 [98.87–98.88] (0.00) |
| S5 | 5 | 19503 [17943–25740] | 19559 [17999–25796] | 700 | 157 | 96.34 [96.10–97.28] (0.47) | 99.18 [99.13–99.39] (0.10) |
| S6 | 5 | 11526 [8406–16207] | 11540 [8420–16221] | 177 | 159 | 98.30 [97.89–98.91] (0.50) | 98.47 [98.11–99.02] (0.45) |

C2 and C3 byte sizes are byte-identical across repetitions within each scenario
(no range shown). The larger C0/C1 raw-byte range (and hence reduction spread)
in S5 and S6 is driven by Suricata `stats`-event emission timing (S5-R1 and
S6-R4/R5 carry one extra `stats` event), not by workload differences. SD is the
population standard deviation over the compliant runs in each scenario.

## 5. Table 3 — Record counts and aggregation (Suricata source events)

| Scenario | n | C0 records | C1 records | C2 records | C3 windows |
|----------|---|-----------|-----------|-----------|------------|
| S1 | 5 | 17 | 17 | 5 | 1 |
| S2 | 4 | 17.25 [17–18] | 17.25 [17–18] | 12 | 1 |
| S3 | 5 | 7 | 7 | 5 | 1 |
| S4 | 5 | 22 | 22 | 15 | 1 |
| S5 | 5 | 6.2 [6–7] | 6.2 [6–7] | 4 | 1 |
| S6 | 5 | 2.4 [2–3] | 2.4 [2–3] | 1 | 1 |

Record-count changes and byte-volume changes are **different metrics**: record
counts drop from C0→C2 because C2 selects a subset of event types/records (e.g.
drops Suricata `stats` events), whereas byte-volume changes additionally reflect
field minimisation and identifier-length changes within retained records. The
record-count reductions are: S1 17→5, S2 17.25→12, S3 7→5, S4 22→15, S5 6.2→4,
S6 2.4→1 (C0→C2). Every run produced exactly **one C3 60-second window**.

## 6. Table 4 — Privacy-related validation outcomes

| Scenario | n | Raw-identifier absence (no-leak) | Pseudonym linkability | Checks performed |
|----------|---|----------------------------------|-----------------------|------------------|
| S1 | 5 | 5/5 PASS | 5/5 ok | src_ip, dest_ip, http.hostname |
| S2 | 4 | 4/4 PASS | 4/4 ok | src_ip, dest_ip, dns.rrname |
| S3 | 5 | 5/5 PASS | 5/5 ok | src_ip, dest_ip |
| S4 | 5 | 5/5 PASS | 5/5 ok | src_ip, dest_ip, http.hostname |
| S5 | 5 | 5/5 PASS | 5/5 ok | src_ip, dest_ip |
| S6 | 5 | 5/5 PASS | 5/5 ok | src_ip, dest_ip |

- **Identifier exposure**: validator scans C1/C2/C3 (Suricata) and C1/C2 (Zeek)
  for the raw identifiers `10.10.10.10`, `10.10.10.20`, `10.10.10.30`,
  `10.10.10.40`, and `probe.pp-nsmf.test`. **29/29 runs had no raw identifiers.**
- **Linkability**: mapping-consistency checks confirm C1/C2 pseudonyms are
  injective and consistent (one token per distinct raw value). Overall status
  "ok" in **29/29 runs**. C3 and Zeek `.C2` linkability are "not_applicable"
  (identifiers removed by minimisation/aggregation), which is expected.
- **Limitations**: a passing validator proves the checked identifiers are absent
  and the checked mappings are consistent; it is **not** a formal proof of
  complete privacy or anonymity. Pseudonymisation is *linkable*, not
  anonymising. The check is limited to the enumerated identifiers and field
  inventory, not an exhaustive deanonymisation-resistance analysis.

## 7. Table 5 — Scenario-specific observed event counts (per run)

| Scenario | Observed metric | Zeek | Suricata |
|----------|-----------------|------|----------|
| S1 | HTTP requests / HTTP events | 5 | 5 |
| S2 | DNS queries / DNS events | 6 | 12 |
| S3 | Scan connections / flow events | 5 | 5 |
| S4 | 401 auth attempts / HTTP events | 5 | 5 |
| S5 | Beacon connections / flow events | 4 | 4 |
| S6 | Bulk connections / flow events (orig_bytes) | 1 (65536) | 1 |

These counts are scenario-specific and are **not** interchangeable across
scenarios (they measure different workloads).

## 8. Table 6 — Detection scope (rule firing, not detection effectiveness)

| Scenario | Alert rule | Alerts/run | Interpretation |
|----------|------------|------------|----------------|
| S1 | none | not recorded | no detection result |
| S2 | none | not recorded | no detection result |
| S3 | `-S /dev/null` (flows only) | 0 | flow observation only |
| S4 | HTTP-401, sid 1000001 | 5 | configured rule firing |
| S5 | `-S /dev/null` (flows only) | 0 | flow observation only |
| S6 | `-S /dev/null` (flows only) | 0 | flow observation only |

S4's 5 alerts per run confirm the configured HTTP-401 rule loads and fires on
the known 401 pattern; this is **not** a detection-effectiveness result (no
labelled ground truth, no false-positive/negative measurement). S3/S5/S6 have no
detection result.

## 9. Supplementary descriptive statistics (full)

Per-scenario mean [min–max], standard deviation where > 0.

| Metric | S1 (n=5) | S2 (n=4) | S3 (n=5) | S4 (n=5) | S5 (n=5) | S6 (n=5) |
|--------|----------|----------|----------|----------|----------|----------|
| Suricata C0 bytes | 23439 [23435–23444] sd 3.16 | 22105 [21977–22475] sd 213.8 | 18525 [18523–18528] sd 1.79 | 27870 [27692–27958] sd 102.2 | 19503 [17943–25740] sd 3118.5 | 11526 [8406–16207] sd 3821.3 |
| Suricata C1 bytes | 23889 [23885–23894] sd 3.16 | 22388 [22271–22727] sd 195.6 | 18595 [18593–18598] sd 1.79 | 28505 [28327–28593] sd 102.2 | 19559 [17999–25796] sd 3118.5 | 11540 [8420–16221] sd 3821.3 |
| Suricata C2 bytes | 1065 (sd 0) | 3144 (sd 0) | 878 (sd 0) | 3405 (sd 0) | 700 (sd 0) | 177 (sd 0) |
| Suricata C3 bytes | 180 (sd 0) | 236 (sd 0) | 194 (sd 0) | 313 (sd 0) | 157 (sd 0) | 159 (sd 0) |
| C1 red% | −1.92 (sd 0) | −1.29 [−1.34–−1.12] sd 0.10 | −0.38 (sd 0) | −2.28 [−2.29–−2.27] sd 0.01 | −0.29 [−0.31–−0.22] sd 0.04 | −0.14 [−0.17–−0.09] sd 0.04 |
| C2 red% | 95.46 (sd 0) | 85.78 [85.69–86.01] sd 0.14 | 95.26 (sd 0) | 87.78 [87.70–87.82] sd 0.05 | 96.34 [96.10–97.28] sd 0.47 | 98.30 [97.89–98.91] sd 0.50 |
| C3 red% | 99.23 (sd 0) | 98.94 [98.93–98.95] sd 0.01 | 98.95 (sd 0) | 98.88 [98.87–98.88] sd 0 | 99.18 [99.13–99.39] sd 0.10 | 98.47 [98.11–99.02] sd 0.45 |
| C0 records | 17 (sd 0) | 17.25 [17–18] | 7 (sd 0) | 22 (sd 0) | 6.2 [6–7] | 2.4 [2–3] |
| C2 records | 5 (sd 0) | 12 (sd 0) | 5 (sd 0) | 15 (sd 0) | 4 (sd 0) | 1 (sd 0) |
| C3 windows | 1 (sd 0) | 1 (sd 0) | 1 (sd 0) | 1 (sd 0) | 1 (sd 0) | 1 (sd 0) |

Standard deviation uses population SD over the compliant runs in each scenario.
Run-level values are preserved in `aggregate-metrics-v2.csv` and
`consolidated-runs.csv`.

## 10. Safe metric definitions for the paper

- **Byte-volume reduction (use):**
  `suricata_c2_reduction_pct = 100 × (1 − suricata_c2_bytes / suricata_raw_bytes)`,
  and likewise for C3. Baseline is `suricata/eve.json`; this is a telemetry-size
  reduction only.
- **Pseudonymisation overhead (use):** `suricata_c1_reduction_pct` is negative in
  every run (−0.14% to −2.28%), showing C1 grows because HMAC tokens are longer
  than IPv4 addresses.
- **Record-count reduction (separate):** reported from `source_events`/`c1_records`/
  `c2_records`/`c3_windows`; never mixed with byte metrics.
- **Do not combine** Zeek and Suricata byte counts into one reduction percentage.
- **Zeek byte-size changes** are confounded by the transform's log-header rewrite
  and are therefore **not** reported as a pure data-reduction measure.
- **Do not** describe byte-volume reduction as direct privacy-risk reduction, and
  **do not** equate identifier exposure, pseudonym linkability, aggregation,
  investigation utility, and detection effectiveness.

## Run-level transparency

All 29 run-level rows (corrected source-scoped metrics, legacy combined-scope
values retained as `legacy_combined_*`, record counts, observed events, and
documented deviations) are in `evidence-backup/reports/aggregate-metrics-v2.csv`
and `evidence-backup/reports/consolidated-runs.csv`. Known benign deviations
(preserved, not altered) are: S2-R3 one extra non-DNS source event; S5-R1 one
extra Suricata `stats` event; S6-R4/R5 one extra `stats` event and R4
`bytes_toserver = 68844` vs 68778.
