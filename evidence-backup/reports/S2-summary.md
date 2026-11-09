# S2 Summary — DNS Queries and Responses (R1–R5)

Generated 2026-10-21. Covers the five S2 repetitions, distinguishing legacy and
current-pipeline runs.

## Key distinction

| Repetition | HMAC key | Transformation | Capture boundary |
|---|---|---|---|
| R1 | replacement key (original lost) | legacy `transform-S2-R1-corrected.py` | unclean (readiness + run) |
| R2 | `e04d6b0475fd` | `transform_telemetry.py` v2.0.0 | clean |
| R3 | `e04d6b0475fd` | `transform_telemetry.py` v2.0.0 | clean |
| R4 | `e04d6b0475fd` | `transform_telemetry.py` v2.0.0 | clean |
| R5 | `e04d6b0475fd` | `transform_telemetry.py` v2.0.0 | clean |

R1 was produced before the current pipeline and is **not numerically comparable**
to R2–R5. It used a recovered replacement HMAC key, a different (legacy)
transformation script, a different traffic pattern, an unclean capture boundary,
and its Zeek logs were not transformed. R2–R5 use the current key and pipeline
and are the comparable clean set.

## Event counts

| Repetition | Zeek DNS queries | Zeek udp:53 | Suricata DNS events | Suricata source events | C3 windows |
|---|---|---|---|---|---|
| R1 | 2 (A-only, empty answers) | 2 | 8 | 275 | 4 (unclean) |
| R2 | 6 | 3 | 12 | 17 | 1 |
| R3 | 6 | 3 | 12 | 18 | 1 |
| R4 | 6 | 3 | 12 | 17 | 1 |
| R5 | 6 | 3 | 12 | 17 | 1 |

R2–R5 are consistent: 6 DNS queries (3 A + 3 AAAA), 3 udp:53 connections, and 12
Suricata DNS events (6 query + 6 answer). The only variation is the total
Suricata source-event count (17 vs 18), caused by one extra non-DNS flow/stats
event in R3 — not by the DNS traffic itself.

## Volume measurements (bytes)

| Repetition | Raw (C0) | C1 | C2 | C3 |
|---|---|---|---|---|
| R1 | n/a (legacy dir) | n/a | n/a | n/a |
| R2 | 31949 | 22271 | 3144 | 236 |
| R3 | 33107 | 22727 | 3144 | 236 |
| R4 | 31720 | 22276 | 3144 | 236 |
| R5 | 31958 | 22279 | 3144 | 236 |

C2 (3144 bytes) and C3 (236 bytes) are byte-identical across R2–R5. Raw and C1
sizes vary by <5% because of Suricata's per-run flow/stat event content
(timestamps, flow IDs), not because of differing DNS evidence.

## Field minimisation

C2 retains only the explicit operational field-selection policy: timestamp,
event type, pseudonymised source/destination IP, protocol, destination port, DNS
type, query type, response code, opcode, and recursion/authoritative flags. C3
further aggregates into 60-second windows. This is identical across R2–R5.

## Identifier-exposure checks

Targeted checks for `10.10.10.10`, `10.10.10.20`, `10.10.10.30`, `10.10.10.40`,
and `probe.pp-nsmf.test` found **no occurrences** in C1, C2, or C3 for R2–R5.
Pseudonym linkability is consistent (one token per source/destination IP within
each run).

## 60-second aggregation

R2–R5 each produced exactly one 60-second window (all 12 DNS events fall inside
one window). R1 produced 4 windows because its capture was not clean and spanned
readiness checks.

## Validation status

R2, R3, R4, R5: **PASS** (all required checks passed).

## Deviations

- R1: legacy run — replacement HMAC key, legacy transform script, unclean
  boundary, Zeek not transformed. Excluded from clean comparison.
- R3: one extra non-DNS Suricata source event (17 → 18). No impact on DNS event
  counts or transformed outputs.

## Evidence paths

- Raw evidence: `evidence-backup/raw-runs/S2-R2/`, `.../S2-R3/`, `.../S2-R4/`, `.../S2-R5/`
- Legacy R1 raw evidence: `evidence-backup/S2-R1-zeek/`, `evidence-backup/S2-R1-suricata/`
- Transformed datasets: `evidence-backup/transformed-runs/S2-R{2,3,4,5}/`
- Checksums: `evidence-backup/SHA256SUMS.txt` (48 entries, all verified)
- Run log: `evidence-backup/protocol/experiment-run-log.csv`
- Per-run reports: `evidence-backup/reports/S2-R{2,3,4,5}.md` and `.validation.json`
- Aggregate metrics: `evidence-backup/reports/aggregate-metrics.csv`
