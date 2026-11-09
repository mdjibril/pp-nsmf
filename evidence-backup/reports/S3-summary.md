# PP-NSMF S3 Summary (Controlled Port Scan)

Repetitions R1–R5, scenario S3 (attacker performs a controlled five-port TCP
connect scan of the server).

## Result

| Rep | Status | Scan conn | Flow events | Alerts | C2 records | C3 windows | Linkability |
|---|---|---|---|---|---|---|---|
| R1 | PASS | 5 | 5 | 0 | 5 | 1 | ok |
| R2 | PASS | 5 | 5 | 0 | 5 | 1 | ok |
| R3 | PASS | 5 | 5 | 0 | 5 | 1 | ok |
| R4 | PASS | 5 | 5 | 0 | 5 | 1 | ok |
| R5 | PASS | 5 | 5 | 0 | 5 | 1 | ok |

All five repetitions passed. Each run produced 5 Zeek `conn.log` connection
attempts from `10.10.10.30` to `10.10.10.20` (4 `REJ` closed ports + 1 `SF`
open port 80), 5 Suricata `flow` events (one per port), 2 `stats` events, and
0 `alert` events. Every scanned port (`21, 22, 80, 443, 8080`) was observed
exactly once per run.

## Software, keys, and versions (identical across R1–R5)

- Transformation version: **2.1.0** (flow-event minimisation/aggregation)
- Validator version: **1.1.0**
- HMAC key ID: **e04d6b0475fd**
- Scan method: payload-free `bash /dev/tcp` connect, 1 s timeout, 0.5 s interval

No software, transformation-version, or key differences between repetitions.

## Volume and event variation

| Rep | Raw bytes | C1 bytes | C2 bytes | C3 bytes | Raw→C2 | Raw→C3 |
|---|---|---|---|---|---|---|
| R1 | 27399 | 18598 | 878 | 194 | 96.80% | 99.29% |
| R2 | 27862 | 18594 | 878 | 194 | 96.85% | 99.30% |
| R3 | 27861 | 18593 | 878 | 194 | 96.85% | 99.30% |
| R4 | 27630 | 18596 | 878 | 194 | 96.82% | 99.30% |
| R5 | 27941 | 18594 | 878 | 194 | 96.86% | 99.31% |

- Raw source events: constant at 7 per run (5 flow + 2 stats).
- C2 records: constant at 5; C2 bytes constant at 878.
- C3 windows: constant at 1; C3 bytes constant at 194.
- Raw bytes vary (27399–27941) and C1 bytes vary by a few bytes; this is
  timestamp/UID variation only and is not a deviation.

## Flows vs alerts

All runs used Suricata with no alert rules (`-S /dev/null`); the scan is
therefore measured as **observed flows**, not an IDS **detection**. The
`alert_count` was 0 in every run. No detection effectiveness is claimed — S3
has no validated scan detector or labelled ground truth.

## Deviations and failed runs

None. All five repetitions are shown above; nothing was silently excluded.

## Timestamps

- R1: 2026-10-21T20:12:36Z
- R2: 2026-10-21T20:18:35Z
- R3: 2026-10-21T20:18:52Z
- R4: 2026-10-21T20:19:09Z
- R5: 2026-10-21T20:19:33Z
