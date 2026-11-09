# PP-NSMF S1 Summary (Normal Web Traffic)

Repetitions R1–R5, scenario S1 (normal web traffic: client issues 5 HTTP GET
requests to the busybox `nc` responder at `10.10.10.20:80`).

## Result

| Rep | Status | HTTP req | Suricata HTTP | C0 records | C2 records | C3 windows | Status codes | Linkability |
|---|---|---|---|---|---|---|---|---|
| R1 | PASS | 5 | 5 | 17 | 5 | 1 | 200 × 5 | ok |
| R2 | PASS | 5 | 5 | 17 | 5 | 1 | 200 × 5 | ok |
| R3 | PASS | 5 | 5 | 17 | 5 | 1 | 200 × 5 | ok |
| R4 | PASS | 5 | 5 | 17 | 5 | 1 | 200 × 5 | ok |
| R5 | PASS | 5 | 5 | 17 | 5 | 1 | 200 × 5 | ok |

All five repetitions passed. Each run produced 5 Zeek HTTP requests, 5 tcp:80
connections, 5 Suricata HTTP EVE events, 17 raw EVE source events
(5 http + 5 flow + 5 fileinfo + 2 stats), 5 C2 records, and 1 C3 60-second
window. Every HTTP response was `200 OK`.

## Software, keys, and versions (identical across R1–R5)

- Transformation version: **2.0.0**
- Validator version: **1.1.0**
- HMAC key ID: **e04d6b0475fd** (same key for all five runs)
- HTTP responder: busybox `nc -lk -p 80 -e /tmp/http_responder.sh`
  (`scripts/http_responder.sh`), served the same fixed HTML page.
- Capture: Zeek and Suricata on `eth0`, clean per-run directories.

No software, transformation-version, or key differences were observed between
the five repetitions.

## Volume reduction

| Rep | Raw bytes | C1 bytes | C2 bytes | C3 bytes | Raw→C2 | Raw→C3 |
|---|---|---|---|---|---|---|
| R1 | 36544 | 23888 | 1065 | 180 | 97.09% | 99.51% |
| R2 | 36552 | 23894 | 1065 | 180 | 97.09% | 99.51% |
| R3 | 36390 | 23887 | 1065 | 180 | 97.07% | 99.51% |
| R4 | 36558 | 23891 | 1065 | 180 | 97.09% | 99.51% |
| R5 | 36149 | 23885 | 1065 | 180 | 97.05% | 99.50% |

C2 and C3 sizes are constant (1065 and 180 bytes). Raw and C1 sizes vary by a few
bytes because timestamps and connection UIDs differ between runs; the variation
is not a deviation.

## Capture conditions and timestamps

All runs used the same capture boundaries (clean capture directories, graceful
stop, SHA-256 copy verification) and the same traffic timing (5 requests at
1-second intervals). Actual start timestamps:

- R1: 2026-10-21T18:09:52Z
- R2: 2026-10-21T19:35:48Z
- R3: 2026-10-21T19:36:19Z
- R4: 2026-10-21T19:37:20Z
- R5: 2026-10-21T19:37:47Z

## Deviations and failed runs

No deviations and no failed runs. All five repetitions are included above;
nothing was silently excluded.

## Detection effectiveness

S1 has no validated alert-based detector and no labelled ground truth. These
runs do **not** establish detection effectiveness; they measure traffic
generation, event observation, pseudonymisation, minimisation, aggregation, and
privacy only.
