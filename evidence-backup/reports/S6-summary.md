# PP-NSMF S6 Summary — Synthetic Data Transfer (R1–R5)

**Scenario:** S6 (single synthetic bulk transfer from client `10.10.10.10` to
server `10.10.10.20:9999`). Transformation **2.2.0**, validator **1.1.0**, HMAC
key ID **e04d6b0475fd**.

## Result

All five repetitions (R1–R5) **PASS** validation. Each transferred a
deterministic, non-sensitive 65,536-byte (NUL) payload over one TCP connection.

| Run | Status | Conn | orig_bytes | Flow | bytes_toserver | Alerts | C0 | C2 | C3 win | C2 red% | C3 red% |
|-----|--------|------|-----------|------|----------------|--------|----|----|--------|---------|---------|
| R1  | PASS   | 1    | 65536     | 1    | 68778          | 0      | 2  | 1  | 1      | 98.75   | 98.88   |
| R2  | PASS   | 1    | 65536     | 1    | 68778          | 0      | 2  | 1  | 1      | 98.77   | 98.90   |
| R3  | PASS   | 1    | 65536     | 1    | 68778          | 0      | 2  | 1  | 1      | 98.77   | 98.90   |
| R4  | PASS   | 1    | 65536     | 1    | 68844          | 0      | 3  | 1  | 1      | 99.30   | 99.37   |
| R5  | PASS   | 1    | 65536     | 1    | 68778          | 0      | 3  | 1  | 1      | 99.29   | 99.36   |

Consistent across all repetitions:

- Zeek: 1 `tcp:9999` connection from `10.10.10.10` to `10.10.10.20`,
  `orig_bytes = 65536`, `resp_bytes = 0`.
- Suricata: 1 flow event, `bytes_toserver = 68778` (or 68844 for R4), 0 alerts.
- Privacy: no raw identifiers in any C1/C2/C3 or Zeek C1/C2 output.
- Linkability: ok.
- C3: one 60-second window (flow event only).

## Payload handling

The payload is 65,536 NUL bytes generated with `dd if=/dev/zero` — deterministic,
synthetic, and non-sensitive. It is discarded by the server-side receiver
(`scripts/bulk_receiver.sh`). **No payload content is stored**: Zeek and Suricata
record byte counts only (the NUL bytes themselves never appear in raw logs or
transformed output; verified).

Byte-count distinction: Zeek `orig_bytes = 65536` is the application payload;
Suricata `bytes_toserver = 68778` is wire bytes including TCP/IP overhead.

## Observed traffic vs detection performance

S6 runs with the default no-rule Suricata configuration (`-S /dev/null`), so it
records **flows only** — 0 alerts. This is a byte/flow observation, not a
detection result. No detection effectiveness is claimed.

## Deviation

R4–R5 recorded one extra Suricata `stats` event (2 vs 1), yielding 3 source (C0)
events and a larger raw byte count than R1–R3 (2 C0 events). R4's `bytes_toserver`
was 68844 (vs 68778) — a small TCP segmentation/timing difference. The 1 flow
event, 65536-byte payload, and all C2/C3 outputs (177 and 159 bytes) are
unchanged. These are Suricata stats-emission/segmentation timing variations, not
differences in the transfer itself.

## Evidence paths

- Raw: `evidence-backup/raw-runs/S6-R{1..5}/` (7 files each).
- Transformed: `evidence-backup/transformed-runs/S6-R{1..5}/` (6 files each).
- Reports: `evidence-backup/reports/S6-R{1..5}.validation.json` / `.md` / `.json`,
  plus this `S6-summary.md`.
- Run log: `evidence-backup/protocol/experiment-run-log.csv` (**30 data rows**;
  S6 R1–R5 appended).
- Checksums: `evidence-backup/SHA256SUMS.txt` (**243 entries**, all verified;
  S1–S5 entries unchanged).

## Limitations

- Single lab; the transfer is a one-directional NUL-byte stream, not realistic
  application file transfer.
- No alert rule loaded, so the run cannot and does not assess detection.
- S6 is isolated; it is not part of the frozen S1–S4 set.
