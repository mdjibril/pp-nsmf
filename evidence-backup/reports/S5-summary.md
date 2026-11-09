# PP-NSMF S5 Summary — Periodic Beacon-like Traffic (R1–R5)

**Scenario:** S5 (periodic payload-free TCP connect to `10.10.10.20:80`, every
3 s). Transformation **2.2.0**, validator **1.1.0**, HMAC key ID
**e04d6b0475fd**.

## Result

All five repetitions (R1–R5) **PASS** validation. Each emitted 4 periodic
payload-free TCP connections (beacons) to the server.

| Run | Status | Beacon conn | Suricata flow | Alerts | C0 | C2 | C3 win | C2 red% | C3 red% |
|-----|--------|-------------|---------------|--------|----|----|--------|---------|---------|
| R1  | PASS   | 4           | 4             | 0      | 7  | 4  | 1      | 98.15   | 99.58   |
| R2  | PASS   | 4           | 4             | 0      | 6  | 4  | 1      | 97.42   | 99.42   |
| R3  | PASS   | 4           | 4             | 0      | 6  | 4  | 1      | 97.39   | 99.42   |
| R4  | PASS   | 4           | 4             | 0      | 6  | 4  | 1      | 97.42   | 99.42   |
| R5  | PASS   | 4           | 4             | 0      | 6  | 4  | 1      | 97.39   | 99.42   |

Consistent across all repetitions:

- Zeek: 4 `tcp:80` connections from `10.10.10.30` to `10.10.10.20`.
- Suricata: 4 flow events, **0 alert events** (no alert rule loaded for S5).
- Privacy: no raw identifiers in any C1/C2/C3 or Zeek C1/C2 output.
- Linkability: ok.
- C3: one 60-second window (flow events only).

## Observed traffic vs detection performance

S5 runs with the default no-rule Suricata configuration (`-S /dev/null`), so it
records **flows only** — no alerts. This is a flow/pattern observation, not a
detection result. No detection effectiveness is claimed.

## Deviation

R1 recorded one extra Suricata `stats` event (3 vs 2), yielding 7 source (C0)
events and a larger raw byte count than R2–R5 (6 C0 events). The 4 flow events
and all transformed outputs (C2 = 700 bytes, C3 = 157 bytes) are unchanged. The
variation is Suricata's periodic `stats` emission timing, not a difference in
the beacon traffic itself.

## Evidence paths

- Raw: `evidence-backup/raw-runs/S5-R{1..5}/` (7 files each).
- Transformed: `evidence-backup/transformed-runs/S5-R{1..5}/` (6 files each).
- Reports: `evidence-backup/reports/S5-R{1..5}.validation.json` / `.md` / `.json`,
  plus this `S5-summary.md`.
- Run log: `evidence-backup/protocol/experiment-run-log.csv` (**25 data rows**;
  S5 R1–R5 appended).
- Checksums: `evidence-backup/SHA256SUMS.txt` (**208 entries**, all verified;
  S1–S4 entries unchanged from the freeze).

## Limitations

- Single lab; beacon is a payload-free TCP connect, not a real C2 beacon.
- No alert rule loaded, so the run cannot and does not assess detection.
- S5 remains isolated; it is not part of the frozen S1–S4 set.
