# PP-NSMF S4 Summary — Controlled Authentication Failures (R1–R5)

**Scenario:** S4 (repeated failed HTTP Basic authentication against a lab-only
auth responder). Transformation **2.2.0**, validator **1.1.0**, HMAC key ID
**e04d6b0475fd**.

## Result

All five repetitions (R1–R5) **PASS** validation. Each generated 5 deliberately
invalid Basic-auth requests (1 s apart) to `http://10.10.10.20:8080/login`.

| Run | Status | Start (UTC) | 401 | tcp:8080 | http | alerts | C0 | C2 | C3 win | C2 red% | C3 red% |
|-----|--------|-------------|-----|----------|------|--------|----|----|--------|---------|---------|
| R1  | PASS   | 20:39:06    | 5   | 5        | 5    | 5      | 22 | 15 | 1      | 91.99   | 99.26   |
| R2  | PASS   | 20:45:44    | 5   | 5        | 5    | 5      | 22 | 15 | 1      | 91.90   | 99.25   |
| R3  | PASS   | 20:46:06    | 5   | 5        | 5    | 5      | 22 | 15 | 1      | 91.92   | 99.26   |
| R4  | PASS   | 20:46:28    | 5   | 5        | 5    | 5      | 22 | 15 | 1      | 91.99   | 99.26   |
| R5  | PASS   | 20:46:47    | 5   | 5        | 5    | 5      | 22 | 15 | 1      | 91.99   | 99.26   |

Consistent across all repetitions:

- Zeek: 5 `GET /login` (all `401`), 5 `tcp:8080` connections.
- Suricata: 5 http events (401), 5 alert events (sid 1000001), 5 flow events,
  5 fileinfo events, 2 stats events → 22 source (C0) records.
- Privacy: no raw identifiers in any C1/C2/C3 or Zeek C1/C2 output.
- Linkability: ok (attacker/server map to consistent, injective pseudonyms).
- C3: one 60-second mixed window (http/flow/alert).

## Credentials handling

- Only the synthetic account `testuser` is used; the valid password is never
  transmitted and is not a real credential.
- Deliberately invalid passwords (`wrong-password-1..5`) are sent, one per
  attempt, and are **not recorded** anywhere: verified absent from raw evidence,
  transformed data, and reports (Zeek's `password` column is `-`; Suricata does
  not extract Basic-auth credentials; the responder does not log them).
- Zeek's `http.log` extracts the synthetic username `testuser` into its
  `username` column as standard HTTP analyzer behaviour. This is a synthetic,
  non-secret account identifier, not a real credential.

## Suricata rule (flows vs alerts)

The lab-only rule `config/suricata-rules/test-auth-401.rules` (HTTP 401,
sid 1000001) is loaded for S4 only via the per-scenario `suricata_rules` path.
S1/S2/S3 do not set that field and remain unchanged (no alert rules).

The rule fires on each 401 response (5 alerts per run). This confirms the rule
loads and fires on the known pattern; it is **not** a detection-effectiveness
result (no labelled ground truth or false-positive/negative measurement).

## First attempt (failed, preserved)

The original S4/R1 attempt failed validation because `suricata_c1` did not
pseudonymise the nested `flow.src_ip`/`flow.dest_ip` embedded in Suricata alert
events, leaking raw IPs into C1. Fixed in transformation 2.2.0 and re-run. The
failed attempt is preserved at `evidence-backup/failed-runs/S4-R1/` (raw,
transformed, reports, README), and the run log records both the FAILED first
attempt and the PASS retry.

## Evidence paths

- Raw: `evidence-backup/raw-runs/S4-R{1..5}/` (9 files each).
- Transformed: `evidence-backup/transformed-runs/S4-R{1..5}/` (8 files each).
- Reports: `evidence-backup/reports/S4-R{1..5}.validation.json` / `.md` / `.json`,
  plus `S4-R1-notes.md` and this `S4-summary.md`.
- Failed archive: `evidence-backup/failed-runs/S4-R1/`.
- Run log: `evidence-backup/protocol/experiment-run-log.csv` (**20 rows**;
  6 S4 rows: R1 FAILED + R1 PASS + R2–R5 PASS).
- Checksums: `evidence-backup/SHA256SUMS.txt` (**173 entries**, all verified).

## Limitations

- Single lab; the auth endpoint is a minimal single-account Basic-auth
  responder, not a production authentication service.
- The alert rule matches any HTTP 401 by construction; no detection
  effectiveness is claimed from these controlled rule-firing checks.
