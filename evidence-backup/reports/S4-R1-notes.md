# PP-NSMF S4/R1 Notes (Controlled Authentication Failures)

## Experiment definition

- Source: Attacker-1 (`10.10.10.30`) → destination: POC-SERVER-1 (`10.10.10.20`).
- Protocol: HTTP/1.1 with HTTP Basic authentication.
- Endpoint: `http://10.10.10.20:8080/login` (lab-only BusyBox nc responder).
- Attempts: 5, each with a deliberately invalid password, 1 s apart.
- Duration: ~20 s (capture boundaries inclusive).
- Synthetic test account: username `testuser`; the valid password is never
  transmitted and is not a real credential.

## Suricata rule (resolving the no-alerts limitation)

A lab-only detection rule was added and loaded for this run:

- `config/suricata-rules/test-auth-401.rules` (deployed to the Suricata node at
  `/etc/suricata/rules/test-auth-401.rules`).
- Rule: alert on HTTP status `401` (`sid:1000001`).

The controller now reads a per-scenario `suricata_rules` path and passes it to
`capture_manager.start_suricata` (which otherwise uses `-S /dev/null`). S1/S2/S3
are unchanged: their scenario configs do not set `suricata_rules`, so they still
run with no alert rules.

## Flows vs alerts

With the rule loaded, the run produced **5 alert events** (one per 401
response), alongside 5 http events, 5 flow events, 5 fileinfo events, and 2
stats events. This confirms the rule fires on the known 401 pattern; it is a
rule-loading/firing check, not a detection-effectiveness result. No detection
effectiveness is claimed (no labelled ground truth or false-positive/negative
measurement).

## First attempt (failed, preserved)

The first S4/R1 attempt failed validation because `suricata_c1` did not
pseudonymise the nested `flow.src_ip`/`flow.dest_ip` embedded in Suricata alert
events, leaking raw IPs into C1. The bug was fixed in transformation 2.2.0 and
the run re-executed. The failed attempt is preserved under
`evidence-backup/failed-runs/S4-R1/` (raw + transformed + reports + README), and
the run log records both the FAILED first attempt and the successful retry.

## Validation outcome

- Zeek: 5 `GET /login` requests, all `401`; 5 `tcp:8080` connections.
- Suricata: 5 http events (401), 5 alert events (sid 1000001).
- Privacy: no raw identifiers in any C1/C2/C3 or Zeek C1/C2 output.
- Linkability: ok (attacker/server each map to consistent, injective pseudonyms).
- C3: one 60-second window (mixed http/flow/alert); reduction 91.99% (C2) and
  99.26% (C3).

## Limitations

- Single repetition (R1); R2–R5 not yet run.
- The auth endpoint is a minimal single-account Basic-auth responder, not a
  production authentication service.
- The alert rule matches any HTTP 401, so it fires on the synthetic failures by
  construction; this does not demonstrate real-world brute-force detection.
- Credentials are synthetic; no real passwords or production services are used.
