# PP-NSMF S3/R1 Notes (Controlled Port Scan)

## Experiment definition

- Source: Attacker-1 (`10.10.10.30`).
- Destination: POC-SERVER-1 (`10.10.10.20`).
- Ports scanned: `21, 22, 80, 443, 8080` (port 80 open via the HTTP responder;
  all others closed).
- Scan method: payload-free TCP connect scan. Each port is probed with
  `timeout 1 bash -c ': >/dev/tcp/<target>/<port>'`, which opens and closes the
  socket without sending application data (so no service on an open port is
  triggered). Timeout 1 s per port, 0.5 s interval between ports.
- Software: transformation **2.1.0** (adds flow-event minimisation/aggregation),
  validator **1.1.0**, HMAC key **e04d6b0475fd**.

## Observations

- Zeek `conn.log`: 5 connection attempts from `10.10.10.30` to `10.10.10.20`
  (one per scanned port); 4 `REJ` (closed) + 1 `SF` (port 80 open).
- Suricata EVE: 5 `flow` events (one per port), 2 `stats` events, and **0**
  `alert` events.

## Flows vs alerts

This run establishes that the scan produces **flows/packets observed**, not an
IDS **detection**. Suricata ran with `-S /dev/null` (no alert rules), so no
scan-alert rule was in effect; the observed `alert_count` is 0. No detection
effectiveness is claimed for S3 — there is no validated scan detector or
labelled ground truth.

## Validation

- `scan_connections_present`: true (5 connections, all 5 ports observed).
- `suricata_flow_present`: true (5 flow events).
- `alert_count`: 0.
- Linkability: ok (attacker and server each map to a single consistent,
  injective pseudonym).
- Privacy: no raw identifiers in any C1/C2/C3 or Zeek C1/C2 output.
- C3: one 60-second window; volume reduction 96.8% (C2) and 99.29% (C3).

## Limitations

- This is a single repetition (R1); repeatability across R2–R5 is not yet
  established.
- The scan is connect-only and confined to five ports; it is not a full port
  range and is not representative of broader or faster scans.
- The payload-free method avoids triggering the HTTP responder on port 80; a
  data-carrying probe would instead elicit an HTTP response and additional
  `http`/`anomaly` EVE events (this was observed and avoided during preflight).
- No scan detection rule is loaded, so the absence of alerts is expected and
  must not be read as "the scan was not detected".
