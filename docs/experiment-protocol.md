# PP-NSMF Experiment Protocol

This document describes the experiment design, traffic scenarios, privacy
transformation conditions, run procedure, validation, and metrics.

## 1. Objective

Evaluate a privacy-preserving network security monitoring framework that
balances cybersecurity visibility with data protection. The lab captures network
telemetry with Zeek and Suricata, then applies privacy transformations and
measures the resulting reduction in identifying data and volume.

## 2. Topology

Five Docker nodes connected through `Hub1` on `10.10.10.0/24`:

| Node | Address | Role |
|---|---|---|
| POC-CLIENT-1 | 10.10.10.10/24 | traffic generator |
| POC-SERVER-1 | 10.10.10.20/24 | target |
| Attacker-1 | 10.10.10.30/24 | security-test traffic |
| MONITOR-ZEEK-1 | 10.10.10.40/24 | Zeek monitor + DNS responder |
| MONITOR-SURI-1 | passive (no IP) | Suricata IDS, EVE JSON |

## 3. Traffic Scenarios

| ID | Scenario | Generator | Destination |
|---|---|---|---|
| S1 | Normal web traffic | client | server |
| S2 | DNS queries and responses | client | zeek (DNS responder) |
| S3 | Controlled port scan | attacker | server |
| S4 | Repeated authentication failures | attacker | server |
| S5 | Periodic beacon-like traffic | attacker | server |
| S6 | Synthetic data transfer | client | server |

S2 is fully validated end-to-end; the remaining scenarios are defined in
`experiments/scenarios.yaml` and require additional target-service setup before
they can be run.

## 4. Privacy Transformation Conditions

Each traffic run yields one raw capture (C0) and three transformed conditions:

- **C0 — Raw telemetry.** Untouched Zeek logs and Suricata EVE JSON, preserved as
  the ground-truth source.
- **C1 — Pseudonymised.** Identifying fields (IP addresses, DNS query names,
  answer values) replaced with HMAC-SHA256 pseudonyms.
- **C2 — Minimised and pseudonymised.** C1 restricted to an explicit operational
  field-selection policy.
- **C3 — Minimised, pseudonymised, aggregated.** C2 aggregated into 60-second
  windows with per-window event and query-type counts.

Pseudonymisation uses a securely stored 32-byte HMAC key (hex, mode 0600). A
non-secret key identifier (`hmac_key_id`) and transformation version are recorded
in `transformation-metadata.json`. HMAC pseudonyms are **linkable pseudonyms**,
not anonymised data.

DNS query-type counts in C3 count **query events only**, not answers.

## 5. Run Procedure

For each scenario and repetition:

1. Verify nodes, addressing, and connectivity (`verify_topology.py`).
2. Start Zeek and Suricata with clean, run-specific capture directories.
3. Record capture start time.
4. Generate the scenario traffic.
5. Record capture end time.
6. Stop captures (flushing logs).
7. Copy raw evidence from containers to the host and verify SHA-256.
8. Run the C0-C3 transformation pipeline on the verified copy.
9. Validate outputs and record metrics.
10. Append one row to the run log and generate reports.

## 6. Validation

Per run, validation checks:

- Raw and transformed record counts are consistent.
- Expected events are present (Zeek DNS/connection logs, Suricata EVE DNS events).
- Raw identifiers (10.10.10.10/20/30/40, `probe.pp-nsmf.test`) do not appear in
  C1/C2/C3.
- Pseudonymised identifiers are consistently linkable within a run.
- C3 uses 60-second windows.
- SHA-256 integrity of source and copied evidence.

Detection rate/recall, false-positive rate, precision, and F1 are computed only
when a validated detector and labelled ground truth exist. For S2 there is no
alert-based detector, so the report focuses on privacy reduction and
investigation utility rather than detection metrics.

## 7. S2/R2 Result Summary

The first validated run (S2/R2, 2026-10-21) completed end-to-end:

- 6 Zeek DNS query events, 3 UDP:53 connections, 12 Suricata DNS events.
- C1/C2/C3 generated with no raw identifiers present.
- C3 aggregated into one 60-second window: 3 A + 3 AAAA queries, 6 NOERROR
  responses, 6 query / 6 answer message types.
- C2 volume reduction 90.16%; C3 volume reduction 99.26%.
- Validation status: PASS.

## 8. Limitations

- The existing Suricata ICMP visibility rule is not a detector for all six
  scenarios; no alert-based detector is assumed for S2.
- A targeted search for known IP addresses does not prove complete anonymisation;
  the validation confirms only that the specified identifiers were removed.
- The original S2/R1 HMAC key was lost and a replacement key was generated during
  an earlier recovery; this is recorded and the replacement is not treated as
  equivalent to any earlier key.
- Linkability is validated within-run only (see `docs/linkability-validation-report.md`);
  cross-run linkability holds only for shared key + transformation version.
- The Zeek `http.log` `host` field carries `host:port` (e.g. `10.10.10.20:80`)
  and is pseudonymised as a single opaque token rather than normalised, so the
  Host header is not cross-field linkable to `dest_ip`.
