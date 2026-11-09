# PP-NSMF Transformation Version Changelog

This document records the functional differences between transformation
versions 2.0.0, 2.1.0, and 2.2.0. It is reconstructed from preserved evidence
because the project has no formal `CHANGELOG` file and is not under version
control. Every statement below is traceable to a preserved file (listed in
"Evidence references").

## Summary

| Version | Scenarios | Functional change |
|---------|-----------|-------------------|
| **2.0.0** | S1, S2 | Baseline pipeline: pseudonymisation (C1), minimisation (C2), and 60-second aggregation (C3) for **`dns` and `http`** event types; Zeek C1/C2 for `dns.log`/`conn.log`/`http.log`. |
| **2.1.0** | S3 | Added **`flow`** event-type support to Suricata C2 (timestamp, src_ip, dest_ip, proto, dest_port, state) and C3 (`flow_ports`, `flow_states` counters), for port-scan flow telemetry. |
| **2.2.0** | S4–S6 | (1) Added **`alert`** event-type support to C2 (`signature_id`, `signature`, `severity`, `category`) and C3 (`alert_signatures`, `alert_count`). (2) Fixed a privacy defect in `suricata_c1` that did not pseudonymise nested `flow.src_ip`/`flow.dest_ip` inside alert events — the cause of the failed S4/R1 raw-IP leak. |

Each increment **added** support for an additional Suricata event type and left
the handling of previously supported event types unchanged. The C2/C3
field-selection policy is defined per event type, so cross-scenario byte-volume
differences reflect workload and event-type composition, not a changed
transformation policy.

## Detailed changes

### 2.0.0 (S1, S2)

- **C1 (Suricata):** pseudonymises top-level `src_ip`, `dest_ip`, `dest_host`;
  the `dns` object (`rrname`, `answers[*].rrname`, `answers[*].rdata`, `grouped`);
  and the `http` object (`hostname`, `url`).
- **C2 (Suricata):** minimises `dns` and `http` event types only.
- **C3 (Suricata):** aggregates `dns` and `http` event types only.
- **Zeek:** produces `<log>.C1` (pseudonymised) and `<log>.C2` (identifier
  columns dropped) for `dns.log`, `conn.log`, and `http.log`.

Evidence that 2.0.0 did **not** emit `flow`: the S1 run has `source_events = 17`
(5 http + 5 flow + 5 fileinfo + 2 stats) but `c2_records = 5` (http only) — the
flow/fileinfo/stats events were dropped.

### 2.1.0 (S3)

- Added `flow` handling to Suricata C2 and C3. The C2 flow record retains
  `timestamp`, `event_type`, `src_ip`, `dest_ip`, `proto`, `dest_port`, and
  `state`; C3 adds `flow_ports` and `flow_states` per 60-second window.

### 2.2.0 (S4–S6)

- Added `alert` handling to Suricata C2 and C3. The C2 alert record retains
  `timestamp`, `event_type`, `src_ip`, `dest_ip`, `proto`, `dest_port`,
  `signature_id`, `signature`, `severity`, and `category`; C3 adds
  `alert_signatures` and `alert_count` per 60-second window.
- Fixed `suricata_c1` to pseudonymise the nested `flow` object (`flow.src_ip`,
  `flow.dest_ip`) that Suricata embeds inside alert events. Before this fix, raw
  IPs in alert-embedded flow sub-objects leaked into C1, which caused the first
  S4/R1 attempt to fail validation.

## Within-version note

The failed S4/R1 attempt's `transformation-metadata.json` also records
`transformation_version = 2.2.0`. The nested-flow-IP fix was applied to the
2.2.0 code before any successful S4 output was finalised, so the
failed-versus-fixed S4/R1 difference is a **within-version code fix**, not a
separate version bump.

## Manuscript-ready paragraph

> The transformation pipeline evolved in three increments, each adding support
> for an additional Suricata event type while leaving the handling of
> previously-supported types unchanged. Version 2.0.0 (S1, S2) established
> pseudonymisation, minimisation, and 60-second aggregation for `dns` and `http`
> events. Version 2.1.0 (S3) added `flow`-event minimisation and aggregation
> (`flow_ports`, `flow_states`) for port-scan telemetry. Version 2.2.0 (S4–S6)
> added `alert`-event minimisation and aggregation (`alert_signatures`,
> `alert_count`) and corrected a C1 defect whereby nested `flow.src_ip` and
> `flow.dest_ip` fields inside alert events were not pseudonymised (the defect
> that caused the initial S4/R1 attempt to fail). Because the C2/C3
> field-selection policy is defined per event type, cross-scenario byte-volume
> differences reflect workload and event-type composition rather than a changed
> transformation policy; within-scenario comparisons (which use a single version)
> are unaffected.

## Evidence references

- `scripts/transform_telemetry.py` — current 2.2.0 code; see `suricata_c1`
  (flow block), and the `dns`/`http`/`flow`/`alert` branches of `suricata_c2`
  and `suricata_c3`.
- `evidence-backup/transformed-runs/S1-R1/transformation-metadata.json` — 2.0.0;
  `source_events = 17` vs `c2_records = 5` (flow not emitted in 2.0.0).
- `evidence-backup/transformed-runs/S3-R1/transformation-metadata.json` — 2.1.0;
  `flow_events = 5`.
- `evidence-backup/transformed-runs/S4-R1/transformation-metadata.json` — 2.2.0;
  `alert_events = 5`, `c2_records = 15` (http + flow + alert).
- `evidence-backup/failed-runs/S4-R1/README.md` — states the 2.2.0 nested-flow-IP
  fix explicitly.
- `evidence-backup/reports/S3-summary.md` — "Transformation version: 2.1.0
  (flow-event minimisation/aggregation)".
- `evidence-backup/reports/S4-summary.md` — "Fixed in transformation 2.2.0 and
  re-run" (nested `flow.src_ip`/`flow.dest_ip` leak).
- `evidence-backup/reports/consolidated-runs.csv` — `transformation_version`
  column mapping every run to its version.
