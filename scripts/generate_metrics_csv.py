#!/usr/bin/env python3
"""Generate source-scoped aggregate metrics CSV from per-run validation reports.

Version 2. Corrects the telemetry-reduction scope mismatch (see
docs/metric-scope-resolution-proposal.md and docs/metric-scope-validation.md):

  * Legacy combined-scope values are retained under `legacy_combined_*` columns.
  * Corrected Suricata- and Zeek-scoped byte-volume metrics are computed from
    preserved raw/transformed files via `metrics.compute_source_metrics`.

Writes a NEW file (`aggregate-metrics-v2.csv`) and does not overwrite the
historical `aggregate-metrics.csv`.
"""

import csv
import json
import sys
from pathlib import Path

import metrics

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence-backup"
REPORTS = EVIDENCE / "reports"
RAW_RUNS = EVIDENCE / "raw-runs"
TRANSFORMED_RUNS = EVIDENCE / "transformed-runs"
OUT = REPORTS / "aggregate-metrics-v2.csv"

FIELDS = [
    "run", "status", "zeek_queries", "suricata_dns_events",
    "http_requests", "suricata_http_events", "scan_connections",
    "beacon_connections", "suricata_flow_events", "auth_attempts",
    "suricata_alert_events", "bulk_connections", "bulk_orig_bytes", "c3_windows",
    # Historical combined-scope values (retained for traceability; scope-mismatched).
    "legacy_combined_raw_bytes", "legacy_combined_c1_bytes",
    "legacy_combined_c2_bytes", "legacy_combined_c3_bytes",
    "legacy_combined_c2_reduction_pct", "legacy_combined_c3_reduction_pct",
    # Corrected source-specific values (computed from preserved files).
    *metrics.SOURCE_METRIC_FIELDS,
    "privacy_no_leak",
]


def main():
    rows = []
    for vp in sorted(REPORTS.glob("*.validation.json")):
        report = json.loads(vp.read_text(encoding="utf-8"))
        scenario = report.get("scenario")
        repetition = report.get("repetition")
        run_key = f"{scenario}-{repetition}"

        legacy = report.get("metrics", {})
        privacy = report.get("privacy", {})
        privacy_ok = all(
            v for k, v in privacy.items() if k.endswith("_no_raw_identifiers")
        )
        source = metrics.compute_source_metrics(
            RAW_RUNS / run_key, TRANSFORMED_RUNS / run_key
        )

        row = {
            "run": run_key,
            "status": report.get("validation_status"),
            "zeek_queries": report.get("zeek_dns", {}).get("dns_query_count"),
            "suricata_dns_events": report.get("suricata", {}).get("suricata_dns_count"),
            "http_requests": report.get("zeek_http", {}).get("http_request_count"),
            "suricata_http_events": report.get("suricata", {}).get("suricata_http_count"),
            "scan_connections": report.get("zeek_scan", {}).get("scan_connection_count"),
            "beacon_connections": report.get("zeek_beacon", {}).get("beacon_connection_count"),
            "suricata_flow_events": report.get("suricata", {}).get("suricata_flow_count"),
            "auth_attempts": report.get("zeek_auth", {}).get("auth_401_count"),
            "suricata_alert_events": report.get("suricata", {}).get("alert_count"),
            "bulk_connections": report.get("zeek_bulk", {}).get("bulk_connection_count"),
            "bulk_orig_bytes": report.get("zeek_bulk", {}).get("orig_bytes_total"),
            "c3_windows": report.get("c3", {}).get("c3_window_count"),
            "legacy_combined_raw_bytes": legacy.get("raw_bytes"),
            "legacy_combined_c1_bytes": legacy.get("c1_bytes"),
            "legacy_combined_c2_bytes": legacy.get("c2_bytes"),
            "legacy_combined_c3_bytes": legacy.get("c3_bytes"),
            "legacy_combined_c2_reduction_pct": legacy.get("c2_reduction_pct"),
            "legacy_combined_c3_reduction_pct": legacy.get("c3_reduction_pct"),
            "privacy_no_leak": privacy_ok,
        }
        row.update(source)
        rows.append(row)

    with OUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    for row in rows:
        print(json.dumps(row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
