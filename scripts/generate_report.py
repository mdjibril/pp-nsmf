#!/usr/bin/env python3
"""Generate human-readable Markdown and machine-readable JSON reports."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence-backup"


def main():
    scenario = sys.argv[1] if len(sys.argv) > 1 else "S2"
    repetition = sys.argv[2] if len(sys.argv) > 2 else "R2"
    run_key = f"{scenario}-{repetition}"

    reports_dir = EVIDENCE / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    validation = {}
    vpath = reports_dir / f"{run_key}.validation.json"
    if vpath.is_file():
        validation = json.loads(vpath.read_text(encoding="utf-8"))

    meta = {}
    mpath = EVIDENCE / "transformed-runs" / run_key / "transformation-metadata.json"
    if mpath.is_file():
        meta = json.loads(mpath.read_text(encoding="utf-8"))

    status = validation.get("validation_status", "UNKNOWN")
    lines = []
    lines.append(f"# PP-NSMF Run Report: {run_key}\n")
    lines.append(f"**Status:** {status}\n")
    lines.append(f"**Transformation version:** {meta.get('transformation_version', '-')}")
    lines.append(f"**HMAC key ID:** {meta.get('hmac_key_id', '-')}")
    lines.append(f"**Validator version:** {validation.get('validator_version', '-')}\n")

    if "zeek_http" in validation:
        h = validation["zeek_http"]
        lines.append("## Zeek HTTP")
        lines.append(f"- http_requests_present: {h.get('http_requests_present')}")
        lines.append(f"- requests: {h.get('http_request_count', '-')}")
    if "zeek_dns" in validation:
        d = validation["zeek_dns"]
        lines.append("## Zeek DNS")
        lines.append(f"- dns_query_present: {d.get('dns_query_present')}")
        lines.append(f"- dns_answer_matches_expected: {d.get('dns_answer_matches_expected')}")
        lines.append(f"- queries: {d.get('dns_query_count', '-')}")
    if "zeek_conn" in validation:
        c = validation["zeek_conn"]
        lines.append("\n## Zeek Connections")
        lines.append(f"- udp:53 connections: {c.get('udp_53_count', '-')}")
        lines.append(f"- tcp:80 connections: {c.get('tcp_80_count', '-')}")
    if "zeek_scan" in validation:
        sc = validation["zeek_scan"]
        lines.append("\n## Zeek Scan")
        lines.append(f"- scan_connections_present: {sc.get('scan_connections_present')}")
        lines.append(f"- scan connections: {sc.get('scan_connection_count', '-')}")
        lines.append(f"- ports observed: {sc.get('distinct_ports_observed', '-')}")
    if "zeek_beacon" in validation:
        b = validation["zeek_beacon"]
        lines.append("\n## Zeek Beacon")
        lines.append(f"- periodic_connections_present: {b.get('periodic_connections_present')}")
        lines.append(f"- beacon connections: {b.get('beacon_connection_count', '-')}")
    if "zeek_bulk" in validation:
        bu = validation["zeek_bulk"]
        lines.append("\n## Zeek Bulk Transfer")
        lines.append(f"- bulk_connection_present: {bu.get('bulk_connection_present')}")
        lines.append(f"- bulk connections: {bu.get('bulk_connection_count', '-')}")
        lines.append(f"- orig_bytes: {bu.get('orig_bytes_total', '-')}")
    if "zeek_auth" in validation:
        a = validation["zeek_auth"]
        lines.append("\n## Zeek Authentication")
        lines.append(f"- auth_attempts_present: {a.get('auth_attempts_present')}")
        lines.append(f"- HTTP 401 responses: {a.get('auth_401_count', '-')}")
        lines.append(f"- tcp:8080 connections: {a.get('tcp_8080_count', '-')}")
    if "suricata" in validation:
        s = validation["suricata"]
        lines.append("\n## Suricata")
        lines.append(f"- dns events: {s.get('suricata_dns_count', '-')}")
        lines.append(f"- http events: {s.get('suricata_http_count', '-')}")
        lines.append(f"- flow events: {s.get('suricata_flow_count', '-')}")
        lines.append(f"- alert events: {s.get('alert_count', '-')}")
        lines.append(f"- alert rule fired: {s.get('suricata_alert_present', '-')}")

    if "privacy" in validation:
        lines.append("\n## Privacy")
        for k, v in validation["privacy"].items():
            lines.append(f"- {k}: {v}")

    if "c3" in validation:
        lines.append("\n## C3 Aggregation")
        lines.append(f"- 60s windows: {validation['c3'].get('c3_window_count', '-')}")

    if "linkability" in validation:
        lines.append("\n## Linkability")
        lines.append(f"- overall: {validation['linkability'].get('overall', '-')}")

    if "metrics" in validation:
        m = validation["metrics"]
        lines.append("\n## Metrics")
        lines.append(f"- raw bytes: {m.get('raw_bytes')}")
        lines.append(f"- C1 bytes: {m.get('c1_bytes')}")
        lines.append(f"- C2 bytes: {m.get('c2_bytes')}")
        lines.append(f"- C3 bytes: {m.get('c3_bytes')}")
        lines.append(f"- C2 volume reduction: {m.get('c2_reduction_pct')}%")
        lines.append(f"- C3 volume reduction: {m.get('c3_reduction_pct')}%")

    md = "\n".join(lines) + "\n"
    (reports_dir / f"{run_key}.md").write_text(md, encoding="utf-8")

    summary = {"scenario": scenario, "repetition": repetition, "status": status,
               "validation": validation, "metadata": meta}
    (reports_dir / f"{run_key}.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
