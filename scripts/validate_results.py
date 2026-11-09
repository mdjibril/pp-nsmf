#!/usr/bin/env python3
"""Validation and metrics for PP-NSMF runs.

Checks event presence in raw evidence, verifies that raw identifiers do not
survive into transformed outputs, confirms pseudonym linkability and 60-second
aggregation, and computes record/byte reduction metrics. Exit code 0 means all
required checks passed.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

import linkability

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence-backup"

VALIDATOR_VERSION = "1.1.0"

RAW_IPS = ["10.10.10.10", "10.10.10.20", "10.10.10.30", "10.10.10.40"]
TEST_DOMAIN = "probe.pp-nsmf.test"
SCAN_PORTS = {"21", "22", "80", "443", "8080"}


def _zeek_records(path):
    fields = None
    rows = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            rows.append(line.rstrip("\n").split("\t"))
    return fields, rows


def _zeek_col(fields, name):
    return fields.index(name) if name in fields else None


def check_zeek_dns(dns_path):
    if not dns_path.is_file():
        return {"dns_query_present": False, "dns_answer_matches_expected": False, "detail": "missing dns.log"}
    fields, rows = _zeek_records(dns_path)
    q = _zeek_col(fields, "query")
    a = _zeek_col(fields, "answers")
    queries = [r[q] for r in rows if q is not None and q < len(r) and r[q] == TEST_DOMAIN]
    answers = [r[a] for r in rows if a is not None and a < len(r) and "10.10.10.20" in r[a]]
    return {
        "dns_query_present": len(queries) > 0,
        "dns_answer_matches_expected": len(answers) > 0,
        "dns_query_count": len(queries),
        "detail": f"{len(queries)} queries, {len(answers)} matching answers",
    }


def check_zeek_conn(conn_path):
    if not conn_path.is_file():
        return {"udp_conn_53_present": False, "detail": "missing conn.log"}
    fields, rows = _zeek_records(conn_path)
    proto = _zeek_col(fields, "proto")
    resp_p = _zeek_col(fields, "id.resp_p")
    hits = [
        r for r in rows
        if proto is not None and resp_p is not None and proto < len(r) and resp_p < len(r)
        and r[proto] == "udp" and r[resp_p] == "53"
    ]
    return {"udp_conn_53_present": len(hits) > 0, "udp_53_count": len(hits), "detail": f"{len(hits)} udp:53 connections"}


def check_zeek_http(http_path):
    if not http_path.is_file():
        return {"http_requests_present": False, "detail": "missing http.log"}
    fields, rows = _zeek_records(http_path)
    method = _zeek_col(fields, "method")
    resp_h = _zeek_col(fields, "id.resp_h")
    hits = [
        r for r in rows
        if method is not None and resp_h is not None and method < len(r) and resp_h < len(r)
        and r[method] == "GET" and r[resp_h] == "10.10.10.20"
    ]
    return {
        "http_requests_present": len(hits) > 0,
        "http_request_count": len(hits),
        "detail": f"{len(hits)} GET requests to 10.10.10.20",
    }


def check_zeek_conn_tcp80(conn_path):
    if not conn_path.is_file():
        return {"tcp_conn_80_present": False, "detail": "missing conn.log"}
    fields, rows = _zeek_records(conn_path)
    proto = _zeek_col(fields, "proto")
    resp_p = _zeek_col(fields, "id.resp_p")
    hits = [
        r for r in rows
        if proto is not None and resp_p is not None and proto < len(r) and resp_p < len(r)
        and r[proto] == "tcp" and r[resp_p] == "80"
    ]
    return {"tcp_conn_80_present": len(hits) > 0, "tcp_80_count": len(hits), "detail": f"{len(hits)} tcp:80 connections"}


def check_suricata_dns(eve_path):
    if not eve_path.is_file():
        return {"suricata_dns_present": False, "detail": "missing eve.json"}
    count = 0
    with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if '"dns"' in line and '"event_type":"dns"' in line.replace(" ", ""):
                count += 1
    return {"suricata_dns_present": count > 0, "suricata_dns_count": count, "detail": f"{count} dns events"}


def check_suricata_http(eve_path):
    if not eve_path.is_file():
        return {"suricata_http_present": False, "detail": "missing eve.json"}
    count = 0
    with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if '"http"' in line and '"event_type":"http"' in line.replace(" ", ""):
                count += 1
    return {"suricata_http_present": count > 0, "suricata_http_count": count, "detail": f"{count} http events"}


def check_zeek_scan(conn_path):
    """Confirm conn.log shows a controlled connect scan from attacker to server."""
    if not conn_path.is_file():
        return {"scan_connections_present": False, "detail": "missing conn.log"}
    fields, rows = _zeek_records(conn_path)
    orig_h = _zeek_col(fields, "id.orig_h")
    resp_h = _zeek_col(fields, "id.resp_h")
    resp_p = _zeek_col(fields, "id.resp_p")
    hits = [
        r for r in rows
        if orig_h is not None and resp_h is not None and resp_p is not None
        and orig_h < len(r) and resp_h < len(r) and resp_p < len(r)
        and r[orig_h] == "10.10.10.30" and r[resp_h] == "10.10.10.20"
        and r[resp_p] in SCAN_PORTS
    ]
    distinct_ports = {r[resp_p] for r in hits}
    return {
        "scan_connections_present": SCAN_PORTS.issubset(distinct_ports),
        "scan_connection_count": len(hits),
        "distinct_ports_observed": sorted(distinct_ports),
        "detail": f"{len(hits)} scan connections from 10.10.10.30 to 10.10.10.20",
    }


def check_suricata_flow(eve_path):
    """Count flow events (flows observed); no scan-alert rule is loaded."""
    if not eve_path.is_file():
        return {"suricata_flow_present": False, "detail": "missing eve.json"}
    flow_count = 0
    alert_count = 0
    with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            compact = line.replace(" ", "")
            if '"event_type":"flow"' in compact:
                flow_count += 1
            if '"event_type":"alert"' in compact:
                alert_count += 1
    return {
        "suricata_flow_present": flow_count >= len(SCAN_PORTS),
        "suricata_flow_count": flow_count,
        "alert_count": alert_count,
        "detail": f"{flow_count} flow events, {alert_count} alert events",
    }


def check_zeek_auth(http_path, conn_path):
    """Confirm http.log shows failed (401) auth attempts from attacker."""
    if not http_path.is_file():
        return {"auth_attempts_present": False, "detail": "missing http.log"}
    fields, rows = _zeek_records(http_path)
    method = _zeek_col(fields, "method")
    resp_h = _zeek_col(fields, "id.resp_h")
    status_code = _zeek_col(fields, "status_code")
    hits = [
        r for r in rows
        if method is not None and resp_h is not None and status_code is not None
        and method < len(r) and resp_h < len(r) and status_code < len(r)
        and r[method] == "GET" and r[resp_h] == "10.10.10.20" and r[status_code] == "401"
    ]
    tcp_8080 = 0
    if conn_path.is_file():
        cfields, crows = _zeek_records(conn_path)
        proto = _zeek_col(cfields, "proto")
        resp_p = _zeek_col(cfields, "id.resp_p")
        tcp_8080 = sum(
            1 for r in crows
            if proto is not None and resp_p is not None and proto < len(r) and resp_p < len(r)
            and r[proto] == "tcp" and r[resp_p] == "8080"
        )
    return {
        "auth_attempts_present": len(hits) >= 5,
        "auth_401_count": len(hits),
        "tcp_8080_count": tcp_8080,
        "detail": f"{len(hits)} HTTP 401 responses to 10.10.10.20, {tcp_8080} tcp:8080 connections",
    }


def check_suricata_auth(eve_path):
    """Confirm http events and alert events from the loaded auth rule."""
    if not eve_path.is_file():
        return {"suricata_alert_present": False, "detail": "missing eve.json"}
    http_count = 0
    alert_count = 0
    with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            compact = line.replace(" ", "")
            if '"event_type":"http"' in compact:
                http_count += 1
            if '"event_type":"alert"' in compact:
                alert_count += 1
    return {
        "suricata_alert_present": alert_count > 0,
        "suricata_http_present": http_count > 0,
        "suricata_http_count": http_count,
        "alert_count": alert_count,
        "detail": f"{http_count} http events, {alert_count} alert events",
    }


def check_zeek_beacon(conn_path):
    """Confirm conn.log shows periodic tcp:80 beacon connections from attacker."""
    if not conn_path.is_file():
        return {"periodic_connections_present": False, "detail": "missing conn.log"}
    fields, rows = _zeek_records(conn_path)
    orig_h = _zeek_col(fields, "id.orig_h")
    resp_h = _zeek_col(fields, "id.resp_h")
    proto = _zeek_col(fields, "proto")
    resp_p = _zeek_col(fields, "id.resp_p")
    hits = [
        r for r in rows
        if orig_h is not None and resp_h is not None and proto is not None and resp_p is not None
        and orig_h < len(r) and resp_h < len(r) and proto < len(r) and resp_p < len(r)
        and r[orig_h] == "10.10.10.30" and r[resp_h] == "10.10.10.20"
        and r[proto] == "tcp" and r[resp_p] == "80"
    ]
    return {
        "periodic_connections_present": len(hits) >= 4,
        "beacon_connection_count": len(hits),
        "detail": f"{len(hits)} tcp:80 connections from 10.10.10.30 to 10.10.10.20",
    }


def check_suricata_beacon(eve_path):
    """Confirm flow events for the periodic beacon; no beacon-alert rule loaded."""
    if not eve_path.is_file():
        return {"suricata_flow_present": False, "detail": "missing eve.json"}
    flow_count = 0
    alert_count = 0
    with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            compact = line.replace(" ", "")
            if '"event_type":"flow"' in compact:
                flow_count += 1
            if '"event_type":"alert"' in compact:
                alert_count += 1
    return {
        "suricata_flow_present": flow_count >= 4,
        "suricata_flow_count": flow_count,
        "alert_count": alert_count,
        "detail": f"{flow_count} flow events, {alert_count} alert events",
    }


def check_zeek_bulk(conn_path):
    """Confirm conn.log shows a bulk transfer from client to server:9999."""
    if not conn_path.is_file():
        return {"bulk_connection_present": False, "detail": "missing conn.log"}
    fields, rows = _zeek_records(conn_path)
    orig_h = _zeek_col(fields, "id.orig_h")
    resp_h = _zeek_col(fields, "id.resp_h")
    proto = _zeek_col(fields, "proto")
    resp_p = _zeek_col(fields, "id.resp_p")
    orig_bytes = _zeek_col(fields, "orig_bytes")
    hits = [
        r for r in rows
        if orig_h is not None and resp_h is not None and proto is not None
        and resp_p is not None and orig_bytes is not None
        and orig_h < len(r) and resp_h < len(r) and proto < len(r)
        and resp_p < len(r) and orig_bytes < len(r)
        and r[orig_h] == "10.10.10.10" and r[resp_h] == "10.10.10.20"
        and r[proto] == "tcp" and r[resp_p] == "9999"
        and r[orig_bytes].isdigit() and int(r[orig_bytes]) > 0
    ]
    total_bytes = sum(int(r[orig_bytes]) for r in hits)
    return {
        "bulk_connection_present": len(hits) >= 1 and total_bytes >= 65536,
        "bulk_connection_count": len(hits),
        "orig_bytes_total": total_bytes,
        "detail": f"{len(hits)} tcp:9999 connections, {total_bytes} orig_bytes",
    }


def check_suricata_bulk(eve_path):
    """Confirm flow events with byte counts for the bulk transfer."""
    if not eve_path.is_file():
        return {"suricata_flow_present": False, "detail": "missing eve.json"}
    flow_count = 0
    alert_count = 0
    bytes_toserver = 0
    for event in _read_jsonl(eve_path):
        event_type = event.get("event_type")
        if event_type == "flow":
            flow_count += 1
            flow = event.get("flow")
            if isinstance(flow, dict) and isinstance(flow.get("bytes_toserver"), int):
                bytes_toserver += flow["bytes_toserver"]
        elif event_type == "alert":
            alert_count += 1
    return {
        "suricata_flow_present": flow_count >= 1,
        "suricata_flow_count": flow_count,
        "alert_count": alert_count,
        "bytes_toserver_total": bytes_toserver,
        "detail": f"{flow_count} flow events, {bytes_toserver} bytes_toserver, {alert_count} alert events",
    }


def _raw_identifiers_present(path):
    """Return set of raw identifiers found in a transformed file."""
    found = set()
    text = path.read_text(encoding="utf-8", errors="replace")
    for ip in RAW_IPS:
        if ip in text:
            found.add(ip)
    if TEST_DOMAIN in text:
        found.add(TEST_DOMAIN)
    return found


def check_privacy(transformed_dir):
    results = {}
    for name in ("C1-pseudonymised.jsonl", "C2-minimised-pseudonymised.jsonl", "C3-aggregated-60s.jsonl"):
        p = transformed_dir / "suricata" / name
        if p.is_file():
            found = _raw_identifiers_present(p)
            results[f"{name}_no_raw_identifiers"] = not found
            if found:
                results[f"{name}_leaked"] = sorted(found)
    for name in ("dns.log", "conn.log", "http.log"):
        for variant in ("C1", "C2"):
            p = transformed_dir / "zeek" / f"{name}.{variant}"
            if p.is_file():
                found = _raw_identifiers_present(p)
                results[f"{name}.{variant}_no_raw_identifiers"] = not found
                if found:
                    results[f"{name}.{variant}_leaked"] = sorted(found)
    return results


def _read_jsonl(path):
    events = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                events.append(json.loads(line))
    return events


def _load_transformation_meta(transformed_dir):
    p = transformed_dir / "transformation-metadata.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {}


ZEEK_LINK_COLUMNS = ("id.orig_h", "id.resp_h", "orig_h", "resp_h")


def _zeek_ip_linkability(raw_log, c1_log):
    """Validate within-run IP-column linkability for one Zeek log (C1)."""
    raw_fields, raw_rows = _zeek_records(raw_log)
    c1_fields, c1_rows = _zeek_records(c1_log)
    raw_to_token = defaultdict(lambda: defaultdict(set))
    token_to_raw = defaultdict(lambda: defaultdict(set))
    for name in ZEEK_LINK_COLUMNS:
        if name not in raw_fields or name not in c1_fields:
            continue
        raw_idx = raw_fields.index(name)
        c1_idx = c1_fields.index(name)
        for raw_row, c1_row in zip(raw_rows, c1_rows):
            if raw_idx >= len(raw_row) or c1_idx >= len(c1_row):
                continue
            raw_value = raw_row[raw_idx]
            token_value = c1_row[c1_idx]
            if raw_value and token_value:
                raw_to_token[(name,)][raw_value].add(token_value)
                token_to_raw[(name,)][token_value].add(raw_value)
    return linkability.assess(raw_to_token, token_to_raw)


def _suricata_c2_filter(event):
    """Mirror transform_telemetry.suricata_c2's acceptance of an event."""
    event_type = event.get("event_type")
    if event_type == "dns":
        return isinstance(event.get("dns"), dict)
    if event_type == "http":
        return isinstance(event.get("http"), dict)
    if event_type == "flow":
        return True
    if event_type == "alert":
        return isinstance(event.get("alert"), dict)
    return False


def _overall_linkability(result):
    statuses = []
    for key in ("c1", "c2"):
        if isinstance(result.get(key), dict):
            statuses.append(result[key].get("status"))
    for value in result.get("zeek", {}).values():
        if isinstance(value, dict):
            statuses.append(value.get("status"))
    if "fail" in statuses:
        return "fail"
    if "ok" in statuses:
        return "ok"
    return "no_identifiers"


def check_linkability(raw_dir, transformed_dir):
    result = {}

    raw_events = _read_jsonl(raw_dir / "suricata" / "eve.json")

    c1_path = transformed_dir / "suricata" / "C1-pseudonymised.jsonl"
    if c1_path.is_file() and raw_events:
        c1_events = _read_jsonl(c1_path)
        if len(c1_events) != len(raw_events):
            result["c1_alignment"] = f"mismatch ({len(c1_events)} vs {len(raw_events)})"
        result["c1"] = linkability.assess_suricata(raw_events, c1_events)

    c2_path = transformed_dir / "suricata" / "C2-minimised-pseudonymised.jsonl"
    if c2_path.is_file() and raw_events:
        c2_events = _read_jsonl(c2_path)
        raw_c2 = [e for e in raw_events if _suricata_c2_filter(e)]
        if len(c2_events) != len(raw_c2):
            result["c2_alignment"] = f"mismatch ({len(c2_events)} vs {len(raw_c2)})"
        result["c2"] = linkability.assess_suricata(raw_c2, c2_events, linkability.IP_PATHS)

    result["c3"] = {
        "status": "not_applicable",
        "reason": "aggregated; identifiers removed by minimisation policy",
    }

    result["zeek"] = {}
    for name in ("dns.log", "conn.log", "http.log"):
        raw_log = raw_dir / "zeek" / name
        c1_log = transformed_dir / "zeek" / f"{name}.C1"
        c2_log = transformed_dir / "zeek" / f"{name}.C2"
        if raw_log.is_file() and c1_log.is_file():
            result["zeek"][name] = _zeek_ip_linkability(raw_log, c1_log)
        if c2_log.is_file():
            result["zeek"][f"{name}.C2"] = {
                "status": "not_applicable",
                "reason": "identifier columns dropped by minimisation policy",
            }

    result["overall"] = _overall_linkability(result)
    return result


def check_c3_windows(transformed_dir):
    p = transformed_dir / "suricata" / "C3-aggregated-60s.jsonl"
    if not p.is_file():
        return {"c3_windows_60s": False, "detail": "missing C3"}
    windows = []
    with p.open("r", encoding="utf-8") as handle:
        for line in handle:
            e = json.loads(line)
            windows.append(e.get("window_seconds"))
    ok = all(w == 60 for w in windows)
    return {"c3_windows_60s": ok, "c3_window_count": len(windows), "detail": f"{len(windows)} windows"}


def compute_metrics(raw_dir, transformed_dir):
    def size(p):
        return p.stat().st_size if p.is_file() else 0

    raw_bytes = sum(size(p) for p in raw_dir.rglob("*") if p.is_file())
    c1 = size(transformed_dir / "suricata" / "C1-pseudonymised.jsonl")
    c2 = size(transformed_dir / "suricata" / "C2-minimised-pseudonymised.jsonl")
    c3 = size(transformed_dir / "suricata" / "C3-aggregated-60s.jsonl")
    return {
        "raw_bytes": raw_bytes,
        "c1_bytes": c1,
        "c2_bytes": c2,
        "c3_bytes": c3,
        "c2_reduction_pct": round(100 * (1 - c2 / raw_bytes), 2) if raw_bytes else None,
        "c3_reduction_pct": round(100 * (1 - c3 / raw_bytes), 2) if raw_bytes else None,
    }


def main():
    scenario = sys.argv[1] if len(sys.argv) > 1 else "S2"
    repetition = sys.argv[2] if len(sys.argv) > 2 else "R2"
    run_key = f"{scenario}-{repetition}"
    raw_dir = EVIDENCE / "raw-runs" / run_key
    transformed_dir = EVIDENCE / "transformed-runs" / run_key

    report = {"scenario": scenario, "repetition": repetition, "validator_version": VALIDATOR_VERSION}
    meta = _load_transformation_meta(transformed_dir)
    report["transformation_version"] = meta.get("transformation_version")
    report["hmac_key_id"] = meta.get("hmac_key_id")

    if scenario == "S1":
        report["zeek_http"] = check_zeek_http(raw_dir / "zeek" / "http.log")
        report["zeek_conn"] = check_zeek_conn_tcp80(raw_dir / "zeek" / "conn.log")
        report["suricata"] = check_suricata_http(raw_dir / "suricata" / "eve.json")
    elif scenario == "S2":
        report["zeek_dns"] = check_zeek_dns(raw_dir / "zeek" / "dns.log")
        report["zeek_conn"] = check_zeek_conn(raw_dir / "zeek" / "conn.log")
        report["suricata"] = check_suricata_dns(raw_dir / "suricata" / "eve.json")
    elif scenario == "S3":
        report["zeek_scan"] = check_zeek_scan(raw_dir / "zeek" / "conn.log")
        report["suricata"] = check_suricata_flow(raw_dir / "suricata" / "eve.json")
    elif scenario == "S5":
        report["zeek_beacon"] = check_zeek_beacon(raw_dir / "zeek" / "conn.log")
        report["suricata"] = check_suricata_beacon(raw_dir / "suricata" / "eve.json")
    elif scenario == "S6":
        report["zeek_bulk"] = check_zeek_bulk(raw_dir / "zeek" / "conn.log")
        report["suricata"] = check_suricata_bulk(raw_dir / "suricata" / "eve.json")
    else:
        report["zeek_auth"] = check_zeek_auth(raw_dir / "zeek" / "http.log", raw_dir / "zeek" / "conn.log")
        report["suricata"] = check_suricata_auth(raw_dir / "suricata" / "eve.json")
    report["privacy"] = check_privacy(transformed_dir)
    report["linkability"] = check_linkability(raw_dir, transformed_dir)
    report["c3"] = check_c3_windows(transformed_dir)
    report["metrics"] = compute_metrics(raw_dir, transformed_dir)

    if scenario == "S1":
        required = [
            report["zeek_http"].get("http_requests_present", False),
            report["zeek_conn"].get("tcp_conn_80_present", False),
            report["suricata"].get("suricata_http_present", False),
            report["c3"].get("c3_windows_60s", False),
        ]
    elif scenario == "S2":
        required = [
            report["zeek_dns"].get("dns_query_present", False),
            report["zeek_dns"].get("dns_answer_matches_expected", False),
            report["zeek_conn"].get("udp_conn_53_present", False),
            report["suricata"].get("suricata_dns_present", False),
            report["c3"].get("c3_windows_60s", False),
        ]
    elif scenario == "S3":
        required = [
            report["zeek_scan"].get("scan_connections_present", False),
            report["suricata"].get("suricata_flow_present", False),
            report["c3"].get("c3_windows_60s", False),
        ]
    elif scenario == "S5":
        required = [
            report["zeek_beacon"].get("periodic_connections_present", False),
            report["suricata"].get("suricata_flow_present", False),
            report["c3"].get("c3_windows_60s", False),
        ]
    elif scenario == "S6":
        required = [
            report["zeek_bulk"].get("bulk_connection_present", False),
            report["suricata"].get("suricata_flow_present", False),
            report["c3"].get("c3_windows_60s", False),
        ]
    else:
        required = [
            report["zeek_auth"].get("auth_attempts_present", False),
            report["suricata"].get("suricata_alert_present", False),
            report["c3"].get("c3_windows_60s", False),
        ]
    linkability_ok = report["linkability"].get("overall") != "fail"
    privacy_ok = all(report["privacy"].get(k, True) for k in report["privacy"] if k.endswith("_no_raw_identifiers"))
    report["validation_status"] = "PASS" if all(required) and privacy_ok and linkability_ok else "FAIL"

    out = EVIDENCE / "reports"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{run_key}.validation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(report, indent=2))
    return 0 if report["validation_status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
