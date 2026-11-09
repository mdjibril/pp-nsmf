#!/usr/bin/env python3
"""Privacy transformation pipeline for PP-NSMF (C0-C3).

C0 is the raw telemetry (preserved, never rewritten). C1 is pseudonymised
(HMAC-SHA256). C2 is minimised (explicit field selection) and pseudonymised.
C3 aggregates C2 into 60-second windows.

Pseudonymisation uses a securely stored 32-byte HMAC key (hex). A non-secret key
identifier and a transformation version are recorded in the metadata; the key
itself is never printed. HMAC pseudonyms are linkable pseudonyms, not anonymised
data.

Reuses and generalises the S2/R1 corrected transformation logic; DNS query-type
counts count query events only, not answers.
"""

import hashlib
import hmac
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

TRANSFORM_VERSION = "2.2.0"
WINDOW_SECONDS = 60
ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence-backup"
DEFAULT_KEY = EVIDENCE / "keys" / "hmac.key"

# Suricata EVE fields and nested DNS fields that carry identifiers.
SURI_IP_FIELDS = ("src_ip", "dest_ip", "dest_host")
SURI_DNS_ID_FIELDS = ("rrname", "rdata")
# Zeek log columns that carry identifiers (by column name).
ZEEK_IP_COLUMNS = {"id.orig_h", "id.resp_h", "orig_h", "resp_h", "id.orig_host", "id.resp_host"}
ZEEK_DOMAIN_COLUMNS = {"query", "answers", "host", "hostname", "referrer", "uri"}


def load_key(path=DEFAULT_KEY):
    if not path.is_file():
        raise FileNotFoundError(f"Missing HMAC key: {path}")
    key_text = path.read_text(encoding="utf-8").strip()
    if len(key_text) != 64:
        raise ValueError("Expected a 64-character hexadecimal HMAC key")
    try:
        key = bytes.fromhex(key_text)
    except ValueError as exc:
        raise ValueError("HMAC key is not valid hexadecimal") from exc
    if len(key) != 32:
        raise ValueError("Expected a 32-byte HMAC key")
    return key


def key_id(key):
    return hashlib.sha256(key).hexdigest()[:12]


def token(value, key):
    if value is None or value == "":
        return value
    digest = hmac.new(key, str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return "h_" + digest


def parse_time(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def write_jsonl(path, rows):
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")


def read_events(path):
    events = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_number}: {exc}") from exc
    return events


# --- Suricata ---

def suricata_c1(event, key):
    item = dict(event)
    for field in SURI_IP_FIELDS:
        if item.get(field):
            item[field] = token(item[field], key)
    dns = item.get("dns")
    if isinstance(dns, dict):
        dns = dict(dns)
        if dns.get("rrname"):
            dns["rrname"] = token(dns["rrname"], key)
        answers = dns.get("answers")
        if isinstance(answers, list):
            safe = []
            for answer in answers:
                if not isinstance(answer, dict):
                    continue
                a = dict(answer)
                for field in SURI_DNS_ID_FIELDS:
                    if a.get(field):
                        a[field] = token(a[field], key)
                if a.get("rrname"):
                    a["rrname"] = token(a["rrname"], key)
                safe.append(a)
            dns["answers"] = safe
        grouped = dns.get("grouped")
        if isinstance(grouped, dict):
            dns["grouped"] = {
                str(k): [token(v, key) for v in values] if isinstance(values, list) else values
                for k, values in grouped.items()
            }
        item["dns"] = dns
    http = item.get("http")
    if isinstance(http, dict):
        http = dict(http)
        if http.get("hostname"):
            http["hostname"] = token(http["hostname"], key)
        if http.get("url"):
            http["url"] = token(http["url"], key)
        item["http"] = http
    flow = item.get("flow")
    if isinstance(flow, dict):
        flow = dict(flow)
        for field in SURI_IP_FIELDS:
            if flow.get(field):
                flow[field] = token(flow[field], key)
        item["flow"] = flow
    return item


def suricata_c2(event, key):
    event_type = event.get("event_type")
    if event_type == "dns":
        dns = event.get("dns")
        if not isinstance(dns, dict):
            return None
        result = {
            "timestamp": event.get("timestamp"),
            "event_type": "dns",
            "src_ip": token(event.get("src_ip"), key),
            "dest_ip": token(event.get("dest_ip"), key),
            "proto": event.get("proto"),
            "dest_port": event.get("dest_port"),
            "dns_type": dns.get("type"),
            "query_type": dns.get("rrtype"),
            "response_code": dns.get("rcode"),
            "opcode": dns.get("opcode"),
            "recursion_desired": dns.get("rd"),
            "recursion_available": dns.get("ra"),
            "authoritative": dns.get("aa"),
            "truncated": dns.get("tc"),
            "answer_count": len(dns.get("answers", [])) if isinstance(dns.get("answers"), list) else 0,
        }
        return {k: v for k, v in result.items() if v is not None}
    if event_type == "http":
        http = event.get("http")
        if not isinstance(http, dict):
            return None
        result = {
            "timestamp": event.get("timestamp"),
            "event_type": "http",
            "src_ip": token(event.get("src_ip"), key),
            "dest_ip": token(event.get("dest_ip"), key),
            "proto": event.get("proto"),
            "dest_port": event.get("dest_port"),
            "http_method": http.get("http_method"),
            "status": http.get("status"),
            "response_length": http.get("length"),
        }
        return {k: v for k, v in result.items() if v is not None}
    if event_type == "flow":
        flow = event.get("flow")
        state = flow.get("state") if isinstance(flow, dict) else None
        result = {
            "timestamp": event.get("timestamp"),
            "event_type": "flow",
            "src_ip": token(event.get("src_ip"), key),
            "dest_ip": token(event.get("dest_ip"), key),
            "proto": event.get("proto"),
            "dest_port": event.get("dest_port"),
            "state": state,
        }
        return {k: v for k, v in result.items() if v is not None}
    if event_type == "alert":
        alert = event.get("alert")
        result = {
            "timestamp": event.get("timestamp"),
            "event_type": "alert",
            "src_ip": token(event.get("src_ip"), key),
            "dest_ip": token(event.get("dest_ip"), key),
            "proto": event.get("proto"),
            "dest_port": event.get("dest_port"),
            "signature_id": alert.get("signature_id") if isinstance(alert, dict) else None,
            "signature": alert.get("signature") if isinstance(alert, dict) else None,
            "severity": alert.get("severity") if isinstance(alert, dict) else None,
            "category": alert.get("category") if isinstance(alert, dict) else None,
        }
        return {k: v for k, v in result.items() if v is not None}
    return None


def suricata_c3(events, key):
    windows = defaultdict(lambda: {
        "event_count": 0, "query_types": Counter(), "response_codes": Counter(),
        "dns_message_types": Counter(), "answer_count": 0,
        "methods": Counter(), "status_codes": Counter(), "response_bytes": 0,
        "flow_ports": Counter(), "flow_states": Counter(),
        "alert_signatures": Counter(), "alert_count": 0,
        "sources": set(),
    })
    for event in events:
        event_type = event.get("event_type")
        if event_type not in ("dns", "http", "flow", "alert"):
            continue
        if event_type == "dns":
            nested = event.get("dns")
            if not isinstance(nested, dict):
                continue
        elif event_type == "http":
            nested = event.get("http")
            if not isinstance(nested, dict):
                continue
        elif event_type == "alert":
            if not isinstance(event.get("alert"), dict):
                continue
        dt = parse_time(event.get("timestamp"))
        if dt is None:
            continue
        start = int(dt.timestamp()) - (int(dt.timestamp()) % WINDOW_SECONDS)
        w = windows[start]
        w["event_count"] += 1
        w["sources"].add(event_type)
        if event_type == "dns":
            # Query-type counts count query events only.
            if nested.get("type") == "query" and nested.get("rrtype") is not None:
                w["query_types"][str(nested["rrtype"])] += 1
            if nested.get("rcode") is not None:
                w["response_codes"][str(nested["rcode"])] += 1
            if nested.get("type") is not None:
                w["dns_message_types"][str(nested["type"])] += 1
            if isinstance(nested.get("answers"), list):
                w["answer_count"] += len(nested["answers"])
        elif event_type == "http":
            if nested.get("http_method") is not None:
                w["methods"][str(nested["http_method"])] += 1
            if nested.get("status") is not None:
                w["status_codes"][str(nested["status"])] += 1
            w["response_bytes"] += nested.get("length") or 0
        elif event_type == "flow":
            if event.get("dest_port") is not None:
                w["flow_ports"][str(event["dest_port"])] += 1
            flow = event.get("flow")
            if isinstance(flow, dict) and flow.get("state") is not None:
                w["flow_states"][str(flow["state"])] += 1
        else:
            alert = event["alert"]
            w["alert_count"] += 1
            if alert.get("signature") is not None:
                w["alert_signatures"][str(alert["signature"])] += 1
    out = []
    for start in sorted(windows):
        d = windows[start]
        record = {
            "window_start_utc": datetime.fromtimestamp(start, timezone.utc).isoformat(),
            "window_seconds": WINDOW_SECONDS,
            "source_logs": sorted(d["sources"]),
            "event_count": d["event_count"],
        }
        if "dns" in d["sources"]:
            record["query_types"] = dict(d["query_types"])
            record["response_codes"] = dict(d["response_codes"])
            record["dns_message_types"] = dict(d["dns_message_types"])
            record["answer_count"] = d["answer_count"]
        if "http" in d["sources"]:
            record["methods"] = dict(d["methods"])
            record["status_codes"] = dict(d["status_codes"])
            record["response_bytes"] = d["response_bytes"]
        if "flow" in d["sources"]:
            record["flow_ports"] = dict(d["flow_ports"])
            record["flow_states"] = dict(d["flow_states"])
        if "alert" in d["sources"]:
            record["alert_signatures"] = dict(d["alert_signatures"])
            record["alert_count"] = d["alert_count"]
        out.append(record)
    return out


# --- Zeek ---

def _zeek_header(path):
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("#fields"):
                return line.rstrip("\n").split("\t")[1:]
            if not line.startswith("#"):
                break
    return None


def _zeek_rows(path):
    fields = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            yield fields, line.rstrip("\n").split("\t")


def zeek_pseudonymise(path, out_path, key, minimize=False):
    """Write a pseudonymised (optionally minimised) copy of a Zeek log."""
    header = _zeek_header(path)
    if header is None:
        return 0
    keep = None
    if minimize:
        # Operational-only columns; drop identifier-bearing columns.
        keep = [c for c in header if c not in ZEEK_IP_COLUMNS and c not in ZEEK_DOMAIN_COLUMNS]
        # Always keep a timestamp-like leading column and uid if present.
        if header and header[0] not in keep:
            keep.insert(0, header[0])
        if "uid" in header and "uid" not in keep:
            keep.insert(1, "uid")
    else:
        keep = header

    out_lines = []
    count = 0
    for fields, row in _zeek_rows(path):
        if fields is None:
            continue
        out_row = []
        for i, col in enumerate(fields):
            if col in keep:
                value = row[i] if i < len(row) else ""
                if col in ZEEK_IP_COLUMNS or col in ZEEK_DOMAIN_COLUMNS:
                    value = token(value, key)
                out_row.append(value)
        out_lines.append("\t".join(out_row))
        count += 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Rebuild a minimal header.
    with out_path.open("w", encoding="utf-8") as handle:
        handle.write("#fields\t" + "\t".join(keep) + "\n")
        handle.write("#types\t" + "\t".join(["string"] * len(keep)) + "\n")
        handle.write("\n".join(out_lines) + "\n")
    return count


def transform_suricata(source, out_dir, key):
    out_dir.mkdir(parents=True, exist_ok=True)
    events = read_events(source)
    c1 = [suricata_c1(e, key) for e in events]
    c2 = [r for e in events if (r := suricata_c2(e, key)) is not None]
    c3 = suricata_c3(events, key)
    write_jsonl(out_dir / "C1-pseudonymised.jsonl", c1)
    write_jsonl(out_dir / "C2-minimised-pseudonymised.jsonl", c2)
    write_jsonl(out_dir / "C3-aggregated-60s.jsonl", c3)
    return {
        "source": str(source),
        "source_events": len(events),
        "dns_events": sum(1 for e in events if e.get("event_type") == "dns"),
        "http_events": sum(1 for e in events if e.get("event_type") == "http"),
        "flow_events": sum(1 for e in events if e.get("event_type") == "flow"),
        "alert_events": sum(1 for e in events if e.get("event_type") == "alert"),
        "c1_records": len(c1),
        "c2_records": len(c2),
        "c3_windows": len(c3),
    }


def transform_zeek(raw_dir, out_dir, key):
    """Pseudonymise Zeek logs, producing C1 and C2 variants per log type."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stats = {}
    for name in ("dns.log", "conn.log", "http.log"):
        src = raw_dir / name
        if not src.is_file():
            continue
        c1 = zeek_pseudonymise(src, out_dir / f"{name}.C1", key, minimize=False)
        c2 = zeek_pseudonymise(src, out_dir / f"{name}.C2", key, minimize=True)
        stats[name] = {"c1_records": c1, "c2_records": c2}
    return stats


def main():
    scenario = sys.argv[1] if len(sys.argv) > 1 else "S2"
    repetition = sys.argv[2] if len(sys.argv) > 2 else "R2"
    key = load_key()
    run_dir = EVIDENCE / "raw-runs" / f"{scenario}-{repetition}"
    out_dir = EVIDENCE / "transformed-runs" / f"{scenario}-{repetition}"

    zeek_dir = run_dir / "zeek"
    suricata_eve = run_dir / "suricata" / "eve.json"

    metadata = {
        "scenario": scenario,
        "repetition": repetition,
        "transformation_version": TRANSFORM_VERSION,
        "hmac_key_id": key_id(key),
        "window_seconds": WINDOW_SECONDS,
        "note": "HMAC pseudonyms are linkable pseudonyms, not anonymised data.",
    }

    if zeek_dir.is_dir():
        metadata["zeek"] = transform_zeek(zeek_dir, out_dir / "zeek", key)
    if suricata_eve.is_file():
        metadata["suricata"] = transform_suricata(suricata_eve, out_dir / "suricata", key)

    (out_dir / "transformation-metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
