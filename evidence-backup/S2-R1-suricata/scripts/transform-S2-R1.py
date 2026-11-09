#!/usr/bin/env python3

import json
import hmac
import hashlib
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone

BASE = Path("/var/log/suricata/pp-nsmf")
SOURCE = BASE / "captures/S2/R1-raw-backup/eve.json"
OUT = BASE / "output/S2/R1"
KEY_FILE = BASE / "keys/S2/R1/hmac.key"

WINDOW_SECONDS = 60

def load_key():
    if not KEY_FILE.is_file():
        raise FileNotFoundError(f"Missing HMAC key: {KEY_FILE}")

    key_text = KEY_FILE.read_text().strip()

    if len(key_text) != 64:
        raise ValueError("Expected a 64-character hexadecimal HMAC key")

    try:
        key = bytes.fromhex(key_text)
    except ValueError as exc:
        raise ValueError("HMAC key is not valid hexadecimal") from exc

    if len(key) != 32:
        raise ValueError("Expected a 32-byte HMAC key")

    return key

def token(value, key):
    if value is None or value == "":
        return value
    digest = hmac.new(
        key, str(value).encode("utf-8"), hashlib.sha256
    ).hexdigest()[:16]
    return "h_" + digest

def read_events():
    events = []
    with SOURCE.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at line {line_number}: {exc}"
                ) from exc
    return events

def make_c1(event, key):
    item = dict(event)

    for field in ("src_ip", "dest_ip", "dest_host"):
        if item.get(field):
            item[field] = token(item[field], key)

    dns = item.get("dns")
    if isinstance(dns, dict):
        dns = dict(dns)
        for field in ("rrname",):
            if dns.get(field):
                dns[field] = token(dns[field], key)

        answers = dns.get("answers")
        if isinstance(answers, list):
            safe_answers = []
            for answer in answers:
                if not isinstance(answer, dict):
                    continue
                safe = dict(answer)
                if safe.get("rdata"):
                    safe["rdata"] = token(safe["rdata"], key)
                if safe.get("rrname"):
                    safe["rrname"] = token(safe["rrname"], key)
                safe_answers.append(safe)
            dns["answers"] = safe_answers

        grouped = dns.get("grouped")
        if isinstance(grouped, dict):
            dns["grouped"] = {
                str(k): [token(v, key) for v in values]
                if isinstance(values, list) else values
                for k, values in grouped.items()
            }

        item["dns"] = dns

    return item

def make_c2(event, key):
    dns = event.get("dns")
    if not isinstance(dns, dict):
        return None

    # Keep operational metadata; exclude query names and answer values.
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
        "answer_count": len(dns.get("answers", []))
            if isinstance(dns.get("answers"), list) else 0,
    }
    return {k: v for k, v in result.items() if v is not None}

def parse_time(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None

def make_c3(events, key):
    windows = defaultdict(lambda: {
        "event_count": 0,
        "query_types": Counter(),
        "response_codes": Counter(),
        "dns_message_types": Counter(),
        "answer_count": 0,
    })

    for event in events:
        dns = event.get("dns")
        if event.get("event_type") != "dns" or not isinstance(dns, dict):
            continue

        dt = parse_time(event.get("timestamp"))
        if dt is None:
            continue

        epoch = int(dt.timestamp())
        window_start = epoch - (epoch % WINDOW_SECONDS)
        window = windows[window_start]
        window["event_count"] += 1

        qtype = dns.get("rrtype")
        if qtype is not None:
            window["query_types"][str(qtype)] += 1

        rcode = dns.get("rcode")
        if rcode is not None:
            window["response_codes"][str(rcode)] += 1

        message_type = dns.get("type")
        if message_type is not None:
            window["dns_message_types"][str(message_type)] += 1

        answers = dns.get("answers")
        if isinstance(answers, list):
            window["answer_count"] += len(answers)

    output = []
    for start in sorted(windows):
        data = windows[start]
        output.append({
            "window_start_utc": datetime.fromtimestamp(
                start, timezone.utc
            ).isoformat(),
            "window_seconds": WINDOW_SECONDS,
            "source_log": "suricata_dns",
            "event_count": data["event_count"],
            "query_types": dict(data["query_types"]),
            "response_codes": dict(data["response_codes"]),
            "dns_message_types": dict(data["dns_message_types"]),
            "answer_count": data["answer_count"],
        })

    return output

def write_jsonl(path, rows):
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    key = load_key()
    events = read_events()

    c1 = [make_c1(event, key) for event in events]
    c2 = [
        result for event in events
        if (result := make_c2(event, key)) is not None
    ]
    c3 = make_c3(events, key)

    write_jsonl(OUT / "C1-pseudonymised.jsonl", c1)
    write_jsonl(OUT / "C2-minimised-pseudonymised.jsonl", c2)
    write_jsonl(OUT / "C3-aggregated-60s.jsonl", c3)

    metadata = {
        "scenario": "S2",
        "repetition": "R1",
        "source": str(SOURCE),
        "source_events": len(events),
        "dns_events": sum(
            1 for e in events if e.get("event_type") == "dns"
        ),
        "c1_records": len(c1),
        "c2_dns_records": len(c2),
        "c3_windows": len(c3),
        "window_seconds": WINDOW_SECONDS,
        "hmac_key_status": "replacement key generated during recovery",
        "note": (
            "Original key was unavailable. This replacement key is not "
            "the previously generated key; record this change in the "
            "experiment log. C0 remains the raw backup."
        ),
    }

    (OUT / "transformation-metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(metadata, indent=2))

if __name__ == "__main__":
    main()
