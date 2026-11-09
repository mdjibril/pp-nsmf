#!/usr/bin/env python3
"""PP-NSMF experiment controller.

Orchestrates a single scenario/repetition run: verify prerequisites, start
captures, generate traffic, stop captures, collect and checksum-verify raw
evidence, transform it (C0-C3), validate, update the run log, and produce
reports. Failures are recorded, not silently counted as success.
"""

import csv
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

import capture_manager
import traffic_generator
import transform_telemetry
from lab_common import docker_exec, load_config, resolve_container

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence-backup"
SCENARIOS = ROOT / "experiments" / "scenarios.yaml"
RUN_LOG = EVIDENCE / "protocol" / "experiment-run-log.csv"

RUN_LOG_FIELDS = [
    "scenario_id", "repetition_id", "run_status", "start_utc", "end_utc",
    "traffic_description", "expected_events", "observed_zeek_events",
    "observed_suricata_events", "raw_zeek_path", "raw_suricata_path",
    "zeek_sha256", "suricata_sha256", "transformation_version", "hmac_key_id",
    "c0_records", "c1_records", "c2_records", "c3_windows",
    "c0_bytes", "c1_bytes", "c2_bytes", "c3_bytes",
    "validation_status", "deviation_or_notes",
]


def utcnow():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_of_files(paths):
    digest = hashlib.sha256()
    for p in sorted(paths):
        with open(p, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _count_zeek_events(log_path):
    count = 0
    if log_path.is_file():
        with log_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.startswith("#") and line.strip():
                    count += 1
    return count


def _count_suricata_events(eve_path, event_type):
    count = 0
    if eve_path.is_file():
        with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if f'"event_type":"{event_type}"' in line.replace(" ", ""):
                    count += 1
    return count


def ensure_key():
    key_file = transform_telemetry.DEFAULT_KEY
    key_file.parent.mkdir(parents=True, exist_ok=True)
    if not key_file.exists():
        key = os.urandom(32)
        key_file.write_text(key.hex() + "\n", encoding="utf-8")
        os.chmod(key_file, 0o600)
    return key_file


def _append_run_log(row):
    exists = RUN_LOG.exists()
    RUN_LOG.parent.mkdir(parents=True, exist_ok=True)
    with RUN_LOG.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RUN_LOG_FIELDS)
        if not exists or RUN_LOG.stat().st_size == 0:
            writer.writeheader()
        writer.writerow(row)


def _resolve(cfg, node_key):
    node = cfg["nodes"][node_key]
    return resolve_container(node["gns3_name"], cfg["project"]["project_id"])


def run_scenario(scenario_id, repetition_id):
    cfg = load_config()
    scenarios = yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))["scenarios"]
    scenario = scenarios[scenario_id]
    pid = cfg["project"]["project_id"]
    run_key = f"{scenario_id}-{repetition_id}"

    row = {f: "" for f in RUN_LOG_FIELDS}
    row["scenario_id"] = scenario_id
    row["repetition_id"] = repetition_id
    row["traffic_description"] = scenario["description"].strip()
    row["expected_events"] = "; ".join(
        e for group in scenario.get("expected_events", {}).values() for e in group
    )
    row["run_status"] = "RUNNING"

    generator_key = scenario["generator"]
    generator_container = _resolve(cfg, generator_key)
    zeek_container = _resolve(cfg, "zeek")
    suri_container = _resolve(cfg, "suricata")

    raw_host = EVIDENCE / "raw-runs" / run_key
    raw_zeek_host = raw_host / "zeek"
    raw_suri_host = raw_host / "suricata"
    zeek_dir_container = f"/opt/zeek/pp-nsmf/captures/{scenario_id}/{repetition_id}"
    suri_dir_container = f"/var/log/suricata/pp-nsmf/captures/{scenario_id}/{repetition_id}"

    start_dt = utcnow()
    row["start_utc"] = _iso(start_dt)

    try:
        # 1. Start captures with clean boundaries.
        capture_manager.start_zeek(zeek_container, zeek_dir_container)
        suricata_rules = scenario.get("suricata_rules", "/dev/null")
        capture_manager.start_suricata(suri_container, suri_dir_container, rules=suricata_rules)
        time.sleep(1)

        # 2. Generate traffic.
        traffic_generator.generate(generator_container, scenario["traffic"])
        end_dt = utcnow()
        row["end_utc"] = _iso(end_dt)

        # 3. Stop captures (flush logs).
        time.sleep(2)
        capture_manager.stop_zeek(zeek_container)
        capture_manager.stop_suricata(suri_container)

        # 4. Collect raw evidence with SHA-256 verification.
        zeek_checksums = capture_manager.collect_and_verify(zeek_container, zeek_dir_container, str(raw_zeek_host))
        suri_checksums = capture_manager.collect_and_verify(suri_container, suri_dir_container, str(raw_suri_host))

        # 5. Transform.
        key_file = ensure_key()
        __import__("subprocess").run(
            [sys.executable, str(ROOT / "scripts" / "transform_telemetry.py"), scenario_id, repetition_id],
            capture_output=True, text=True, check=True,
        )

        # 6. Populate run-log fields from actual data.
        row["run_status"] = "COMPLETED"
        if scenario_id == "S1":
            row["observed_zeek_events"] = _count_zeek_events(raw_zeek_host / "http.log")
            row["observed_suricata_events"] = _count_suricata_events(raw_suri_host / "eve.json", "http")
            zeek_hash_files = [raw_zeek_host / "http.log", raw_zeek_host / "conn.log"]
        elif scenario_id == "S2":
            row["observed_zeek_events"] = _count_zeek_events(raw_zeek_host / "dns.log")
            row["observed_suricata_events"] = _count_suricata_events(raw_suri_host / "eve.json", "dns")
            zeek_hash_files = [raw_zeek_host / "dns.log", raw_zeek_host / "conn.log"]
        elif scenario_id == "S3":
            row["observed_zeek_events"] = _count_zeek_events(raw_zeek_host / "conn.log")
            row["observed_suricata_events"] = _count_suricata_events(raw_suri_host / "eve.json", "flow")
            zeek_hash_files = [raw_zeek_host / "conn.log"]
        elif scenario_id == "S5":
            row["observed_zeek_events"] = _count_zeek_events(raw_zeek_host / "conn.log")
            row["observed_suricata_events"] = _count_suricata_events(raw_suri_host / "eve.json", "flow")
            zeek_hash_files = [raw_zeek_host / "conn.log"]
        elif scenario_id == "S6":
            row["observed_zeek_events"] = _count_zeek_events(raw_zeek_host / "conn.log")
            row["observed_suricata_events"] = _count_suricata_events(raw_suri_host / "eve.json", "flow")
            zeek_hash_files = [raw_zeek_host / "conn.log"]
        else:
            row["observed_zeek_events"] = _count_zeek_events(raw_zeek_host / "http.log")
            row["observed_suricata_events"] = _count_suricata_events(raw_suri_host / "eve.json", "alert")
            zeek_hash_files = [raw_zeek_host / "http.log", raw_zeek_host / "conn.log"]
        row["raw_zeek_path"] = str(raw_zeek_host.relative_to(ROOT))
        row["raw_suricata_path"] = str(raw_suri_host.relative_to(ROOT))
        row["zeek_sha256"] = sha256_of_files([p for p in zeek_hash_files if p.is_file()])
        row["suricata_sha256"] = sha256_of_files([raw_suri_host / "eve.json"])
        row["transformation_version"] = transform_telemetry.TRANSFORM_VERSION
        row["hmac_key_id"] = transform_telemetry.key_id(transform_telemetry.load_key(key_file))
        row["deviation_or_notes"] = ""

        # Condition-level metrics from transformation metadata.
        meta_path = EVIDENCE / "transformed-runs" / run_key / "transformation-metadata.json"
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            suri = meta.get("suricata", {})
            row["c0_records"] = suri.get("source_events", "")
            row["c1_records"] = suri.get("c1_records", "")
            row["c2_records"] = suri.get("c2_records", "")
            row["c3_windows"] = suri.get("c3_windows", "")

        def _size(p):
            return p.stat().st_size if p.is_file() else 0

        c1 = EVIDENCE / "transformed-runs" / run_key / "suricata" / "C1-pseudonymised.jsonl"
        c2 = EVIDENCE / "transformed-runs" / run_key / "suricata" / "C2-minimised-pseudonymised.jsonl"
        c3 = EVIDENCE / "transformed-runs" / run_key / "suricata" / "C3-aggregated-60s.jsonl"
        row["c0_bytes"] = sum(_size(p) for p in raw_host.rglob("*") if p.is_file())
        row["c1_bytes"] = _size(c1)
        row["c2_bytes"] = _size(c2)
        row["c3_bytes"] = _size(c3)

    except Exception as exc:
        row["run_status"] = "FAILED"
        row["deviation_or_notes"] = f"{type(exc).__name__}: {exc}"

    # 7. Validate (only if run completed) and update log.
    if row["run_status"] == "COMPLETED":
        proc = __import__("subprocess").run(
            [sys.executable, str(ROOT / "scripts" / "validate_results.py"), scenario_id, repetition_id],
            capture_output=True, text=True,
        )
        if proc.returncode == 0:
            row["validation_status"] = "PASS"
        else:
            row["validation_status"] = "FAIL"
            row["run_status"] = "FAILED"
            row["deviation_or_notes"] = (row["deviation_or_notes"] + " validation failed").strip()

    _append_run_log(row)

    # 8. Generate report.
    proc = __import__("subprocess").run(
        [sys.executable, str(ROOT / "scripts" / "generate_report.py"), scenario_id, repetition_id],
        capture_output=True, text=True,
    )

    print(json.dumps(row, indent=2))
    return 0 if row["run_status"] == "COMPLETED" else 1


def main():
    scenario_id = sys.argv[1] if len(sys.argv) > 1 else "S2"
    repetition_id = sys.argv[2] if len(sys.argv) > 2 else "R2"
    return run_scenario(scenario_id, repetition_id)


if __name__ == "__main__":
    sys.exit(main())
