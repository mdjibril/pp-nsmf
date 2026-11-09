#!/usr/bin/env python3
"""Automated tests for the PP-NSMF linkability validator.

Run:  python3 scripts/test_linkability.py

Covers positive (consistent mapping) and negative (inconsistent mapping,
token collision) cases, plus an integration test that exercises the full
validate_results.check_linkability path and shows it fails when a mapping is
deliberately corrupted.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import linkability
import validate_results


def http_event(src="10.10.10.10", dest="10.10.10.20", hostname="10.10.10.20"):
    return {
        "event_type": "http",
        "src_ip": src,
        "dest_ip": dest,
        "proto": "TCP",
        "dest_port": 80,
        "http": {"hostname": hostname, "http_method": "GET", "status": 200},
    }


def dns_event(src="10.10.10.10", dest="10.10.10.40", rrname="probe.pp-nsmf.test"):
    return {
        "event_type": "dns",
        "src_ip": src,
        "dest_ip": dest,
        "proto": "UDP",
        "dest_port": 53,
        "dns": {"type": "query", "rrname": rrname, "rrtype": "A", "rcode": "NOERROR"},
    }


class TestAssess(unittest.TestCase):
    def test_extract_identifiers(self):
        pairs = linkability.extract_identifiers(http_event())
        self.assertIn((("src_ip",), "10.10.10.10"), pairs)
        self.assertIn((("dest_ip",), "10.10.10.20"), pairs)
        self.assertIn((("http", "hostname"), "10.10.10.20"), pairs)

        dns_pairs = linkability.extract_identifiers(dns_event())
        self.assertIn((("dns", "rrname"), "probe.pp-nsmf.test"), dns_pairs)

    def test_consistent_mapping_is_ok(self):
        raw = [http_event(), http_event()]
        transformed = [
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_bbb", "http": {"hostname": "h_bbb"}},
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_bbb", "http": {"hostname": "h_bbb"}},
        ]
        result = linkability.assess_suricata(raw, transformed)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["fields"]["src_ip"]["distinct_raw_values"], 1)

    def test_inconsistent_mapping_fails(self):
        raw = [http_event(), http_event()]
        transformed = [
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_bbb", "http": {"hostname": "h_bbb"}},
            {"event_type": "http", "src_ip": "h_ccc", "dest_ip": "h_bbb", "http": {"hostname": "h_bbb"}},
        ]
        result = linkability.assess_suricata(raw, transformed)
        self.assertEqual(result["status"], "fail")
        self.assertTrue(any(p["type"] == "inconsistent" for p in result["problems"]))

    def test_collision_fails(self):
        raw = [http_event(), http_event(dest="10.10.10.30", hostname="10.10.10.30")]
        transformed = [
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_bbb", "http": {"hostname": "h_bbb"}},
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_bbb", "http": {"hostname": "h_bbb"}},
        ]
        result = linkability.assess_suricata(raw, transformed)
        self.assertEqual(result["status"], "fail")
        self.assertTrue(any(p["type"] == "collision" for p in result["problems"]))

    def test_no_identifiers(self):
        result = linkability.assess({}, {})
        self.assertEqual(result["status"], "no_identifiers")

    def test_distinct_identifiers_stay_distinct(self):
        raw = [http_event(), http_event(dest="10.10.10.30", hostname="10.10.10.30")]
        transformed = [
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_bbb", "http": {"hostname": "h_bbb"}},
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_ccc", "http": {"hostname": "h_ccc"}},
        ]
        result = linkability.assess_suricata(raw, transformed)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["fields"]["dest_ip"]["injective"])


class TestCheckLinkabilityFiles(unittest.TestCase):
    def _write_run(self, base, raw_events, c1_events, c2_events):
        raw_dir = base / "raw-runs" / "S9-R9"
        trans_dir = base / "transformed-runs" / "S9-R9"
        (raw_dir / "suricata").mkdir(parents=True)
        (trans_dir / "suricata").mkdir(parents=True)
        (raw_dir / "zeek").mkdir(parents=True)
        (trans_dir / "zeek").mkdir(parents=True)
        with (raw_dir / "suricata" / "eve.json").open("w", encoding="utf-8") as f:
            for e in raw_events:
                f.write(json.dumps(e) + "\n")
        with (trans_dir / "suricata" / "C1-pseudonymised.jsonl").open("w", encoding="utf-8") as f:
            for e in c1_events:
                f.write(json.dumps(e) + "\n")
        with (trans_dir / "suricata" / "C2-minimised-pseudonymised.jsonl").open("w", encoding="utf-8") as f:
            for e in c2_events:
                f.write(json.dumps(e) + "\n")
        with (trans_dir / "suricata" / "C3-aggregated-60s.jsonl").open("w", encoding="utf-8") as f:
            f.write('{"window_seconds":60}\n')
        return raw_dir, trans_dir

    def test_overall_ok_then_fail_after_corruption(self):
        raw = [http_event(), http_event()]
        c1 = [
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_bbb", "http": {"hostname": "h_bbb"}},
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_bbb", "http": {"hostname": "h_bbb"}},
        ]
        c2 = [
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_bbb"},
            {"event_type": "http", "src_ip": "h_aaa", "dest_ip": "h_bbb"},
        ]
        with tempfile.TemporaryDirectory() as td:
            raw_dir, trans_dir = self._write_run(Path(td), raw, c1, c2)
            result = validate_results.check_linkability(raw_dir, trans_dir)
            self.assertEqual(result["overall"], "ok")

            bad_c1 = [dict(c1[0]), dict(c1[1])]
            bad_c1[1]["src_ip"] = "h_zzz"
            p = trans_dir / "suricata" / "C1-pseudonymised.jsonl"
            with p.open("w", encoding="utf-8") as f:
                for e in bad_c1:
                    f.write(json.dumps(e) + "\n")
            result = validate_results.check_linkability(raw_dir, trans_dir)
            self.assertEqual(result["overall"], "fail")


if __name__ == "__main__":
    unittest.main(verbosity=2)
