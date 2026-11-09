#!/usr/bin/env python3
"""Regression tests for source-scoped telemetry-volume metrics."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import metrics  # noqa: E402


def _write(path, size):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


class SourceMetricsTests(unittest.TestCase):
    def _layout(self):
        """Build a temporary raw/transformed tree and return its root."""
        root = Path(tempfile.mkdtemp())
        raw = root / "raw"
        tr = root / "transformed"
        _write(raw / "suricata" / "eve.json", 1000)
        _write(tr / "suricata" / "C1-pseudonymised.jsonl", 1100)
        _write(tr / "suricata" / "C2-minimised-pseudonymised.jsonl", 200)
        _write(tr / "suricata" / "C3-aggregated-60s.jsonl", 50)
        _write(raw / "zeek" / "conn.log", 300)
        _write(raw / "zeek" / "http.log", 200)
        _write(tr / "zeek" / "conn.log.C1", 280)
        _write(tr / "zeek" / "conn.log.C2", 150)
        _write(tr / "zeek" / "http.log.C1", 210)
        _write(tr / "zeek" / "http.log.C2", 130)
        return raw, tr

    def test_suricata_values(self):
        raw, tr = self._layout()
        m = metrics.compute_source_metrics(raw, tr)
        self.assertEqual(m["suricata_raw_bytes"], 1000)
        self.assertEqual(m["suricata_c1_bytes"], 1100)
        self.assertEqual(m["suricata_c2_bytes"], 200)
        self.assertEqual(m["suricata_c3_bytes"], 50)
        self.assertEqual(m["suricata_c1_reduction_pct"], -10.0)  # larger than raw
        self.assertEqual(m["suricata_c2_reduction_pct"], 80.0)
        self.assertEqual(m["suricata_c3_reduction_pct"], 95.0)

    def test_zeek_values(self):
        raw, tr = self._layout()
        m = metrics.compute_source_metrics(raw, tr)
        self.assertEqual(m["zeek_raw_bytes"], 500)  # conn 300 + http 200
        self.assertEqual(m["zeek_c1_bytes"], 490)   # 280 + 210
        self.assertEqual(m["zeek_c2_bytes"], 280)   # 150 + 130
        self.assertEqual(m["zeek_c1_reduction_pct"], 2.0)
        self.assertEqual(m["zeek_c2_reduction_pct"], 44.0)

    def test_zeek_excludes_untransformed_logs(self):
        raw, tr = self._layout()
        _write(raw / "zeek" / "files.log", 999)      # not transformed
        _write(raw / "zeek" / "packet_filter.log", 999)
        m = metrics.compute_source_metrics(raw, tr)
        self.assertEqual(m["zeek_raw_bytes"], 500)  # files/packet_filter excluded

    def test_zero_byte_baseline_is_undefined(self):
        raw, tr = self._layout()
        _write(raw / "suricata" / "eve.json", 0)
        m = metrics.compute_source_metrics(raw, tr)
        self.assertIsNone(m["suricata_c1_reduction_pct"])
        self.assertIsNone(m["suricata_c2_reduction_pct"])
        self.assertIsNone(m["suricata_c3_reduction_pct"])

    def test_missing_source_is_none(self):
        raw, tr = self._layout()
        (raw / "suricata" / "eve.json").unlink()
        m = metrics.compute_source_metrics(raw, tr)
        self.assertIsNone(m["suricata_raw_bytes"])
        self.assertIsNone(m["suricata_c1_reduction_pct"])

    def test_missing_transformed_stage_is_none(self):
        raw, tr = self._layout()
        (tr / "suricata" / "C2-minimised-pseudonymised.jsonl").unlink()
        m = metrics.compute_source_metrics(raw, tr)
        self.assertIsNone(m["suricata_c2_bytes"])
        self.assertIsNone(m["suricata_c2_reduction_pct"])

    def test_zeek_missing_logs_is_none(self):
        raw, tr = self._layout()
        for f in list((raw / "zeek").glob("*")):
            f.unlink()
        m = metrics.compute_source_metrics(raw, tr)
        self.assertIsNone(m["zeek_raw_bytes"])
        self.assertIsNone(m["zeek_c1_reduction_pct"])
        self.assertIsNone(m["zeek_c2_reduction_pct"])


if __name__ == "__main__":
    unittest.main()
