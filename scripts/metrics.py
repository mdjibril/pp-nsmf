#!/usr/bin/env python3
"""Source-specific telemetry-volume metrics (corrected scope).

These functions compute byte-volume reduction against the exact source stream
that the transformation pipeline reads, instead of mixing Zeek and Suricata
scopes. See docs/metric-scope-resolution-proposal.md.

Nothing here modifies evidence; it only reads preserved raw and transformed
files.
"""

from pathlib import Path

# Zeek logs that transform_telemetry.transform_zeek actually reads and
# transforms. files.log, packet_filter.log, and reporter.log are not transformed.
ZEEK_TRANSFORMED_LOGS = ("dns.log", "conn.log", "http.log")


def _size(path):
    """Return file size in bytes, or None if the file does not exist."""
    p = Path(path)
    return p.stat().st_size if p.is_file() else None


def _reduction_pct(transformed_bytes, raw_bytes):
    """Return 100*(1 - transformed/raw), or None when undefined.

    A zero or missing baseline yields None (undefined), never 0 and never a
    fabricated value.
    """
    if transformed_bytes is None or raw_bytes is None:
        return None
    if raw_bytes <= 0:
        return None
    return round(100.0 * (1.0 - transformed_bytes / raw_bytes), 2)


def compute_source_metrics(raw_dir, transformed_dir):
    """Compute Suricata- and Zeek-scoped byte-volume metrics for one run.

    Returns a dict keyed by column name. Missing files are None (not 0).
    """
    raw_dir = Path(raw_dir)
    transformed_dir = Path(transformed_dir)

    metrics = {}

    # --- Suricata: baseline = eve.json only; stages = C1/C2/C3 jsonl. ---
    eve = raw_dir / "suricata" / "eve.json"
    c1 = transformed_dir / "suricata" / "C1-pseudonymised.jsonl"
    c2 = transformed_dir / "suricata" / "C2-minimised-pseudonymised.jsonl"
    c3 = transformed_dir / "suricata" / "C3-aggregated-60s.jsonl"

    metrics["suricata_raw_bytes"] = _size(eve)
    metrics["suricata_c1_bytes"] = _size(c1)
    metrics["suricata_c2_bytes"] = _size(c2)
    metrics["suricata_c3_bytes"] = _size(c3)
    metrics["suricata_c1_reduction_pct"] = _reduction_pct(
        metrics["suricata_c1_bytes"], metrics["suricata_raw_bytes"]
    )
    metrics["suricata_c2_reduction_pct"] = _reduction_pct(
        metrics["suricata_c2_bytes"], metrics["suricata_raw_bytes"]
    )
    metrics["suricata_c3_reduction_pct"] = _reduction_pct(
        metrics["suricata_c3_bytes"], metrics["suricata_raw_bytes"]
    )

    # --- Zeek: baseline = transformed logs only; stages = C1/C2 (no C3). ---
    zeek_raw = 0
    zeek_c1 = 0
    zeek_c2 = 0
    zeek_present = False
    for name in ZEEK_TRANSFORMED_LOGS:
        src = raw_dir / "zeek" / name
        if src.is_file():
            zeek_present = True
            zeek_raw += src.stat().st_size
        c1f = transformed_dir / "zeek" / f"{name}.C1"
        c2f = transformed_dir / "zeek" / f"{name}.C2"
        if c1f.is_file():
            zeek_c1 += c1f.stat().st_size
        if c2f.is_file():
            zeek_c2 += c2f.stat().st_size

    if zeek_present:
        metrics["zeek_raw_bytes"] = zeek_raw
        metrics["zeek_c1_bytes"] = zeek_c1
        metrics["zeek_c2_bytes"] = zeek_c2
        metrics["zeek_c1_reduction_pct"] = _reduction_pct(zeek_c1, zeek_raw)
        metrics["zeek_c2_reduction_pct"] = _reduction_pct(zeek_c2, zeek_raw)
    else:
        metrics["zeek_raw_bytes"] = None
        metrics["zeek_c1_bytes"] = None
        metrics["zeek_c2_bytes"] = None
        metrics["zeek_c1_reduction_pct"] = None
        metrics["zeek_c2_reduction_pct"] = None

    return metrics


# Columns emitted by the corrected metrics, in order.
SOURCE_METRIC_FIELDS = [
    "suricata_raw_bytes", "suricata_c1_bytes", "suricata_c2_bytes",
    "suricata_c3_bytes", "suricata_c1_reduction_pct",
    "suricata_c2_reduction_pct", "suricata_c3_reduction_pct",
    "zeek_raw_bytes", "zeek_c1_bytes", "zeek_c2_bytes",
    "zeek_c1_reduction_pct", "zeek_c2_reduction_pct",
]
