#!/usr/bin/env python3
"""Linkability validation for PP-NSMF pseudonymisation.

Linkability is the property that, under a fixed HMAC key and transformation
version, the same raw identifier maps to the same pseudonym (so repeated
observations of one entity can be linked), while distinct identifiers map to
distinct pseudonyms (so different entities are not merged).

This module validates *within-run* consistency: for each identifier field the
raw-value -> pseudonym mapping must be a bijection. Cross-run linkability is not
asserted here; it only holds when two runs share the same key and transformation
version, which are recorded separately in transformation metadata.
"""

from collections import defaultdict

# Suricata EVE field paths that carry entity identifiers. Paths are tuples of
# nested keys. Content fields (http.url, dns answer rdata) are excluded; those
# are covered by the identifier-exposure check, not linkability.
IDENTIFIER_PATHS = [
    ("src_ip",),
    ("dest_ip",),
    ("dns", "rrname"),
    ("http", "hostname"),
]

# Identifier paths that survive minimisation into C2. Nested name/domain fields
# are dropped by C2 by policy, so only IP-level linkability applies there.
IP_PATHS = [("src_ip",), ("dest_ip",)]


def _get(obj, path):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def extract_identifiers(event, paths=IDENTIFIER_PATHS):
    """Return (path, value) pairs for identifier fields present in an event."""
    pairs = []
    for path in paths:
        value = _get(event, path)
        if isinstance(value, str) and value:
            pairs.append((path, value))
    return pairs


def build_mappings(raw_events, transformed_events, paths=IDENTIFIER_PATHS):
    """Correlate raw and transformed events (same order) into two mappings."""
    raw_to_token = defaultdict(lambda: defaultdict(set))
    token_to_raw = defaultdict(lambda: defaultdict(set))
    for raw, transformed in zip(raw_events, transformed_events):
        raw_ids = {path: value for path, value in extract_identifiers(raw, paths)}
        trans_ids = {path: value for path, value in extract_identifiers(transformed, paths)}
        for path, raw_value in raw_ids.items():
            token_value = trans_ids.get(path)
            if token_value is None:
                continue
            raw_to_token[path][raw_value].add(token_value)
            token_to_raw[path][token_value].add(raw_value)
    return raw_to_token, token_to_raw


def assess(raw_to_token, token_to_raw):
    """Assess bijectivity of the raw<->pseudonym mapping per field."""
    fields = {}
    problems = []
    for path in sorted(raw_to_token):
        mapping = raw_to_token[path]
        label = ".".join(path)
        inconsistent = {rv: sorted(toks) for rv, toks in mapping.items() if len(toks) != 1}
        collisions = {
            tok: sorted(rvs)
            for tok, rvs in token_to_raw.get(path, {}).items()
            if len(rvs) != 1
        }
        fields[label] = {
            "distinct_raw_values": len(mapping),
            "distinct_tokens": len(token_to_raw.get(path, {})),
            "consistent": len(inconsistent) == 0,
            "injective": len(collisions) == 0,
        }
        if inconsistent:
            problems.append({"field": label, "type": "inconsistent", "detail": inconsistent})
        if collisions:
            problems.append({"field": label, "type": "collision", "detail": collisions})

    if problems:
        status = "fail"
    elif fields:
        status = "ok"
    else:
        status = "no_identifiers"
    return {"status": status, "fields": fields, "problems": problems}


def assess_suricata(raw_events, transformed_events, paths=IDENTIFIER_PATHS):
    """Convenience wrapper: build mappings and assess them."""
    raw_to_token, token_to_raw = build_mappings(raw_events, transformed_events, paths)
    return assess(raw_to_token, token_to_raw)
