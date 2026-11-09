# Linkability Validator Fix — Report

Date: 2026-10-21. This documents the linkability-validation defect, its fix,
the automated tests, the revalidation of existing evidence, and remaining
limitations.

## 1. The defect

`scripts/validate_results.py:check_linkability` contained a tautology:

```python
tokens = {}                       # field -> set of observed pseudonyms
...
consistent = all(len(v) <= len(tokens.get(k, set())) for k, v in tokens.items())
return {"linkability": "ok" if consistent else "check", ...}
```

`tokens.get(k)` is the *same set* as `v`, so `len(v) <= len(tokens.get(k))` is
`len(v) <= len(v)` and is always `True`. The check therefore always reported
`"ok"` whenever any `h_` token existed. More fundamentally, it never read the raw
(C0) records, so it could not correlate a raw identifier with its pseudonym and
could not substantiate any linkability claim.

## 2. The fix

New module `scripts/linkability.py`:

- `extract_identifiers(event)` returns `(field_path, value)` for entity
  identifiers: `src_ip`, `dest_ip`, `dns.rrname`, `http.hostname`.
- `build_mappings(raw_events, transformed_events)` zips raw and transformed
  records one-to-one and builds two maps per field: raw→token and token→raw.
- `assess(raw_to_token, token_to_raw)` verifies, per field:
  - **consistency** — each raw value maps to exactly one token;
  - **injectivity** — each token maps to exactly one raw value (no collisions);
  - status is `ok`, `fail`, or `no_identifiers`.

`check_linkability` in `validate_results.py` was rewritten to:

- **C1** — validate the full identifier set (bijective within a run).
- **C2** — validate IP fields only (`src_ip`, `dest_ip`); nested name/domain
  fields are dropped by the minimisation policy, not treated as failures.
- **C3** — `not_applicable` (identifiers are aggregated away).
- **Zeek C1** — validate IP columns (`id.orig_h`, `id.resp_h`); **Zeek C2** —
  `not_applicable` (identifier columns dropped).

An `overall` status of `fail` now fails validation.

## 3. Automated tests

`scripts/test_linkability.py` (7 tests, all pass):

- `test_extract_identifiers` — DNS/HTTP identifier extraction.
- `test_consistent_mapping_is_ok` — positive: repeated identifiers map
  consistently.
- `test_inconsistent_mapping_fails` — negative: one raw value mapped to two
  tokens is detected as `inconsistent`.
- `test_collision_fails` — negative: two distinct raw values mapped to one token
  is detected as a `collision`.
- `test_distinct_identifiers_stay_distinct` — injectivity holds.
- `test_no_identifiers` — empty input is `no_identifiers`.
- `test_overall_ok_then_fail_after_corruption` — integration: the full
  `check_linkability` path reports `ok`, then `fail` after a pseudonym is
  deliberately corrupted.

Run with `python3 scripts/test_linkability.py`.

## 4. Revalidation of existing evidence

Re-ran `validate_results.py` (validator v1.1.0) on the existing datasets without
modifying raw evidence, transformed outputs, keys, or the checksum manifest:

| Run | Transformation | HMAC key | Linkability | Validation |
|---|---|---|---|---|
| S1-R1 | 2.0.0 | e04d6b0475fd | ok | PASS |
| S2-R2 | 2.0.0 | e04d6b0475fd | ok | PASS |
| S2-R3 | 2.0.0 | e04d6b0475fd | ok | PASS |
| S2-R4 | 2.0.0 | e04d6b0475fd | ok | PASS |
| S2-R5 | 2.0.0 | e04d6b0475fd | ok | PASS |

## 5. HTTP Host-header behaviour

The Zeek `http.log` `host` field carries the raw HTTP Host header. BusyBox
`wget` sends `Host: 10.10.10.20:80`, i.e. the IP **with the port**. The current
transformation does **not** normalise this value; the full string
`10.10.10.20:80` is pseudonymised as a single opaque token.

Consequences (documented, not silently changed):

- No raw identifier leaks: the `10.10.10.20` substring is removed.
- The `host` pseudonym differs from the `id.resp_h`/`dest_ip` pseudonym for the
  same server, so cross-field linkability between the HTTP Host header and the
  network-layer destination IP is **not** preserved.

Normalisation (stripping the port before pseudonymising) would be appropriate if
cross-field linkability between the Host header and `dest_ip` is required, but
it is a transformation change. It is recorded here as a candidate for a future
transformation version and was intentionally not applied, to avoid rewriting
existing outputs.

## 6. Within-run vs cross-run linkability

The validator asserts **within-run** consistency only: within one dataset, each
raw identifier maps bijectively to one pseudonym.

**Cross-run** linkability is not asserted automatically. It holds only when two
runs share the same HMAC key and transformation version; both are recorded in
each validation report (`hmac_key_id`, `transformation_version`). S1-R1 and
S2-R2–R5 share key `e04d6b0475fd` and version `2.0.0`, so they are cross-run
linkable. The legacy S2-R1 used a different key and is not.

## 7. Remaining limitations

- Linkability is checked within-run only; cross-run linkability is documented
  but not machine-checked.
- Host-header `host:port` is not normalised (see section 5).
- Collision resistance relies on HMAC-SHA256 truncated to 64 bits; no collision
  is observed at lab scale, but this is probabilistic, not absolute.
- Zeek linkability checks IP columns only; domain columns (`query`, `host`) are
  covered by the identifier-exposure check rather than linkability.
