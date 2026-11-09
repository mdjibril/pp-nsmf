# PP-NSMF Automation Guide

How to verify, configure, run, transform, validate, and report experiments.

## Prerequisites

- Ubuntu host with GNS3 (local server on `127.0.0.1:3080`) and Docker.
- Python 3 with PyYAML (already present as a GNS3 dependency).
- The five PP-NSMF Docker nodes running.

## Configuration

`config/lab.yaml` is the single source of truth for node identities and intended
addressing. It contains no secrets.

The HMAC key is stored at `evidence-backup/keys/hmac.key` (mode 0600), generated
on first run if absent, and is excluded from source control by `.gitignore`.

## Verify the lab

```bash
python3 scripts/verify_topology.py
```

Checks container state, IP addresses and routes, client-to-node ping, DNS
resolution, and monitoring processes. Exit code 0 means all checks passed.

## Configure addressing (idempotent)

```bash
python3 scripts/configure_lab.py            # dry run
python3 scripts/configure_lab.py --apply    # apply missing addresses
```

Addressing is restart-persistent via the GNS3 Docker `start_command` (applied in
`PP-NSMF.gns3` and verified by a restart test). `configure_lab.py` is the
recovery/fallback path.

## Services

Two per-run target services must be running before their scenarios execute:

```bash
# DNS responder on the Zeek node (S2) — deploy inside the Zeek container.
#   docker cp scripts/dns_responder.py <zeek>:/tmp/dns_responder.py
#   docker exec -d <zeek> python3 /tmp/dns_responder.py

# HTTP responder on the server node (S1) — idempotent host-side deploy script.
python3 scripts/deploy_http_server.py
```

`deploy_http_server.py` copies `scripts/http_responder.sh` (a BusyBox `nc -lk`
persistent HTTP server, since the Alpine server has no `httpd` or Python),
restarts the listener, and verifies a 200 response before returning.

## Run an experiment

```bash
python3 scripts/experiment_controller.py S1 R1
python3 scripts/experiment_controller.py S2 R2
```

The controller verifies prerequisites, starts clean Zeek and Suricata captures,
generates traffic, collects and checksum-verifies raw evidence, runs the C0-C3
transformations, validates, updates the run log, and generates reports.

Run a specific scenario/repetition with `python3 scripts/experiment_controller.py <scenario> <repetition>`.

## Transform (standalone)

```bash
python3 scripts/transform_telemetry.py S2 R2
```

Reads `evidence-backup/raw-runs/<scenario>-<repetition>/` and writes
`evidence-backup/transformed-runs/<scenario>-<repetition>/`.

## Validate

```bash
python3 scripts/validate_results.py S2 R2
```

Writes `evidence-backup/reports/<run>.validation.json` and exits 0 on PASS.

## Reports and metrics

```bash
python3 scripts/generate_report.py S2 R2
python3 scripts/generate_metrics_csv.py
```

Produces per-run Markdown/JSON reports and `reports/aggregate-metrics.csv`.

## Evidence layout

```
evidence-backup/
├── raw-runs/<scenario>-<repetition>/     # collected raw Zeek + Suricata
├── transformed-runs/<scenario>-<repetition>/  # C0-C3 + metadata
├── reports/                             # validation, report, aggregate metrics
├── protocol/experiment-run-log.csv      # one row per run
├── keys/hmac.key                        # HMAC key (0600, not committed)
└── SHA256SUMS.txt                       # integrity manifest
```

## Restart recovery

After a node/container restart:

1. `python3 scripts/verify_topology.py`
2. If addresses are missing, `python3 scripts/configure_lab.py --apply`
3. Redeploy/restart the DNS responder if needed (`scripts/dns_responder.py`)
4. Redeploy the HTTP responder if needed (`python3 scripts/deploy_http_server.py`)
5. Restart Zeek/Suricata captures as part of the next run

## Safety rules

- Never delete, overwrite, rename, or modify existing experimental evidence,
  logs, HMAC keys, transformation outputs, or checksum manifests.
- Never run `docker rm`, `docker system prune`, or rebuild images without approval.
- Each rerun must use a distinct run identifier.
