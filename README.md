# PP-NSMF — Privacy-Preserving Network Security Monitoring Framework

A research lab for evaluating a framework that balances cybersecurity and data
protection in Nigerian organisations. The lab runs on Ubuntu 24.04 with GNS3 and
Docker-based network nodes.

## Repository layout

```
config/lab.yaml              Node identities and intended addressing (no secrets)
scripts/                     Automation (see below)
experiments/                 Scenario definitions and run log
evidence-backup/             Raw, transformed, and reported experimental evidence
docs/                        Topology audit, addressing, protocol, and guides
PP-NSMF.gns3                 GNS3 project (do not edit casually)
```

## Nodes

| Node | Address | Role |
|---|---|---|
| POC-CLIENT-1 | 10.10.10.10/24 | traffic generator |
| POC-SERVER-1 | 10.10.10.20/24 | target service |
| Attacker-1 | 10.10.10.30/24 | controlled security-test traffic |
| MONITOR-ZEEK-1 | 10.10.10.40/24 | Zeek monitor + DNS responder |
| MONITOR-SURI-1 | (passive) | Suricata IDS / EVE JSON logging |

All nodes connect through `Hub1` on the `10.10.10.0/24` subnet.

## Scripts

- `verify_topology.py` — read-only topology and connectivity checks.
- `configure_lab.py` — controlled, idempotent address configuration (dry run by default; `--apply` to change).
- (Phase Three+) experiment controller, capture, traffic, transformation, validation, and reporting scripts.

## Quick start

```bash
python3 scripts/verify_topology.py          # verify the lab
python3 scripts/configure_lab.py            # dry-run address config
python3 scripts/configure_lab.py --apply    # apply if needed
```

See `docs/` for the topology audit and IP-addressing details.

## Safety rules

- Never delete, overwrite, or rename existing experimental evidence, logs, HMAC
  keys, transformation outputs, or checksum manifests.
- HMAC keys and credentials are kept out of source control (see `.gitignore`).
- Destructive commands (`docker rm`, `docker system prune`, etc.) require explicit approval.
