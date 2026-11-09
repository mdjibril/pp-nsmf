# PP-NSMF Topology Audit

Date: 2026-10-21
Auditor: automated (Command Code)
Scope: read-only inspection of the GNS3 project, Docker containers, network interfaces, running services, and existing evidence. No network or configuration changes were made during this phase.

---

## 1. Verified Facts

### 1.1 GNS3 project and server

- Project file: `PP-NSMF.gns3` (GNS3 project version `2.2.61`, `revision: 9`).
- Project name: `PP-NSMF`, `project_id: 63f44bbf-fd98-49c1-a510-0678bb500780`.
- Project flags: `auto_open: false`, `auto_start: false`, `auto_close: true`.
- The GNS3 server is running locally (`gns3server --local`) and listening on `127.0.0.1:3080`.
- The GNS3 GUI (`/usr/bin/gns3`) is also running.
- One `ubridge` process is active per Docker node (5 total), confirming the GNS3 Ethernet hub/switch data path is live.

### 1.2 Topology (from PP-NSMF.gns3)

- A single Ethernet hub `Hub1` (`node_id 22eb39e6-0171-4bbd-8710-6b1ebf7ce4e9`, `ethernet_hub`, 8 ports) connects all five Docker nodes.
- Each Docker node exposes one adapter (`eth0`, adapter 0, port 0) linked to `Hub1`:

| Node | node_id | Hub1 port |
|---|---|---|
| MONITOR-ZEEK-1 | 46cf6f3e-9bd9-4604-8211-266cf641653b | e0 |
| POC-CLIENT-1 | 7e54cd55-f185-444e-bb6f-3f66f0f08106 | e1 |
| POC-SERVER-1 | 9f26d5dc-6ce4-4aaa-83f0-85debb2eb2f3 | e2 |
| MONITOR-SURI-1 | bca94062-d742-4d01-91e6-3aeb60e1939e | e3 |
| Attacker-1 | bcdf2324-4541-4795-8dcd-a1a970f4f918 | e4 |

### 1.3 Containers (all five running)

All five expected containers are running (`Up 21 hours` at audit time).

| Node | Container name | Image | Base OS | Container ID (short) | Restart policy | Start command |
|---|---|---|---|---|---|---|
| POC-CLIENT-1 | GNS3.POC-CLIENT-1.63f44bbf-fd98-49c1-a510-0678bb500780 | alpine:latest | Alpine | f3e06ab6b28c | no | tail -f /dev/null |
| POC-SERVER-1 | GNS3.POC-SERVER-1.63f44bbf-fd98-49c1-a510-0678bb500780 | alpine:latest | Alpine | b45d324457c3 | no | tail -f /dev/null |
| Attacker-1 | GNS3.Attacker-1.63f44bbf-fd98-49c1-a510-0678bb500780 | ubuntu:24.04 | Ubuntu 24.04.5 (minimal) | e8dd43aadfb9 | no | tail -f /dev/null |
| MONITOR-ZEEK-1 | GNS3.MONITOR-ZEEK-1.63f44bbf-fd98-49c1-a510-0678bb500780 | pp-nsmf-zeek:9.0.0 | Debian 13 (trixie) | 19862bc19b22 | no | tail -f /dev/null |
| MONITOR-SURI-1 | GNS3.MONITOR-SURI-1.63f44bbf-fd98-49c1-a510-0678bb500780 | pp-nsmf-suri:7.0.3 | Ubuntu 24.04.5 | 1110d4f281ca | no | tail -f /dev/null |

Container `container_id` values in the project file match the running containers (verified against `docker inspect`).

Additional host containers (`kdsj-wordpress`, `kdsj-db`, both `Exited`) are unrelated to PP-NSMF and were not touched.

Common container properties:
- `Privileged: true`, `CapAdd: [ALL]`.
- `NetworkMode: bridge` in `HostConfig`, but **no Docker network is attached** (`.NetworkSettings.Networks` is empty). GNS3 connects each node through `ubridge` TAP interfaces, not the Docker bridge. IP addresses are therefore configured inside each container namespace, not by Docker.
- MAC addresses: client `02:42:54:cd:55:00`, server `02:42:26:d5:dc:00`, attacker `02:42:df:23:24:00`, zeek `02:42:cf:6f:3e:00`, suricata `02:42:a9:40:62:00`.

### 1.4 Interface addresses and routes

| Node | eth0 IPv4 | Route | State |
|---|---|---|---|
| POC-CLIENT-1 | 10.10.10.10/24 | 10.10.10.0/24 via eth0 (scope link) | UP |
| POC-SERVER-1 | 10.10.10.20/24 | 10.10.10.0/24 via eth0 (scope link) | UP |
| Attacker-1 | 10.10.10.30/24 | 10.10.10.0/24 via eth0 (scope link) | UP |
| MONITOR-ZEEK-1 | 10.10.10.40/24 | 10.10.10.0/24 via eth0 (scope link) | UP |
| MONITOR-SURI-1 | none (IPv6 link-local only) | (none) | UP |

No default gateway is configured on any node; this is correct for a single-subnet lab.

### 1.5 Services and monitoring state

- **Zeek 9.0.0 — RUNNING**: `/usr/local/zeek/bin/zeek -i eth0` (PID 575). Current working directory `/opt/zeek/pp-nsmf/captures/S2/R2` (actively writing `conn.log`, `dns.log`, `packet_filter.log`).
- **DNS responder — RUNNING**: `python3 /tmp/dns_responder.py` (PID 353), listening on `10.10.10.40:53` (UDP). It answers any query with a hard-coded A record `10.10.10.20`.
- **Suricata 7.0.3 — INSTALLED but NOT RUNNING**. Last activity was a test-mode (`-T`) configuration validation at `2026-10-21 00:36:48` which loaded 1 rule successfully and exited. There is no active Suricata capture process.
- Suricata capture mode is **passive**: `af-packet` on `eth0` (`cluster-id: 99`, `cluster-type: cluster_flow`, `defrag: yes`), no `copy-mode: ips/tap`. Output: `eve-log` to `eve.json` under `default-log-dir: /var/log/suricata/`.

### 1.6 Connectivity (freshly verified)

- Client `10.10.10.10` pings server `.20`, attacker `.30`, and zeek `.40` with **0% packet loss**.
- `nslookup probe.pp-nsmf.test 10.10.10.40` from the client returns `10.10.10.20`. DNS resolution works.

### 1.7 Existing evidence (intact)

- `evidence-backup/SHA256SUMS.txt` contains 16 entries; `sha256sum -c` reports **all OK**.
- `evidence-backup/protocol/experiment-run-log.csv` exists but contains only the header row (no completed runs logged yet).
- S2/R1 evidence is present under `evidence-backup/S2-R1-zeek/` and `evidence-backup/S2-R1-suricata/`.
- `evidence-backup/S2-R2-zeek/` exists and is empty (placeholder for the next run).
- In-container equivalents exist under `/opt/zeek/pp-nsmf/` (Zeek) and `/var/log/suricata/pp-nsmf/` (Suricata).

---

## 2. Expected but Unverified Settings

The following were previously reported and are consistent with the current state, but were not independently re-proven in this audit:

- Whether a freshly started Suricata `af-packet` capture actually observes DNS traffic on `eth0` in a clean run.
- Whether Suricata EVE JSON contains well-formed DNS events for `probe.pp-nsmf.test` (S2/R1 `eve.json` has 275 events / 8 DNS events per `transformation-metadata.json`, but the event fields were not re-parsed here).
- Whether the `auto eth0` static block in the client's `/etc/network/interfaces` is automatically applied on container restart (the container's PID 1 is `tail -f /dev/null`, so no init runs `ifup`; this must be confirmed by an approved restart test).

---

## 3. Problems Found

1. **No automatic IP persistence.** All five nodes use `start_command: tail -f /dev/null` and `RestartPolicy: no`. Addresses for server, attacker, and zeek are set at runtime only and will be lost on restart. The client's static `/etc/network/interfaces` block is present but has no init to apply it at boot.

2. **Attacker lacks standard networking tools.** The `ubuntu:24.04` image has no `ip`, `ifconfig`, `ifupdown`, `net-tools`, or `python3` on `PATH`. However, GNS3 provides `/gns3/bin/busybox` with `ip`, `ifconfig`, and `route` applets — verified working (`/gns3/bin/busybox ip addr show eth0` returns `10.10.10.30/24`).

3. **Suricata is not running.** It must be started with `af-packet` on `eth0` for each monitored run, and stopped cleanly afterward to preserve evidence.

4. **Live partial S2/R2 Zeek capture.** Zeek is currently capturing into `/opt/zeek/pp-nsmf/captures/S2/R2` and already contains one DNS query/connection (from ~16:54). This directory is not a clean S2/R2 run and must be treated as contaminated or rotated before a formal S2/R2 run.

5. **Malformed directory in Suricata container.** `/var/log/suricata/pp-nsmf/{scripts,keys` exists (a literal directory name from an unexpanded brace in a prior `mkdir`). It is harmless but should be removed (with approval).

6. **HMAC key history.** The original S2/R1 HMAC key was lost; a replacement 32-byte key was generated during recovery and is stored at `0600` permissions (65 bytes = 64 hex chars + newline). The replacement is **not** equivalent to the original and is documented as such in `transformation-metadata.json`. This must remain recorded in the experiment log.

7. **Manifest does not cover all transformation scripts.** `transform-S2-R1-corrected.py` exists under `evidence-backup/S2-R1-suricata/scripts/` but is not listed in `SHA256SUMS.txt` (only `transform-S2-R1.py` is).

8. **S2/R1 Zeek DNS log spans readiness + run.** The recovery note already flags that captured DNS events span readiness checks and the later run; these must not be counted as a formal repetition without a clean capture boundary.

9. **Run log has no rows.** The experiment log schema is present but no run has been recorded.

---

## 4. Recommended Changes

### 4.1 Persistent IP addressing (Phase Two)

Recommended mechanism, in order of preference:

1. **GNS3 Docker `start_command`** — change each node's `start_command` to configure the intended address idempotently and then keep the container alive, e.g. `sh -c "ip addr add 10.10.10.20/24 dev eth0 2>/dev/null || true; tail -f /dev/null"`. Use the container's own `ip` where available and `/gns3/bin/busybox ip` for the Attacker. This is the GNS3-native, restart-persistent approach and requires no image rebuild.
2. **Version-controlled script** — `scripts/configure_lab.py` (idempotent) re-applies addresses via `docker exec` and is used both for the restart test and as a fallback/recovery path.

This must be implemented and verified by an **approved restart test** (stop/start the nodes and confirm addresses, connectivity, and monitor visibility are restored).

### 4.2 Suricata capture lifecycle

Start Suricata in `af-packet` mode on `eth0` at the beginning of each monitored run and stop it cleanly at the end, preserving `eve.json`/`fast.log`/`stats.log`/`suricata.log` before any restart.

### 4.3 S2/R2 clean run

Before the S2/R2 run, stop the current Zeek capture or rotate its output so the run has a clean boundary. S2/R2 evidence must go to a directory distinct from S2/R1.

### 4.4 Minor cleanups (require approval)

- Remove `/var/log/suricata/pp-nsmf/{scripts,keys`.
- Optionally add `transform-S2-R1-corrected.py` to a future manifest.

---

## 5. Changes Requiring Approval

- Restarting any node or container (needed for the Phase Two persistence test).
- Starting/stopping Suricata or Zeek to establish clean capture boundaries.
- Modifying the GNS3 project file (`PP-NSMF.gns3`) to change `start_command`.
- Removing the malformed `{scripts,keys` directory.
- Any `docker rm`, `docker system prune`, or container/image rebuild.

No such changes were made during this phase.
