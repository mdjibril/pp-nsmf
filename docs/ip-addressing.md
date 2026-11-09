# PP-NSMF IP Addressing and Persistence

Date: 2026-10-21
Status: addressing verified correct; automatic restart persistence pending an approved restart test.

---

## 1. Intended Addressing

| Node | Role | Interface | Intended address | Current state |
|---|---|---|---|---|
| POC-CLIENT-1 | traffic generator | eth0 | 10.10.10.10/24 | correct |
| POC-SERVER-1 | target | eth0 | 10.10.10.20/24 | correct |
| Attacker-1 | security-test traffic | eth0 | 10.10.10.30/24 | correct |
| MONITOR-ZEEK-1 | Zeek monitor + DNS responder | eth0 | 10.10.10.40/24 | correct |
| MONITOR-SURI-1 | Suricata monitor | eth0 | none (passive) | correct |

No default gateway is configured; the lab is a single subnet (`10.10.10.0/24`) reached through `Hub1`.

## 2. Current Configuration Mechanism

GNS3 connects each Docker node to `Hub1` through a `ubridge` TAP interface that appears inside the container as `eth0`. GNS3 does **not** assign IP addresses; the container's own startup or a manual step must configure `eth0`.

Findings from the audit:

- Every node's GNS3 `start_command` is `tail -f /dev/null`, and `RestartPolicy` is `no`.
- The container PID 1 is `tail -f /dev/null`, so no init process runs `ifup`. A static block in `/etc/network/interfaces` is therefore **stored** (GNS3 persists it to `project-files/docker/<node_id>/etc/network/interfaces`) but **not automatically applied** on restart.
- Only the client currently has a static block appended to `/etc/network/interfaces` (with a `.bak` of the original sample). Server, attacker, and zeek addresses are set at runtime only.
- The attacker image (`ubuntu:24.04`, minimal) has no `iproute2`/`net-tools`/`ifupdown`, but GNS3 provides `/gns3/bin/busybox` with `ip`, `ifconfig`, and `route` applets (verified working).

Consequence: the current addresses are correct but will be lost on a normal container restart unless re-applied.

## 3. Persistent Configuration Strategy

Two complementary mechanisms are used:

1. **`scripts/configure_lab.py` (version-controlled, idempotent).** This is the immediate and recovery tool. It reads `config/lab.yaml`, resolves the live container for each node, detects the current address, and applies only the missing expected address. It never silently replaces a conflicting address (`--force` is required for that). Running it repeatedly is safe.

2. **GNS3 Docker `start_command` (automatic on node start).** For true restart persistence, each node's `start_command` should configure `eth0` idempotently before keeping the container alive, for example:

   ```
   sh -c 'for i in 1 2 3 4 5; do ip addr add 10.10.10.20/24 dev eth0 2>/dev/null && break; sleep 1; done; tail -f /dev/null'
   ```

   The short retry handles the case where `eth0` is attached by `ubridge` slightly after the container starts. For the attacker node, `/gns3/bin/busybox ip` replaces `ip`.

   This change is made by editing `PP-NSMF.gns3` (node `properties.start_command`) and requires approval; it must be followed by a restart test to confirm the retry timing is sufficient.

## 4. Idempotency Guarantees

- `configure_lab.py` checks the current address before acting; it adds an address only when absent.
- A conflicting (different) address is reported and left untouched unless `--force` is passed.
- Passive nodes (Suricata) are checked for the *absence* of an IPv4 address; no address is ever assigned to them.
- Re-running the script produces no duplicate addresses and does not disturb the interface.

## 5. Verification Procedure

Run from the project root:

```
python3 scripts/verify_topology.py
python3 scripts/configure_lab.py          # dry run
python3 scripts/configure_lab.py --apply  # apply only if needed
python3 scripts/verify_topology.py        # confirm
```

`verify_topology.py` checks, per node: container running, interface IP + route (or passive no-IP), client-to-node ping reachability, DNS resolution of `probe.pp-nsmf.test` to `10.10.10.20`, and the Zeek/DNS-responder processes (Suricata is reported but not required to be running between runs).

## 6. Restart Test (performed 2026-10-21)

The `start_command` mechanism was applied and verified through a full server restart.

Sequence and result:

1. `PP-NSMF.gns3` was backed up (`PP-NSMF.gns3.bak.*`) and the four addressed nodes' `start_command` values were set to the idempotent `sh -c 'for n in ...; do <ip-tool> addr replace <ip>/24 dev eth0 2>/dev/null && break; sleep 1; done; tail -f /dev/null'` (Suricata left passive).
2. The GNS3 server's node-lifecycle API was found hung (stop/update/start timed out on the compute). The server was restarted to clear it.
3. Restarting the server recreated all five Docker containers (new container IDs). This lost in-container runtime data (the DNS responder script and in-container Zeek/Suricata logs), but the host `evidence-backup/` remained intact (16/16 checksums OK) and the HMAC key remained on the host.
4. On `start all nodes`, every addressed node auto-configured its IP via the new `start_command` with no manual step:

| Node | Address after restart |
|---|---|
| POC-CLIENT-1 | 10.10.10.10/24 |
| POC-SERVER-1 | 10.10.10.20/24 |
| Attacker-1 | 10.10.10.30/24 (via `/gns3/bin/busybox ip`) |
| MONITOR-ZEEK-1 | 10.10.10.40/24 |
| MONITOR-SURI-1 | none (passive) |

5. `verify_topology.py` confirmed addresses, routes, and client-to-node ping reachability (14/17 pass). The three failures were only the DNS responder and Zeek processes, which are runtime processes not part of the container startup and were re-established afterward.
6. The DNS responder was version-controlled to `scripts/dns_responder.py`, redeployed, and verified resolving `probe.pp-nsmf.test` to `10.10.10.20`.

Conclusion: addressing is restart-persistent through the GNS3 Docker `start_command` mechanism, verified end-to-end.

## 7. Restart Recovery Procedure

After any node/container restart:

1. `python3 scripts/verify_topology.py` — confirm addresses and connectivity.
2. If addresses are missing (older node config without `start_command`), run `python3 scripts/configure_lab.py --apply`.
3. Redeploy/restart the DNS responder if needed (`scripts/dns_responder.py`).
4. Restart Zeek and Suricata captures as part of the next run's capture lifecycle.
