#!/usr/bin/env python3
"""Read-only topology and connectivity verification for PP-NSMF.

Exit code 0 means all checks passed; non-zero means at least one check failed.
"""

import json
import sys

from lab_common import (
    LabError,
    container_running,
    docker_exec,
    get_interface_ip,
    get_route_prefix,
    load_config,
    resolve_container,
)


def check_ip(node, container, cfg):
    ip_tool = node.get("ip_tool", "ip")
    iface = node["interface"]
    ip, prefix = get_interface_ip(container, ip_tool, iface)
    expected_ip = node.get("ip")
    expected_prefix = node.get("prefix")
    route = get_route_prefix(container, ip_tool, iface)

    if node.get("passive"):
        ok = ip is None
        detail = f"{iface} has no IPv4 (passive) = {'OK' if ok else 'FAIL (got ' + str(ip) + ')'}"
        return {"name": node["gns3_name"], "check": "passive-no-ip", "ok": ok, "detail": detail}

    problems = []
    if ip != expected_ip:
        problems.append(f"ip {ip} != {expected_ip}")
    if prefix != expected_prefix:
        problems.append(f"prefix /{prefix} != /{expected_prefix}")
    if route != f"{cfg['project']['subnet'].split('/')[0]}/24":
        problems.append(f"route {route} unexpected")
    ok = not problems
    detail = f"{iface} {ip}/{prefix}, route {route}" + (f" [{'; '.join(problems)}]" if problems else "")
    return {"name": node["gns3_name"], "check": "ip-route", "ok": ok, "detail": detail}


def ping_check(source_container, target_ip, label):
    proc = docker_exec(source_container, ["ping", "-c", "1", "-W", "2", target_ip])
    ok = proc.returncode == 0 and "1 packets received" in proc.stdout
    return {"name": label, "check": "ping", "ok": ok, "detail": f"{target_ip} {'reachable' if ok else 'unreachable'}"}


def dns_check(container, cfg):
    dns = cfg["dns_responder"]
    proc = docker_exec(
        container,
        ["nslookup", dns["test_name"], dns["address"]],
        timeout=20,
    )
    ok = dns["expected_answer"] in proc.stdout and proc.returncode == 0
    return {"name": "dns", "check": "dns-resolution", "ok": ok, "detail": proc.stdout.strip().splitlines()[-1] if proc.stdout else "(empty)"}


def process_check(container, match):
    proc = docker_exec(container, ["ps", "aux"])
    found = match in proc.stdout
    return found


def main():
    cfg = load_config()
    project_id = cfg["project"]["project_id"]
    nodes = cfg["nodes"]
    results = []
    containers = {}

    for key, node in nodes.items():
        container = resolve_container(node["gns3_name"], project_id)
        if container is None:
            results.append({"name": node["gns3_name"], "check": "container", "ok": False, "detail": "no container found"})
            continue
        containers[key] = container
        running = container_running(container)
        results.append({"name": node["gns3_name"], "check": "container-running", "ok": running, "detail": container})
        if running:
            results.append(check_ip(node, container, cfg))

    # Connectivity (from the configured source node).
    conn = cfg.get("connectivity", {})
    source_key = conn.get("source")
    if source_key and source_key in containers:
        src = containers[source_key]
        for target_key in conn.get("ping_targets", []):
            target = nodes[target_key]
            results.append(ping_check(src, target["ip"], f"ping {source_key}->{target_key}"))

    # DNS resolution.
    if source_key and source_key in containers:
        results.append(dns_check(containers[source_key], cfg))

    # Monitoring processes.
    for label, spec in cfg.get("monitoring", {}).items():
        node_key = spec.get("node")
        if node_key not in containers:
            results.append({"name": label, "check": "process", "ok": False, "detail": "node not resolved"})
            continue
        found = process_check(containers[node_key], spec["match"])
        required = spec.get("required_running", True)
        ok = found if required else True
        detail = f"{'running' if found else 'not running'}" + ("" if required else " (not required)")
        results.append({"name": label, "check": "process", "ok": ok, "detail": detail})

    for r in results:
        mark = "OK  " if r["ok"] else "FAIL"
        print(f"[{mark}] {r['check']:18} {r['name']:18} {r['detail']}")

    failed = [r for r in results if not r["ok"]]
    print()
    print(f"Checks: {len(results)} total, {len(results) - len(failed)} passed, {len(failed)} failed")
    if "--json" in sys.argv:
        print(json.dumps(results, indent=2))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
