#!/usr/bin/env python3
"""Controlled, idempotent address configuration for PP-NSMF nodes.

Default is a dry run: report what would change without touching anything.
Pass --apply to make changes. Existing addresses are never silently replaced:
a conflicting address is reported and skipped unless --force is given.
"""

import sys

from lab_common import (
    get_interface_ip,
    ip_tool_argv,
    load_config,
    resolve_container,
    run,
)


def plan_for_node(node, container):
    ip_tool = node.get("ip_tool", "ip")
    iface = node["interface"]

    if node.get("passive"):
        current_ip, _ = get_interface_ip(container, ip_tool, iface)
        if current_ip is not None:
            return {"action": "conflict", "detail": f"passive node has {current_ip} on {iface}"}
        return {"action": "ok", "detail": "passive, no address (correct)"}

    expected = f"{node['ip']}/{node['prefix']}"
    current_ip, current_prefix = get_interface_ip(container, ip_tool, iface)

    if current_ip is None:
        return {"action": "add", "detail": f"add {expected} to {iface}", "ip": expected}
    if current_ip == node["ip"] and current_prefix == node["prefix"]:
        return {"action": "ok", "detail": f"{iface} already {expected}"}
    return {
        "action": "conflict",
        "detail": f"{iface} has {current_ip}/{current_prefix}, expected {expected}",
        "current": f"{current_ip}/{current_prefix}",
        "ip": expected,
    }


def main():
    apply = "--apply" in sys.argv
    force = "--force" in sys.argv
    cfg = load_config()
    project_id = cfg["project"]["project_id"]
    nodes = cfg["nodes"]

    # Each entry: (node_key, node, container, plan).
    entries = []
    for key, node in nodes.items():
        container = resolve_container(node["gns3_name"], project_id)
        if container is None:
            entries.append((key, node, None, {"action": "missing", "detail": "no container found"}))
            continue
        entries.append((key, node, container, plan_for_node(node, container)))

    changed = False
    for key, node, container, plan in entries:
        action = plan["action"]
        marker = {
            "ok": "OK      ",
            "add": "ADD     ",
            "conflict": "CONFLICT",
            "missing": "MISSING ",
        }[action]
        print(f"[{marker}] {node['gns3_name']:18} {plan['detail']}")

        ip_tool = node.get("ip_tool", "ip")
        iface = node["interface"]

        if action == "add" and apply:
            argv = ip_tool_argv(ip_tool) + ["addr", "add", plan["ip"], "dev", iface]
            run(["docker", "exec", container] + argv, check=True)
            changed = True
        elif action == "conflict" and apply and force:
            del_argv = ip_tool_argv(ip_tool) + ["addr", "del", plan["current"], "dev", iface]
            run(["docker", "exec", container] + del_argv, check=True)
            add_argv = ip_tool_argv(ip_tool) + ["addr", "add", plan["ip"], "dev", iface]
            run(["docker", "exec", container] + add_argv, check=True)
            changed = True
        elif action == "conflict" and not force:
            print("            (conflict skipped; re-run with --apply --force to replace)")

    if not apply:
        print("\nDry run. Pass --apply to make changes.")
    elif changed:
        print("\nConfiguration applied.")
    else:
        print("\nNo changes needed.")

    conflicts = [p for _, _, _, p in entries if p["action"] in ("conflict", "missing")]
    return 1 if conflicts else 0


if __name__ == "__main__":
    sys.exit(main())
