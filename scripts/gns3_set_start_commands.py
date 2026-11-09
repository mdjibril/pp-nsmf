#!/usr/bin/env python3
"""Apply restart-persistent start_command to GNS3 Docker nodes.

Generates an idempotent start command per node from config/lab.yaml and writes it
through the GNS3 API (keeping the running GUI in sync). Dry run by default;
pass --apply to write.

The generated command retries address configuration for a few seconds to cover
the case where eth0 is attached by ubridge slightly after the container starts,
then keeps the container alive with `tail -f /dev/null`.
"""

import base64
import configparser
import json
import os
import sys
import urllib.error
import urllib.request

from lab_common import load_config

GNS3_HOST = "127.0.0.1"
GNS3_PORT = 3080


def build_start_command(node):
    iface = node["interface"]
    ip_tool = node.get("ip_tool", "ip")
    if node.get("passive"):
        return "tail -f /dev/null"
    addr = f"{node['ip']}/{node['prefix']}"
    retry = " ".join(str(n) for n in range(1, 11))
    return (
        "sh -c 'for n in " + retry
        + f"; do {ip_tool} addr replace {addr} dev {iface} 2>/dev/null && break; "
        + "sleep 1; done; tail -f /dev/null'"
    )


def gns3_auth():
    conf = configparser.ConfigParser()
    conf.read(os.path.expanduser("~/.config/GNS3/2.2/gns3_server.conf"))
    user = conf.get("Server", "user")
    password = conf.get("Server", "password")
    return base64.b64encode(f"{user}:{password}".encode()).decode()


def api(method, path, data=None):
    url = f"http://{GNS3_HOST}:{GNS3_PORT}{path}"
    headers = {"Authorization": f"Basic {gns3_auth()}", "Content-Type": "application/json"}
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def main():
    apply = "--apply" in sys.argv
    cfg = load_config()
    pid = cfg["project"]["project_id"]

    status, nodes = api("GET", f"/v2/projects/{pid}/nodes")
    if status != 200:
        print(f"error listing nodes: {status} {nodes}")
        return 1

    by_id = {n["node_id"]: n for n in nodes if n["node_type"] == "docker"}

    for key, node in cfg["nodes"].items():
        node_id = None
        for nid, n in by_id.items():
            if n["name"] == node["gns3_name"]:
                node_id = nid
                break
        if node_id is None:
            print(f"[MISSING] {node['gns3_name']}: not found in GNS3 API")
            continue

        new_cmd = build_start_command(node)
        current = by_id[node_id]["properties"].get("start_command")
        if current == new_cmd:
            print(f"[OK     ] {node['gns3_name']}: already set")
            continue

        print(f"[UPDATE ] {node['gns3_name']}:")
        print(f"           from: {current!r}")
        print(f"           to:   {new_cmd!r}")
        if apply:
            body = {"properties": {"start_command": new_cmd}}
            s, _ = api("PUT", f"/v2/projects/{pid}/nodes/{node_id}", body)
            if s == 200:
                print(f"           -> applied ({s})")
            else:
                print(f"           -> FAILED ({s})")

    if not apply:
        print("\nDry run. Pass --apply to write via the GNS3 API.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
