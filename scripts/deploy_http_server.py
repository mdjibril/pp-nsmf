#!/usr/bin/env python3
"""Deploy and start the S1 HTTP responder on the server node.

Idempotent: copies the version-controlled responder script, restarts the
listener, and verifies a 200 response before returning. Kept on the host so the
service can be redeployed after a container recreation.
"""

import sys
import time
from pathlib import Path

from lab_common import docker_exec, load_config, resolve_container, run

ROOT = Path(__file__).resolve().parent.parent


def main():
    cfg = load_config()
    pid = cfg["project"]["project_id"]
    server = resolve_container(cfg["nodes"]["server"]["gns3_name"], pid)
    client = resolve_container(cfg["nodes"]["client"]["gns3_name"], pid)
    server_ip = cfg["nodes"]["server"]["ip"]
    if not server or not client:
        print("ERROR: could not resolve server/client containers", file=sys.stderr)
        return 1

    responder = ROOT / "scripts" / "http_responder.sh"
    run(["docker", "cp", str(responder), f"{server}:/tmp/http_responder.sh"], check=True)
    docker_exec(server, ["chmod", "+x", "/tmp/http_responder.sh"], check=True)

    docker_exec(server, ["sh", "-c", 'pkill -f "nc -lk -p 80" 2>/dev/null; true'])
    time.sleep(1)
    run(["docker", "exec", "-d", server, "sh", "-c",
         "nc -lk -p 80 -e /tmp/http_responder.sh"], check=True)
    time.sleep(1)

    for _ in range(10):
        proc = docker_exec(client, ["wget", "-q", "-O", "-",
                                    f"http://{server_ip}/"], timeout=15)
        if proc.returncode == 0 and "PP-NSMF" in proc.stdout:
            print(f"HTTP server responding on {server_ip}:80")
            return 0
        time.sleep(1)

    print("ERROR: HTTP server did not respond", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
