"""Scenario traffic generation for PP-NSMF.

Dispatches on the scenario's traffic.type. S2 (DNS) is implemented and validated;
other traffic types raise a clear error until their target services are deployed.
"""

import base64
import time

from lab_common import docker_exec


def generate_dns(container, spec):
    name = spec["query_name"]
    server = spec["dns_server"]
    count = int(spec.get("queries", 3))
    interval = float(spec.get("interval_seconds", 2))
    for i in range(count):
        proc = docker_exec(container, ["nslookup", name, server], timeout=30)
        if proc.returncode != 0:
            raise RuntimeError(f"nslookup failed: {proc.stdout} {proc.stderr}")
        if i < count - 1:
            time.sleep(interval)
    return {"queries": count}


def generate_http(container, spec):
    target = spec["target"]
    count = int(spec.get("requests", 5))
    interval = float(spec.get("interval_seconds", 1))
    for i in range(count):
        proc = docker_exec(container, ["wget", "-q", "-O", "/dev/null", target], timeout=30)
        if proc.returncode != 0:
            raise RuntimeError(f"wget failed: {proc.stdout} {proc.stderr}")
        if i < count - 1:
            time.sleep(interval)
    return {"requests": count}


def generate_tcp_connect_scan(container, spec):
    target = spec["target"]
    ports = [str(p) for p in spec.get("ports", [])]
    timeout = float(spec.get("timeout_seconds", 1))
    interval = float(spec.get("interval_seconds", 0.5))
    open_ports = []
    for i, port in enumerate(ports):
        # Payload-free connect: bash /dev/tcp opens then closes the socket
        # without sending application data, so no service on an open port is
        # triggered. A connect-only scan is a flow observation, not an alert.
        cmd = f'timeout {int(timeout)} bash -c ": >/dev/tcp/{target}/{port}" 2>/dev/null'
        proc = docker_exec(container, ["bash", "-c", cmd], timeout=int(timeout) + 5)
        if proc.returncode == 0:
            open_ports.append(int(port))
        if i < len(ports) - 1:
            time.sleep(interval)
    return {"ports_scanned": len(ports), "open_ports": open_ports}


def generate_auth_failures(container, spec):
    target = spec["target"]
    port = int(spec.get("port", 8080))
    attempts = int(spec.get("attempts", 5))
    username = spec.get("username", "testuser")
    interval = float(spec.get("interval_seconds", 1))
    for i in range(attempts):
        # Synthetic invalid credential only; the valid password is never used.
        password = f"wrong-password-{i + 1}"
        creds = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        request = (
            "GET /login HTTP/1.1\\r\\n"
            f"Host: {target}:{port}\\r\\n"
            f"Authorization: Basic {creds}\\r\\n"
            "Connection: close\\r\\n\\r\\n"
        )
        cmd = (
            f"exec 3<>/dev/tcp/{target}/{port}; "
            f"printf '{request}' >&3; "
            "cat <&3 >/dev/null; "
            "exec 3<&-"
        )
        docker_exec(container, ["bash", "-c", cmd], timeout=30)
        if i < attempts - 1:
            time.sleep(interval)
    return {"attempts": attempts, "status_expected": 401}


def generate_periodic_beacon(container, spec):
    target = spec["target"]
    port = int(spec.get("port", 80))
    count = int(spec.get("count", 4))
    interval = float(spec.get("interval_seconds", 3))
    for i in range(count):
        # Payload-free periodic connect: opens and closes a socket without
        # sending application data. A fixed-interval single-destination connect
        # is a flow observation (beacon pattern), not an IDS alert.
        cmd = f'timeout 5 bash -c ": >/dev/tcp/{target}/{port}" 2>/dev/null'
        docker_exec(container, ["bash", "-c", cmd], timeout=10)
        if i < count - 1:
            time.sleep(interval)
    return {"beacons": count, "port": port}


def generate_bulk_transfer(container, spec):
    target = spec["target"]
    port = int(spec.get("port", 9999))
    byte_count = int(spec.get("bytes", 65536))
    # Deterministic, non-sensitive synthetic payload (NUL bytes) streamed over
    # a single TCP connection and discarded by the server-side receiver.
    cmd = f"dd if=/dev/zero bs={byte_count} count=1 2>/dev/null | nc -w 5 {target} {port}"
    proc = docker_exec(container, ["sh", "-c", cmd], timeout=60)
    return {"bytes_sent": byte_count, "port": port, "returncode": proc.returncode}


def generate(container, spec):
    traffic_type = spec.get("type")
    if traffic_type == "dns_query":
        return generate_dns(container, spec)
    if traffic_type == "http_get":
        return generate_http(container, spec)
    if traffic_type == "tcp_connect_scan":
        return generate_tcp_connect_scan(container, spec)
    if traffic_type == "auth_failures":
        return generate_auth_failures(container, spec)
    if traffic_type == "periodic_beacon":
        return generate_periodic_beacon(container, spec)
    if traffic_type == "bulk_transfer":
        return generate_bulk_transfer(container, spec)
    raise NotImplementedError(
        f"traffic type '{traffic_type}' is defined but not yet runnable "
        "(target service setup required)"
    )
