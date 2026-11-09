"""Shared helpers for PP-NSMF lab automation.

Standard-library only, with one exception: PyYAML is used to read config/lab.yaml.
PyYAML is already present on the host as a GNS3 dependency (verified 6.0.1), so it
does not introduce a new dependency.
"""

import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config" / "lab.yaml"

_IP_RE = re.compile(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)")


class LabError(RuntimeError):
    pass


def load_config(path=CONFIG_PATH):
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def run(argv, timeout=30, check=False):
    """Run a command with an argument list (no shell) and return CompletedProcess."""
    proc = subprocess.run(
        list(argv), capture_output=True, text=True, timeout=timeout
    )
    if check and proc.returncode != 0:
        raise LabError(
            f"command failed ({proc.returncode}): {' '.join(map(str, argv))}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return proc


def resolve_container(gns3_name, project_id):
    """Return the running container name for a GNS3 node, or None if absent."""
    expected = f"GNS3.{gns3_name}.{project_id}"
    proc = run(["docker", "ps", "-a", "--format", "{{.Names}}"])
    for name in proc.stdout.splitlines():
        if name.strip() == expected:
            return expected
    return None


def container_running(container):
    proc = run(["docker", "ps", "--format", "{{.Names}}"])
    return container in {n.strip() for n in proc.stdout.splitlines()}


def docker_exec(container, argv, timeout=30, check=False):
    return run(["docker", "exec", container] + list(argv), timeout=timeout, check=check)


def ip_tool_argv(ip_tool):
    """Split a configured ip tool ('ip' or '/gns3/bin/busybox ip') into argv."""
    return ip_tool.split()


def get_interface_ip(container, ip_tool, interface):
    """Return (ip, prefix_len) for an interface, or (None, None)."""
    argv = ip_tool_argv(ip_tool) + ["addr", "show", interface]
    proc = docker_exec(container, argv)
    if proc.returncode != 0:
        return None, None
    for line in proc.stdout.splitlines():
        match = _IP_RE.search(line)
        if match:
            return match.group(1), int(match.group(2))
    return None, None


def get_route_prefix(container, ip_tool, interface):
    """Return the connected route prefix for an interface, or None."""
    argv = ip_tool_argv(ip_tool) + ["route"]
    proc = docker_exec(container, argv)
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        if interface in line and "scope link" in line:
            return line.split()[0]
    return None
