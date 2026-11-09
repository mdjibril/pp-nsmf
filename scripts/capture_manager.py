"""Zeek and Suricata capture lifecycle for PP-NSMF runs.

Each capture is started with a clean, run-specific output directory and stopped
gracefully so logs are flushed before they are collected and checksum-verified.
"""

import hashlib
import time

from lab_common import docker_exec, run

ZEEK_BIN = "/usr/local/zeek/bin/zeek"
SURICATA_BIN = "/usr/bin/suricata"
SURICATA_CONF = "/etc/suricata/suricata.yaml"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_remote(container, path):
    proc = docker_exec(container, ["sha256sum", path])
    if proc.returncode != 0:
        return None
    return proc.stdout.split()[0]


def ensure_dir(container, path):
    docker_exec(container, ["mkdir", "-p", path], check=True)


def clean_capture_dir(container, capture_dir):
    """Remove any leftover capture files so each run has a clean boundary."""
    ensure_dir(container, capture_dir)
    docker_exec(container, ["sh", "-c", f"rm -rf {capture_dir}/*"])


def _pkill(container, pattern, signal="TERM"):
    docker_exec(container, ["pkill", f"-{signal}", "-f", pattern])


def _process_running(container, pattern):
    proc = docker_exec(container, ["pgrep", "-f", pattern])
    return proc.returncode == 0


def start_zeek(container, capture_dir, interface="eth0"):
    clean_capture_dir(container, capture_dir)
    out_file = f"/tmp/zeek-{int(time.time())}.out"
    cmd = f"cd {capture_dir} && {ZEEK_BIN} -i {interface} >{out_file} 2>&1"
    run(["docker", "exec", "-d", container, "sh", "-c", cmd], check=True)
    # Poll for the "listening" readiness signal.
    for _ in range(30):
        time.sleep(1)
        proc = docker_exec(container, ["cat", out_file])
        if "listening" in proc.stdout:
            return {"process": f"{ZEEK_BIN} -i {interface}", "dir": capture_dir, "out": out_file}
    raise RuntimeError("Zeek did not become ready")


def stop_zeek(container):
    if _process_running(container, f"{ZEEK_BIN} -i"):
        _pkill(container, f"{ZEEK_BIN} -i", "TERM")
        for _ in range(10):
            if not _process_running(container, f"{ZEEK_BIN} -i"):
                return
            time.sleep(1)
        raise RuntimeError("Zeek did not stop cleanly")


def start_suricata(container, capture_dir, interface="eth0", rules="/dev/null"):
    clean_capture_dir(container, capture_dir)
    # -S /dev/null loads no alert rules; Suricata still logs DNS/flow protocol
    # events to EVE JSON, which is what the passive monitor records.
    cmd = [SURICATA_BIN, "-c", SURICATA_CONF, "-i", interface, "-l", capture_dir, "-S", rules]
    run(["docker", "exec", "-d", container] + cmd, check=True)
    # Poll for the capture engine to be started.
    for _ in range(30):
        time.sleep(1)
        proc = docker_exec(container, ["grep", "-E", "Engine started", f"{capture_dir}/suricata.log"])
        if proc.returncode == 0:
            return {"process": SURICATA_BIN, "dir": capture_dir}
    raise RuntimeError("Suricata did not become ready")


def stop_suricata(container):
    if _process_running(container, SURICATA_BIN):
        _pkill(container, SURICATA_BIN, "TERM")
        for _ in range(15):
            if not _process_running(container, SURICATA_BIN):
                return
            time.sleep(1)
        raise RuntimeError("Suricata did not stop cleanly")


def collect_and_verify(container, src_dir, dest_dir):
    """Copy a directory from the container to the host and verify SHA-256."""
    ensure_dir(container, src_dir)
    run(["mkdir", "-p", dest_dir], check=True)
    run(["docker", "cp", f"{container}:{src_dir}/.", dest_dir], check=True)

    # List files in source and verify each copy matches by SHA-256.
    proc = docker_exec(container, ["find", src_dir, "-type", "f"])
    checksums = {}
    for rel in proc.stdout.splitlines():
        rel = rel.strip()
        if not rel:
            continue
        src = rel
        local = rel.replace(src_dir, dest_dir, 1)
        src_sha = sha256_remote(container, src)
        local_sha = sha256_file(local)
        if src_sha is None or local_sha != src_sha:
            raise RuntimeError(f"SHA-256 mismatch for {rel}: {src_sha} != {local_sha}")
        checksums[rel] = local_sha
    return checksums
