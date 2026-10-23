"""P7U host PID-namespace Docker and UART owner evidence, read-only.

A Docker container's init PID is usually NOT the node.js process that holds
the UART. Trust no PID name, cached PID, addon slug or serial symlink target.
An owner is proven by EXACT immutable container ID + docker top PID membership,
matching host cgroup, stable Linux proc start ticks, and opened character
device rdev. Any unavailable /proc entry or changed identity is HOLD.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from urllib.request import Request, urlopen
from dataclasses import dataclass
from p7u_lifecycle_core import LifecycleHold, Owner, guard

SLUGS = {
    "official": "45df7312_zigbee2mqtt",
    "diagnostic": "local_p7u_r4_native_host",
    "fallback": "local_p7u_r4_fallback",
    "guard": "local_p7u_recovery",
}
BY_ID = re.compile(r"^/dev/serial/by-id/[A-Za-z0-9_.:+@-]{4,200}$")


def run_argv(argv: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LifecycleHold("P7U_HOLD_INSPECTION_COMMAND_UNAVAILABLE") from exc


def inspect_docker(slot: str) -> dict | None:
    guard(slot in SLUGS and slot != "guard", "UNRECOGNIZED_SLOT")
    p = run_argv(["docker", "inspect", "app_" + SLUGS[slot]])
    if p.returncode:
        error = p.stderr.casefold()
        if "no such object" in error or "no such container" in error:
            return None
        raise LifecycleHold("P7U_HOLD_DOCKER_INSPECT_UNAVAILABLE")
    try:
        data = json.loads(p.stdout)
    except ValueError as exc:
        raise LifecycleHold("P7U_HOLD_DOCKER_INSPECT_INVALID") from exc
    guard(type(data) is list and len(data) == 1, "DOCKER_INSPECT_CARDINALITY")
    return data[0]


def inspect_addon(slot: str) -> dict:
    guard(slot in SLUGS, "UNRECOGNIZED_SLOT")
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    if token:
        guard(len(token) >= 20 and not any(c.isspace() for c in token),
              "SUPERVISOR_TOKEN_INVALID")
        request = Request("http://supervisor/addons/" + SLUGS[slot] + "/info",
                          method="GET", headers={"Authorization":"Bearer "+token})
        try:
            with urlopen(request, timeout=12) as stream:
                raw = stream.read(65537)
        except OSError as exc:
            raise LifecycleHold("P7U_HOLD_SUPERVISOR_INFO_UNAVAILABLE") from exc
        guard(len(raw) <= 65536, "SUPERVISOR_INFO_SIZE")
    else:
        p = run_argv(["ha", "apps", "info", SLUGS[slot], "--raw-json"], 20)
        guard(p.returncode == 0, "SUPERVISOR_INFO_UNAVAILABLE")
        raw = p.stdout
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise LifecycleHold("P7U_HOLD_SUPERVISOR_INFO_INVALID") from exc
    guard(data.get("result") == "ok" and type(data.get("data")) is dict,
          "SUPERVISOR_INFO_SHAPE")
    result = {k: data["data"].get(k) for k in
              ("state", "boot", "watchdog", "version")}
    if slot == "guard":
        # Reduce the policy to one attestation. Never emit the options,
        # which may contain credentials and private recovery configuration.
        options = data["data"].get("options")
        result["passive"] = (type(options) is dict and
            options.get("enabled") is False and options.get("dry_run") is True and
            options.get("serial_owner_approved") is False and
            options.get("allow_private_http_fallback") is False)
    return result


def check_host_namespace():
    guard(os.geteuid() == 0, "NOT_ROOT")
    try:
        init = Path("/proc/1/comm").read_text().strip()
    except OSError as exc:
        raise LifecycleHold("P7U_HOLD_HOST_PID_NAMESPACE_UNAVAILABLE") from exc
    guard(init in ("systemd", "init"), "UNPROVEN_HOST_PID_NAMESPACE")


def proc_identity(pid: int) -> tuple[int, str]:
    """Linux /proc/<pid>/stat field 22 + full cgroup v2 path."""
    guard(type(pid) is int and pid > 1, "BAD_PID")
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        after = raw.rsplit(")", 1)[1].strip().split()
        start_ticks = int(after[19])  # stat[22] when [3] is first token
        groups = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        paths = [l.split("::", 1)[1] for l in groups if l.startswith("0::")]
    except (OSError, ValueError, IndexError) as exc:
        raise LifecycleHold("P7U_HOLD_PROC_IDENTITY_MISSING") from exc
    guard(start_ticks > 0 and len(paths) == 1 and paths[0].startswith("/"),
          "PROC_IDENTITY_UNQUALIFIED")
    return start_ticks, paths[0]


def docker_top_pids(immutable_container_id: str) -> frozenset[int]:
    guard(re.fullmatch(r"[a-f0-9]{64}", immutable_container_id) is not None,
          "DOCKER_TOP_INVALID_ID")
    p = run_argv(["docker", "top", immutable_container_id, "-eo", "pid"], 15)
    guard(p.returncode == 0, "DOCKER_TOP_UNAVAILABLE")
    lines = p.stdout.strip().splitlines()
    guard(len(lines) >= 2 and lines[0].strip().upper() == "PID",
          "DOCKER_TOP_SCHEMA")
    try:
        pids = frozenset(int(x.strip()) for x in lines[1:])
    except ValueError as exc:
        raise LifecycleHold("P7U_HOLD_DOCKER_TOP_NONNUMERIC_PID") from exc
    guard(bool(pids) and all(x > 1 for x in pids), "DOCKER_TOP_NO_HOST_PIDS")
    return pids


def tty_holders(serial_path: str) -> frozenset[int]:
    guard(type(serial_path) is str and BY_ID.fullmatch(serial_path) is not None,
          "SERIAL_BY_ID_REQUIRED")
    check_host_namespace()
    try:
        device = os.stat(serial_path)
    except OSError as exc:
        raise LifecycleHold("P7U_HOLD_SERIAL_DEVICE_MISSING") from exc
    guard(stat.S_ISCHR(device.st_mode), "NOT_CHARACTER_DEVICE")
    holders: set[int] = set()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        try:
            fds = list((entry / "fd").iterdir())
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise LifecycleHold("P7U_HOLD_INCOMPLETE_PROC_ENUMERATION") from exc
        for fd in fds:
            try:
                state = fd.stat()
            except FileNotFoundError:
                continue
            except (PermissionError, OSError) as exc:
                raise LifecycleHold("P7U_HOLD_FD_ACCESS_DENIED") from exc
            if stat.S_ISCHR(state.st_mode) and state.st_rdev == device.st_rdev:
                holders.add(pid)
    return frozenset(holders)


@dataclass(frozen=True)
class ContainerProof:
    owner: Owner
    eligible_pids: frozenset[int]
    process_ticks: tuple[tuple[int, int], ...]
    cgroup: str


def prove_container(raw: dict) -> ContainerProof:
    owner = Owner.from_inspect(raw)
    host_pids = docker_top_pids(owner.container_id)
    guard(owner.pid in host_pids, "INIT_PID_NOT_IN_DOCKER_TOP")
    init_tick, init_group = proc_identity(owner.pid)
    guard(owner.container_id in init_group, "HOST_CGROUP_NOT_PINNED_TO_CONTAINER")
    ticks: dict[int, int] = {}
    for pid in sorted(host_pids):
        tick, cg = proc_identity(pid)
        guard(cg == init_group or cg.startswith(init_group.rstrip("/") + "/"),
              "FOREIGN_CGROUP_PROCESS")
        ticks[pid] = tick
    guard(ticks[owner.pid] == init_tick, "INIT_PID_REUSED")
    # Detect a process replacement while enumeration runs.
    for pid in ticks:
        guard(proc_identity(pid)[0] == ticks[pid], "PROCESS_PID_REUSED")
    return ContainerProof(owner, host_pids, tuple(sorted(ticks.items())), init_group)


def bind_tty_to_owner(holders: frozenset[int], proof: ContainerProof) -> frozenset[int]:
    guard(type(holders) is frozenset and len(holders) > 0,
          "NO_UART_HOLDER_FOR_RUNNING_OWNER")
    guard(holders <= proof.eligible_pids, "FOREIGN_UART_OWNER")
    for pid, prior in proof.process_ticks:
        if pid in holders:
            tick, cg = proc_identity(pid)
            guard(tick == prior and (cg == proof.cgroup or
                  cg.startswith(proof.cgroup.rstrip("/") + "/")),
                  "UART_OWNER_PID_REUSED")
    return holders


def inspect(serial_path: str) -> dict:
    check_host_namespace()
    slots = {}
    proofs: dict[str, ContainerProof] = {}
    for slot in ("official", "diagnostic", "fallback"):
        raw = inspect_docker(slot)
        if raw is not None and raw.get("State", {}).get("Running") is True:
            proof = prove_container(raw)
            proofs[slot] = proof
            slots[slot] = {
                "running": True, "container_id": proof.owner.container_id,
                "init_pid": proof.owner.pid,
                "image_digest": proof.owner.image_digest,
                "started_at": proof.owner.started_at,
            }
        else:
            slots[slot] = {"running": False}
    holders = tty_holders(serial_path)
    count = len(proofs)
    qualified = False
    if count == 1:
        proof = next(iter(proofs.values()))
        try:
            bind_tty_to_owner(holders, proof)
            qualified = True
        except LifecycleHold:
            qualified = False
    elif count == 0:
        qualified = len(holders) == 0
    return {
        "schema": "p7u-host-tty-cgroup-evidence-v2",
        "slots": slots, "tty_holders_pids": sorted(holders),
        "only_known_owners_hold_serial": qualified,
        "exclusive_owner_verified": qualified and count <= 1,
        "guard": inspect_addon("guard"),
        "mutation_authorized": False, "serial_opened": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--serial-by-id", required=True)
    args = p.parse_args()
    try:
        result = inspect(args.serial_by_id)
        print(json.dumps(result, sort_keys=True, indent=2))
        if not result["exclusive_owner_verified"]:
            raise SystemExit(2)
    except LifecycleHold as exc:
        print("HOLD", exc)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
