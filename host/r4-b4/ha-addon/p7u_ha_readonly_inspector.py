"""Read-only host PID/tty identity inspector for P7U lifecycle admission.

Run only within a proven host PID namespace with privileges to enumerate all
/proc/*/fd entries. No user database/options secrets, no serial open, no
Docker stop/start/kill, no Supervisor mutations. UNKNOWN means HOLD.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from p7u_lifecycle_core import LifecycleHold, Owner, guard

SLUGS = {
    "official": "45df7312_zigbee2mqtt",
    "diagnostic": "local_p7u_r4_native_host",
    "guard": "local_p7u_recovery",
}
BY_ID = re.compile(r"^/dev/serial/by-id/[A-Za-z0-9_.:+@-]{4,200}$")


def inspect_docker(slot: str) -> dict | None:
    guard(slot in SLUGS, "UNRECOGNIZED_SLOT")
    # Read-only, argv-typed, bounded. No shell or dynamic command operators.
    cmd = ["docker", "inspect", "app_" + SLUGS[slot]]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if p.returncode:
        if "No such object" in p.stderr or "No such container" in p.stderr:
            return None
        raise LifecycleHold("P7U_HOLD_DOCKER_INSPECT_UNAVAILABLE")
    try:
        values = json.loads(p.stdout)
    except ValueError as exc:
        raise LifecycleHold("P7U_HOLD_DOCKER_INSPECT_INVALID") from exc
    guard(type(values) is list and len(values) == 1, "DOCKER_INSPECT_CARDINALITY")
    return values[0]


def inspect_addon(slot: str) -> dict:
    guard(slot in SLUGS, "UNRECOGNIZED_SLOT")
    p = subprocess.run(
        ["ha", "apps", "info", SLUGS[slot], "--raw-json"],
        capture_output=True, text=True, timeout=20,
    )
    guard(p.returncode == 0, "SUPERVISOR_INFO_UNAVAILABLE")
    try:
        value = json.loads(p.stdout)
    except ValueError as exc:
        raise LifecycleHold("P7U_HOLD_SUPERVISOR_INFO_INVALID") from exc
    guard(value.get("result") == "ok" and type(value.get("data")) is dict,
          "SUPERVISOR_INFO_SHAPE")
    d = value["data"]
    # Return ONLY nonsecret fields; options may include MQTT credentials.
    return {k: d.get(k) for k in ("state", "boot", "watchdog", "version")}


def check_host_namespace():
    guard(os.geteuid() == 0, "NOT_ROOT")
    try:
        init_comm = Path("/proc/1/comm").read_text().strip()
    except OSError as exc:
        raise LifecycleHold("P7U_HOLD_HOST_PID_NAMESPACE_UNAVAILABLE") from exc
    # On HAOS host PID1 is systemd. A container-local PID namespace must
    # never claim a complete host fd scan.
    guard(init_comm in ("systemd", "init"), "UNPROVEN_HOST_PID_NAMESPACE")


def tty_holders(serial_path: str) -> frozenset[int]:
    guard(type(serial_path) is str and BY_ID.fullmatch(serial_path) is not None,
          "SERIAL_BY_ID_REQUIRED")
    check_host_namespace()
    try:
        d = os.stat(serial_path)
    except OSError as exc:
        raise LifecycleHold("P7U_HOLD_SERIAL_DEVICE_MISSING") from exc
    guard(stat.S_ISCHR(d.st_mode), "NOT_CHARACTER_DEVICE")
    holders: set[int] = set()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        fd_dir = entry / "fd"
        try:
            fd_list = list(fd_dir.iterdir())
        except FileNotFoundError:
            continue  # process has already exited
        except PermissionError as exc:
            raise LifecycleHold("P7U_HOLD_INCOMPLETE_PROC_ENUMERATION") from exc
        for fd in fd_list:
            try:
                state = fd.stat()
            except FileNotFoundError:
                continue
            except PermissionError as exc:
                raise LifecycleHold("P7U_HOLD_FD_ACCESS_DENIED") from exc
            if stat.S_ISCHR(state.st_mode) and state.st_rdev == d.st_rdev:
                holders.add(pid)
    return frozenset(holders)


def inspect(serial_path: str) -> dict:
    check_host_namespace()
    official = inspect_docker("official")
    diagnostic = inspect_docker("diagnostic")
    # Source-only guard: no serial access is performed.
    slots = {}
    for name, raw in (("official", official), ("diagnostic", diagnostic)):
        if raw and raw.get("State", {}).get("Running") is True:
            owner = Owner.from_inspect(raw)
            slots[name] = {
                "running": True, "container_id": owner.container_id,
                "pid": owner.pid, "started_at": owner.started_at,
                "image_digest": owner.image_digest,
            }
        else:
            slots[name] = {"running": False}
    holders = tty_holders(serial_path)
    expected = frozenset(v["pid"] for v in slots.values() if v["running"])
    return {
        "schema": "p7u-readonly-host-inspection-v1",
        "slots": slots, "tty_holders_pids": sorted(holders),
        "only_known_owners_hold_serial": holders == expected,
        "guard": inspect_addon("guard"),
        "mutation_authorized": False, "serial_opened": False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--serial-by-id", required=True)
    args=p.parse_args()
    try:
        result=inspect(args.serial_by_id)
        print(json.dumps(result, sort_keys=True, indent=2))
        if not result["only_known_owners_hold_serial"]:
            raise SystemExit(2)
    except LifecycleHold as exc:
        print("HOLD", exc)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
