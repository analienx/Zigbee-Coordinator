"""One-shot read-only true host-PID Zigbee process owner inspection.

Only prints nonsecret container ID, start time, cgroup/FD qualification.
No daemon, no serial open, no mutating Supervisor requests, no Docker exec.
Fails HOLD when protection-mode/host_pid/procfd capability is unavailable.
"""
import json
import os
from pathlib import Path
from p7u_ha_readonly_inspector import inspect
from p7u_lifecycle_core import LifecycleHold

def main():
    try:
        opts=json.loads(Path("/data/options.json").read_text())
        serial=opts["serial_by_id"]
        result=inspect(serial)
        # Only the result schema (which excludes options/tokens) is printed.
        print(json.dumps(result,sort_keys=True),flush=True)
        return 0 if result["exclusive_owner_verified"] else 2
    except (OSError, ValueError, KeyError, LifecycleHold) as exc:
        print(json.dumps({"schema":"p7u-host-tty-cgroup-evidence-v2",
                          "exclusive_owner_verified":False,
                          "status":"HOLD", "reason":type(exc).__name__}),flush=True)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
