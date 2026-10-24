#!/usr/bin/env python3
"""HA ARM64 P7U *read-only* fast-path readiness.

No BSL, serial open, Zigbee2MQTT stop/start, MQTT writes, secrets, reset or
FLASH. Fail closed unless the live OS and independent native reader pins match.
Proves host readiness only, never device/firmware qualification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT=Path("/config/.p7u_fast")
Z2M="45df7312_zigbee2mqtt"
READER_SHA="ef46af9c5e1f44cc02a591f7e24165e76443ada0fa65f508d0d580924edcc057"
SERIAL_RE=re.compile(r"usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U[0-9]+-if00\Z")
WHEELS={
  "pyserial-3.5-py2.py3-none-any.whl":
    "c4451db6ba391ca6ca299fb3ec7bae67a5c55dde170964c7a14ceefec02f2cf0",
  "pyserial_asyncio-0.6-py3-none-any.whl":
    "de9337922619421b62b9b1a84048634b3ac520e1d690a674ed246a2af7ce1fc5",
}

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def addon_state():
    p=subprocess.run(["ha","apps","info",Z2M,"--raw-json"],
                     capture_output=True,text=True,timeout=12)
    if p.returncode:return None
    try:return json.loads(p.stdout)["data"]
    except (KeyError,ValueError,TypeError):return None

def inspect(root=ROOT):
    root=Path(root)
    checks={}
    reasons=[]
    def check(name,condition):
        checks[name]=bool(condition)
        if not condition:reasons.append(name)
    check("architecture_aarch64_python314",platform.machine()=="aarch64" and
          sys.version_info[:2]==(3,14))
    check("isolated_runtime_provision_receipt",
          (root/"serial-runtime-receipt.json").is_file())
    wheels_ok=all((root/"wheels"/name).is_file() and
                  sha(root/"wheels"/name)==digest for name,digest in WHEELS.items())
    check("serial_wheel_hash_pins",wheels_ok)
    install=(root/"python")
    check("isolated_runtime_available",
          install.is_dir() and (install/"serial").is_dir()
          and (install/"serial_asyncio").is_dir())
    reader=root/"security-reader-arm64"
    check("arm64_native_reader_exact_sha",reader.is_file() and
          sha(reader)==READER_SHA)
    by_id=Path("/dev/serial/by-id")
    names=[p for p in by_id.iterdir() if p.is_symlink()] if by_id.is_dir() else []
    eligible=[p for p in names if SERIAL_RE.fullmatch(p.name)]
    check("single_matching_slzb06p7u_serial_path",
          len(eligible)==1 and eligible[0].resolve().as_posix().startswith("/dev/ttyACM"))
    owner=addon_state()
    check("original_zigbee2mqtt_serving_before_change",
          type(owner) is dict and owner.get("state")=="started" and
          owner.get("boot")=="manual" and owner.get("watchdog") is False)
    check("approved_immutable_ti_sdk_not_yet_provisioned",False)
    check("previous_r4_state9_boot_and_device_traffic_not_yet_proven",False)
    check("hardware_mutating_operator_not_yet_qualified",False)
    return {"schema":"p7u-ha-fast-readonly-preflight-v1",
            "status":"HOST_CHECKS_COMPLETE_FLASH_BLOCKED",
            "checks":checks,"hold_reasons":reasons,
            "port_opened":False,"z2m_service_mutated":False,
            "radio_reset_requested":False,"flash_authorized":False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true",required=True)
    parser.add_argument("--root",type=Path,default=ROOT)
    a=parser.parse_args()
    print(json.dumps(inspect(a.root),sort_keys=True,indent=2))

if __name__=="__main__":main()
