#!/usr/bin/env python3
"""Provision pinned pure-Python serial dependencies on HA without touching Z2M.

Executed on HA ARM64 from an already transferred, privately staged directory.
No pip/network access, firmware writes or serial device open. Atomic install.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

WHEELS = {
 "pyserial-3.5-py2.py3-none-any.whl":
   "c4451db6ba391ca6ca299fb3ec7bae67a5c55dde170964c7a14ceefec02f2cf0",
 "pyserial_asyncio-0.6-py3-none-any.whl":
   "de9337922619421b62b9b1a84048634b3ac520e1d690a674ed246a2af7ce1fc5",
}
SCHEMA="p7u-ha-serial-dependency-provision-v1"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def provision(root, *, apply=False):
    root=Path(root).resolve()
    wheelroot=root/"wheels"
    packages=root/"python"
    assert wheelroot.is_dir(), "P7U_HA_WHEELS_NOT_TRANSFERRED"
    for name, expected in WHEELS.items():
        p=wheelroot/name
        assert p.is_file() and not p.is_symlink() and sha(p.read_bytes())==expected, (
            "P7U_HA_WHEEL_SHA_PIN_REJECTED_"+name)
    check={"schema":SCHEMA,"architecture":"aarch64","python":"3.14",
           "wheels_sha256":WHEELS,"source":"PINNED_OFFLINE_WHEELS"}
    import platform
    assert platform.machine()=="aarch64" and sys.version_info[:2]==(3,14), (
        "P7U_HA_EXECUTION_ARCHITECTURE_CHANGED")
    if not apply:
        return {"status":"PREPARED_WHEELS_VERIFIED_NOT_INSTALLED",**check}
    assert not packages.is_symlink(), "P7U_HA_DEP_PATH_IS_SYMLINK"
    with tempfile.TemporaryDirectory(prefix=".p7u-serial-",dir=root) as td:
        t=Path(td)
        for name in WHEELS:
            with zipfile.ZipFile(wheelroot/name) as arc:
                for member in arc.infolist():
                    path=Path(member.filename)
                    assert not path.is_absolute() and ".." not in path.parts and (
                        not member.is_dir() or member.filename.endswith("/")
                    ),"P7U_HA_WHEEL_TRAVERSAL"
                arc.extractall(t)
        old=list(sys.path)
        try:
            sys.path.insert(0,str(t))
            from serial import VERSION as pyserial_version
            import serial_asyncio
            assert pyserial_version=="3.5" and callable(
                serial_asyncio.open_serial_connection)
        finally:
            sys.path[:]=old
            for m in ("serial","serial_asyncio"):
                sys.modules.pop(m,None)
        if packages.exists():
            raise ValueError("P7U_HA_DEPENDENCIES_ALREADY_PROVISIONED_NO_OVERWRITE")
        os.replace(t,packages)
    check["status"]="PINNED_SERIAL_RUNTIME_PROVISIONED"
    receipt=root/"serial-runtime-receipt.json"
    with receipt.open("x",encoding="utf-8") as fh:
        json.dump(check,fh,sort_keys=True,indent=2)
        fh.flush(); os.fsync(fh.fileno())
    return check


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",default="/config/.p7u_fast")
    parser.add_argument("--apply",action="store_true")
    args=parser.parse_args()
    print(json.dumps(provision(args.root,apply=args.apply),sort_keys=True))


if __name__=="__main__":
    main()
