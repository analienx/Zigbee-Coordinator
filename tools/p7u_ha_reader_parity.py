#!/usr/bin/env python3
"""Compare pinned HA ARM64 reader with trusted Win64 TI reader on private fixtures.

Private network data is piped over authenticated SSH stdin only, never put in
arguments, logs, repo, GitHub artifacts, or an HA file. No radio UART access.
Exactly identical private record contents and no mutation counts are required.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7u/r4/qualification"))
from stock20260311_security_preflight import parse_private_pipe,read_private,NV_START,NV_END,MAX_OUTPUT


def require(ok,why):
    if not ok:raise RuntimeError("P7U_HA_ARM_READER_HOLD_"+why)


def compare(*, windows_reader, snapshots, arm_receipt,
            ha_reader="/config/.p7u_fast/security-reader-arm64"):
    receipt=json.loads(Path(arm_receipt).read_bytes())
    require(receipt.get("schema")=="p7u-native-arm64-reader-v1" and
            receipt.get("platform")=="linux-aarch64" and
            receipt.get("single_pinned_native_build") is True and
            receipt.get("private_fixture_parity")=="NOT_TESTED_ON_HOSTED_RUNNER",
            "UPSTREAM_READER_PROVENANCE")
    h=subprocess.run(["ssh","-o","BatchMode=yes","-o","ConnectTimeout=6",
                      "ha","sha256sum "+ha_reader],
                     capture_output=True,text=True,timeout=15)
    require(h.returncode==0 and h.stdout.strip().split()[0]==receipt["binary_sha256"],
            "HA_BINARY_SHA256_MISMATCH")
    count=0
    for image in snapshots:
        data=Path(image).read_bytes()
        expected,win_stats=read_private(Path(windows_reader),data)
        try:
            native=subprocess.run(["ssh","-o","BatchMode=yes","-o","ConnectTimeout=6",
                                   "ha",ha_reader],
                                   input=data[NV_START:NV_END],
                                   capture_output=True,timeout=24)
        except subprocess.TimeoutExpired:
            raise RuntimeError("P7U_HA_ARM_READER_HOLD_REMOTE_READER_TIMED_OUT") from None
        require(native.returncode==0 and not native.stderr and
                len(native.stdout)<=MAX_OUTPUT,"ARM_READER_REJECTED_PRIVATE_INPUT")
        actual,linux_stats=parse_private_pipe(native.stdout)
        require(actual==expected and linux_stats==win_stats,
                "PRIVATE_NV_RECORDS_DIVERGE_BETWEEN_ARCHITECTURES")
        count+=1
    return {"schema":"p7u-ha-reader-private-parity-v1",
            "status":"ARM64_READER_PARITY_PASS",
            "private_fixture_count":count,
            "arm_binary_sha256":receipt["binary_sha256"],
            "windows_reader_verified":True,
            "nv_secret_fields_disclosed":False,
            "flash_authorized":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--win64-reader",required=True,type=Path)
    p.add_argument("--arm-receipt",required=True,type=Path)
    p.add_argument("--fixture",action="append",type=Path,required=True)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    if args.out.exists():raise RuntimeError("P7U_HA_PARITY_RECEIPT_ALREADY_EXISTS")
    x=compare(windows_reader=args.win64_reader,snapshots=args.fixture,
              arm_receipt=args.arm_receipt)
    args.out.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
    print("P7U_ARM64_READER_PRIVATE_FIXTURE_PARITY_PASS",x["private_fixture_count"])


if __name__=="__main__":main()
