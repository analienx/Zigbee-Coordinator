#!/usr/bin/env python3
"""B3 native NV3/NV5 DIFFERENTIAL verifier.

Audits real B0 ELF/XML/HEX/BIN with every B0 check retained except explicitly
substituted flash geometry, and additionally requires generated board + vendor
CCFG unchanged. Exact B0 auditor Git blob preimage pin prevents silent scope
drift. Experimental only; does NOT validate an old-stock on-device NV.
"""
import argparse
import hashlib
import json
from pathlib import Path
from b3_native_candidate import profile, git_blob

B0_AUDIT_BLOB = "9745e0366d43b26ef202669f56a8348545265861"


def swap_one(src, a, b):
    if src.count(a) != 1:
        raise ValueError("B3 audit derivation anchor absent or ambiguous")
    return src.replace(a, b, 1)


def audit(base, artifacts, pages):
    geometry = profile(pages)
    original = (Path(base) / "tools/b0_image_audit.py").read_bytes()
    if git_blob(original) != B0_AUDIT_BLOB:
        raise ValueError("B3 native profile audit refused B0 auditor drift")
    src = original.decode("utf-8")
    nv_start = geometry["nv_start"]
    nv_size = geometry["nv_size"]
    replacements = (
        ("DONOR_NVS_BASE = 0xAA000", "DONOR_NVS_BASE = 0x%X" % nv_start),
        ("DONOR_NVS_SIZE = 0x4000", "DONOR_NVS_SIZE = 0x%X" % nv_size),
        ('"FLASH": (0x00000000, 0xAA000),',
         '"FLASH": (0x00000000, 0x%X),' % nv_start),
        ('"FLASH_NV": (0xAA000, 0x4000),',
         '"FLASH_NV": (0x%X, 0x%X),' % (nv_start, nv_size)),
    )
    for old, new in replacements:
        src = swap_one(src, old, new)
    ctx = {"__file__": str(Path(base) / "tools/b0_image_audit.py"),
           "__name__": "b3_b0_differential_audit"}
    exec(compile(src, ctx["__file__"], "exec"), ctx)
    rc, message = ctx["audit"](Path(base), Path(artifacts))
    if rc != 0:
        raise RuntimeError("B3 actual B0-derived image binding rejected: " + message)
    receipt = {"schema": "r4-b3-native-profile-audit-v1",
               "pages": pages, "profile": "EXPERIMENTAL_NOT_FLASH_READY",
               "base_b0_audit_blob": B0_AUDIT_BLOB,
               "derivation_sha256": hashlib.sha256(src.encode("utf-8")).hexdigest(),
               "geometry": geometry, "b0_image_audit_return": rc,
               "b0_image_audit_message": message,
               "flash_authorized": False, "migration_authorized": False,
               "stock_20260310_nv_compatible": "UNKNOWN"}
    return receipt


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--b0-dir",type=Path,required=True)
    p.add_argument("--artifacts",type=Path,required=True)
    p.add_argument("--pages",type=int,choices=(3,5),required=True)
    p.add_argument("--receipt",type=Path,required=True)
    args=p.parse_args()
    receipt=audit(args.b0_dir,args.artifacts,args.pages)
    args.receipt.parent.mkdir(parents=True,exist_ok=True)
    args.receipt.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,sort_keys=True))


if __name__=="__main__":
    main()
