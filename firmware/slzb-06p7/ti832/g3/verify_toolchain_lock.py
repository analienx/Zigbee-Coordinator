#!/usr/bin/env python3
"""Fail-closed SHA256 validation of exact downloaded historical TI installers.

This confirms frozen bytes observed from official TI HTTPS download hosts,
NOT an independent TI vendor signature or downstream web-installer components.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import re
from pathlib import Path

LOCK=Path(__file__).with_name("toolchain-lock.json")
EXPECTED={
    "ccs":("12.8.0.00012","CCS12.8.0.00012_web_linux-x64.tar.gz",
           "3b56d5d07a47132408a116f01cc01587c88e78de7372e9623754f035e1c9d550",
           "dr-download.ti.com"),
    "sysconfig":("1.21.1.3772","sysconfig-1.21.1_3772-setup.run",
           "0c1674f82a53b187f60e376de3da2b719f003187c7437998c2ce3f975504d1d5",
           "software-dl.ti.com"),
}

def require(ok:bool,err:str)->None:
    if not ok:
        raise ValueError(err)

def audit_lock(obj:dict)->None:
    require(obj["schema"]=="p7-ti832-vendor-archive-sha256-lock-v1","SCHEMA")
    require(obj["hardware_flash_authorized"] is False,"FLASH_STATE")
    require("not independently" in obj["provenance_limit"],"PROVENANCE_LIMIT_MISSING")
    require(set(obj["packages"])==set(EXPECTED),"PACKAGE_COVERAGE")
    for name,(version,filename,digest,domain) in EXPECTED.items():
        a=obj["packages"][name]
        require((a["version"],a["filename"],a["sha256"])==
                (version,filename,digest),"TOOLCHAIN_LOCK_DRIFT_"+name)
        require(re.fullmatch(r"[a-f0-9]{64}",a["sha256"]) is not None,
                "DIGEST_FORMAT_"+name)
        require(a["url"].startswith("https://"+domain+"/") and
                a["url"].endswith("/"+filename),"VENDOR_URL_"+name)
        require(a["kind"] and "BOOTSTRAP" in obj["packages"]["ccs"]["kind"],
                "DOWNSTREAM_BOOTSTRAP_BOUNDARY")

def audit_download(lock:dict, name:str, path:Path)->str:
    audit_lock(lock)
    require(name in EXPECTED,"UNEXPECTED_PACKAGE")
    data=lock["packages"][name]
    require(path.is_file() and path.name==data["filename"],"MISSING_OR_WRONG_ARCHIVE")
    sha=hashlib.sha256(path.read_bytes()).hexdigest()
    require(sha==data["sha256"],"VENDOR_ARCHIVE_HASH_MISMATCH_"+name)
    return sha

def selftest()->None:
    d=json.loads(LOCK.read_text())
    audit_lock(d)
    failures=[
        lambda x:x["packages"]["ccs"].update(sha256="0"*64),
        lambda x:x["packages"]["sysconfig"].update(version="1.21.0"),
        lambda x:x["packages"]["ccs"].update(filename="CCS12.8.0.00012_linux-x64.tar.gz"),
        lambda x:x["packages"]["sysconfig"].update(url="https://example.com/installer"),
        lambda x:x.update(hardware_flash_authorized=True),
        lambda x:x["packages"].pop("ccs"),
        lambda x:x["packages"]["ccs"].update(kind="TRUSTED_STATIC_FILE"),
        lambda x:x.update(provenance_limit="Vendor signed and independently verified"),
    ]
    for i,fn in enumerate(failures):
        copy_doc=copy.deepcopy(d);fn(copy_doc)
        try:audit_lock(copy_doc)
        except (ValueError,KeyError):continue
        raise AssertionError(f"ARCHIVE_LOCK_CORRUPTION_NOT_REJECTED_{i}")
    print(f"PASS G3 pinned observed TI archive lock; {len(failures)} fail-closed mutations")

def main()->None:
    p=argparse.ArgumentParser()
    p.add_argument("--lock",type=Path,default=LOCK)
    p.add_argument("--name",choices=sorted(EXPECTED))
    p.add_argument("--download",type=Path)
    p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    if a.selftest:selftest()
    if a.name or a.download:
        require(bool(a.name and a.download),"NAME_AND_DOWNLOAD_REQUIRED")
        obj=json.loads(a.lock.read_text())
        sha=audit_download(obj,a.name,a.download)
        print("PASS observed TI archive SHA256 lock",a.name,sha)

if __name__=="__main__":
    main()
