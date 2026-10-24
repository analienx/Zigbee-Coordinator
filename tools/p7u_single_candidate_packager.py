#!/usr/bin/env python3
"""Package ONE genuinely rebuilt R4 APP with pinned ELF, source and handoff.

Offline only: never opens serial devices, stores keys, or authorizes flashing.
A separate conservative candidate format remains supported for forensic flows.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

FILES = {
    "app":"P7U-CURRENT-APP-ONLY.hex",
    "handoff":"P7U-CURRENT-AC000-HANDOFF.bin",
    "elf":"P7U-CURRENT.elf",
    "source_manifest":"source-manifest.json",
}
EXTRA = {
    "profile":"profile.json",
    "native_manifest":"native-manifest.json",
    "handoff_receipt":"handoff-receipt.json",
}
SOURCE_RE=re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE=re.compile(r"[0-9a-f]{64}\Z")


class PackagingHold(ValueError): pass


def need(test,code):
    if not test:raise PackagingHold("P7U_SINGLE_CANDIDATE_HOLD_"+code)


def sha(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj)->bytes:
    return json.dumps(obj,sort_keys=True,separators=(",",":"),
                      allow_nan=False).encode()


def package(*,source_sha:str,prepared_identity:str,files:dict,
            worker_receipt:dict,out_dir:Path):
    need(isinstance(source_sha,str) and SOURCE_RE.fullmatch(source_sha)
         and isinstance(prepared_identity,str) and DIGEST_RE.fullmatch(prepared_identity),
         "SOURCE_OR_PREPARED_PIN")
    need(type(worker_receipt) is dict and
         worker_receipt.get("worker")=="build-1" and
         worker_receipt.get("source_sha")==source_sha and
         worker_receipt.get("dependency_identity")==prepared_identity and
         worker_receipt.get("clean_app_build") is True and
         worker_receipt.get("reused_app_objects") is False,
         "ONE_CLEAN_NATIVE_BUILD_NOT_PROVEN")
    need(type(files) is dict and set(files)==set(FILES)|set(EXTRA),
         "EXACT_FILE_SET_REQUIRED")
    raw={}
    for tag,filename in {**FILES,**EXTRA}.items():
        p=Path(files[tag])
        need(p.is_file() and not p.is_symlink() and
             0<p.stat().st_size<=32*1024*1024, "INVALID_"+tag.upper())
        raw[filename]=p.read_bytes()
    hashes={tag:sha(raw[filename]) for tag,filename in FILES.items()}
    need(worker_receipt.get("artifact_hashes")==hashes,
         "ACTUAL_COMPILER_OUTPUT_HASHES_CHANGED")
    profile_sha=sha(raw[EXTRA["profile"]])
    native_sha=sha(raw[EXTRA["native_manifest"]])
    handoff_receipt=json.loads(raw[EXTRA["handoff_receipt"]])
    need(handoff_receipt.get("schema")=="r4-p7u-stock20260311-compiled-handoff-v1"
         and handoff_receipt.get("status")=="COMPILED_M4F_SINGLE_SECTOR_TRANSFER_AUDITED"
         and handoff_receipt.get("sector_sha256")==hashes["handoff"]
         and handoff_receipt.get("profile_sha256")==profile_sha
         and handoff_receipt.get("source_native_manifest_sha256")==native_sha,
         "HANDOFF_MUST_BE_COMPILED_AND_PROVEN")
    native=json.loads(raw[EXTRA["native_manifest"]])
    review=json.loads(raw[FILES["source_manifest"]])
    need(native.get("schema")=="r4-b0-artifact-manifest-v1" and
         review.get("schema")=="r4-p7u-final-ti-source-snapshot-v1" and
         review.get("firmware_source_sha")==source_sha and
         review.get("compiled_source_unchanged_after_snapshot") is True and
         review.get("flash_authorized") is False,
         "SOURCE_NATIVE_MANIFEST_NOT_EXACT_COMMIT")
    candidate={
        "schema":"p7u-stock20260311-candidate-v1",
        "build_mode":"SINGLE_CLEAN_APP_PINNED_DEPENDENCIES",
        "build_count":1,
        "source_sha":source_sha,
        "prepared_identity_sha256":prepared_identity,
        "board":"SLZB-06P7U-r1.73-CC2652P7",
        "boot_contract":"APP0_REQUIRES_SEPARATE_AC000_HANDOFF",
        "profile_sha256":profile_sha,
        "native_manifest_sha256":native_sha,
        "app_hex_sha256":hashes["app"],
        "handoff_sha256":hashes["handoff"],
        "private_current_capture_and_security_preflight_required":True,
        "flash_authorized":False,"hardware_boot_qualified":False,
        "replicas":[worker_receipt],
        "files":{filename:sha(data) for filename,data in raw.items()}
    }
    output=Path(out_dir)
    need(not output.exists() and not output.is_symlink(),
         "OUTPUT_MUST_BE_EXCLUSIVE_NEW_DIRECTORY")
    need(output.parent.is_dir(),"PARENT_MUST_PREEXIST")
    with tempfile.TemporaryDirectory(prefix=".p7u-single-",dir=output.parent) as temp:
        staging=Path(temp)
        for filename,data in raw.items():
            with (staging/filename).open("xb") as f:
                f.write(data);f.flush();os.fsync(f.fileno())
        with (staging/"candidate.json").open("xb") as f:
            f.write(canonical(candidate));f.flush();os.fsync(f.fileno())
        # All hashes checked again before atomic rename; no partial candidate.
        for filename,data in raw.items():
            need(sha((staging/filename).read_bytes())==sha(data),
                 "STAGED_INPUT_CHANGED")
        os.replace(staging,output)
    return {"status":"ONE_CLEAN_APP_CANDIDATE_BUNDLED_NOT_FLASH_APPROVED",
            "source_sha":source_sha,
            "candidate_sha256":sha(canonical(candidate)),
            "dependency_identity":prepared_identity,
            "files":len(raw),"out":str(output)}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",required=True)
    ap.add_argument("--dependency-identity",required=True)
    ap.add_argument("--build-receipt",type=Path,required=True)
    ap.add_argument("--out",required=True,type=Path)
    for key in list(FILES)+list(EXTRA):
        ap.add_argument("--"+key.replace("_","-"),type=Path,required=True)
    a=ap.parse_args()
    print(json.dumps(package(source_sha=a.source,
        prepared_identity=a.dependency_identity,
        worker_receipt=json.loads(a.build_receipt.read_bytes()),
        files={k:getattr(a,k) for k in list(FILES)+list(EXTRA)},out_dir=a.out),
        sort_keys=True))


if __name__=="__main__":main()
