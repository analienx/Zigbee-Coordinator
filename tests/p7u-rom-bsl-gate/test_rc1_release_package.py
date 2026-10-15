#!/usr/bin/env python3
"""Hostile first-release package mutations using the pinned actual stock BIN."""
from __future__ import annotations
import argparse
import json
import sys
import tempfile
import subprocess
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"firmware/slzb-06p7u/qualification"))
import p7u_rc1_package as rc
import p7u_rc1_native_provenance as native
import p7u_strict_sector_writer as core
import p7u_stock_rollback as stock


def reject(fn,code):
    try:fn()
    except ValueError as e:assert str(e)==code,(str(e),code)
    else:raise AssertionError("Expected rejection "+code)

def main():
    args=argparse.ArgumentParser()
    args.add_argument("--vendor",type=Path,required=True)
    args.add_argument("--native-full-hex",type=Path)
    args.add_argument("--native-evidence-dir",type=Path)
    a=args.parse_args()
    # An empty self-consistent manifest must not verify as a usable recovery kit.
    with tempfile.TemporaryDirectory() as d:
        stage=Path(d)
        empty={"flash_authorized":False,
               "qualification":"SOFTWARE_RELEASE_CANDIDATE_READY_FOR_SPARE_P7U_HARDWARE_QUALIFICATION_ONLY",
               "model":"SMLIGHT_SLZB_06P7U", "profile":"p7u-f07-stock", "release":"0.1.0-rc1",
               "files":{}}
        (stage/"RC1-MANIFEST.json").write_text(json.dumps(empty))
        (stage/"SHA256SUMS").write_text("")
        reject(lambda:rc.verify_directory(stage),"RC1_REQUIRED_FILE_SET_CHANGED")
        (stage/"RC1-MANIFEST.json").write_text("[]")
        reject(lambda:rc.verify_directory(stage),"RC1_MANIFEST_SCHEMA_INVALID")
        # Malformed JSON must produce bounded diagnostics, not expose its contents.
        (stage/"RC1-MANIFEST.json").write_text('{"private-marker": INVALID}')
        process=subprocess.run([sys.executable,str(Path(rc.__file__).with_name("p7u_rc1_verify.py")),
                                "--directory",str(stage)],capture_output=True,text=True)
        assert process.returncode==2
        assert json.loads(process.stdout)["reason"]=="RC1_MANIFEST_OR_FILE_UNREADABLE"
        assert "private-marker" not in process.stdout and not process.stderr
    blob=a.vendor.read_bytes()
    m=stock.extract(blob,"p7u-f07-stock")
    assert m[3]["custom_tail_cleanup_erased_to_all_ff"]
    assert m[3]["app_payload_bytes"]==179688
    assert m[2]["sector_count"]==23

    # Build tests use genuine CCS native full image rather than inventing authority
    if a.native_full_hex is None:
        reject(lambda:stock.extract(blob[:-1],"p7u-f07-stock"),
               "STOCK_VENDOR_SOURCE_HASH_MISMATCH")
        print("P7U_RC1_STOCK_ONLY_HOSTILE_SOURCE_PASS")
        return

    native_hex=a.native_full_hex.read_bytes()
    evidence=a.native_evidence_dir
    COMMIT=(evidence/"candidate-sha.txt").read_text().strip()
    for profile in ("p7u-f07-stock",):  # profile of supplied native image
        r,files=rc.build(native_hex,blob,profile,COMMIT)
        assert r["flash_authorized"] is False
        assert r["fully_covered_application_sectors"]==23
        assert r["stock_extra_tail_sector_erased"]=="0x2C000"
        assert r["vendor_20240710_verified_and_extracted"]
    prove=native.qualify(evidence,native_hex,"p7u-f07-stock",COMMIT)
    r["native_ccs_provenance"]=prove
    assert prove["candidate_origin_exact_ccs_native"]
    reject(lambda:native.qualify(evidence,native_hex,"p7u-f07-stock","a"*40),
           "RC1_NATIVE_BUILD_COMMIT_MISMATCH")
    rejected=bytearray(native_hex)
    rejected[-5]^=1
    # Invalid Intel HEX checksum or changed content must be rejected before publication.
    try:rc.build(bytes(rejected),blob,"p7u-f07-stock",COMMIT)
    except ValueError:pass
    else:raise AssertionError("Corrupt CCS source unexpectedly packaged")
    with tempfile.TemporaryDirectory() as d:
        stage=Path(d)
        stage.joinpath("RC1-MANIFEST.json").write_text(
            json.dumps(r,indent=2,sort_keys=True)+"\n")
        for k,v in files.items():stage.joinpath(k).write_bytes(v)
        stage.joinpath("SHA256SUMS").write_text("".join(
            f"{r['files'][n]['sha256']}  {n}\n" for n in sorted(files)))
        assert rc.verify_directory(stage)["files"]==7
        # Top-level identities and claimed provenance must agree with the actual
        # images/plans, even when every ordinary file checksum still matches.
        for key,value,code in (
            ("profile","p7u-cap192-f07","RC1_PACKAGE_PROFILE_MISMATCH"),
            ("radio","CC2674P10","RC1_PACKAGE_IDENTITY_CHANGED"),
            ("physical_stock_restore_verified",True,"RC1_UNSUPPORTED_HARDWARE_QUALIFICATION_CLAIM"),
            ("release_custom_app_hex_sha256","0"*64,"RC1_MANIFEST_IMAGE_HASH_MISMATCH"),
            ("git_commit","a"*40,"RC1_NATIVE_PROVENANCE_MISMATCH"),
            ("native_ccs_provenance",None,"RC1_NATIVE_PROVENANCE_MISMATCH"),
        ):
            bad={**r,key:value}
            stage.joinpath("RC1-MANIFEST.json").write_text(json.dumps(bad))
            reject(lambda:rc.verify_directory(stage),code)
        stage.joinpath("RC1-MANIFEST.json").write_text(json.dumps(r))
        # Rehash a modified plan: checksums alone used to accept invalid geometry.
        plan_file=stage/"candidate.plan.json"
        bad_plan=json.loads(plan_file.read_text())
        bad_plan["sector_count"]=22
        plan_file.write_text(json.dumps(bad_plan))
        bad=json.loads(json.dumps(r))
        bad["files"][plan_file.name]={"sha256":core.sha(plan_file.read_bytes()),"size":plan_file.stat().st_size}
        stage.joinpath("RC1-MANIFEST.json").write_text(json.dumps(bad))
        stage.joinpath("SHA256SUMS").write_text("".join(
            f"{bad['files'][n]['sha256']}  {n}\n" for n in sorted(files)))
        reject(lambda:rc.verify_directory(stage),"SECTOR_PLAN_NOT_REDERIVED_EXACTLY")
        plan_file.write_bytes(files[plan_file.name])
        stage.joinpath("RC1-MANIFEST.json").write_text(json.dumps(r))
        stage.joinpath("SHA256SUMS").write_text("".join(
            f"{r['files'][n]['sha256']}  {n}\n" for n in sorted(files)))
        image_file=stage/"candidate.APP-ONLY-NOT-FLASHABLE.hex"
        image_file.write_bytes(image_file.read_bytes()+b"BAD")
        reject(lambda:rc.verify_directory(stage),"RC1_PACKAGE_HASH_MISMATCH")
        image_file.write_bytes(files[image_file.name])
        (stage/"undeclared.secret").write_text("forbidden")
        reject(lambda:rc.verify_directory(stage),"RC1_DIRECTORY_CONTAINS_UNDECLARED_FILE")
    print("P7U_RC1_PACKAGE_NATIVE_PROVENANCE_HOSTILE_PASS_NO_HARDWARE")

if __name__=="__main__":
    main()
