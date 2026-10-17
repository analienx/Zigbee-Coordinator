#!/usr/bin/env python3
"""Seal a genuine P0/P1/P3 B2 native-capacity deliverable, NEVER full B2.

Input files must already pass B0's ELF/HEX/BIN/CCFG audit, independently
re-extracted ELF symbols, and the strict native P0/P1 comparator.
The P3 negative comes from the SAME GitHub Actions run's P3 artifact.
This deliberately cannot grant a merge/flash or B2_SOURCE_READY verdict.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

COMPARISON_STATUS="B2_NATIVE_CAPACITY_EVIDENCE_COMPLETE_NOT_B2_SOURCE_READY"
ELF_STATUS="B2_NATIVE_CLAIMS_INDEPENDENTLY_REDERIVED"
P3_STATUS="HOSTED_NATIVE_LINKER_OVERBUDGET_REJECTED"
SOURCE_SHA_FORMAT=r"[a-f0-9]{40}"
RUN_ID_FORMAT=r"[0-9]{8,20}"

class SealError(ValueError): pass

def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>1024*1024:
        raise SealError("missing/symlinked/oversized receipt "+str(path))
    try:
        return json.loads(path.read_text())
    except (ValueError, UnicodeError) as err:
        raise SealError("invalid JSON receipt: "+str(err)) from err

def seal(native,proofs,p3,source_sha,run_id):
    if not re.fullmatch(SOURCE_SHA_FORMAT,source_sha) or not re.fullmatch(RUN_ID_FORMAT,run_id):
        raise SealError("invalid expected source SHA or run identifier")
    if native.get("status")!=COMPARISON_STATUS or native.get("source_sha")!=source_sha:
        raise SealError("missing exact-HEAD independently audited P1 comparator")
    if native.get("B2_SOURCE_READY") is not False or native.get("physical_verified") is not False:
        raise SealError("unexpected full readiness / RF claim in native comparison")
    if native.get("table_delta_bytes")!=3488 or native.get("unattributed_below_heap_delta_bytes")!=0:
        raise SealError("P1 native 3488-byte RAM accounting not proven")
    if native.get("binary_reproducible") is not True or native.get("elf_reproducible") is not True:
        raise SealError("P1 genuine duplicate BIN/ELF reproduction missing")
    if native.get("closed_ti_routing_body_tests")!="BLOCKED_SOURCE_UNAVAILABLE":
        raise SealError("unjustified TI closed-source routing tests success")
    if len(proofs)!=3:
        raise SealError("expected three independently rederived ELF receipts")
    for i,p in enumerate(proofs):
        if p.get("status")!=ELF_STATUS or p.get("source_sha")!=source_sha or str(p.get("run_id"))!=run_id:
            raise SealError("stale or missing P0/P1 genuine re-extraction "+str(i))
        if p.get("runtime_heap_high_water_measured") is not False or p.get("B2_SOURCE_READY") is not False:
            raise SealError("re-extraction claims runtime or source readiness")
        expected=native["elf_sha256"]["P0" if i==0 else "P1"]
        if p.get("elf_sha256")!=expected:
            raise SealError("P0/P1 raw ELF digest mismatch at "+str(i))
        if set(p.get("linked_tables_verified",[]))!={
            "source_routes","neighbors","nwk_routes","children","route_requests","relay_path"
        }:
            raise SealError("not all six genuine ELF table identities checked")
    if p3.get("status")!=P3_STATUS or p3.get("reason")!="TI_CLANG_CCS_ERROR_10099_SRAM_EXHAUSTION":
        raise SealError("no genuine TI CCS linker memory negative")
    if p3.get("linker_exit_status")==0 or not isinstance(p3.get("linker_exit_status"),int):
        raise SealError("P3 unexpectedly linked")
    if p3.get("test_only_bss_bytes")!=0x24000 or p3.get("sram_bytes")!=0x24000:
        raise SealError("not the 144KiB RAM overbudget profile")
    if p3.get("usable_firmware_produced") is not False or p3.get("physical_verified") is not False:
        raise SealError("P3 falsely claims usable firmware")
    if p3.get("TI_SDK_PIN")!=native.get("sdk_sha"):
        raise SealError("native P1 and P3 are from different TI SDK pins")
    linked=native.get("linked_sram_partitions",{})
    for name in ("P0","P1a","P1b"):
        part=linked.get(name)
        if not isinstance(part,dict) or sum(part.get(k,0) for k in (
            "below_heap_linker_reserved_span_bytes",
            "heap_linker_address_span_bytes",
            "above_heap_linker_reserved_span_bytes"))!=0x24000:
            raise SealError("disjoint linker SRAM partition missing for "+name)
    return {
        "schema":"r4-b2-capacity-only-hosted-seal-v1",
        "status":"B2_CAPACITY_ONLY_NATIVELY_VERIFIED",
        "source_sha":source_sha,"native_run_id":run_id,
        "TI_SDK_PIN":native["sdk_sha"],
        "P0_and_twin_P1_actual_ELF_rederived":True,
        "P1_ELF_and_BIN_bit_reproducible":True,
        "P1_sram_static_delta_bytes":3488,
        "P1_unattributed_sram_delta_bytes":0,
        "P3_actual_TICLANG_SRAM_overbudget_rejected":True,
        "p0_elf_sha256":native["elf_sha256"]["P0"],
        "p1_elf_sha256":native["elf_sha256"]["P1"],
        "p0_bin_sha256":native["binary_sha256"]["P0"],
        "p1_bin_sha256":native["binary_sha256"]["P1"],
        "C_IRQ_stack_linker_only":True,
        "runtime_heap_high_water_measured":False,
        "MTO_cache_runtime_enabled":None,
        "T05_T28_actual_TI_routing_C":False,
        "P2_queue_latency_and_rediscovery_repair":False,
        "B1_B2_combined_native_security_verified":False,
        "independent_review_attestations":False,
        "physical_verified":False,
        "B2_SOURCE_READY":False,
        "B1_B2_INTEGRATED_READY":False,
        "flash_or_release_authorized":False,
        "github_PR_merge_authorized":False,
        "blocking_dependency":"TI_PUBLIC_SDK_8_33_CLOSED_ROUTE_CORE_ISSUE_101",
        "qualification_scope":"GITHUB_HOSTED_CC1352P7_STATIC_CAPACITY_ONLY_NOT_NETWORK_RELIABILITY",
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--comparison",required=True,type=Path)
    ap.add_argument("--p0",required=True,type=Path)
    ap.add_argument("--p1a",required=True,type=Path)
    ap.add_argument("--p1b",required=True,type=Path)
    ap.add_argument("--p3",required=True,type=Path)
    ap.add_argument("--p3-output",required=True,type=Path)
    ap.add_argument("--source-sha",required=True)
    ap.add_argument("--run-id",required=True)
    ap.add_argument("--out",required=True,type=Path)
    a=ap.parse_args()
    # Negative P3 must not be treated as a releasable image.
    if a.p3_output.is_symlink() or not a.p3_output.is_dir():
        ap.exit(2,"B2-SEAL-BLOCKED: missing P3 artifact directory\n")
    for extension in (".bin",".hex",".out",".elf"):
        if list(a.p3_output.glob("*"+extension)):
            ap.exit(2,"B2-SEAL-BLOCKED: accidental P3 firmware artifact\n")
    try:
        receipt=seal(read_json(a.comparison),
                     [read_json(a.p0),read_json(a.p1a),read_json(a.p1b)],
                     read_json(a.p3),a.source_sha,a.run_id)
    except (SealError,KeyError,TypeError,ValueError) as exc:
        ap.exit(2,"B2-SEAL-BLOCKED: "+str(exc)+"\n")
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,sort_keys=True))
if __name__=="__main__":
    main()
