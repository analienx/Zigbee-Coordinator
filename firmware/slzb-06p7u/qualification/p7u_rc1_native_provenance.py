#!/usr/bin/env python3
"""Join native CCS provenance to RC1 image with fail-closed exact hashes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import p7u_strict_sector_writer as core


def need(ok: bool, code: str) -> None:
    if not ok: raise ValueError(code)


def qualify(evidence: Path, native_hex: bytes, profile: str, commit: str) -> dict:
    expected_sha=commit.lower()
    need((evidence/"candidate-sha.txt").read_text().strip()==expected_sha,
         "RC1_NATIVE_BUILD_COMMIT_MISMATCH")
    raw=core.gate.parse_hex(native_hex)
    audit=core.gate.candidate_audit(raw,profile)
    app=core.gate.application_only_hex(raw,profile)
    audit["derived_app_only_hex_sha256"]=core.sha(app)
    audit["derived_app_only_never_flash_with_bank_erase"]=True
    audit["qualification"]="SOURCE_HEX_BSL_GEOMETRY_PASS_NOT_FLASHABLE"
    plan=core.sector.plan(app,audit)

    native_audit=json.loads((evidence/"P7U-ROM-BSL-GATE.json").read_text())
    need(native_audit==audit,"RC1_NATIVE_CCFG_OR_HEX_GATE_DIFFERENT")
    native_plan=json.loads((evidence/"P7U-SECTOR-ONLY-PLAN-NO-EXECUTION.json").read_text())
    need(native_plan==plan,"RC1_NATIVE_SECTOR_PLAN_DIFFERENT")
    need((evidence/"P7U-APP-ONLY-SOURCE-NOT-FLASHABLE.hex").read_bytes()==app,
         "RC1_NATIVE_APP_IMAGE_DIFFERENT")
    f07=json.loads((evidence/"F07-INTEGRATION-EVIDENCE.json").read_text())
    need(f07.get("qualification")=="F07_COMBINED_G7_LINKED_SOURCE_ONLY_NOT_FLASHABLE"
         and f07.get("profile")==profile and f07.get("flash_authorized") is False,
         "RC1_NATIVE_F07_LINKAGE_UNQUALIFIED")
    call_edges={
        "ZDApp_NetworkStartEvt":"p7_f07_commit_nib_before_ready",
        "ZDOInitDeviceEx":"p7_f07_nv_restore_preflight",
        "ZDApp_RestoreNetworkState":"p7_f07_nwk_counter_escrow",
        "ZDApp_SaveNwkKey":"p7_f07_nwk_checkpoint",
    }
    need(f07.get("verified_call_edges")==call_edges,
         "RC1_NATIVE_F07_GUARD_EDGES_MISSING")
    src=f07.get("source",{})
    for key in ("nwk_counter_escrow_precedes_network_restore",
                "restoration_guard_precedes_restore_and_touchlink",
                "no_implicit_network_clear_on_failed_restore",
                "coordinator_ready_preceded_by_nib_commit",
                "raw_nv_success_only",
                "periodic_nwk_checkpoint_guarded"):
        need(src.get(key) is True,"RC1_NATIVE_F07_GUARD_LOST")
    need(f07.get("board_io_qualified") is False
         and f07.get("nv_power_loss_qualified") is False
         and f07.get("frame_counters_and_security_keys_qualified") is False,
         "RC1_UNSUPPORTED_HARDWARE_QUALIFICATION_CLAIM")
    expected_full_hex_sha=core.sha(native_hex)
    declared_sha=[]
    for line in (evidence/"artifact-sha256.txt").read_text().splitlines():
        parts=line.split()
        if len(parts)==2 and parts[1]=="bundle-diag/DIAG-NOT-FLASHABLE.hex":
            declared_sha.append(parts[0])
    need(declared_sha==[expected_full_hex_sha],"RC1_ORIGINAL_BUILD_HEX_HASH_MISMATCH")
    return {
        "native_build_commit":expected_sha,
        "native_g7_f07_guards_verified":True,
        "ccfg_and_bsl_exact_native":True,
        "native_build_full_hex_sha256":expected_full_hex_sha,
        "native_f07_evidence_sha256":core.sha((evidence/"F07-INTEGRATION-EVIDENCE.json").read_bytes()),
        "native_app_hex_sha256":core.sha(app),
        "native_sector_plan_sha256":core.sha(core.canonical(plan)),
        "candidate_origin_exact_ccs_native":True,
        "native_was_physically_flushed":False,
        "hardware_qualification":False,
        "flash_authorized":False,
    }
