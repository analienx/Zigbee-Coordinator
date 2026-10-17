#!/usr/bin/env python3
"""B1-authoritative + selected B3-security fusion on disposable pinned TI SDK.

B1 MUST already own the fail-closed RF admission/NVOCMP, NWK restore,
APS/TCLK checkpoints, ZDO startup, and NPI HOLD. B3 contributes its independently
tested RNG failure propagation and a monotonic NWK SAVE checkpoint; it does not
reapply conflicting patches or claim the unmerged B3 NVOCMP compaction profile.

Input B3 script is fetched at immutable GitHub commit, checked by SHA before
using. Only a disposable TI checkout under /tmp is allowed. No hardware I/O.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path

TI_SHA="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
B3_SHA="b481e0beabf1966900644f69d7f5d024708ebf73"
B3_SOURCE_PATH="firmware/slzb-06p7u/r4/b3/tools/b3_source_overlay.py"
ZD="source/ti/zstack/stack/zdo/zd_app.c"
SEC="source/ti/zstack/stack/zdo/zd_sec_mgr.c"
HDR="source/ti/zstack/stack/zdo/zd_sec_mgr.h"
GLO="source/ti/zstack/stack/sys/zglobals.c"
TASK="source/ti/zstack/stack/api/zstacktask.c"
OWNERSHIP={
    "source/ti/common/nv/nvocmp.c":"B1_ONLY_NOT_YET_B3_COMPACTION",
    "source/ti/zstack/osal/osal_nv.c":"B1_ONLY",
    ZD:"B1_RESTORE_PLUS_B3_MONOTONIC_SAVE_AND_TRNG",
    SEC:"B1_HOLD_APS_TCLK_PLUS_B3_TRNG_ONLY",
    GLO:"B1_RESTORE_VALIDATION_PLUS_B3_TRNG",
    HDR:"B3_RNG_SIGNATURE_ONLY",
    TASK:"B3_ENTROPY_ERROR_CHECK",
}

def git(root,*args):
    return subprocess.check_output(["git","-C",str(root),*args],stderr=subprocess.DEVNULL)

def git_blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def replace_one(text,old,new,label):
    if text.count(old)!=1:
        raise ValueError("FUSION_SOURCE_DRIFT "+label+" count="+str(text.count(old)))
    return text.replace(old,new,1)

def function(text,signature):
    anchor=signature+"\n{"
    if text.count(anchor)!=1:
        raise ValueError("FUSION_C_FUNCTION_NOT_UNIQUE "+signature)
    start=text.index(anchor)
    i=start+len(signature)+1
    depth=0
    for j in range(i,len(text)):
        if text[j]=="{": depth+=1
        if text[j]=="}":
            depth-=1
            if depth==0:return text[start:j+1]
    raise ValueError("FUSION_UNBALANCED "+signature)

def b3_save_from_ast(source):
    tree=ast.parse(source)
    for node in tree.body:
        if isinstance(node,ast.FunctionDef) and node.name=="nwk_checkpoint_changes":
            for child in node.body:
                if isinstance(child,ast.Assign) and len(child.targets)==1 and isinstance(child.targets[0],ast.Name) and child.targets[0].id=="save":
                    if isinstance(child.value,ast.Constant) and isinstance(child.value.value,str):
                        return child.value.value
    raise ValueError("B3_MONOTONIC_SAVE_AST_MISSING")

def run(sdk,b3script,b3_git_sha,b1_receipt):
    sdk=sdk.resolve()
    if not str(sdk).startswith("/tmp/") or not (sdk/".git").exists():
        raise ValueError("ONLY_DISPOSABLE_TMP_SDK_CHECKOUT")
    if git(sdk,"rev-parse","HEAD").decode().strip()!=TI_SHA:
        raise ValueError("TI_SDK_PIN_DRIFT")
    if b3_git_sha!=B3_SHA or b3script.is_symlink() or not b3script.is_file():
        raise ValueError("B3_EXACT_COMMIT_REQUIRED")
    script=b3script.read_text(encoding="utf-8")
    if ("def nwk_checkpoint_changes(" not in script or
        "if (nwkSecMaterialDesc.FrameCounter > keyItems.frameCounter)" not in script or
        script.count("if (nwkSecMaterialDesc.FrameCounter > keyItems.frameCounter)")!=2):
        raise ValueError("B3_ROLLBACK_GUARDS_MISSING")
    b3_spec=importlib.util.spec_from_file_location("r4_immutable_b3",b3script)
    b3=importlib.util.module_from_spec(b3_spec);b3_spec.loader.exec_module(b3)
    raw={}
    vendor={}
    for name in (ZD,SEC,HDR,GLO,TASK):
        path=sdk/name
        if path.is_symlink() or not path.is_file():raise ValueError("UNSAFE_SOURCE "+name)
        vendor_raw=git(sdk,"show",TI_SHA+":"+name)
        if git_blob(vendor_raw)!=b3.PINNED_BLOBS[name]:
            raise ValueError("B3_DONOR_PIN_DRIFT "+name)
        vendor[name]=vendor_raw.decode("utf-8")
        raw[name]=path.read_text(encoding="utf-8")
    if raw[HDR]!=vendor[HDR] or raw[TASK]!=vendor[TASK]:
        raise ValueError("B1_MUST_NOT_HAVE_CHANGED_B3_ONLY_FILES")

    # Require the exact B1 ownership and RF denial sources. Merely having a
    # B1 marker in an unrelated comment can never substitute these bodies.
    if ("b1_management_note_zdo_state" not in raw[ZD] or
        "b1_nv_runtime_hold_active() || FrameCounterUpdated" not in raw[ZD] or
        "b1_sec_write_checked(" not in raw[SEC] or
        "b1_sec_validate_restored" not in raw[GLO] or
        "b1_security_runtime_hold_latch()" not in raw[SEC]):
        raise ValueError("B1_SECURITY_OWNER_NOT_PRESENT")

    # B3 NWK SAVE is the production TI 8.33 source-extracted, independently
    # native-tested implementation from immutable #123. Add sticky B1 HOLD
    # for a failed checkpoint or stale-high-water rollback; the unified
    # admission gate is responsible for rejecting NEW ZMac RF submissions.
    save=b3_save_from_ast(script)
    if save.count("goto b3_checkpoint_done;")<5:
        raise ValueError("B3_CHECKPOINT_DENIAL_PATH_COUNT_DRIFT")
    save=replace_one(save,"void ZDApp_SaveNwkKey( void )\n{",
                     "void ZDApp_SaveNwkKey( void )\n{\n"
                     "  if (b1_nv_runtime_hold_active()) return;",
                     "B3_SAVE_ON_HOLD")
    save=save.replace("goto b3_checkpoint_done;",
                      "do { b1_security_runtime_hold_latch(); "
                      "goto b3_checkpoint_done; } while (0);")
    # The B3 standalone checkpoint deliberately leaves pendingFlag set if
    # NWKKEY write/readback fails. In the composite, B1 must ALSO latch the
    # sticky security HOLD or secured RF could continue with torn key/counter
    # materials even though pending changes remain. Branch only on the
    # immutable B3 exact source shape; missing guard is a fatal preflight.
    save=replace_one(save,
        "    nwkFrameCounterChanges = 0;\n  }\n\n"
        "b3_checkpoint_done:",
        "    nwkFrameCounterChanges = 0;\n  }\n"
        "  else\n  {\n"
        "    b1_security_runtime_hold_latch();\n"
        "    /* NWKKEY failed, was unreadable, or returned corrupt bytes. */\n"
        "  }\n\n"
        "b3_checkpoint_done:",
        "B3_NWKKEY_COMPOSITE_STICKY_HOLD")
    source=raw[ZD]
    baseline_save=function(source,"void ZDApp_SaveNwkKey( void )")
    if baseline_save!=function(vendor[ZD],"void ZDApp_SaveNwkKey( void )"):
        raise ValueError("B1_OR_OTHER_PHASE_OWNS_NWK_SAVE")
    source=replace_one(source,baseline_save,save,"ZDAPP_B3_SAVE_CHECKPOINT")
    source=b3.entropy_zdapp_changes(source)
    raw[ZD]=source

    # B1 retains its checked void-ABI seed-derivation, APS/TCLK persistence,
    # seed-read failure latch and existing-network denial. B3 cannot blindly
    # replace this entire function with its standalone status API.
    vendor_sec=b3.security_changes(vendor[SEC])
    vendor_rng=function(vendor[SEC],"void ZDSecMgrGenerateRndKey(uint8_t* pKey)")
    patched_rng=function(vendor_sec,"uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey)")
    baseline_rng=function(raw[SEC],"void ZDSecMgrGenerateRndKey(uint8_t* pKey)")
    if baseline_rng!=vendor_rng:
        raise ValueError("B1_ALREADY_OWNS_RNG_CANNOT_OVERWRITE")
    sec=replace_one(raw[SEC],baseline_rng,patched_rng,"CHECKED_TRNG")
    sec=replace_one(sec,"  ZDSecMgrGenerateRndKey(SeedKey);",
        "  if (ZDSecMgrGenerateRndKey(SeedKey) != ZSuccess)\n"
        "  {\n"
        "    memset(SeedKey, 0, SEC_KEY_LEN);\n"
        "    b1_security_runtime_hold_latch();\n"
        "    return; /* refuse seed NV mutation on TRNG failure */\n"
        "  }","TC_SEED_ENTROPY_DENY")
    raw[SEC]=sec
    raw[HDR]=replace_one(raw[HDR],
        "extern void ZDSecMgrGenerateRndKey(uint8_t* pKey);",
        "extern uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey);",
        "B3_RNG_STATUS_HEADER")
    raw[GLO]=b3.entropy_zglobals_changes(raw[GLO])
    raw[TASK]=b3.entropy_zstacktask_changes(raw[TASK])

    # Full consistency: original void RNG declaration and unchecked calls
    # anywhere in our changed source are an ABI/security bypass.
    for name in (ZD,SEC,HDR,GLO,TASK):
        if "void ZDSecMgrGenerateRndKey(" in raw[name]:
            raise ValueError("UNRECONCILED_RNG_VOID_DECL "+name)
    changed={}
    for name,body in raw.items():
        before=(sdk/name).read_text(encoding="utf-8")
        if before!=body:
            changed[name]={"before_sha256":hashlib.sha256(before.encode()).hexdigest(),
                           "after_sha256":hashlib.sha256(body.encode()).hexdigest()}
    if set(changed)!={ZD,SEC,HDR,GLO,TASK}:
        raise ValueError("FUSION_EXPECTED_FIVE_MODIFIED_FILES "+str(sorted(changed)))
    # Do not disguise a changed B1 body as its old source SHA: bind the
    # final SDK hashes to B1's existing native manifest ONLY after comparing
    # each BEFORE hash to the exact B1 receipt. Separate fusion receipt still
    # discloses which phase owns each function and what remains unmerged.
    original_b1=json.loads(b1_receipt.read_text(encoding="utf-8"))
    binding_keys={
        ZD:"modified_zdapp_sha256",
        SEC:"modified_security_sha256",
        GLO:"modified_zglobals_sha256",
    }
    if original_b1.get("schema")!="r4-b1-admission-overlay-v2":
        raise ValueError("B1_RECEIPT_SCHEMA_DRIFT")
    for name,key in binding_keys.items():
        if original_b1.get(key)!=changed[name]["before_sha256"]:
            raise ValueError("B1_RECEIPT_PREIMAGE_MISMATCH "+name)
    for name in changed:
        (sdk/name).write_text(raw[name],encoding="utf-8",newline="")
    for name,key in binding_keys.items():
        original_b1[key]=changed[name]["after_sha256"]
    original_b1["post_b1_security_fusion"]="B1_PLUS_SELECTED_B3_IMMUTABLE_INPUTS"
    original_b1["b3_source_commit"]=B3_SHA
    original_b1["unmerged_security_paths"]=[
        "B3 NVOCMP compaction reconciliation",
        "B3 checked seed-derived key status ABI",
        "B2/B4 cross-phase composition",
    ]
    b1_receipt.write_text(json.dumps(original_b1,indent=2,sort_keys=True)+"\n")
    return {
        "schema":"r4-b1-b3-partial-security-fusion-v1",
        "ti_sdk_sha":TI_SHA,"b3_input_sha":B3_SHA,
        "ownership":OWNERSHIP,"changed":changed,
        "b1_nwk_restore_owns_floor":True,
        "b3_nwk_save_monotonic_and_B1_HOLD":True,
        "B3_entropy_error_checks_added":True,
        "B3_NVOCMP_compaction_semantic_fusion_complete":False,
        "B3_checked_seed_derivation_signature_adopted":False,
        "B2_routing_merged":False,"B4_diagnostics_merged":False,
        "native_compilation":"REQUIRED_BEFORE_ACCEPTANCE",
        "source_ready":False,"flash_authorized":False,
        "physical_verified":False,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--b3-script",type=Path,required=True)
    p.add_argument("--b3-git-sha",required=True)
    p.add_argument("--b1-overlay-receipt",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    receipt=run(a.sdk,a.b3_script,a.b3_git_sha,a.b1_overlay_receipt)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,sort_keys=True))

if __name__=="__main__":
    main()
