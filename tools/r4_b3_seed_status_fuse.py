#!/usr/bin/env python3
"""Fuse checked B3 seed-derived transport-key ABI with B1 sticky security HOLD.

Requires disposable TI 8.33 SDK after genuine B1+B3, B3 NVOCMP source fixes.
Uses B3's independently native-verified function/prototype/caller as semantic
donor; refuses changed B1 source shapes. Never reads actual keys/hardware.
"""
import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

TI="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
B3_SHA="b481e0beabf1966900644f69d7f5d024708ebf73"
SEC="source/ti/zstack/stack/zdo/zd_sec_mgr.c"
HDR="source/ti/zstack/stack/zdo/zd_sec_mgr.h"
SIGN_VOID="void ZDSecMgrGenerateKeyFromSeed(uint8_t *extAddr, uint8_t shift, uint8_t *key)"
SIGN_STATUS="ZStatus_t ZDSecMgrGenerateKeyFromSeed(uint8_t *extAddr, uint8_t shift, uint8_t *key)"
CALL="      ZDSecMgrGenerateKeyFromSeed(TCLKDevEntry.extAddr,TCLKDevEntry.SeedShift,req.key);"
DENIED="""      if (ZDSecMgrGenerateKeyFromSeed(TCLKDevEntry.extAddr,
                                      TCLKDevEntry.SeedShift, req.key) != ZSuccess)
      {
        memset(req.key, 0, SEC_KEY_LEN);
        b1_security_runtime_hold_latch();
        return; // do not call APSME_TransportKeyReq with missing seed
      }"""

def extract(text,signature):
    anchor=signature+"\n{"
    if text.count(anchor)!=1: raise ValueError("NOT_UNIQUE_C_FUNC "+signature)
    first=text.index(anchor);i=first+len(signature)+1;level=0
    for j in range(i,len(text)):
        if text[j]=="{":level+=1
        elif text[j]=="}":
            level-=1
            if level==0:return text[first:j+1]
    raise ValueError("UNTERMINATED_C_FUNC "+signature)

def one(s,a,b,label):
    if s.count(a)!=1:raise ValueError("SEED_C_SRC_CONFLICT "+label+" count="+str(s.count(a)))
    return s.replace(a,b,1)

def run(sdk,b3_script,b1_receipt,b3sha):
    sdk=sdk.resolve()
    if not str(sdk).startswith("/tmp/") or not (sdk/".git").exists() or b3sha!=B3_SHA:
        raise ValueError("IMMUTABLE_DISPOSABLE_SOURCE_ONLY")
    if subprocess.check_output(["git","-C",str(sdk),"rev-parse","HEAD"],text=True).strip()!=TI:
        raise ValueError("TI_SDK_PIN_DRIFT")
    if b3_script.is_symlink() or not b3_script.is_file():raise ValueError("B3_SCRIPT_MISSING")
    f=importlib.util.spec_from_file_location("b3_exact_seed_donor",b3_script)
    b3=importlib.util.module_from_spec(f);f.loader.exec_module(b3)
    original=subprocess.check_output(["git","-C",str(sdk),"show",TI+":"+SEC]).decode()
    donor=b3.security_changes(original)
    B3_function=extract(donor,SIGN_STATUS)
    if "osal_nv_read(ZCD_NV_TCLK_SEED, 0, SEC_KEY_LEN, tempKey) != SUCCESS" not in B3_function:
        raise ValueError("B3_CHECKED_SEED_SOURCE_ABSENT")
    if "return ZFailure;" not in B3_function:raise ValueError("B3_STATUS_FAILURE_ABSENT")
    old=(sdk/SEC).read_text()
    beforehash=hashlib.sha256(old.encode()).hexdigest()
    receipt=json.loads(b1_receipt.read_text())
    if (receipt.get("nvocmp_compaction_fusion_source")!="B1_HOLD_PLUS_B3_THREE_DONOR_GUARDS" or
        receipt.get("modified_security_sha256")!=beforehash):
        raise ValueError("B1_NVOCMP_AND_SECURITY_CHAIN_MISMATCH")
    prior=extract(old,SIGN_VOID)
    if ("b1_security_runtime_hold_latch();" not in prior or
        "osal_nv_read(ZCD_NV_TCLK_SEED" not in prior):
        raise ValueError("B1_CHECKED_SEED_READ_HOLD_MISSING")
    fused=one(B3_function,SIGN_STATUS+"\n{",
              SIGN_STATUS+"\n{\n  if (b1_nv_runtime_hold_active()) return ZFailure;",
              "KEEP_B1_HOLD_ON_ENTRY")
    fused=one(fused,
              "    memset(tempKey, 0, sizeof(tempKey));\n    return ZFailure;",
              "    memset(tempKey, 0, sizeof(tempKey));\n"
              "    b1_security_runtime_hold_latch();\n    return ZFailure;",
              "READ_FAILURE_LATCH")
    new=one(old,prior,fused,"REPLACE_B1_VOID_WITH_CHECKED_B3")
    new=one(new,SIGN_VOID+";",SIGN_STATUS+";","LOCAL_FORWARD_DECLARATION")
    new=one(new,CALL,DENIED,"TC_TRANSPORT_FAILSTOP_CALLER")
    h=(sdk/HDR).read_text()
    hnew=one(h,"extern "+SIGN_VOID+";","extern "+SIGN_STATUS+";","SDK_HEADER_STATUS_ABI")
    if ("ZDSecMgrGenerateKeyFromSeed(" not in new or
        new.count("ZDSecMgrGenerateKeyFromSeed(")!=3):
        raise ValueError("UNREVIEWED_KEY_FROM_SEED_CALLSITE_COUNT")
    if "APSME_TransportKeyReq" not in new:
        raise ValueError("TC_TRANSPORT_PUBLICATION_GATE_ABSENT")
    (sdk/SEC).write_text(new,encoding="utf-8",newline="")
    (sdk/HDR).write_text(hnew,encoding="utf-8",newline="")
    after=hashlib.sha256(new.encode()).hexdigest()
    receipt["modified_security_sha256"]=after
    receipt["seed_transport_return_status_integration"]="B3_STATUS_AND_B1_HOLD"
    b1_receipt.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    return {
        "schema":"r4-b1-b3-seed-transport-status-fusion-v1",
        "b3_source_sha":B3_SHA,"ti_sdk_sha":TI,
        "security_c_before_sha256":beforehash,"security_c_after_sha256":after,
        "security_header_after_sha256":hashlib.sha256(hnew.encode()).hexdigest(),
        "checked_return_status":True,"caller_prevents_TC_key_transport_on_failure":True,
        "b1_sticky_HOLD_on_missing_seed":True,
        "all_other_TI_callers_reviewed":False,
        "source_ready":False,"flash_authorized":False
    }

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--b3-script",type=Path,required=True)
    p.add_argument("--b1-overlay-receipt",type=Path,required=True)
    p.add_argument("--b3-git-sha",required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    out=run(a.sdk,a.b3_script,a.b1_overlay_receipt,a.b3_git_sha)
    a.receipt.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(out,sort_keys=True))
