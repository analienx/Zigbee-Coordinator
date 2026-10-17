#!/usr/bin/env python3
"""Semantic B1+B3 NVOCMP compaction fusion; exact B3 AST patch snippets.

B1 remains owner of NVOCMP preflight/read/erase and sticky NV HOLD.
Adds THREE independent B3-proven compaction ordering/incomplete-write fixes
without replaying B3's conflicting pristine-only NVOCMP replacement.
Disposable GitHub TI checkout only. Never a flash or migration tool.
"""
import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path

TI_SHA="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
B3_SHA="b481e0beabf1966900644f69d7f5d024708ebf73"
NVO="source/ti/common/nv/nvocmp.c"
SELECTORS={
    "COMPACTION_ITEM_COPY_WRITE":("NVOCMP_itemBuffer, iLen);","// Advance to next location"),
    "COMPACTION_DATA_BEFORE_HEADER":("NVOCMP_write(dstPg, dstOff, pBuf, dLen);","// Write header"),
    "NV2_DESTINATION_COMMIT_BEFORE_SOURCE_ERASE":("// clean XSRC pages","NVOCMP_PGCDONE"),
}

def pair_list(script):
    tree=ast.parse(script)
    out=[]
    for node in tree.body:
        if isinstance(node,ast.FunctionDef) and node.name=="nvocmp_changes":
            for statement in node.body:
                if not isinstance(statement,ast.Assign):continue
                call=statement.value
                if (not isinstance(call,ast.Call) or
                    not isinstance(call.func,ast.Name) or call.func.id!="one" or
                    len(call.args)!=3):
                    continue
                try:
                    before=ast.literal_eval(call.args[1])
                    after=ast.literal_eval(call.args[2])
                except (ValueError,TypeError):
                    continue
                if isinstance(before,str) and isinstance(after,str):
                    out.append((before,after))
    return out

def apply(sdk,b3script,b1receipt,b3_sha):
    sdk=sdk.resolve()
    if not str(sdk).startswith("/tmp/") or not (sdk/".git").exists():
        raise ValueError("NVOCMP_FUSION_DISPOSABLE_TI_ONLY")
    if b3_sha!=B3_SHA or b3script.is_symlink() or not b3script.is_file():
        raise ValueError("B3_IMMUTABLE_SHA_REQUIRED")
    if subprocess.check_output(["git","-C",str(sdk),"rev-parse","HEAD"],text=True).strip()!=TI_SHA:
        raise ValueError("TI_PIN_MISMATCH")
    b1=json.loads(b1receipt.read_text())
    if b1.get("post_b1_security_fusion")!="B1_PLUS_SELECTED_B3_IMMUTABLE_INPUTS":
        raise ValueError("REQUIRE_B1_B3_PREVIOUS_FUSION")
    path=sdk/NVO
    text=path.read_text()
    beforehash=hashlib.sha256(text.encode()).hexdigest()
    if beforehash!=b1.get("modified_nv_sha256"):
        raise ValueError("B1_NVO_HASH_CHAIN_MISMATCH")
    if ("b1_nv_runtime_hold_latch()" not in text or
        "#include \"b1_management.c\"" not in text):
        raise ValueError("B1_NVOCMP_STICKY_HOLD_ABSENT")
    items=pair_list(b3script.read_text())
    output={}
    for label,markers in SELECTORS.items():
        matches=[(old,new) for old,new in items if all(marker in old for marker in markers)]
        if len(matches)!=1:
            raise ValueError("PINNED_B3_COMPATION_AST_PAIR_MISSING_OR_AMBIGUOUS "+label)
        old,new=matches[0]
        if text.count(old)!=1:
            raise ValueError("B1_AND_B3_COMPACTION_CONFLICT_REQUIRES_MANUAL_REVIEW "+
                             label+" count="+str(text.count(old)))
        if label in ("COMPACTION_ITEM_COPY_WRITE","COMPACTION_DATA_BEFORE_HEADER"):
            # B3 already aborts compaction on failed NVS write. Include the
            # sticky B1 NV-domain HOLD in the same previously reviewed branch.
            needle="NVOCMP_failF = NVINTF_FAILURE;\n                return;"
            hits=new.count(needle)
            if not hits: raise ValueError("B3_FAILURE_GUARD_REMOVED "+label)
            new=new.replace(needle,
                "NVOCMP_failF = NVINTF_FAILURE;\n"
                "                b1_nv_runtime_hold_latch();\n"
                "                return;")
        elif label=="NV2_DESTINATION_COMMIT_BEFORE_SOURCE_ERASE":
            if "#if(NVOCMP_NVPAGES > NVOCMP_NVONEP)" not in new:
                raise ValueError("DESTINATION_COMMIT_SOURCE_ORDER_MISSING")
            new=new.replace(
                "    NVOCMP_failF = NVINTF_FAILURE;\n    return(0);",
                "    NVOCMP_failF = NVINTF_FAILURE;\n"
                "    b1_nv_runtime_hold_latch();\n    return(0);")
        text=text.replace(old,new,1)
        output[label]={"donor_fragment_sha256":hashlib.sha256(old.encode()).hexdigest(),
                       "fused_fragment_sha256":hashlib.sha256(new.encode()).hexdigest(),
                       "B3_source_ast_reconciled_with_B1":True}
    path.write_text(text,encoding="utf-8",newline="")
    afterhash=hashlib.sha256(text.encode()).hexdigest()
    b1["modified_nv_sha256"]=afterhash
    b1["nvocmp_compaction_fusion_source"]="B1_HOLD_PLUS_B3_THREE_DONOR_GUARDS"
    b1receipt.write_text(json.dumps(b1,indent=2,sort_keys=True)+"\n")
    return {"schema":"r4-b1-b3-nvocmp-compaction-fusion-v1",
            "source_sdk_sha":TI_SHA,"b3_sha":B3_SHA,
            "nvocmp_modified_before_sha256":beforehash,
            "nvocmp_modified_after_sha256":afterhash,
            "reconciled_guards":output,
            "NVOCMP_source_only":True,
            "B3_other_compaction_fault_paths_may_exist":True,
            "physical_powercut_verified":False,
            "source_ready":False,"flash_authorized":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--b3-script",type=Path,required=True)
    p.add_argument("--b1-overlay-receipt",type=Path,required=True)
    p.add_argument("--b3-git-sha",required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    x=apply(a.sdk,a.b3_script,a.b1_overlay_receipt,a.b3_git_sha)
    a.receipt.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
    print(json.dumps(x,sort_keys=True))

if __name__=="__main__":main()
