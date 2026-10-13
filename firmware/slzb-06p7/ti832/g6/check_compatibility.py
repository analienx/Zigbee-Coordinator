"""Fail closed on actual SYS command IDs; byte-wide grep is not a collision test."""
import argparse, json, re
from pathlib import Path
from g6_overlay import function

def check(sdk,herdsman):
    definition=(herdsman/"src/adapter/z-stack/znp/definition.ts").read_text()
    m=re.search(r'\[Subsystem\.SYS\]: \[(.*?)\n    \],',definition,re.S)
    if not m:raise ValueError("SYS_DEFINITION_MISSING")
    ids=[int(x,0) for x in re.findall(r'\bID:\s*(0x[\da-fA-F]+|\d+)\s*,',m.group(1))]
    if not ids or len(ids)!=len(set(ids)):raise ValueError("SYS_IDS_INVALID")
    if 240 in ids:raise ValueError("HERDSMAN_SYS_F0_COLLISION")
    sysc=(sdk/"source/ti/zstack/mt/mt_sys.c").read_text()
    defs={}
    for p in (sdk/"source/ti/zstack/mt").glob("*.h"):
        defs.update({k:int(v,0) for k,v in re.findall(r'#define\s+(MT_SYS_\w+)\s+\(?\s*(0x[\da-fA-F]+|\d+)\b',p.read_text())})
    body=function(sysc,"MT_SysCommandProcessing")
    cases=re.findall(r'\bcase\s+(\w+)\s*:',body)
    unknown=[c for c in cases if c not in defs]
    if unknown:raise ValueError("UNRESOLVED_SYS_CASES:"+str(unknown))
    if 240 in [defs[c] for c in cases]:raise ValueError("TI_SYS_F0_COLLISION")
    result={"sys_f0_collision":False,"herdsman_sys_ids":ids,"ti_sys_cases":{c:defs[c] for c in cases},
        "herdsman_builtin_g6_client":False,"client":"raw MT SREQ SYS/0xF0 [1,0]; stock named-command API has no definition",
        "broad_grep_matches":"status MAC_TRANSACTION_EXPIRED, nibble masks and 240-byte NV block sizes; different namespaces"}
    print(json.dumps(result,indent=2));return result

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--herdsman",type=Path,required=True)
    a=p.parse_args();check(a.sdk,a.herdsman)
