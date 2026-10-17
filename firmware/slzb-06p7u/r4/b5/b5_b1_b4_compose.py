"""Exact-pinned source-only B1 management/B4 coexistence check. No hardware."""
import argparse, hashlib, json, sys, subprocess
from pathlib import Path
B1="a514c194ea0d94b5d38b28c7b07ca5caba9aeffd"
TI="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
MT="source/ti/zstack/mt/mt.c"
SYS="source/ti/zstack/mt/mt_sys.c"
NPI="source/ti/zstack/npi/npi_task.c"
UART="source/ti/zstack/npi/npi_tl_uart.c"
def head(p):
    return subprocess.check_output(["git","-C",str(p),"rev-parse","HEAD"],text=True).strip()
def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()
def require(ok,reason):
    if not ok: raise ValueError("B5 BLOCKED: "+reason)
def main():
    ap=argparse.ArgumentParser()
    for name in ("sdk","b1","definition","receipt"): ap.add_argument("--"+name,required=True,type=Path)
    a=ap.parse_args()
    sdk=a.sdk.resolve(); b1=a.b1.resolve()
    require(str(sdk).startswith("/tmp/") and str(b1).startswith("/tmp/"),"disposable source only")
    require(head(sdk)==TI and head(b1)==B1,"immutable upstream refs")
    sys.path.insert(0,str(b1/"firmware/slzb-06p7u/r4/b1/tools"))
    import patch_management as b1management
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"b4"))
    import b4_native_patch,b4_v4_native_patch
    definition=a.definition.read_text()
    # B1's own complete pristine pin audit and SYS dictionary check first.
    pristine,proof=b1management.prepare(sdk,definition)
    require(set(pristine)=={MT,NPI,UART},"B1 touch set")
    require(proof["collision"]["command"]=="MT SYS 0xF1","B1 opcode")
    v3=b4_native_patch.apply(sdk)
    v4=b4_v4_native_patch.apply(sdk)
    require(v3["f0_opcode"]=="0xF0" and v4["command"]=="SYS_F2","B4 owners")
    before={p:(sdk/p).read_text() for p in (MT,NPI,UART,SYS)}
    # Actual B1 MT/NPI/UART transforms on B4-patched source, no guessed splice.
    patches={
        MT:b1management.patch_mt(before[MT]),
        NPI:b1management.patch_npi(before[NPI]),
        UART:b1management.patch_uart(before[UART]),
    }
    require(all(patches[p]!=before[p] for p in patches),"B1 patch inactive")
    require(patches[MT].index("b1_management_mt_filter(")<
            patches[MT].index("  /* check length */"),"HOLD bypass")
    require("B4_V4BootInitAttempted" in patches[NPI] and
            "B4_V4BootInitialize();" in patches[NPI] and
            "B4_NpiSrspEnqueued" in patches[NPI],"B4 NPI provenance lost")
    require("B4_NpiUartTxFinishedCallback" in patches[UART] and
            "b1_management_transport_failed" in patches[UART],"UART owners lost")
    require(before[SYS].count("case 0xF0:")==1 and
            before[SYS].count("case 0xF2:")==1 and
            "case 0xF1:" not in before[SYS],"SYS collision")
    cs=(b1/"firmware/slzb-06p7u/r4/b1/b1_management.c").read_text()
    hs=(b1/"firmware/slzb-06p7u/r4/b1/b1_management.h").read_text()
    require("#define B1_STATUS_COMMAND 0xF1u" in hs and
            "if (!held) return B1_MT_CONTINUE;" in cs and
            "return B1_MT_REJECT;" in cs and
            "frame[2] == B1_STATUS_COMMAND" in cs and "0xF2" not in cs,
            "F2 not rejected via default HOLD")
    for path,body in patches.items(): (sdk/path).write_text(body,encoding="utf-8",newline="")
    require((sdk/SYS).read_text()==before[SYS],"F2 altered")
    receipt={"schema":"b5-b1-management-b4-sources-v1",
      "stage":"SOURCE_COMPOSE_ONLY_NOT_LINKED","b1_sha":B1,"ti_sha":TI,
      "b4_sha":head(Path(__file__).resolve().parents[4]),
      "scope":"B1_MANAGEMENT_ONLY_NOT_FULL_NV_SECURITY","b1_hold_allows_f2":False,
      "commands":{"B4_F0":240,"B1_F1":241,"B4_F2":242},
      "flash_authorized":False,"native_linked":False,"physical_verified":False,
      "files":{p:{"before":sha(before[p]),"after":sha(patches[p])} for p in patches},
      "mt_sys_sha256":sha(before[SYS])}
    a.receipt.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,sort_keys=True))
if __name__=="__main__": main()
