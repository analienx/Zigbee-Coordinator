#!/usr/bin/env python3
"""Extract only actual B1-patched TI 8.33 entropy implementation, refuse stubs."""
import argparse
from pathlib import Path
import sys
root=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(root/"firmware/slzb-06p7u/r4/b1/tools"))
from patch_zdapp import extract_function
from b1_b3_entropy import RND
CALLS = {
    "zdo/zd_sec_mgr.c": "if (ZDSecMgrGenerateRndKey(SeedKey) != ZSuccess)",
    "zdo/zd_app.c": "if (ZDSecMgrGenerateRndKey(tmpKey) != ZSuccess)",
    "sys/zglobals.c": "if (ZDSecMgrGenerateRndKey(zgPreConfigKey) != ZSuccess)",
    "api/zstacktask.c": "if (ZDSecMgrGenerateRndKey(&nwkKey.key[0]) != ZSuccess)",
}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--stack",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    s=(a.stack/"zdo/zd_sec_mgr.c").read_text()
    actual=extract_function(s,"uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey)")
    if actual!=RND: raise SystemExit("B1_B3_ENTROPY_UNEXPECTED_REAL_FUNCTION")
    for file,call in CALLS.items():
        if (a.stack/file).read_text().count(call)!=1:
            raise SystemExit("B1_B3_ENTROPY_CALLER_NOT_GUARDED "+file)
    if "extern uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey);" not in (
            a.stack/"zdo/zd_sec_mgr.h").read_text():
        raise SystemExit("B1_B3_ENTROPY_HEADER_NOT_GUARDED")
    a.out.write_text('#include "entropy_stub.h"\n'+actual+'\n')
    print("B1_B3_PINNED_TI_FOUR_ENTROPY_PUBLISHERS_AND_HOLD_GUARDED")
if __name__=="__main__":main()
