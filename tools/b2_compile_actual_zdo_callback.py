#!/usr/bin/env python3
"""Compile ACTUAL pinned TI zd_app.c callback body in hosted ASan/UBSan test.

Only RTG_MTORouteReq (not reachable as C in public SDK) is stubbed as the
API boundary. Reports real ZDO callback behavior, NOT closed NWK route behavior.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SDK_SHA="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
SRC="source/ti/zstack/stack/zdo/zd_app.c"
NAME="ZDO_ManytoOneFailureIndicationCB"

class HarnessError(ValueError):pass

def body(source):
    pattern=re.compile(r"\bvoid\s+"+NAME+r"\s*\(\s*(?:void\s*)?\)\s*\{")
    matches=list(pattern.finditer(source))
    if len(matches)!=1:
        raise HarnessError("expected exactly one pinned TI callback definition")
    m=matches[0]
    level=0
    for i in range(m.end()-1,len(source)):
        if source[i]=="{":
            level+=1
        elif source[i]=="}":
            level-=1
            if level==0:
                src=source[m.start():i+1]
                if src.count("RTG_MTORouteReq();")!=1:
                    raise HarnessError("call expression moved or changed")
                return src
    raise HarnessError("unbalanced TI callback source")

def prepare(sdk,out,mutation):
    if subprocess.check_output(["git","-C",str(sdk),"rev-parse","HEAD"],text=True).strip()!=SDK_SHA:
        raise HarnessError("unpinned SDK")
    file=sdk/SRC
    if not file.is_file() or file.is_symlink():
        raise HarnessError("missing genuine pinned TI C source")
    pristine=subprocess.check_output(["git","-C",str(sdk),"show","HEAD:"+SRC])
    if file.read_bytes()!=pristine:
        raise HarnessError("TI callback C source modified")
    source=pristine.decode("utf-8")
    callback=body(source)
    if mutation=="drop-mto-call":
        callback=callback.replace("RTG_MTORouteReq();","(void)0;")
    elif mutation!="none":
        raise HarnessError("unapproved source mutation")
    # Only a documented API boundary is stubbed. NO replacement logic for
    # the actual vendor function body inside zd_app.c.
    harness = '''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
static volatile uint32_t mto_requests;
void RTG_MTORouteReq(void) { ++mto_requests; }
'''+callback+'''
int main(void)
{
    mto_requests=0;
    '''+NAME+'''();
    assert(mto_requests==1); /* single failure => one MTO request */
    '''+NAME+'''();
    assert(mto_requests==2); /* duplicate indication => repeated request */
    for (unsigned int i=0;i<998;i++) {
        '''+NAME+'''();
    }
    assert(mto_requests==1000); /* 1000 indications => 1000 API invocations */
    return 0;
}
'''
    out.mkdir(parents=True,exist_ok=True)
    path=out/"ti_zdo_mto_host.c"
    path.write_text(harness,encoding="utf-8")
    record={"sdk_sha":SDK_SHA,"path":SRC,
            "source_sha256":hashlib.sha256(pristine).hexdigest(),
            "actual_ti_c_function":NAME,
            "callback_sha256":hashlib.sha256(callback.encode()).hexdigest(),
            "stubbed_boundary_only":"RTG_MTORouteReq",
            "mutated_function_body":mutation!="none",
            "mutation":mutation,
            "test_mode":"HOSTED_SYNTHETIC_REAL_TI_ZDO_C_BODY_NOT_RTg_LIBRARY",
            "physical_qualified":False,
            "fail_reason_if_mutant_survives":"CALLBACK_MTO_CALL_MUTATION_NOT_CAUGHT"}
    (out/"B2_T10_COMPILED_TI_CALLBACK_RECEIPT.json").write_text(
        json.dumps(record,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return record

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    p.add_argument("--mutation",choices=("none","drop-mto-call"),default="none")
    a=p.parse_args()
    print(json.dumps(prepare(a.sdk,a.out,a.mutation),sort_keys=True))

if __name__=="__main__":main()
