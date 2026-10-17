#!/usr/bin/env python3
"""Compile authentic TI zd_app.c concentrator NV/timer callback in host ASan.

Mocks only OSAL NV and timer interfaces. Deliberate source mutations must
kill the exact start/stop assertions; does not test actual RTG or RF.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SDK_SHA="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
SRC="source/ti/zstack/stack/zdo/zd_app.c"
NAME="ZDApp_ForceConcentratorChange"
class SourceError(ValueError):pass

def take_function(text):
    regex=re.compile(r"\bvoid\s+"+NAME+r"\s*\(\s*void\s*\)\s*\{")
    positions=list(regex.finditer(text))
    if len(positions)!=1:raise SourceError("callback location not unique")
    start=positions[0].start()
    level=0
    for pos in range(positions[0].end()-1,len(text)):
        if text[pos]=="{": level+=1
        elif text[pos]=="}":
            level-=1
            if level==0: return text[start:pos+1]
    raise SourceError("unbalanced TI C callback body")

def produce(sdk,out,mutant):
    if subprocess.check_output(["git","-C",str(sdk),"rev-parse","HEAD"],text=True).strip()!=SDK_SHA:
        raise SourceError("TI SDK pin mismatch")
    path=sdk/SRC
    original=subprocess.check_output(["git","-C",str(sdk),"show","HEAD:"+SRC])
    if not path.is_file() or path.is_symlink() or path.read_bytes()!=original:
        raise SourceError("not pristine vendor source")
    body=take_function(original.decode("utf-8"))
    start="OsalPortTimers_startTimer( NWK_TaskID, NWK_MTO_RTG_REQ_EVT, 100 );"
    stop="OsalPortTimers_stopTimer( NWK_TaskID, NWK_MTO_RTG_REQ_EVT );"
    for candidate in (start,stop):
        if body.count(candidate)!=1:raise SourceError("expected exact vendor timer site absent")
    if mutant=="start-delay-1000":
        body=body.replace(start,start.replace(", 100 );",", 1000 );"))
    elif mutant=="skip-stop":
        body=body.replace(stop,"(void)0;")
    elif mutant!="none":
        raise SourceError("mutation not approved")
    header=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#define TRUE 1
#define NWK_MTO_RTG_REQ_EVT 0x0100
#define ZCD_NV_CONCENTRATOR_ENABLE 0x0001
#define ZCD_NV_CONCENTRATOR_DISCOVERY 0x0002
static uint8_t NWK_TaskID=7;
static uint8_t zgConcentratorEnable, zgConcentratorDiscoveryTime;
static uint8_t nv_enable, nv_discovery, nv_fail;
static unsigned start_count, stop_count;
static uint32_t last_timer_delay;
uint8_t osal_nv_read(uint16_t key, uint16_t offset, uint16_t len, void *out)
{
    assert(offset==0 && len==1 && out!=0);
    if (nv_fail) return 1; /* real callback ignores read status */
    uint8_t value=0;
    if (key==ZCD_NV_CONCENTRATOR_ENABLE) value=nv_enable;
    else if (key==ZCD_NV_CONCENTRATOR_DISCOVERY) value=nv_discovery;
    else assert(0 && "unexpected NV key");
    *(uint8_t *)out=value;
    return 0;
}
void OsalPortTimers_startTimer(uint8_t task,uint16_t event,uint32_t delay)
{
    assert(task==7 && event==NWK_MTO_RTG_REQ_EVT);
    ++start_count; last_timer_delay=delay;
}
void OsalPortTimers_stopTimer(uint8_t task,uint16_t event)
{
    assert(task==7 && event==NWK_MTO_RTG_REQ_EVT);
    ++stop_count;
}
'''
    tests=r'''
int main(void)
{
    nv_enable=0; nv_discovery=0;
    '''+NAME+r'''();
    assert(start_count==0 && stop_count==1 && zgConcentratorEnable==0);

    nv_enable=1; nv_discovery=60;
    '''+NAME+r'''();
    assert(start_count==1 && stop_count==1 && last_timer_delay==100);
    assert(zgConcentratorEnable==1 && zgConcentratorDiscoveryTime==60);

    /* Negative NV-read return is silently ignored by this TI callback.
       Deliberately record the observed stale-enable behavior; this is
       NOT a test claiming the B1 hold gate or radio admission is safe. */
    nv_fail=1; nv_enable=0;
    '''+NAME+r'''();
    assert(start_count==2 && stop_count==1 && last_timer_delay==100);
    assert(zgConcentratorEnable==1);

    nv_fail=0;
    '''+NAME+r'''();
    assert(start_count==2 && stop_count==2 && zgConcentratorEnable==0);
    return 0;
}
'''
    out.mkdir(parents=True,exist_ok=True)
    (out/"ti_zdo_nv_mto_host.c").write_text(header+body+"\n"+tests,encoding="utf-8")
    result={
        "status":"HOSTED_ACTUAL_TI_ZDO_NV_TIMER_C_BODY",
        "sdk_sha":SDK_SHA,
        "source_path":SRC,
        "source_sha256":hashlib.sha256(original).hexdigest(),
        "function_name":NAME,
        "mutation":mutant,
        "only_stubbed_boundaries":["osal_nv_read","OsalPortTimers_startTimer","OsalPortTimers_stopTimer"],
        "observed_source_policy":{
            "nv_enabled_timer_delay_ms":100,
            "nv_disabled_stops_timer":True,
            "failed_nv_read_uses_existing_ram_concentrator_state":True,
            "b1_hold_gate_not_exercised":True,
        },
        "physical_verified":False,
        "rtg_library_tested":False,
    }
    (out/"B2_T10_NV_TIMER_SOURCE_RECEIPT.json").write_text(
        json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--mutation",choices=("none","start-delay-1000","skip-stop"),default="none")
    a=p.parse_args()
    print(json.dumps(produce(a.sdk,a.out,a.mutation),sort_keys=True))
if __name__=="__main__":main()
