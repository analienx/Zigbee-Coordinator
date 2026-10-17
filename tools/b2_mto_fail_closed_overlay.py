#!/usr/bin/env python3
"""Pinned TI zd_app.c MTO-NV fail-closed source candidate + actual-body C tests.

Standalone B2 experiment ONLY. Never runs against a live coordinator; caller
must still compose B1/B3 and prove radio effects. No MTO enable/write occurs.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from b2_compile_actual_mto_nv_timer import SDK_SHA, SRC, NAME, take_function, SourceError

ORIGINAL = """void ZDApp_ForceConcentratorChange( void )
{
  osal_nv_read( ZCD_NV_CONCENTRATOR_ENABLE, 0, sizeof(zgConcentratorEnable), &zgConcentratorEnable );
  osal_nv_read( ZCD_NV_CONCENTRATOR_DISCOVERY, 0, sizeof(zgConcentratorDiscoveryTime), &zgConcentratorDiscoveryTime );

  if ( zgConcentratorEnable == TRUE )
  {
    // Start next event
    OsalPortTimers_startTimer( NWK_TaskID, NWK_MTO_RTG_REQ_EVT, 100 );
  }
  else
  {
    // Stop the next event
    OsalPortTimers_stopTimer( NWK_TaskID, NWK_MTO_RTG_REQ_EVT );
  }
}"""

FIXED = """void ZDApp_ForceConcentratorChange( void )
{
  uint8_t enable = 0u;
  uint8_t discovery = 0u;
  /* Evaluate both NV reads before publishing either global. Never let an
   * old RAM value schedule MTO after storage failure. B1 must independently
   * latch the NV/storage error and gate new RF. */
  uint8_t enable_ok = osal_nv_read(ZCD_NV_CONCENTRATOR_ENABLE, 0,
                                   sizeof(enable), &enable) == SUCCESS;
  uint8_t discovery_ok = osal_nv_read(ZCD_NV_CONCENTRATOR_DISCOVERY, 0,
                                      sizeof(discovery), &discovery) == SUCCESS;
  if (!enable_ok || !discovery_ok || enable > 1u)
  {
    zgConcentratorEnable = 0u;
    zgConcentratorDiscoveryTime = 0u;
    OsalPortTimers_stopTimer(NWK_TaskID, NWK_MTO_RTG_REQ_EVT);
    return;
  }
  zgConcentratorEnable = enable;
  zgConcentratorDiscoveryTime = discovery;
  if (zgConcentratorEnable == TRUE)
    OsalPortTimers_startTimer(NWK_TaskID, NWK_MTO_RTG_REQ_EVT, 100);
  else
    OsalPortTimers_stopTimer(NWK_TaskID, NWK_MTO_RTG_REQ_EVT);
}"""

HEADER = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#define TRUE 1u
#define SUCCESS 0u
#define NWK_MTO_RTG_REQ_EVT 0x0100u
#define ZCD_NV_CONCENTRATOR_ENABLE 1u
#define ZCD_NV_CONCENTRATOR_DISCOVERY 2u
static uint8_t NWK_TaskID = 7u;
static uint8_t zgConcentratorEnable, zgConcentratorDiscoveryTime;
static uint8_t stored_enable, stored_discovery, fail_enable, fail_discovery;
static unsigned start_count, stop_count;
static uint32_t last_delay;
uint8_t osal_nv_read(uint16_t key, uint16_t offset, uint16_t len, void *out)
{
    assert(offset==0u && len==1u && out);
    if (key == ZCD_NV_CONCENTRATOR_ENABLE) {
        if (fail_enable) return 1u;
        *(uint8_t*)out=stored_enable;
    } else if(key == ZCD_NV_CONCENTRATOR_DISCOVERY) {
        if (fail_discovery) return 1u;
        *(uint8_t*)out=stored_discovery;
    } else assert(!"unexpected NV id");
    return SUCCESS;
}
void OsalPortTimers_startTimer(uint8_t task,uint16_t event,uint32_t delay)
{
    assert(task==7u && event==NWK_MTO_RTG_REQ_EVT);
    ++start_count; last_delay=delay;
}
void OsalPortTimers_stopTimer(uint8_t task,uint16_t event)
{
    assert(task==7u && event==NWK_MTO_RTG_REQ_EVT);
    ++stop_count;
}
'''
TESTS = r'''
int main(void)
{
    /* Neither the baseline default nor the repair may activate MTO itself. */
    stored_enable=0u;stored_discovery=0u;
    ZDApp_ForceConcentratorChange();
    assert(!start_count && stop_count==1u && zgConcentratorEnable==0u);
    stored_enable=1u;stored_discovery=60u;
    ZDApp_ForceConcentratorChange();
    assert(start_count==1u && last_delay==100u && zgConcentratorEnable==1u);
    assert(zgConcentratorDiscoveryTime==60u);

    /* Stale enabled globals must NEVER remain enabled after failed read. */
    fail_enable=1u;stored_enable=0u;
    ZDApp_ForceConcentratorChange();
    assert(start_count==1u && stop_count==2u);
    assert(zgConcentratorEnable==0u && zgConcentratorDiscoveryTime==0u);

    fail_enable=0u;stored_enable=1u;
    ZDApp_ForceConcentratorChange();
    assert(start_count==2u);
    fail_discovery=1u;
    ZDApp_ForceConcentratorChange();
    assert(start_count==2u && stop_count==3u);
    assert(zgConcentratorEnable==0u && zgConcentratorDiscoveryTime==0u);

    fail_discovery=0u;stored_enable=2u; /* corrupt boolean */
    ZDApp_ForceConcentratorChange();
    assert(start_count==2u && stop_count==4u && zgConcentratorEnable==0u);
    stored_enable=0u;
    ZDApp_ForceConcentratorChange();
    assert(start_count==2u && stop_count==5u && zgConcentratorEnable==0u);
    return 0;
}
'''

def build(sdk: Path, out: Path, mutation: str) -> dict:
    sdk=sdk.resolve()
    sha=subprocess.check_output(["git","-C",str(sdk),"rev-parse","HEAD"],text=True).strip()
    if sha != SDK_SHA:
        raise SourceError("TI SDK SHA mismatch")
    path=sdk/SRC
    orig=subprocess.check_output(["git","-C",str(sdk),"show","HEAD:"+SRC])
    if path.is_symlink() or not path.is_file() or path.read_bytes()!=orig:
        raise SourceError("TI source modified or symlinked")
    original=take_function(orig.decode("utf-8"))
    if original!=ORIGINAL:
        raise SourceError("actual TI callback differs from strict reviewed bytes")
    if mutation=="ignore-second-read":
        fixed=FIXED.replace("if (!enable_ok || !discovery_ok || enable > 1u)",
                            "if (!enable_ok || enable > 1u)")
    elif mutation=="ignore-first-read":
        fixed=FIXED.replace("if (!enable_ok || !discovery_ok || enable > 1u)",
                            "if (!discovery_ok || enable > 1u)")
    elif mutation=="none":
        fixed=FIXED
    else:
        raise SourceError("mutation unsupported")
    assert fixed!=original
    out.mkdir(parents=True,exist_ok=True)
    (out/"ti_mto_fail_closed.c").write_text(HEADER+fixed+"\n"+TESTS)
    (out/"zd_app_mto_callback_replacement.c").write_text(fixed+"\n")
    receipt={
        "schema":"r4-b2-mto-nv-fail-closed-candidate-v1",
        "ti_sdk_sha":SDK_SHA,"ti_source_path":SRC,
        "vendor_callback_sha256":hashlib.sha256(original.encode()).hexdigest(),
        "replacement_sha256":hashlib.sha256(fixed.encode()).hexdigest(),
        "mutation":mutation,"source_is_candidate_only":True,
        "integrated_in_firmware":False,"mto_enabled_by_this_patch":False,
        "actual_radio_or_opaque_rtg_tested":False,"flash_authorized":False
    }
    (out/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    return receipt

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--mutation",default="none",
                   choices=("none","ignore-second-read","ignore-first-read"))
    a=p.parse_args()
    print(json.dumps(build(a.sdk,a.out,a.mutation),sort_keys=True))
