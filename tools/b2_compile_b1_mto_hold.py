#!/usr/bin/env python3
"""Compile real B1 patched ZMac + pinned TI MTO callbacks into one host test.

Only radio, MTO routing API, timer and NV backends are mocked. B1 admission
implementation and the two real TI ZMac transmit bodies are compiled directly.
This is a PARTIAL late-HOLD wrapper test, never proof of ROM or queued RF.
"""
import argparse
import hashlib
import json
from pathlib import Path
from b2_compile_actual_mto_nv_timer import take_function
from b2_compile_actual_zdo_callback import body as take_failure_callback

B1_SHA="c86ccd1aa6ca6fc0405f656a7b8d9ce78784746f"
MARK="int main(void)\n{"
GUARD="if (b1_nv_runtime_hold_active()) return MAC_NO_RESOURCES;"
class IntegrationError(ValueError):pass

def compose(zmac_host,patched_zdapp,variant):
    if zmac_host.count(MARK)!=1 or zmac_host.count(GUARD)!=1:
        raise IntegrationError("actual B1 host function/hold guard missing or ambiguous")
    prefix=zmac_host.split(MARK,1)[0]
    if variant=="remove-hold-data":
        prefix=prefix.replace(GUARD,"(void)0;",1)
    elif variant!="none":
        raise IntegrationError("unapproved negative mutation")
    callback=take_function(patched_zdapp)
    failure=take_failure_callback(patched_zdapp)
    if "OsalPortTimers_startTimer" not in callback or "RTG_MTORouteReq();" not in failure:
        raise IntegrationError("genuine TI MTO callbacks missing")
    bridge=r'''
#define TRUE 1
#define NWK_MTO_RTG_REQ_EVT 0x0100
#define ZCD_NV_CONCENTRATOR_ENABLE 0x0001
#define ZCD_NV_CONCENTRATOR_DISCOVERY 0x0002
static uint8_t NWK_TaskID=7;
static uint8_t zgConcentratorEnable, zgConcentratorDiscoveryTime;
static uint8_t nv_enable, nv_discovery, nv_fail;
static unsigned start_count, stop_count, route_requests;
static uint32_t last_timer_delay;
static uint8_t payload[3]={1,2,3};
static ZMacDataReq_t pending={0};

uint8_t osal_nv_read(uint16_t key,uint16_t offset,uint16_t len,void *out)
{
    assert(offset==0 && len==1 && out);
    if (nv_fail)return 1;
    uint8_t value=0;
    if(key==ZCD_NV_CONCENTRATOR_ENABLE)value=nv_enable;
    else if(key==ZCD_NV_CONCENTRATOR_DISCOVERY)value=nv_discovery;
    else assert(!"unexpected NV key");
    *(uint8_t *)out=value;
    return 0;
}
void OsalPortTimers_startTimer(uint8_t task,uint16_t event,uint32_t delay)
{
    assert(task==7 && event==NWK_MTO_RTG_REQ_EVT);
    ++start_count;last_timer_delay=delay;
}
void OsalPortTimers_stopTimer(uint8_t task,uint16_t event)
{
    assert(task==7 && event==NWK_MTO_RTG_REQ_EVT);
    ++stop_count;
}
void RTG_MTORouteReq(void)
{
    ++route_requests;
    uint8_t status=ZMacDataReqSec(&pending,NULL);
    if(b1_nv_runtime_hold_active())
        assert(status==MAC_NO_RESOURCES);
    else
        assert(status==ZSuccess);
}
'''
    main=r'''
int main(void)
{
    pending.msdu=payload;pending.msduLength=sizeof(payload);
    assert(!b1_nv_runtime_hold_active());
    nv_enable=1;nv_discovery=60;
    ZDApp_ForceConcentratorChange();
    assert(start_count==1 && stop_count==0 && last_timer_delay==100);
    ZDO_ManytoOneFailureIndicationCB();
    assert(route_requests==1 && mock_mac_submissions==1);

    /* Fault after MTO is scheduled but before a new source-originated
       ZMacDataReqSec call. A late callback must not admit more mock RF. */
    b1_nv_runtime_hold_latch();
    assert(b1_nv_runtime_hold_active());
    nv_fail=1;nv_enable=0; /* TI ignores NV-read status; stale enable=1 */
    ZDApp_ForceConcentratorChange();
    assert(start_count==2 && last_timer_delay==100);
    ZDO_ManytoOneFailureIndicationCB();
    assert(route_requests==2 && mock_mac_submissions==1);
    ZMacSendNoData(0x2345u,0x1234u);
    assert(mock_mac_submissions==1);

    /* Healthy NV read does not clear latched RF hold. */
    nv_fail=0;nv_enable=0;
    ZDApp_ForceConcentratorChange();
    assert(stop_count==1);
    ZDO_ManytoOneFailureIndicationCB();
    assert(route_requests==3 && mock_mac_submissions==1);
    return 0;
}
'''
    return prefix+bridge+callback+"\n"+failure+"\n"+main

def run(zmac_host,zdapp,out,variant):
    if zmac_host.is_symlink() or zdapp.is_symlink():
        raise IntegrationError("symlinked input not authorized")
    c=compose(zmac_host.read_text(),zdapp.read_text(),variant)
    out.mkdir(parents=True,exist_ok=True)
    path=out/"b1_b2_mto_rf_hold_host.c"
    path.write_text(c)
    receipt={
        "status":"B1_B2_ACTUAL_SOURCE_MTO_RF_WRAPPER_HOST_TEST_PENDING_COMPILATION",
        "b1_source_sha":B1_SHA,
        "real_TI_functions":["ZMacDataReqSec","ZMacSendNoData",
                              "ZDApp_ForceConcentratorChange",
                              "ZDO_ManytoOneFailureIndicationCB"],
        "source_sha256":hashlib.sha256(c.encode()).hexdigest(),
        "variant":variant,
        "mocked":["osal_nv_read","timer backend","RTG_MTORouteReq",
                  "MAP_MAC_McpsDataReq"],
        "test_case":"MTO scheduled then NV fault then late RTG callback wrapper must not submit new MAC request",
        "B1_B2_INTEGRATED_READY":False,"PHYSICAL_UNVERIFIED":True,
        "MAC_ROM_AND_QUEUED_RF_NOT_TESTED":True,
        "B2_ROUTING_CORE_NOT_TESTED":True,
    }
    (out/"B1_B2_MTO_HOST_RECEIPT.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    return receipt

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--zmac-host",type=Path,required=True)
    a.add_argument("--zdapp",type=Path,required=True)
    a.add_argument("--out",type=Path,required=True)
    a.add_argument("--variant",choices=("none","remove-hold-data"),default="none")
    x=a.parse_args()
    print(json.dumps(run(x.zmac_host,x.zdapp,x.out,x.variant),sort_keys=True))
if __name__=="__main__":main()
