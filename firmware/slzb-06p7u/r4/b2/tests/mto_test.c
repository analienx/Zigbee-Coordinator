/* Actual extracted pinned TI C, mock only NV storage and OSAL timer backend.
 * This never starts physical MTO routing and does not read device NV.
 */
#include "mto_stub.h"
#include <stdio.h>
#include <string.h>
uint8_t zgConcentratorEnable = 0u;
uint8_t zgConcentratorDiscoveryTime = 0u;
uint8_t NWK_TaskID = 3u;
int devState = DEV_HOLD;
static int repairRequests;
void RTG_MTORouteReq(void) { ++repairRequests; }
static uint8_t desiredEnable, desiredDiscovery;
static int failId;
static int starts, stops, nvReads;
uint8_t osal_nv_read(uint16_t id,uint16_t offset,uint16_t len,void *buf) {
    assert(offset == 0 && len == 1u && buf != NULL);
    ++nvReads;
    if (failId == (int)id) {
        *(uint8_t *)buf = 2u;  /* failure still writes garbage to output */
        return 8u;
    }
    if (id == ZCD_NV_CONCENTRATOR_ENABLE) *(uint8_t *)buf=desiredEnable;
    else if (id == ZCD_NV_CONCENTRATOR_DISCOVERY) *(uint8_t *)buf=desiredDiscovery;
    else { assert(!"unknown NV ID"); return 8u; }
    return SUCCESS;
}
void OsalPortTimers_startTimer(uint8_t task,uint16_t evt,uint32_t ticks) {
    assert(task == NWK_TaskID && evt == NWK_MTO_RTG_REQ_EVT && ticks == 100);
    ++starts;
}
void OsalPortTimers_stopTimer(uint8_t task,uint16_t evt) {
    assert(task == NWK_TaskID && evt == NWK_MTO_RTG_REQ_EVT);
    ++stops;
}
extern void ZDApp_ForceConcentratorChange(void);
static void reset(void) {
    zgConcentratorEnable = TRUE; zgConcentratorDiscoveryTime = 77;
    desiredEnable = FALSE; desiredDiscovery = 11;
    failId=starts=stops=nvReads=0;
}
int main(void) {
    reset();
    ZDApp_ForceConcentratorChange();
    assert(zgConcentratorEnable==FALSE && zgConcentratorDiscoveryTime==11);
    assert(starts==0 && stops==1 && nvReads==2);

    reset(); desiredEnable=TRUE; desiredDiscovery=42;
    ZDApp_ForceConcentratorChange();
    assert(zgConcentratorEnable==TRUE && zgConcentratorDiscoveryTime==42);
    assert(starts==1 && stops==0 && nvReads==2);

    reset(); desiredEnable=TRUE; failId=ZCD_NV_CONCENTRATOR_ENABLE;
    ZDApp_ForceConcentratorChange();
    assert(zgConcentratorEnable==FALSE && zgConcentratorDiscoveryTime==0);
    assert(starts==0 && stops==1 && nvReads==1);

    reset(); desiredEnable=TRUE; failId=ZCD_NV_CONCENTRATOR_DISCOVERY;
    ZDApp_ForceConcentratorChange();
    assert(zgConcentratorEnable==FALSE && zgConcentratorDiscoveryTime==0);
    assert(starts==0 && stops==1 && nvReads==2);

    reset(); desiredEnable=2;
    ZDApp_ForceConcentratorChange();
    assert(zgConcentratorEnable==FALSE && zgConcentratorDiscoveryTime==0);
    assert(starts==0 && stops==1 && nvReads==2);

    /* Only formed active concentrators may initiate MTO repair. Do not
     * insert new source-side delays when TI already has an opaque limiter. */
    reset(); zgConcentratorEnable=FALSE;
    devState=DEV_ZB_COORD; repairRequests=0;
    ZDO_ManytoOneFailureIndicationCB();
    assert(repairRequests==0);  /* concentrator disabled */
    zgConcentratorEnable=TRUE; devState=DEV_HOLD;
    ZDO_ManytoOneFailureIndicationCB();
    assert(repairRequests==0);  /* forming, cannot transmit */
    devState=DEV_ZB_COORD;
    ZDO_ManytoOneFailureIndicationCB();
    assert(repairRequests==1);  /* first enabled/formed failure: immediate */
    for (int i=0; i<1000; ++i) ZDO_ManytoOneFailureIndicationCB();
    assert(repairRequests==1001); /* API calls, NOT confirmed RF broadcasts */
    zgConcentratorEnable=FALSE;
    ZDO_ManytoOneFailureIndicationCB();
    zgConcentratorEnable=TRUE; devState=DEV_ROUTER;
    ZDO_ManytoOneFailureIndicationCB();
    assert(repairRequests==1002); /* router concentrator also supported */
    puts("B2_ACTUAL_TI_MTO_NV_AND_FORMATION_GUARD_PASS");
    return 0;
}
