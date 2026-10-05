/* Runs ONLY from ZStackTaskProcessEvent, at most once / 60 seconds.
 * Tables and queues are owned by this shared OSAL/ZStack task. No timer,
 * new task, locks, allocation, or task-priority changes are introduced. */
#include "rtg.h"
#include "nwk_bufs.h"
#include "ti_zstack_config.h"
extern bcastEntry_t bcastTable[];

void T832Diag_sampleNwk(void)
{
    uint16_t i, routes = 0u, discover = 0u, source = 0u, broadcast = 0u;
    uint16_t active = 0u, repair = 0u;
    if (!T832Diag_nwkDue()) return;
    /* Byte-returning TI API is reported without claiming a queue limit. */
    for (i = NWK_DATABUF_WAITING; i <= NWK_DATABUF_DONE; i++)
        T832Diag_nwkPressure((uint8_t)(i - 1u), nwkDB_CountTypes((byte)i), 0u);
    for (i = 0u; i < MAX_RTG_ENTRIES; i++) {
        if (rtgTable[i].status != RT_INIT) routes++;
        if (rtgTable[i].status == RT_ACTIVE) active++;
        if (rtgTable[i].status == RT_REPAIR || rtgTable[i].status == RT_LINK_FAIL) repair++;
    }
    /* Expiry == 0 is TI's unused slot marker. Source relayList is not
     * dereferenced: expiry / count only, bounded by configured capacities. */
    for (i = 0u; i < MAX_RREQ_ENTRIES; i++) if (rtDiscTable[i].expiryTime) discover++;
    for (i = 0u; i < MAX_RTG_SRC_ENTRIES; i++) if (rtgSrcTable[i].expiryTime) source++;
    for (i = 0u; i < MAX_BCAST; i++) if (bcastTable[i].bdt) broadcast++;
    T832Diag_nwkPressure(6u, routes, MAX_RTG_ENTRIES);
    T832Diag_nwkPressure(7u, active, MAX_RTG_ENTRIES);
    T832Diag_nwkPressure(8u, repair, MAX_RTG_ENTRIES);
    T832Diag_nwkPressure(9u, discover, MAX_RREQ_ENTRIES);
    T832Diag_nwkPressure(10u, source, MAX_RTG_SRC_ENTRIES);
    T832Diag_nwkPressure(11u, broadcast, MAX_BCAST);
}
