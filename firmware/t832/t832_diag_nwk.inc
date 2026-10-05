/* Runs ONLY from ZStackTaskProcessEvent, at most once / 60 seconds.
 * Tables and queues are owned by this shared OSAL/ZStack task. No timer,
 * new task, locks, allocation, or task-priority changes are introduced. */
#include "rtg.h"
#include "nwk_bufs.h"
#include "nwk_globals.h"
#include "ti_zstack_config.h"
extern bcastEntry_t bcastTable[];

void T832Diag_sampleNwk(void)
{
    uint16_t i, routes = 0u, discover = 0u, source = 0u, broadcast = 0u, total = 0u;
    uint16_t active = 0u, repair = 0u, disc = 0u, link = 0u, expired = 0u;
    uint16_t limits[6] = {gNWK_MAX_DATABUFS_WAITING, gNWK_MAX_DATABUFS_TOTAL,
        gNWK_MAX_DATABUFS_CONFIRMED, gNWK_MAX_DATABUFS_SCHEDULED,
        gNWK_MAX_DATABUFS_TOTAL, gNWK_MAX_DATABUFS_TOTAL};
    if (!T832Diag_nwkDue()) return;
    /* Byte-returning TI API is reported without claiming a queue limit. */
    for (i = NWK_DATABUF_WAITING; i <= NWK_DATABUF_DONE; i++) {
        uint16_t count = nwkDB_CountTypes((byte)i);
        total += count;
        T832Diag_nwkPressure((uint8_t)(i - 1u), count, limits[i - 1u]);
    }
    T832Diag_nwkPressure(6u, total, gNWK_MAX_DATABUFS_TOTAL);
    for (i = 0u; i < MAX_RTG_ENTRIES; i++) {
        if (rtgTable[i].status != RT_INIT) routes++;
        if (rtgTable[i].status == RT_ACTIVE) active++;
        if (rtgTable[i].status == RT_REPAIR) repair++;
        if (rtgTable[i].status == RT_DISC) disc++;
        if (rtgTable[i].status == RT_LINK_FAIL) link++;
        if (rtgTable[i].status != RT_INIT && !rtgTable[i].expiryTime) expired++;
    }
    /* Expiry == 0 is TI's unused slot marker. Source relayList is not
     * dereferenced: expiry / count only, bounded by configured capacities. */
    for (i = 0u; i < MAX_RREQ_ENTRIES; i++) if (rtDiscTable[i].expiryTime) discover++;
    for (i = 0u; i < MAX_RTG_SRC_ENTRIES; i++) if (rtgSrcTable[i].expiryTime) source++;
    for (i = 0u; i < MAX_BCAST; i++) if (bcastTable[i].bdt) broadcast++;
    T832Diag_nwkPressure(7u, routes, MAX_RTG_ENTRIES);
    T832Diag_nwkPressure(8u, active, MAX_RTG_ENTRIES);
    T832Diag_nwkPressure(9u, disc, MAX_RTG_ENTRIES);
    T832Diag_nwkPressure(10u, link, MAX_RTG_ENTRIES);
    T832Diag_nwkPressure(11u, repair, MAX_RTG_ENTRIES);
    T832Diag_nwkPressure(12u, expired, MAX_RTG_ENTRIES);
    T832Diag_nwkPressure(13u, discover, MAX_RREQ_ENTRIES);
    T832Diag_nwkPressure(14u, source, MAX_RTG_SRC_ENTRIES);
    T832Diag_nwkPressure(15u, broadcast, MAX_BCAST);
    /* Age of the task-context sampler, not a synthetic fresh occupancy. */
    T832Diag_nwkPressure(16u, 1u, 1u);
}
