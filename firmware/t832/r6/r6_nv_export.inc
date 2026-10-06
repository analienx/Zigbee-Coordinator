/* MT task context only. No NV lock, flash reads or NV API calls. */
#include "nv_r6_probe.h"
_Static_assert(sizeof(T832DiagState)+sizeof(T832R5State)+sizeof(T832FatalLatch)+
               sizeof(T832R6NvSnapshot)+16u<=4096u,"All R6 diagnostic RAM remains within 4 KiB");
static uint32_t t832R6NvLastSequence,t832R6NvLastMs;
static void T832R6Nv_poll(uint32_t now)
{
    T832R6NvSnapshot s;
    uint32_t key=OsalPort_enterCS();
    uint32_t sequence=t832R6Nv.sequence;
    if(!sequence || (sequence&1u) ||
       (sequence==t832R6NvLastSequence && (uint32_t)(now-t832R6NvLastMs)<60000u)) {
        OsalPort_leaveCS(key);return;
    }
    /* The single-core scheduler cannot switch the serialized NV writer
     * during this bounded copy; an already interrupted writer is skipped. */
    s=t832R6Nv;
    OsalPort_leaveCS(key);
    t832R6NvLastSequence=sequence;t832R6NvLastMs=now;
    T832Diag_record(T832_DIAG_EV_NV_TOPOLOGY,0u,s.pages,s.ready);
    T832Diag_record(T832_DIAG_EV_NV_TOPOLOGY,1u,s.head,s.tail);
    T832Diag_record(T832_DIAG_EV_NV_TOPOLOGY,2u,s.active,s.active_offset);
    uint32_t free=0;
    for(unsigned i=0;i<s.pages && i<NVOCMP_NVPAGES;i++) {
        /* Available-page RAM estimate, not TI getFreeNV's flash-header scan.
         * The hosted test compares it at serialized operation boundaries. */
        if(i!=s.tail && s.offsets[i]<=2048u &&
           (s.states[i]==0xFFu || s.states[i]==0x7Eu || s.states[i]==0x7Cu))free+=2048u-s.offsets[i];
        T832Diag_record(T832_DIAG_EV_NV_SPACE,(uint16_t)i,s.offsets[i],s.states[i]);
    }
    T832Diag_record(T832_DIAG_EV_NV_SPACE,0xFFFFu,(uint16_t)free,(uint16_t)(free>>16));
    T832Diag_record(T832_DIAG_EV_NV_COUNTERS,0u,(uint16_t)s.requests,(uint16_t)(s.requests>>16));
    T832Diag_record(T832_DIAG_EV_NV_COUNTERS,1u,(uint16_t)s.compactions,(uint16_t)(s.compactions>>16));
    T832Diag_record(T832_DIAG_EV_NV_COUNTERS,2u,(uint16_t)s.compact_failures,(uint16_t)(s.compact_failures>>16));
    T832Diag_record(T832_DIAG_EV_NV_RESULT,s.stage,s.requested,s.status);
    T832Diag_record(T832_DIAG_EV_NV_RESULT,7u,s.init_action,s.first_failure);
}
