/* Included inside nvocmp.c. Called only on its existing serialized paths.
 * POD stores and bounded RAM copies only: no clock, gate, heap, IO or NV API. */
volatile T832R6NvSnapshot t832R6Nv;
_Static_assert(sizeof(T832R6NvSnapshot)<=128u,"R6 NV observer RAM bound");
void T832R6Nv_capture(uint16_t stage,uint16_t requested,uint16_t status)
{
    t832R6Nv.sequence++;
    t832R6Nv.stage=stage;
    t832R6Nv.requested=requested;
    t832R6Nv.status=status;
    if(stage==5u && t832R6Nv.requests!=UINT32_MAX)t832R6Nv.requests++;
    if(stage==1u && t832R6Nv.compactions!=UINT32_MAX)t832R6Nv.compactions++;
    if(stage==3u && t832R6Nv.compact_failures!=UINT32_MAX)t832R6Nv.compact_failures++;
    /* EXIST/NOTFOUND at a completed API boundary are ordinary lookup/create
     * outcomes. Preserve their raw status, without declaring a storage fault. */
    if((stage==3u || stage==6u || stage==8u) && status && !t832R6Nv.first_failure &&
       !(stage==8u && (status==NVINTF_EXIST || status==NVINTF_NOTFOUND))) {
        t832R6Nv.first_failure=status;
        t832R6Nv.first_failure_requested=requested;
    }
    if(stage==7u)t832R6Nv.init_action=status;
    t832R6Nv.pages=NVOCMP_nvHandle.nvSize;
    t832R6Nv.head=NVOCMP_nvHandle.headPage;
    t832R6Nv.tail=NVOCMP_nvHandle.tailPage;
    t832R6Nv.active=NVOCMP_nvHandle.actPage;
    t832R6Nv.active_offset=NVOCMP_nvHandle.actOffset;
    t832R6Nv.ready=(NVOCMP_failF==NVINTF_SUCCESS && NVOCMP_failW==NVINTF_SUCCESS);
    for(unsigned i=0;i<NVOCMP_NVPAGES;i++) {
        t832R6Nv.offsets[i]=NVOCMP_nvHandle.pageInfo[i].offset;
        t832R6Nv.states[i]=NVOCMP_nvHandle.pageInfo[i].state;
    }
    t832R6Nv.sequence++;
}
