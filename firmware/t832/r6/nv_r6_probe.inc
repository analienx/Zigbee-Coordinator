/* Included inside nvocmp.c. Called only on its existing serialized paths.
 * POD stores and bounded RAM copies only: no clock, gate, heap, IO or NV API.
 * Failure classification (F1): the inner NVOCMP_compact result is tested
 * with TI's own predicate `status == NVOCMP_COMPACT_FAILURE` (nvocmp.c:4145
 * and :4319). SRCDONE/DSTDONE/BOTHDOE (1/2/3) are successful progress and
 * never latch a fault, never count a compact failure. Completed-API results
 * are NVINTF-domain and judged separately: expected EXIST/NOTFOUND stay
 * benign ordinary outcomes, and only the source-proven explicit-compaction
 * no-work BADPARAM (compactNvApi reports BADPARAM when no compaction was
 * needed, nvocmp.c:1242/:1247) is benign -- never a blanket BADPARAM
 * exemption. Prelock validation/voltage exits return before any capture
 * site and are explicitly unavailable in this POD. */
volatile T832R6NvSnapshot t832R6Nv;
_Static_assert(sizeof(T832R6NvFirst)==16u,"R11 first-fault context must be 16 bytes");
_Static_assert(sizeof(T832R6NvCurrent)==12u,"R11 current context must be 12 bytes");
_Static_assert(sizeof(T832R6NvSnapshot)<=128u,"R11 NV observer RAM bound");
static uint8_t T832R6Nv_meaningful(uint16_t stage,uint8_t api,uint16_t status)
{
    if(stage==3u)return (uint8_t)(status==NVOCMP_COMPACT_FAILURE);
    if(stage==6u)
    {
        if(status==0u)return 0u;
        if(status==NVINTF_EXIST||status==NVINTF_NOTFOUND)return 0u;
        return 1u;
    }
    if(stage==8u)
    {
        if(status==0u)return 0u;
        if(status==NVINTF_EXIST||status==NVINTF_NOTFOUND)return 0u;
        /* Narrowed: only explicit-compact no-work BADPARAM is benign --
         * pinned TI nvocmp.c compactNvApi reports BADPARAM when no
         * compaction was needed (:1242/:1247); all other BADPARAM latch. */
        if(api==T832R6NV_API_COMPACT&&status==NVINTF_BADPARAM)return 0u;
        return 1u;
    }
    return 0u;
}
static void T832R6Nv_store(uint16_t stage,uint8_t api,uint8_t site,
                           uint16_t item_id,uint16_t sub_id,uint8_t system_id,
                           uint16_t requested,uint16_t status,
                           uint8_t phase_domain,uint8_t known_flags,
                           uint8_t install_ctx)
{
    t832R6Nv.sequence++;
    t832R6Nv.stage=stage;
    t832R6Nv.requested=requested;
    t832R6Nv.status=status;
    t832R6Nv.current.generation++;
    if(t832R6Nv.current.generation==0u)t832R6Nv.current.generation=1u;
    if(install_ctx)
    {
        t832R6Nv.current.api=api;
        t832R6Nv.current.site=site;
        t832R6Nv.current.item_id=item_id;
        t832R6Nv.current.sub_id=sub_id;
        t832R6Nv.current.system_id=system_id;
        t832R6Nv.current.known_flags=(uint8_t)(known_flags&0x7Fu);
    }
    if(stage==5u && t832R6Nv.requests!=UINT32_MAX)t832R6Nv.requests++;
    if(stage==1u && t832R6Nv.compactions!=UINT32_MAX)t832R6Nv.compactions++;
    if(stage==3u && status==NVOCMP_COMPACT_FAILURE &&
       t832R6Nv.compact_failures!=UINT32_MAX)t832R6Nv.compact_failures++;
    /* First meaningful failure per boot is immutable: later failures can
     * never overwrite it. Inner compact captures inherit the installed
     * caller api/item (automatic compaction reports its caller, never its
     * own class); only the site/status/requested of the compact instant
     * are taken from this capture. */
    if(T832R6Nv_meaningful(stage,api,status) && t832R6Nv.first.fault_id==0u)
    {
        if(install_ctx)
        {
            t832R6Nv.first.requested=requested;
            t832R6Nv.first.item_id=item_id;
            t832R6Nv.first.sub_id=sub_id;
            t832R6Nv.first.api=api;
            t832R6Nv.first.system_id=system_id;
            t832R6Nv.first.site=site;
            t832R6Nv.first.status=(uint8_t)status;
            t832R6Nv.first.phase_domain=phase_domain;
            t832R6Nv.first.known_flags=(uint8_t)(known_flags&0x7Fu);
        }
        else
        {
            t832R6Nv.first.requested=requested;
            t832R6Nv.first.item_id=t832R6Nv.current.item_id;
            t832R6Nv.first.sub_id=t832R6Nv.current.sub_id;
            t832R6Nv.first.api=t832R6Nv.current.api;
            t832R6Nv.first.system_id=t832R6Nv.current.system_id;
            t832R6Nv.first.site=site;
            t832R6Nv.first.status=(uint8_t)status;
            t832R6Nv.first.phase_domain=phase_domain;
            t832R6Nv.first.known_flags=(uint8_t)((t832R6Nv.current.known_flags|
                T832R6NV_KNOWN_SITE|T832R6NV_KNOWN_STATUS|
                T832R6NV_KNOWN_REQUESTED)&0x7Fu);
        }
        /* fault_id commits last from the current generation. */
        t832R6Nv.first.fault_id=t832R6Nv.current.generation;
    }
    if(stage==7u)t832R6Nv.init_action=status;
    /* Q3: the classifier rejects before scanPage/gAction selects an init
     * action. The handle may already contain defaults/image-derived scan
     * metadata, but it carries no reject diagnosis; init_action still reads
     * NORMAL_INIT. The latch keeps the true cause. Same TU (included at the
     * end of nvocmp.c). */
    t832R6Nv.rej_status=t832R10Reject.status;
    t832R6Nv.rej_page=t832R10Reject.page;
    t832R6Nv.rej_site=t832R10Reject.site;
    t832R6Nv.rej_raw=t832R10Reject.raw;
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
void T832R6Nv_capture(uint16_t stage,uint16_t requested,uint16_t status)
{
    uint8_t site=T832R6NV_SITE_UNKNOWN;
    uint8_t domain=T832R6NV_DOMAIN_UNKNOWN;
    if(stage==1u||stage==2u||stage==3u){site=T832R6NV_SITE_COMPACT_INNER;domain=T832R6NV_DOMAIN_COMPACT;}
    else if(stage==7u){site=T832R6NV_SITE_INIT_ACTION;domain=T832R6NV_DOMAIN_INIT;}
    T832R6Nv_store(stage,T832R6NV_API_UNKNOWN,site,0u,0u,0u,requested,status,
                   (uint8_t)((domain<<4u)|(stage&0x0Fu)),
                   (uint8_t)(T832R6NV_KNOWN_SITE|T832R6NV_KNOWN_STATUS|
                             T832R6NV_KNOWN_REQUESTED),0u);
}
void T832R6Nv_captureCtx(uint16_t stage,uint8_t api,uint8_t site,
                         uint16_t item_id,uint16_t sub_id,uint8_t system_id,
                         uint16_t requested,uint16_t status,
                         uint8_t phase_domain,uint8_t known_flags)
{
    T832R6Nv_store(stage,api,site,item_id,sub_id,system_id,requested,status,
                   phase_domain,known_flags,1u);
}
