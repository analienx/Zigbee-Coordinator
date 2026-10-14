static void ZDSecMgrRestoreFromNV(void)
{
    nvDeviceListHdr_t hdr = {0};
    APSME_ApsLinkKeyNVEntry_t key = {0};
    uint16_t x, y, count = 0;
    const uint32_t delta = (uint32_t)MAX_APS_FRAMECOUNTER_CHANGES + 1u;
    if (!ZDSecMgrEntries || !delta || !p7_security_persistence_ok() ||
        osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE, 0, sizeof(hdr), &hdr) != SUCCESS ||
        hdr.numRecs > gZDSECMGR_ENTRY_MAX) goto fault;
    /* TI initializes an unused table to zero bytes (including ami). A zero
     * header means no records; retain EntryInit's INVALID_NODE_ADDR defaults. */
    if (hdr.numRecs == 0) goto trust_center;
    /* Validate all indexes/counts before writing any counter. */
    for (x = 0; x < gZDSECMGR_ENTRY_MAX; ++x)
    {
        if (osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE,
                sizeof(hdr) + x * sizeof(ZDSecMgrEntry_t), sizeof(ZDSecMgrEntry_t),
                &ZDSecMgrEntries[x]) != SUCCESS) goto fault;
        if (ZDSecMgrEntries[x].ami == INVALID_NODE_ADDR) continue;
        if (ZDSecMgrEntries[x].keyNvId >= gZDSECMGR_ENTRY_MAX) goto fault;
        for (y = 0; y < x; ++y)
            if (ZDSecMgrEntries[y].ami != INVALID_NODE_ADDR &&
                ZDSecMgrEntries[y].keyNvId == ZDSecMgrEntries[x].keyNvId) goto fault;
        ++count;
    }
    if (count != hdr.numRecs) goto fault;
    for (x = 0; x < gZDSECMGR_ENTRY_MAX; ++x)
    {
        uint16_t slot = ZDSecMgrEntries[x].keyNvId;
        if (ZDSecMgrEntries[x].ami == INVALID_NODE_ADDR) continue;
        if (!p7_security_read(ZCD_NV_EX_APS_KEY_DATA_TABLE, slot, sizeof(key), &key) ||
            key.txFrmCntr > UINT32_MAX - delta) goto fault;
        key.txFrmCntr += delta;
        if (!p7_security_commit(ZCD_NV_EX_APS_KEY_DATA_TABLE, slot, sizeof(key), &key)) goto fault;
        ApsLinkKeyRAMEntry[slot].txFrmCntr = key.txFrmCntr;
        ApsLinkKeyRAMEntry[slot].rxFrmCntr = key.rxFrmCntr;
        ApsLinkKeyRAMEntry[slot].pendingFlag = FALSE;
        p7_security_clear(&key, sizeof(key));
    }
trust_center:
    if (osal_nv_read(ZCD_NV_TRUSTCENTER_ADDR, 0, Z_EXTADDR_LEN, zgApsTrustCenterAddr) != SUCCESS)
        goto fault;
    return;
fault:
    p7_security_clear(&key, sizeof(key));
    p7_security_latch_failure();
}
