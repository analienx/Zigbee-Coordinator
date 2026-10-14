/* Update the complete legacy table once; a header-only update is not a partial
 * NVINTF write and must not replace/read beyond the full record. */
static void ZDSecMgrUpdateNV(uint16_t index)
{
    nvDeviceListHdr_t hdr = {0};
    uint16_t i;
    uint32_t length = sizeof(hdr) + gZDSECMGR_ENTRY_MAX * sizeof(ZDSecMgrEntry_t);
    uint8_t *packed;
    if (!p7_security_persistence_ok() || !ZDSecMgrEntries ||
        index >= gZDSECMGR_ENTRY_MAX || length > UINT16_MAX) goto fault;
    packed = OsalPort_malloc(length);
    if (!packed) goto fault;
    for (i = 0; i < gZDSECMGR_ENTRY_MAX; ++i)
    {
        if (ZDSecMgrEntries[i].ami != INVALID_NODE_ADDR) ++hdr.numRecs;
        memcpy(packed + sizeof(hdr) + i * sizeof(ZDSecMgrEntry_t),
               &ZDSecMgrEntries[i], sizeof(ZDSecMgrEntry_t));
    }
    memcpy(packed, &hdr, sizeof(hdr));
    if (!p7_security_commit(ZCD_NV_EX_LEGACY, ZCD_NV_APS_LINK_KEY_TABLE, (uint16_t)length, packed))
    {
        p7_security_clear(packed, length);
        OsalPort_free(packed);
        goto fault;
    }
    p7_security_clear(packed, length);
    OsalPort_free(packed);
    return;
fault:
    p7_security_latch_failure();
    ZDApp_PauseNwk();
    ZDApp_ChangeState(DEV_HOLD);
}
