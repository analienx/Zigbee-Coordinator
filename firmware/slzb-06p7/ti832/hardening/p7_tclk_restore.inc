void APSME_TCLinkKeyInit(uint8_t setDefault)
{
    APSME_TCLinkKeyNVEntry_t row = {0};
    uint16_t i;
    const uint32_t delta = (uint32_t)MAX_TCLK_FRAMECOUNTER_CHANGES + 1u;
    if (!delta || !p7_security_persistence_ok()) goto fault;
    for (i = 0; i < gZDSECMGR_TC_DEVICE_MAX; ++i)
    {
        uint8_t status, used = FALSE;
        memset(&row, 0, sizeof(row));
        row.keyAttributes = ZG_DEFAULT_KEY;
        status = osal_nv_item_init_ex(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row);
        if (status != SUCCESS && status != NV_ITEM_UNINIT) goto fault;
        if (status == SUCCESS && setDefault)
        {
            if (!p7_security_commit(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row)) goto fault;
        }
        else
        {
            if (!p7_security_read(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row)) goto fault;
            used = !OsalPort_isBufSet(row.extAddr, 0, Z_EXTADDR_LEN);
            if (used)
            {
                if (row.txFrmCntr > UINT32_MAX - delta) goto fault;
                row.txFrmCntr += delta;
                if (!p7_security_commit(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row)) goto fault;
            }
        }
        /* Publish only after the persisted floor has read back. */
        TCLinkKeyRAMEntry[i].txFrmCntr = row.txFrmCntr;
        TCLinkKeyRAMEntry[i].rxFrmCntr = row.rxFrmCntr;
        TCLinkKeyRAMEntry[i].entryUsed = used;
        TCLinkKeyRAMEntry[i].pendingFlag = FALSE;
    }
    memset(&row, 0, sizeof(row));
    if (setDefault) APSME_EraseICEntry(NULL); /* explicit TI factory-reset path */
    return;
fault:
    memset(&row, 0, sizeof(row));
    p7_security_latch_failure();
}
