/* Template specialized for APS/TCLK without altering their public signatures. */
void P7_SAVE_FUNCTION(void)
{
    P7_KEY_TYPE row = {0};
    uint16_t i;
    if (!p7_security_persistence_ok()) goto fault;
    for (i = 0; i < P7_SLOT_COUNT; ++i)
    {
        if (P7_RAM_TABLE[i].pendingFlag != TRUE) continue;
        if (!p7_security_read(P7_NV_SECTION, i, sizeof(row), &row) ||
            P7_RAM_TABLE[i].txFrmCntr < row.txFrmCntr ||
            P7_RAM_TABLE[i].rxFrmCntr < row.rxFrmCntr ||
            P7_RAM_TABLE[i].txFrmCntr > UINT32_MAX - (uint32_t)P7_COUNTER_CHANGES) goto fault;
        row.txFrmCntr = P7_RAM_TABLE[i].txFrmCntr;
        row.rxFrmCntr = P7_RAM_TABLE[i].rxFrmCntr;
        if (!p7_security_commit(P7_NV_SECTION, i, sizeof(row), &row)) goto fault;
        P7_RAM_TABLE[i].pendingFlag = FALSE;
        p7_security_clear(&row, sizeof(row));
    }
    p7_security_clear(&row, sizeof(row));
    return;
fault:
    p7_security_clear(&row, sizeof(row));
    p7_security_latch_failure();
    ZDApp_PauseNwk();
    ZDApp_ChangeState(DEV_HOLD);
}
