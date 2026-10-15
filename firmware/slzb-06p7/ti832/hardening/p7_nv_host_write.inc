static void MT_SysOsalNVWrite(uint8_t *pBuf)
{
    uint8_t cmdId = pBuf[MT_RPC_POS_CMD1], frameLen = pBuf[MT_RPC_POS_LEN];
    uint8_t result = ZInvalidParameter;
    uint16_t item, offset, length, storedLength;
    uint8_t *data, *copy = NULL;
#if defined(ZCD_NV_POLL_RATE_OLD16)
    uint8_t converted[4];
#endif
    uint8_t header = cmdId == MT_SYS_OSAL_NV_WRITE ? 4 : 6;
    if (frameLen < header) goto respond;
    pBuf += MT_RPC_FRAME_HDR_SZ;
    item = OsalPort_buildUint16(pBuf);
    offset = header == 4 ? pBuf[2] : OsalPort_buildUint16(pBuf + 2);
    length = header == 4 ? pBuf[3] : OsalPort_buildUint16(pBuf + 4);
    if (!length || length > frameLen - header) goto respond;
    data = pBuf + header;
#if defined(ZCD_NV_POLL_RATE_OLD16)
    if (item == ZCD_NV_POLL_RATE_OLD16)
    {
        if (offset || length != 2) goto respond;
        OsalPort_bufferUint32(converted, OsalPort_buildUint16(data));
        data = converted;
        item = ZCD_NV_POLL_RATE;
        length = sizeof(converted);
    }
#endif
    storedLength = osal_nv_item_len(item);
    if (length > storedLength || offset > storedLength - length) goto respond;
    /* OSAL/NVINTF update writes an entire item. Preserve surrounding bytes for
     * the MT protocol's offset/chunk write, including normal backup restore. */
    if (offset || length != storedLength)
    {
        copy = OsalPort_malloc(storedLength);
        if (!copy) { result = ZMemError; goto respond; }
        if (osal_nv_read(item, 0, storedLength, copy) != ZSUCCESS)
        { result = NV_OPER_FAILED; goto respond; }
        OsalPort_memcpy(copy + offset, data, length);
        data = copy;
    }
    if (osal_nv_write(item, storedLength, data) != ZSUCCESS)
    { result = NV_OPER_FAILED; goto respond; }
    zgSetItem(item, storedLength, data); /* publish globals only after persistence */
    result = item == ZCD_NV_EXTADDR ? ZMacSetReq(ZMacExtAddr, data) : ZSuccess;
respond:
    if (copy) OsalPort_free(copy);
    MT_BuildAndSendZToolResponse(MT_SRSP_SYS, cmdId, sizeof(result), &result);
}
