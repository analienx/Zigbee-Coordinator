static void MT_SysOsalNVItemInit(uint8_t *pBuf)
{
    uint8_t result = ZInvalidParameter;
    uint16_t item, length;
    uint8_t prefix, *initial, *copy = NULL;
    uint8_t frameLen = pBuf[MT_RPC_POS_LEN];
    if (frameLen < 5) goto respond;
    pBuf += MT_RPC_FRAME_HDR_SZ;
    item = OsalPort_buildUint16(pBuf);
    length = OsalPort_buildUint16(pBuf + 2);
    prefix = pBuf[4];
    if (!length || prefix > frameLen - 5) goto respond;
#if defined(ZCD_NV_POLL_RATE_OLD16)
    if (item == ZCD_NV_POLL_RATE_OLD16) { result = ZSuccess; goto respond; }
#endif
    if (osal_nv_item_len(item) == length) { result = ZSuccess; goto respond; }
    initial = prefix ? pBuf + 5 : NULL;
    if (prefix && prefix < length)
    {
        copy = OsalPort_malloc(length);
        if (!copy) { result = ZMemError; goto respond; }
        memset(copy, 0, length);
        OsalPort_memcpy(copy, initial, prefix);
        initial = copy;
    }
    result = osal_nv_item_init(item, length, initial);
respond:
    if (copy) OsalPort_free(copy);
    MT_BuildAndSendZToolResponse(MT_SRSP_SYS, MT_SYS_OSAL_NV_ITEM_INIT, sizeof(result), &result);
}
