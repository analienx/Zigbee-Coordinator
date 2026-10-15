static void MT_AfDataRetrieve(uint8_t *pBuf)
{
    mtAfInMsgList_t *previous = NULL, *item = pMtAfInMsgList;
    uint8_t response[2] = { afStatus_INVALID_PARAMETER, 0 };
    uint16_t offset;
    uint8_t length;
    uint32_t timestamp;
    if (pBuf[MT_RPC_POS_LEN] < 7) goto respond;
    pBuf += MT_RPC_FRAME_HDR_SZ;
    timestamp = OsalPort_buildUint32(pBuf, 4);
    offset = OsalPort_buildUint16(pBuf + 4);
    length = pBuf[6];
    while (item && item->timestamp != timestamp)
    {
        previous = item;
        item = item->next;
    }
    if (!item) { response[0] = afStatus_FAILED; goto respond; }
    if (!length)
    {
        if (previous) previous->next = item->next;
        else pMtAfInMsgList = item->next;
        OsalPort_free(item);
        response[0] = afStatus_SUCCESS;
    }
    else if (length <= MT_RPC_DATA_MAX - sizeof(response) &&
             offset <= item->dataLen && length <= item->dataLen - offset)
    {
        uint8_t *reply = OsalPort_malloc((uint16_t)length + sizeof(response));
        if (!reply) { response[0] = afStatus_MEM_FAIL; goto respond; }
        reply[0] = afStatus_SUCCESS;
        reply[1] = length;
        OsalPort_memcpy(reply + sizeof(response), item->data + offset, length);
        MT_BuildAndSendZToolResponse(MT_RPC_CMD_SRSP | MT_RPC_SYS_AF,
            MT_AF_DATA_RETRIEVE, length + sizeof(response), reply);
        OsalPort_free(reply);
        return;
    }
respond:
    MT_BuildAndSendZToolResponse(MT_RPC_CMD_SRSP | MT_RPC_SYS_AF,
        MT_AF_DATA_RETRIEVE, sizeof(response), response);
}
