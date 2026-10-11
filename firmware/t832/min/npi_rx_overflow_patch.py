"""Fail-closed NPI RX-overflow resynchronization, instead of TI for(;;).

Overflow invalidates the current UART batch, buffered ring data and any partial
UNPI parser frame. Do NOT stitch corrupted partial bytes back into host commands.
"""
from npi_scoped_patcher import replace_in_path_function

TASK="source/ti/zstack/npi/npi_task.c"
RXBUF="source/ti/zstack/npi/npi_rxbuf.c"
RXHEAD="source/ti/zstack/npi/npi_rxbuf.h"
FRAME="source/ti/zstack/npi/npi_frame_mt.c"
FRAMEHEAD="source/ti/zstack/npi/npi_frame.h"

def apply(sdk, replace_exact, changes):
    replace_exact(sdk,TASK,
        "static volatile uint32_t npiRxFrameFailed;\n",
        "static volatile uint32_t npiRxFrameFailed;\n"
        "static volatile uint32_t npiRxOverflowEvents;\n"
        "static volatile uint32_t npiRxOverflowDiscardedBytes;\n"
        "static volatile uint8_t npiRxOverflowPending;\n",changes)
    replace_exact(sdk,RXHEAD,
        "uint16 NPIRxBuf_GetRxBufAvail();\n",
        "uint16 NPIRxBuf_GetRxBufAvail();\n"
        "void NPIRxBuf_DiscardAll(void);\n",changes)
    replace_exact(sdk,RXBUF,
        "uint16 NPIRxBuf_GetRxBufCount(void)\n",
        "void NPIRxBuf_DiscardAll(void)\n"
        "{\n"
        "    // Called by NPI task during overflow recovery, not from the ISR.\n"
        "    RxBufHead = RxBufTail;\n"
        "}\n"
        "\n"
        "uint16 NPIRxBuf_GetRxBufCount(void)\n",changes)
    replace_exact(sdk,FRAMEHEAD,
        "extern void NPIFrame_collectFrameData(void);\n",
        "extern void NPIFrame_collectFrameData(void);\n"
        "extern void NPIFrame_resetOnOverflow(void);\n",changes)
    # NPI parser owns pMsg only while assembling it. After handing the
    # completed message to the callback, pMsg is not ours to free.
    replace_in_path_function(sdk,FRAME,"void NPIFrame_collectFrameData(void)\n{",[
        ("                state = NPIFRAMEMT_SOP_STATE;\n"
         "\n"
         "                break;\n",
         "                state = NPIFRAMEMT_SOP_STATE;\n"
         "                pMsg = NULL; // Ownership transferred or freed at FCS.\n"
         "\n"
         "                break;\n")
    ],changes)
    # New function at file end keeps all parser state within parser task.
    from npi_diag_patch import append
    append(sdk,FRAME,'''
/* A broken UART chunk cannot be merged with an in-progress UNPI frame.
   Executed in the NPI task before accepting any further buffered input. */
void NPIFrame_resetOnOverflow(void)
{
    if (pMsg != NULL)
    {
        OsalPort_msgDeallocate(pMsg);
        pMsg = NULL;
    }
    state = NPIFRAMEMT_SOP_STATE;
    LEN_Token = 0;
    FSC_Token = 0;
    tempDataLen = 0;
}
''',changes)
    replace_in_path_function(sdk,TASK,"static void NPITask_transportRXCallBack(int size)\n{",[
        ("    // Check for overflow of RxBuf:\n"
         "    // If the buffer has overflowed there is no way to safely recover. All\n"
         "    // received bytes can be packet fragments so if a packet fragment is lost\n"
         "    // the frame parser behavior becomes undefined. The only way to prevent\n"
         "    // RxBuf overflow is to enable NPI_FLOW_CTRL.\n"
         "    //\n"
         "    // If NPI_FLOW_CTRL is not enabled then there is no way to for slave to\n"
         "    // control the master transfer rate. With NPI_FLOW_CTRL the slave has SRDY\n"
         "    // to use as a software flow control mechanism.\n"
         "    // When using NPI_FLOW_CTRL make sure to increase NPI_TL_BUF_SIZE\n"
         "    // to suit the NPI frame length that is expected to be received.\n"
         "    if ( size < NPIRxBuf_GetRxBufAvail() )\n",
         "    // No flow control: overflow invalidates every partial fragment.\n"
         "    // While recovery is pending, discard subsequent callbacks as well.\n"
         "    if (!npiRxOverflowPending && size > 0 &&\n"
         "        (uint32_t)size < (uint32_t)NPIRxBuf_GetRxBufAvail())\n"),
        ("    else\n"
         "    {\n"
         "        // Trap here for pending buffer overflow. If NPI_FLOW_CTRL is\n"
         "        // enabled, increase size of RxBuf to handle larger frames from host.\n"
         "        for(;;);\n"
         "    }\n",
         "    else\n"
         "    {\n"
         "        // Drop ONLY the rejected UART chunk; do not enqueue a fragment.\n"
         "        // NPITL_readTL drains the transport receive buffer, bounded by\n"
         "        // the physical callback length. No allocation or radio action.\n"
         "        uint8_t scratch[32];\n"
         "        int remaining = size > 0 ? size : 0;\n"
         "        npiRxOverflowPending = 1;\n"
         "        ++npiRxOverflowEvents;\n"
         "        while (remaining > 0)\n"
         "        {\n"
         "            uint16_t portion = (uint16_t)(remaining > 32 ? 32 : remaining);\n"
         "            uint16_t got = NPITL_readTL(scratch, portion);\n"
         "            if (!got) break;\n"
         "            npiRxOverflowDiscardedBytes += got;\n"
         "            remaining -= got;\n"
         "        }\n"
         "        TRANSPORT_RX_ISR_EVENT_FLAG = NPITASK_TRANSPORT_RX_EVENT;\n"
         "        Semaphore_post(npiSemHandle);\n"
         "    }\n")
    ],changes)
    replace_in_path_function(sdk,TASK,"static void NPITask_process(void)\n{",[
        ("                NPIFrame_collectFrameData();\n",
         "                if (npiRxOverflowPending)\n"
         "                {\n"
         "                    // In task context: free unfinished frame and invalidate\n"
         "                    // buffered ring. Never dispatch a truncated command.\n"
         "                    NPIFrame_resetOnOverflow();\n"
         "                    NPIRxBuf_DiscardAll();\n"
         "                    npiRxOverflowPending = 0;\n"
         "                }\n"
         "                else\n"
         "                {\n"
         "                    NPIFrame_collectFrameData();\n"
         "                }\n")
    ],changes)
    return [TASK,RXBUF,RXHEAD,FRAME,FRAMEHEAD]
