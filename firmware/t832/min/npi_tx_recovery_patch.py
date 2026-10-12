"""Bounded non-flow-control UART TX recovery for pinned TI P10 NPI.

Only an *immediately rejected* write may be retried; a returned accepted
write must never be retransmitted merely because its later ACK is missing.
"""
def apply(sdk, replace_exact, changes):
    tl = "source/ti/zstack/npi/npi_tl.c"
    replace_exact(sdk, tl,
        "    len = transportWrite(npiTxBufLen);\n"
        "\n"
        "#if (NPI_FLOW_CTRL == 1)",
        "    len = transportWrite(npiTxBufLen);\n"
        "    if (len == 0)\n"
        "    {\n"
        "        // Transport rejected the write synchronously. No bytes accepted:\n"
        "        // release busy ownership and discard any pending fragment view.\n"
        "        npiTxActive = FALSE;\n"
        "        npiTxBufLen = 0;\n"
        "        msgFrag = NULL;\n"
        "        msgFragLen = 0;\n"
        "    }\n"
        "\n"
        "#if (NPI_FLOW_CTRL == 1)", changes)

    task = "source/ti/zstack/npi/npi_task.c"
    replace_exact(sdk, task,
        "#define NPITASK_PRIORITY 4\n",
        "#define NPITASK_PRIORITY 4\n"
        "\n"
        "// A refused UART write (return 0) has NOT accepted the message.\n"
        "// Limit retry attempts and use a one-shot ClockP rather than spinning.\n"
        "#define NPI_TX_RETRY_MAX 3\n"
        "#define NPI_TX_RETRY_US 50000u\n", changes)
    replace_exact(sdk, task,
        "static Queue_Handle npiRxQueue;\n",
        "static Queue_Handle npiRxQueue;\n"
        "\n"
        "static ClockP_Struct npiTxRetryClock;\n"
        "static ClockP_Handle npiTxRetryHandle;\n"
        "static volatile uint8_t npiTxRetryPending = 0;\n"
        "static uint8_t npiTxRetryAttempts = 0;\n"
        "static volatile uint32_t npiTxImmediateRejects = 0;\n"
        "static volatile uint32_t npiTxRejectedDrops = 0;\n", changes)
    replace_exact(sdk, task,
        "static void NPITask_ProcessTXQ(void);\n",
        "static void NPITask_ProcessTXQ(void);\n"
        "static void NPITask_txRetryClockCB(uintptr_t arg);\n", changes)
    replace_exact(sdk, task,
        "    npiSemHandle = Semaphore_handle(&structSem);\n",
        "    npiSemHandle = Semaphore_handle(&structSem);\n"
        "\n"
        "    // Construct a fixed-size one-shot timer: no runtime heap allocation.\n"
        "    ClockP_Params txClockParams;\n"
        "    ClockP_Params_init(&txClockParams);\n"
        "    uint32_t tickUs = ClockP_getSystemTickPeriod();\n"
        "    uint32_t delayTicks = tickUs ? ((NPI_TX_RETRY_US + tickUs - 1u) / tickUs) : 1u;\n"
        "    if (!delayTicks) { delayTicks = 1u; }\n"
        "    npiTxRetryHandle = ClockP_construct(&npiTxRetryClock,\n"
        "                                           NPITask_txRetryClockCB,\n"
        "                                           delayTicks, &txClockParams);\n", changes)
    replace_exact(sdk, task,
        "            // An ASYNC message is ready to send to the Host\n"
        "            if(npiServiceTaskEvents & NPITASK_TX_READY_EVENT)",
        "            // An ASYNC message is ready to send to the Host\n"
        "            if(npiServiceTaskEvents & NPITASK_TX_READY_EVENT)", changes)
    replace_exact(sdk, task,
        "                    if ((!Queue_empty(npiTxQueue)) && !NPITL_checkNpiBusy())\n",
        "                    if ((!Queue_empty(npiTxQueue)) && !npiTxRetryPending &&\n"
        "                        !NPITL_checkNpiBusy())\n", changes)
    replace_exact(sdk, task,
        "                else\n"
        "                {\n"
        "                    // Q is not empty, there's more to handle so preserve the\n"
        "                    // flag and repost to the task semaphore.\n"
        "                    Semaphore_post(npiSemHandle);\n"
        "                }\n"
        "            }\n\n\n"
        "            // The Transport Layer has received some bytes",
        "                else\n"
        "                {\n"
        "                    if (npiTxRetryPending)\n"
        "                    {\n"
        "                        // The one-shot timer will re-enable this event;\n"
        "                        // keep other NPI traffic responsive meanwhile.\n"
        "                        npiServiceTaskEvents &= ~NPITASK_TX_READY_EVENT;\n"
        "                    }\n"
        "                    else\n"
        "                    {\n"
        "                        Semaphore_post(npiSemHandle);\n"
        "                    }\n"
        "                }\n"
        "            }\n\n\n"
        "            // The Transport Layer has received some bytes", changes)
    replace_exact(sdk, task,
        "    recPtr = Queue_dequeue(npiTxQueue);\n"
        "\n"
        "    if (recPtr != NULL)\n"
        "    {\n"
        "        NPITL_writeTL(recPtr->npiMsg->pBuf, recPtr->npiMsg->pBufSize);\n"
        "\n"
        "        //free the Queue record\n"
        "        OsalPort_msgDeallocate(recPtr->npiMsg->pBuf);\n"
        "        OsalPort_free(recPtr->npiMsg);\n"
        "        OsalPort_free(recPtr);\n"
        "    }\n"
        "\n"
        "    OsalPort_leaveCS(key);\n"
        "}\n"
        "\n"
        "#if defined(NPI_SREQRSP)",
        "    recPtr = Queue_dequeue(npiTxQueue);\n"
        "\n"
        "    if (recPtr != NULL)\n"
        "    {\n"
        "        if (NPITL_writeTL(recPtr->npiMsg->pBuf, recPtr->npiMsg->pBufSize) == 0)\n"
        "        {\n"
        "            ++npiTxImmediateRejects;\n"
        "            if ((npiTxRetryHandle != NULL) &&\n"
        "                (npiTxRetryAttempts < NPI_TX_RETRY_MAX))\n"
        "            {\n"
        "                ++npiTxRetryAttempts;\n"
        "                // Only safe to retry because transport explicitly\n"
        "                // rejected BEFORE accepting any bytes.\n"
        "                Queue_putHead(npiTxQueue, &recPtr->_elem);\n"
        "                npiTxRetryPending = 1;\n"
        "                ClockP_start(npiTxRetryHandle);\n"
        "                recPtr = NULL; // Ownership remains with the TX queue.\n"
        "            }\n"
        "            else\n"
        "            {\n"
        "                // Bounded failure: avoid heap growth or infinite retry.\n"
        "                ++npiTxRejectedDrops;\n"
        "                npiTxRetryAttempts = 0;\n"
        "            }\n"
        "        }\n"
        "        else\n"
        "        {\n"
        "            npiTxRetryAttempts = 0;\n"
        "        }\n"
        "\n"
        "        if (recPtr != NULL)\n"
        "        {\n"
        "            OsalPort_msgDeallocate(recPtr->npiMsg->pBuf);\n"
        "            OsalPort_free(recPtr->npiMsg);\n"
        "            OsalPort_free(recPtr);\n"
        "        }\n"
        "    }\n"
        "\n"
        "    OsalPort_leaveCS(key);\n"
        "}\n"
        "\n"
        "static void NPITask_txRetryClockCB(uintptr_t arg)\n"
        "{\n"
        "    (void)arg;\n"
        "    uint32_t key = OsalPort_enterCS();\n"
        "    npiTxRetryPending = 0;\n"
        "    npiServiceTaskEvents |= NPITASK_TX_READY_EVENT;\n"
        "    OsalPort_leaveCS(key);\n"
        "    Semaphore_post(npiSemHandle);\n"
        "}\n"
        "\n"
        "#if defined(NPI_SREQRSP)", changes)
    return [tl, task]
