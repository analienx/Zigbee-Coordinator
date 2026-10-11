"""Prioritize host SRSP messages without changing ZNP wire semantics.

A dedicated FIFO for SRSP avoids waiting behind large AREQ bursts. Every
fifth accepted TX is an AREQ when both queues are populated (fairness).
No queue capacity is fabricated; telemetry captures the backlog for lab QC.
"""
import hashlib

TASK = "source/ti/zstack/npi/npi_task.c"

def replace_in_function(sdk, signature, pairs, changes):
    p = sdk / TASK
    original = p.read_text()
    if original.count(signature) != 1:
        raise ValueError("NPI function definition not unique: " + signature[:45])
    start = original.index(signature)
    brace = original.index("{", start)  # signature includes the opening brace
    level = 0
    stop = None
    for i in range(brace, len(original)):
        if original[i] == "{":
            level += 1
        elif original[i] == "}":
            level -= 1
            if level == 0:
                stop = i + 1
                break
    if stop is None:
        raise ValueError("Unclosed NPI function: " + signature[:45])
    body = original[start:stop]
    for before, after in pairs:
        if body.count(before) != 1:
            raise ValueError("NPI scoped anchor expected once; got %d: %s" %
                             (body.count(before), before[:80]))
        body = body.replace(before, after, 1)
    new_text = original[:start] + body + original[stop:]
    p.write_text(new_text)
    changes.append({"path": TASK,
                    "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
                    "after_sha256": hashlib.sha256(new_text.encode()).hexdigest()})

def apply(sdk, replace_exact, changes):
    replace_exact(sdk, TASK,
        "    NPIMSG_msg_t *npiMsg;\n"
        "} NPI_QueueRec;",
        "    NPIMSG_msg_t *npiMsg;\n"
        "    uint8_t rejectCount;  // Per-frame immediate-write rejection budget.\n"
        "} NPI_QueueRec;", changes)
    replace_exact(sdk, TASK,
        "static uint8_t npiTxRetryAttempts = 0;\n",
        "", changes)
    replace_exact(sdk, TASK,
        "#define NPI_TX_RETRY_US 50000u\n",
        "#define NPI_TX_RETRY_US 50000u\n"
        "#define NPI_SRSP_BURST_LIMIT 4u\n"
        "// UNPI: byte0 SOF, byte1 length, byte2 command0.\n"
        "#define NPI_UNPI_CMD0_INDEX 2u\n", changes)
    replace_exact(sdk, TASK,
        "static Queue_Handle npiTxQueue;\n",
        "static Queue_Handle npiTxQueue;\n"
        "// Host responses are not allowed to wait behind unrelated AREQs.\n"
        "static Queue_Handle npiSrspTxQueue;\n"
        "static volatile uint32_t npiSrspQueueDepth;\n"
        "static volatile uint32_t npiSrspQueueHighWater;\n"
        "static volatile uint32_t npiSrspQueueFallback;\n"
        "static uint8_t npiSrspBurst;\n", changes)
    replace_exact(sdk, TASK,
        "    npiTxQueue = Queue_create(NULL, NULL);\n",
        "    npiTxQueue = Queue_create(NULL, NULL);\n"
        "    npiSrspTxQueue = Queue_create(NULL, NULL);\n"
        "    // On allocation failure, keep the original FIFO path alive.\n"
        "    if (npiSrspTxQueue == NULL) { ++npiSrspQueueFallback; }\n", changes)

    # Both entry points produce the same on-wire UNPI frames and use the same
    # queue ownership contract; modify their valid ASYNC enqueue branch only.
    enqueue_old = "Queue_enqueue(npiTxQueue, &recPtr->_elem);"
    enqueue_new = (
        "// Prioritize MT SRSP replies over unsolicited AREQ bursts.\n"
        "                    if (npiSrspTxQueue != NULL &&\n"
        "                        pNPIMsg->pBufSize > NPI_UNPI_CMD0_INDEX &&\n"
        "                        (pNPIMsg->pBuf[NPI_UNPI_CMD0_INDEX] &\n"
        "                         MTRPC_CMD_TYPE_MASK) == MTRPC_CMD_SRSP)\n"
        "                    {\n"
        "                        Queue_enqueue(npiSrspTxQueue, &recPtr->_elem);\n"
        "                        ++npiSrspQueueDepth;\n"
        "                        if (npiSrspQueueDepth > npiSrspQueueHighWater)\n"
        "                            npiSrspQueueHighWater = npiSrspQueueDepth;\n"
        "                    }\n"
        "                    else\n"
        "                    {\n"
        "                        Queue_enqueue(npiTxQueue, &recPtr->_elem);\n"
        "                    }"
    )
    replace_in_function(sdk, "static void NPITask_processStackMsg(uint8_t *pMsg)\n{",
                        [(enqueue_old, enqueue_new)], changes)
    replace_in_function(sdk, "void NPITask_sendToHost(uint8_t *pMsg)\n{",
                        [(enqueue_old, enqueue_new)], changes)

    replace_in_function(sdk, "static void NPITask_incomingFrameCB(uint8_t frameSize, uint8_t *pFrame,\n                                    NPIMSG_Type msgType)\n{",
                        [("recPtr->npiMsg = npiMsgPtr;",
                          "recPtr->npiMsg = npiMsgPtr;\n        recPtr->rejectCount = 0;")], changes)
    replace_in_function(sdk, "static void NPITask_processStackMsg(uint8_t *pMsg)\n{",
                        [("recPtr->npiMsg = pNPIMsg;",
                          "recPtr->npiMsg = pNPIMsg;\n            recPtr->rejectCount = 0;")], changes)
    replace_in_function(sdk, "void NPITask_sendToHost(uint8_t *pMsg)\n{",
                        [("recPtr->npiMsg = pNPIMsg;",
                          "recPtr->npiMsg = pNPIMsg;\n        recPtr->rejectCount = 0;")], changes)

    replace_in_function(sdk, "static void NPITask_process(void)\n{", [
        ("if ((!Queue_empty(npiTxQueue)) && !npiTxRetryPending &&",
         "if ((!Queue_empty(npiTxQueue) ||\n"
         "                         (npiSrspTxQueue != NULL && !Queue_empty(npiSrspTxQueue))) &&\n"
         "                        !npiTxRetryPending &&"),
        ("if (Queue_empty(npiTxQueue))\n",
         "if (Queue_empty(npiTxQueue) &&\n"
         "                    (npiSrspTxQueue == NULL || Queue_empty(npiSrspTxQueue)))\n"),
        ("if (!Queue_empty(npiTxQueue))\n",
         "if (!Queue_empty(npiTxQueue) ||\n"
         "                        (npiSrspTxQueue != NULL && !Queue_empty(npiSrspTxQueue)))\n")
    ], changes)
    replace_in_function(sdk, "static void NPITask_ProcessTXQ(void)\n{",
                        [("npiTxRetryAttempts < NPI_TX_RETRY_MAX",
                          "recPtr->rejectCount < NPI_TX_RETRY_MAX"),
                         ("++npiTxRetryAttempts;", "++recPtr->rejectCount;"),
                         ("                npiTxRetryAttempts = 0;\n",
                          "                // Terminal refusal: free this record below.\n"),
                         ("            npiTxRetryAttempts = 0;\n",
                          "            // Accepted write consumes this record below.\n")], changes)
    replace_in_function(sdk, "static void NPITask_ProcessTXQ(void)\n{", [
        ("    recPtr = Queue_dequeue(npiTxQueue);\n",
         "    Queue_Handle selectedQueue = npiTxQueue;\n"
         "    uint8_t selectedSrsp = 0;\n"
         "    if ((npiSrspTxQueue != NULL) && !Queue_empty(npiSrspTxQueue) &&\n"
         "        (Queue_empty(npiTxQueue) || npiSrspBurst < NPI_SRSP_BURST_LIMIT))\n"
         "    {\n"
         "        selectedQueue = npiSrspTxQueue;\n"
         "        selectedSrsp = 1;\n"
         "    }\n"
         "    recPtr = Queue_dequeue(selectedQueue);\n"
         "    if (selectedSrsp && recPtr && npiSrspQueueDepth)\n"
         "        --npiSrspQueueDepth;\n"),
        ("Queue_putHead(npiTxQueue, &recPtr->_elem);",
         "Queue_putHead(selectedQueue, &recPtr->_elem);\n"
         "                if (selectedSrsp) ++npiSrspQueueDepth;"),
        ("            // Accepted write consumes this record below.\n"
         "        }\n"
         "\n"
         "        if (recPtr != NULL)",
         "            // Accepted write consumes this record below.\n"
         "            if (selectedSrsp)\n"
         "            {\n"
         "                if (npiSrspBurst < NPI_SRSP_BURST_LIMIT)\n"
         "                    ++npiSrspBurst;\n"
         "            }\n"
         "            else npiSrspBurst = 0;\n"
         "        }\n"
         "\n"
         "        if (recPtr != NULL)")
    ], changes)
    return [TASK]
