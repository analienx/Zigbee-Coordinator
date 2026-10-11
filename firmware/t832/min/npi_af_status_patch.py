"""Precise AF submission/confirmation counters, no extra radio or OSAL allocation.

These counters describe the AF entry boundary, not undocumented APS/NWK pool
occupancy. A returned 0x11 must not be mislabelled as a proven OSAL heap leak.
"""
from npi_srsp_fairness_patch import replace_in_function
from npi_diag_patch import append

TASK="source/ti/zstack/npi/npi_task.c"
HEADER="source/ti/zstack/npi/npi_task.h"
MT_AF="source/ti/zstack/mt/mt_af.c"

def apply(sdk, replace_exact, changes):
    replace_exact(sdk, TASK,
        "static volatile uint32_t npiRxFrameFailed;\n",
        "static volatile uint32_t npiRxFrameFailed;\n"
        "static volatile uint32_t npiAfDirectAccepted;\n"
        "static volatile uint32_t npiAfDirectBufferFull;\n"
        "static volatile uint32_t npiAfDirectMemFailed;\n"
        "static volatile uint32_t npiAfDirectOther;\n"
        "static volatile uint32_t npiAfSourceAccepted;\n"
        "static volatile uint32_t npiAfSourceBufferFull;\n"
        "static volatile uint32_t npiAfConfirmCcaFailed;\n"
        "static volatile uint32_t npiAfConfirmOtherFailed;\n", changes)
    replace_exact(sdk, HEADER,
        "extern void NPITask_noteSrspEnqueueFailure(void);\n",
        "extern void NPITask_noteSrspEnqueueFailure(void);\n"
        "extern void NPITask_noteAfSubmit(uint8_t status, uint8_t sourceRoute);\n"
        "extern void NPITask_noteAfConfirm(uint8_t status);\n", changes)
    append(sdk,TASK,'''
/* Counters classify the AF *return stage*, not internal APS/NWK queues.
   Never allocate, sleep, issue retries, or log from a failure callback. */
void NPITask_noteAfSubmit(uint8_t status, uint8_t sourceRoute)
{
    uint32_t key = OsalPort_enterCS();
    if (sourceRoute)
    {
        if (status == 0u) ++npiAfSourceAccepted;
        else if (status == 0x11u) ++npiAfSourceBufferFull;
    }
    else
    {
        if (status == 0u) ++npiAfDirectAccepted;
        else if (status == 0x11u) ++npiAfDirectBufferFull;
        else if (status == 0x10u || status == 0x13u) ++npiAfDirectMemFailed;
        else ++npiAfDirectOther;
    }
    OsalPort_leaveCS(key);
}
void NPITask_noteAfConfirm(uint8_t status)
{
    uint32_t key = OsalPort_enterCS();
    if (status == 0xE1u) ++npiAfConfirmCcaFailed;
    else if (status != 0u) ++npiAfConfirmOtherFailed;
    OsalPort_leaveCS(key);
}
''',changes)
    replace_exact(sdk,MT_AF,
        '#include "mt.h"\n',
        '#include "mt.h"\n#include "npi_task.h"\n',changes)
    replace_in_function(sdk,"static void MT_AfDataRequest(uint8_t *pBuf)\n{",[
        ("    retValue = AF_DataRequest(&dstAddr, epDesc, cId, dataLen, pBuf, &transId, txOpts, radius);\n",
         "    retValue = AF_DataRequest(&dstAddr, epDesc, cId, dataLen, pBuf, &transId, txOpts, radius);\n"
         "    NPITask_noteAfSubmit(retValue, 0u);\n")
    ],changes)
    replace_in_function(sdk,"static void MT_AfDataRequestSrcRtg(uint8_t *pBuf)\n{",[
        ("    /* Free the memory allocated */\n",
         "    /* Count only a real AF source-route invocation, not earlier parse failure. */\n"
         "    if (epDesc != NULL)\n"
         "        NPITask_noteAfSubmit(retValue, 1u);\n"
         "    /* Free the memory allocated */\n")
    ],changes)
    replace_in_function(sdk,"static void MT_AfDataStore(uint8_t *pBuf)\n{",[
        ("    (void)OsalPort_free(pMtAfDataReq);\n",
         "    NPITask_noteAfSubmit(rtrn, 0u);\n"
         "    (void)OsalPort_free(pMtAfDataReq);\n")
    ],changes)
    replace_in_function(sdk,"void MT_AfDataConfirm(afDataConfirm_t *pMsg)\n{",[
        ("  retArray[0] = pMsg->hdr.status;\n",
         "  retArray[0] = pMsg->hdr.status;\n"
         "  NPITask_noteAfConfirm(retArray[0]);\n")
    ],changes)
    return [TASK,HEADER,MT_AF]
