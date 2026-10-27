#!/usr/bin/env python3
"""Source-pinned SYS F2 v4.2: 18 MT/NPI response-stage counters in unused slots.

Apply ONLY after canonical B4 F2 and the existing, already-tested
r4_af_register_handoff overlay on a disposable TI 8.33 source checkout.
No other UART owner, changed queue policy, RF command or NV operation.
"""
from pathlib import Path
import hashlib

CLIENT="source/ti/zstack/npi/npi_client_mt.c"
TASK="source/ti/zstack/npi/npi_task.c"
SYS="source/ti/zstack/mt/mt_sys.c"
MARKER="B4_F2_V42_RESPONSE_LIFECYCLE"
GENERAL=("Produced","Enqueued","AllocFailed","SendFailed","NpiReceived",
         "FramedQueued","FramingFailed","TlSubmitted","TlRejected")
AF=("Produced","Enqueued","AllocFailed","SendFailed","NpiReceived",
    "FramedQueued","FramingFailed","Dequeued","TlRejected")

def one(src, old, new, tag):
    if src.count(old)!=1:
        raise ValueError("F2_V42_SOURCE_DRIFT_"+tag+":"+str(src.count(old)))
    return src.replace(old,new,1)

def apply(sdk):
    sdk=Path(sdk)
    original={p:(sdk/p).read_text(encoding="utf-8") for p in (CLIENT,TASK,SYS)}
    c,n,s=(original[p] for p in (CLIENT,TASK,SYS))
    if (any(MARKER in x for x in original.values()) or
        "B4_AfRspProduced" not in c or
        "B4_AfRspNpiReceived" not in n or
        "B4_SysReadOnlyDiagnosticsV4" not in s or
        "B4_SysAfResponseTrace" not in s):
        raise ValueError("F2_V42_REQUIRES_PINNED_R4_F2_AND_AF_F3")
    c=one(c,"volatile uint32_t B4_AfRspProduced = 0u;",
        "/* "+MARKER+": ALL synchronous MT replies. */\n"+
        "\n".join("volatile uint32_t B4_AllRsp"+k+" = 0u;" for k in GENERAL[:4])+
        "\nvolatile uint32_t B4_AfRspProduced = 0u;","PRODUCER_COUNTER_DEFS")
    c=one(c,"    uint8_t afReg = (cmdType == 0x64u && cmdId == 0x00u);",
        "    uint8_t afReg = (cmdType == 0x64u && cmdId == 0x00u);\n"
        "    uint8_t allSrsp = ((cmdType & 0xE0u) == 0x60u);","ALL_SRSP_CLASS")
    c=one(c,"    if (afReg) B4_AfRspTick(&B4_AfRspProduced);",
        "    if (afReg) B4_AfRspTick(&B4_AfRspProduced);\n"
        "    if (allSrsp) B4_AfRspTick(&B4_AllRspProduced);","PRODUCED")
    c=one(c,"            if (afReg) B4_AfRspTick(&B4_AfRspSendFailed);",
        "            if (afReg) B4_AfRspTick(&B4_AfRspSendFailed);\n"
        "            if (allSrsp) B4_AfRspTick(&B4_AllRspSendFailed);",
        "SEND_FAILED")
    c=one(c,
        """        else if (afReg)
        {
            B4_AfRspTick(&B4_AfRspEnqueued);
        }""",
        """        else
        {
            if (afReg) B4_AfRspTick(&B4_AfRspEnqueued);
            if (allSrsp) B4_AfRspTick(&B4_AllRspEnqueued);
        }""",
        "SEND_SUCCEEDED")
    c=one(c,"        if (afReg) B4_AfRspTick(&B4_AfRspAllocFailed);",
        "        if (afReg) B4_AfRspTick(&B4_AfRspAllocFailed);\n"
        "        if (allSrsp) B4_AfRspTick(&B4_AllRspAllocFailed);",
        "ALLOC_FAILED")
    n=one(n,"volatile uint32_t B4_AfRspNpiReceived = 0u;",
        "/* "+MARKER+": original NPI consumer and TL. */\n"+
        "\n".join("volatile uint32_t B4_AllRsp"+k+" = 0u;" for k in GENERAL[4:])+
        "\nvolatile uint32_t B4_AfRspNpiReceived = 0u;","NPI_COUNTER_DEFS")
    n=one(n,
        "    uint8_t afResponse = (pMsg != NULL && pMsg[1] == 0x64u && pMsg[2] == 0x00u);",
        "    uint8_t afResponse = (pMsg != NULL && pMsg[1] == 0x64u && pMsg[2] == 0x00u);\n"
        "    uint8_t allSrspResponse = (pMsg != NULL && (pMsg[1] & 0xE0u) == 0x60u);",
        "NPI_RX_SRSP_CLASS")
    n=one(n,"    if (afResponse) B4_AfNpiTick(&B4_AfRspNpiReceived);",
        "    if (afResponse) B4_AfNpiTick(&B4_AfRspNpiReceived);\n"
        "    if (allSrspResponse) B4_AfNpiTick(&B4_AllRspNpiReceived);",
        "NPI_RX_COUNT")
    n=one(n,
        "                    if (afResponse) B4_AfNpiTick(&B4_AfRspFramedQueued);",
        "                    if (afResponse) B4_AfNpiTick(&B4_AfRspFramedQueued);\n"
        "                    if (allSrspResponse) B4_AfNpiTick(&B4_AllRspFramedQueued);",
        "NPI_QUEUE_COUNT")
    fail="if (afResponse) B4_AfNpiTick(&B4_AfRspFramingFailed);"
    n=one(n,fail,fail+"\n          if (allSrspResponse) B4_AfNpiTick(&B4_AllRspFramingFailed);",
          "NPI_RECORD_ALLOC_FAIL")
    fail_null="if (afResponse && pNPIMsg == NULL) B4_AfNpiTick(&B4_AfRspFramingFailed);"
    n=one(n,fail_null,fail_null+"\n    if (allSrspResponse && pNPIMsg == NULL) B4_AfNpiTick(&B4_AllRspFramingFailed);",
          "NPI_FRAME_NULL")
    n=one(n,
        """uint8_t afResponse = (recPtr->npiMsg->pBufSize >= 6u &&
                                  recPtr->npiMsg->pBuf[2] == 0x64u &&
                                  recPtr->npiMsg->pBuf[3] == 0x00u);""",
        """uint8_t afResponse = (recPtr->npiMsg->pBufSize >= 6u &&
                                  recPtr->npiMsg->pBuf[2] == 0x64u &&
                                  recPtr->npiMsg->pBuf[3] == 0x00u);
            uint8_t allSrspResponse = (recPtr->npiMsg->pBufSize >= 5u &&
                                  (recPtr->npiMsg->pBuf[2] & 0xE0u) == 0x60u);""",
        "NPI_TX_SRSP_CLASS")
    n=one(n,
        """            if (afResponse)
            {
                if (submitted == recPtr->npiMsg->pBufSize)""",
        """            if (allSrspResponse)
                B4_AfNpiTick(submitted == recPtr->npiMsg->pBufSize ?
                    &B4_AllRspTlSubmitted : &B4_AllRspTlRejected);
            if (afResponse)
            {
                if (submitted == recPtr->npiMsg->pBufSize)""",
        "NPI_TL_RESULT")
    s=one(s,"static uint32_t B4_V4SampleSequence = 0u;",
        "/* "+MARKER+": COUNTS ARE SUBMISSION EVENTS, NOT PHYSICAL UART DONE. */\n"+
        "\n".join("extern volatile uint32_t B4_AllRsp"+k+";" for k in GENERAL)+"\n"+
        "\n".join("extern volatile uint32_t B4_AfRsp"+k+";" for k in AF)+"\n"+
        "static uint32_t B4_V4SampleSequence = 0u;","F2_COUNTER_EXTERN")
    s=one(s,"    uint32_t i;\n    uint32_t key = OsalPort_enterCS();",
        "    uint32_t i;\n    uint32_t causal[18]; /* 72B native stack check mandatory */\n"
        "    uint32_t key = OsalPort_enterCS();","F2_STACK")
    s=one(s,"    seq = ++B4_V4SampleSequence;",
        "    seq = ++B4_V4SampleSequence;\n"+
        "\n".join("    causal["+str(i)+"] = B4_AllRsp"+k+";" for i,k in enumerate(GENERAL))+"\n"+
        "\n".join("    causal["+str(9+i)+"] = B4_AfRsp"+k+";" for i,k in enumerate(AF)),
        "F2_ATOMIC_SNAPSHOT")
    s=one(s,"    payload[12] = 0x2Cu;",
        "    payload[12] = 0xECu; payload[13] = 0xFFu; payload[14] = 0xFFu;",
        "F2_VALID_ASYNC_MASK")
    s=one(s,"    payload[12] = 0x3Fu;",
        "    payload[12] = 0xFFu; payload[13] = 0xFFu; payload[14] = 0xFFu;",
        "F2_VALID_SRSP_MASK")
    s=one(s,"    B4_DiagPutU32(payload + 52, uart_finished);",
        "    B4_DiagPutU32(payload + 52, uart_finished);\n"
        "    for (i = 0u; i < 18u; ++i)\n"
        "        B4_DiagPutU32(payload + 56u + i * 4u, causal[i]);",
        "F2_18_BOUNDED_SLOTS")
    s=one(s,"    payload[157] = 1u; /* v4 ABI minor */",
        "    payload[157] = 2u; /* F2 v4.2 MT/NPI causality */",
        "F2_MINOR")
    # The steady-state outage was AF_DATA_REQUEST SRSP starvation.
    # F3 already exposes all nine AF_REGISTER counters; reuse F2 slots
    # 15..23 for the *frequent* AF data-request family instead.
    af_data=("Produced","Enqueued","AllocFailed","SendFailed","NpiReceived",
             "FramedQueued","FramingFailed","TlSubmitted","TlRejected")
    c=one(c,"volatile uint32_t B4_AfRspProduced = 0u;",
        "\n".join("volatile uint32_t B4_AfDataRsp"+k+" = 0u;" for k in af_data[:4])+
        "\nvolatile uint32_t B4_AfRspProduced = 0u;","AFDATA_PRODUCER_DEFS")
    key="    uint8_t allSrsp = ((cmdType & 0xE0u) == 0x60u);"
    c=one(c,key,key+
        "\n    uint8_t afData = (cmdType == 0x64u && cmdId >= 0x01u && cmdId <= 0x03u);",
        "AFDATA_PRODUCER_CLASS")
    for tag,needle in (
        ("Produced","    if (allSrsp) B4_AfRspTick(&B4_AllRspProduced);"),
        ("SendFailed","            if (allSrsp) B4_AfRspTick(&B4_AllRspSendFailed);"),
        ("Enqueued","            if (allSrsp) B4_AfRspTick(&B4_AllRspEnqueued);"),
        ("AllocFailed","        if (allSrsp) B4_AfRspTick(&B4_AllRspAllocFailed);"),
    ):
        c=one(c,needle,needle+
            "\n    if (afData) B4_AfRspTick(&B4_AfDataRsp"+tag+");",
            "AFDATA_PRODUCER_"+tag)
    n=one(n,"volatile uint32_t B4_AfRspNpiReceived = 0u;",
        "\n".join("volatile uint32_t B4_AfDataRsp"+k+" = 0u;" for k in af_data[4:])+
        "\nvolatile uint32_t B4_AfRspNpiReceived = 0u;","AFDATA_NPI_DEFS")
    key="    uint8_t allSrspResponse = (pMsg != NULL && (pMsg[1] & 0xE0u) == 0x60u);"
    n=one(n,key,key+
        "\n    uint8_t afDataResponse = (pMsg != NULL && pMsg[1] == 0x64u && "
        "pMsg[2] >= 0x01u && pMsg[2] <= 0x03u);",
        "AFDATA_NPI_RX_CLASS")
    for tag,needle in (
        ("NpiReceived","    if (allSrspResponse) B4_AfNpiTick(&B4_AllRspNpiReceived);"),
        ("FramedQueued","                    if (allSrspResponse) B4_AfNpiTick(&B4_AllRspFramedQueued);"),
        ("FramingFailed","          if (allSrspResponse) B4_AfNpiTick(&B4_AllRspFramingFailed);"),
    ):
        n=one(n,needle,needle+
            "\n    if (afDataResponse) B4_AfNpiTick(&B4_AfDataRsp"+tag+");",
            "AFDATA_NPI_"+tag)
    key="    if (allSrspResponse && pNPIMsg == NULL) B4_AfNpiTick(&B4_AllRspFramingFailed);"
    n=one(n,key,key+
        "\n    if (afDataResponse && pNPIMsg == NULL) B4_AfNpiTick(&B4_AfDataRspFramingFailed);",
        "AFDATA_NPI_FRAME_NULL")
    key="            uint8_t allSrspResponse = (recPtr->npiMsg->pBufSize >= 5u &&\n                                  (recPtr->npiMsg->pBuf[2] & 0xE0u) == 0x60u);"
    n=one(n,key,key+
        "\n            uint8_t afDataResponse = (recPtr->npiMsg->pBufSize >= 6u && "
        "recPtr->npiMsg->pBuf[2] == 0x64u && "
        "recPtr->npiMsg->pBuf[3] >= 0x01u && "
        "recPtr->npiMsg->pBuf[3] <= 0x03u);",
        "AFDATA_NPI_TX_CLASS")
    key="            if (allSrspResponse)\n                B4_AfNpiTick(submitted == recPtr->npiMsg->pBufSize ?\n                    &B4_AllRspTlSubmitted : &B4_AllRspTlRejected);"
    n=one(n,key,key+
        "\n            if (afDataResponse)\n"
        "                B4_AfNpiTick(submitted == recPtr->npiMsg->pBufSize ?\n"
        "                    &B4_AfDataRspTlSubmitted : &B4_AfDataRspTlRejected);",
        "AFDATA_TL_SUBMIT")
    s=one(s,"static uint32_t B4_V4SampleSequence = 0u;",
        "\n".join("extern volatile uint32_t B4_AfDataRsp"+k+";" for k in af_data)+
        "\nstatic uint32_t B4_V4SampleSequence = 0u;","AFDATA_F2_EXTERNS")
    for i,name in enumerate(AF):
        s=one(s,"    causal["+str(9+i)+"] = B4_AfRsp"+name+";",
            "    causal["+str(9+i)+"] = B4_AfDataRsp"+af_data[i]+";",
            "AFDATA_F2_SLOT_"+str(i))
    changed={CLIENT:c,TASK:n,SYS:s}
    for p,data in changed.items():
        (sdk/p).write_text(data,encoding="utf-8",newline="")
    return {
        "schema":"p7u-f2-v42-causal-18-counter-v1",
        "source_ready_only":True,"physical_radio_changed":False,
        "uart_extra_requests":0,"no_nv_writes":True,
        "response_abi":"SYS_F2_160_MINOR2",
        "slot6_14":["all_"+k for k in GENERAL],
        "slot15_23":["af_data_"+k for k in AF],
        "before_sha256":{p:hashlib.sha256(data.encode()).hexdigest()
                         for p,data in original.items()},
        "modified_sha256":{p:hashlib.sha256(data.encode()).hexdigest()
                           for p,data in changed.items()},
    }
