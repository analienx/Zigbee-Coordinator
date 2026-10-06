#!/usr/bin/env python3
"""Layer T832-DIAG-R0 instrumentation on the exact T832-KCTRL-R0 source delta.

This patcher is intentionally fail-closed: every source edit is exact-match
and the control patch is applied first from its pinned manifest. No fuzzy
patching is permitted.
"""
from __future__ import annotations

import argparse
import importlib.util
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
VARIANT = "T832-DIAG-R0"


def candidate_build_id() -> str:
    """Immutable source identity: short git SHA of the candidate repo checkout."""
    root = HERE.parent.parent
    proc = subprocess.run(
        ["git", "rev-parse", "--short=8", "HEAD"],
        cwd=str(root),
        check=False,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise SystemExit(f"cannot determine candidate build id: {proc.stderr.strip()}")
    value = proc.stdout.strip().lower()
    if len(value) != 8 or any(c not in "0123456789abcdef" for c in value):
        raise SystemExit(f"candidate build id is not 8 hex chars: {value!r}")
    return value


def load_control_module():
    spec = importlib.util.spec_from_file_location("t832_apply_kctrl", HERE / "apply_kctrl.py")
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load apply_kctrl.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Exact:
    def __init__(self) -> None:
        self.edits: list[dict[str, Any]] = []

    def replace(self, path: Path, old: str, new: str, label: str, count: int = 1) -> None:
        text = path.read_text(encoding="utf-8")
        actual = text.count(old)
        if actual != count:
            raise SystemExit(f"{path}: {label}: expected {count} exact match(es), found {actual}")
        result = text.replace(old, new, count)
        path.write_text(result, encoding="utf-8")
        self.edits.append({"label": label, "path": str(path).replace("\\", "/"),
                           "before_sha256": hashlib.sha256(text.encode()).hexdigest(),
                           "after_sha256": hashlib.sha256(result.encode()).hexdigest()})

    def append(self, path: Path, text: str, label: str) -> None:
        existing = path.read_text(encoding="utf-8")
        if text.strip() in existing:
            raise SystemExit(f"{path}: {label}: diagnostic block already present")
        result = existing.rstrip() + "\n\n" + text.rstrip() + "\n"
        path.write_text(result, encoding="utf-8")
        self.edits.append({"label": label, "path": str(path).replace("\\", "/"),
                           "before_sha256": hashlib.sha256(existing.encode()).hexdigest(),
                           "after_sha256": hashlib.sha256(result.encode()).hexdigest()})


def include_after(ex: Exact, path: Path, marker: str, header: str, label: str) -> None:
    ex.replace(path, marker, marker + f'#include "{header}"\n', label)


def apply_diag(sdk: Path, examples: Path, control_manifest: Path) -> dict[str, Any]:
    control = load_control_module()
    control_evidence = control.apply(sdk, examples, control_manifest)
    ex = Exact()

    mt = sdk / "source/ti/zstack/mt"
    npi = sdk / "source/ti/zstack/npi"
    api = sdk / "source/ti/zstack/stack/api"
    startup = sdk / "source/ti/zstack/startup/main.c"

    shutil.copy2(HERE / "t832_diag.h", mt / "t832_diag.h")
    shutil.copy2(HERE / "t832_diag_impl.inc", mt / "t832_diag_impl.inc")
    for name in ("t832_diag_r5.inc", "t832_fatal.h", "t832_diag_nwk.inc"):
        shutil.copy2(HERE / name, mt / name)

    # R06: capture the reset source at the top of main(), the first proven
    # executed application path. Boot.c/Boot.o is not linked into the ZNP
    # image (absent from map and symbols), so the previous Boot-driver
    # writer was dead code. SysCtrlResetSourceGet is a pure register read and
    # nothing in the image clears the source, so main() entry is the earliest
    # safe capture point. Validity is marked with T832_DIAG_BOOT_MAGIC and
    # checked by T832Diag_init before use.
    ex.replace(
        startup,
        "int main()\n{\n#ifndef USE_DEFAULT_USER_CFG\n",
        "int main()\n{\n"
        "    extern void T832Diag_captureResetCauseEarly(uint32_t cause);\n"
        "    T832Diag_captureResetCauseEarly((uint32_t)SysCtrlResetSourceGet());\n"
        "#ifndef USE_DEFAULT_USER_CFG\n",
        "diag.boot.reset_cause",
    )

    # Compile-time diagnostic identity without changing KCTRL routing/resource semantics.
    # T832_BUILD_ID is the immutable source identity (candidate short SHA).
    build_id = candidate_build_id()
    version = mt / "mt_version.c"
    # Herdsman interprets revision as a feature/date threshold. A random
    # git SHA here would enable assoc/LED paths that the matched control
    # does not enable. Keep the diagnostic identity in the same bucket;
    # exact candidate SHA remains in DEBUG and the package manifest.
    ex.replace(version, "CODE_REVISION_NUMBER >>", "8320002u >>",
               "diag.sys_version_variant_id", count=4)
    opts = sdk / "source/ti/zstack/apps/znp/znp_cnf.opts"
    ex.replace(
        opts,
        "-DMT_APP_CNF_FUNC\n",
        f"-DMT_APP_CNF_FUNC\n-DT832_DIAG_R0=1\n-DT832_BUILD_ID=0x{build_id}\n",
        "diag.compile_identity",
    )

    # Reserve a dedicated MT event bit for the once-per-second exporter scheduler.
    mth = mt / "mt.h"
    ex.replace(
        mth,
        "#define MT_ZNP_BASIC_RSP_EVENT          0x2000\n#endif\n",
        "#define MT_ZNP_BASIC_RSP_EVENT          0x2000\n#endif\n"
        "#define MT_DIAG_TICK_EVENT              0x4000\n",
        "diag.mt_event",
    )

    # Runtime implementation lives in the existing MT debug translation unit.
    mt_debug = mt / "mt_debug.c"
    ex.append(mt_debug, '#include "t832_diag_impl.inc"', "diag.runtime_include")

    # MT scheduler progress and periodic exporter. Telemetry scheduling is distinct
    # from real MT/Zigbee work in the emitted fields.
    mt_task = mt / "mt_task.c"
    include_after(ex, mt_task, '#include "mt.h"\n', "t832_diag.h", "diag.mt_task.include")
    ex.replace(
        mt_task,
        "  MT_TaskID = task_id;\n",
        "  MT_TaskID = task_id;\n  T832Diag_init(task_id);\n",
        "diag.mt_task.init",
    )
    ex.replace(
        mt_task,
        "  OsalPort_setEvent(task_id, MT_SECONDARY_INIT_EVENT);\n",
        "  OsalPort_setEvent(task_id, MT_SECONDARY_INIT_EVENT);\n"
        "  OsalPortTimers_startTimer(task_id, MT_DIAG_TICK_EVENT, 1000u);\n",
        "diag.mt_task.timer_start",
    )
    ex.replace(
        mt_task,
        "  mtOSALSerialData_t *pMsg;\n\n",
        "  mtOSALSerialData_t *pMsg;\n\n"
        "  T832Diag_taskScheduled(task_id, events);\n",
        "diag.mt_task.schedule",
    )
    ex.replace(
        mt_task,
        "      MT_ProcessIncomingCommand(pMsg);\n",
        "      T832Diag_taskWork(T832_DIAG_WORK_MT, SYS_EVENT_MSG);\n"
        "      MT_ProcessIncomingCommand(pMsg);\n",
        "diag.mt_task.command_work",
    )
    ex.replace(
        mt_task,
        "  if ( events & MT_SECONDARY_INIT_EVENT )\n  {\n    MT_Init();\n",
        "  if ( events & MT_SECONDARY_INIT_EVENT )\n  {\n"
        "    T832Diag_taskWork(T832_DIAG_WORK_MT, MT_SECONDARY_INIT_EVENT);\n"
        "    MT_Init();\n",
        "diag.mt_task.init_work",
    )
    ex.replace(
        mt_task,
        "  if ( events & MT_ZTOOL_SERIAL_RCV_BUFFER_FULL )\n  {\n"
        "    /* Return unproccessed events */\n",
        "  if ( events & MT_ZTOOL_SERIAL_RCV_BUFFER_FULL )\n  {\n"
        "    T832Diag_rxBufferFull();\n"
        "    /* Return unproccessed events */\n",
        "diag.mt_task.rx_full",
    )
    ex.replace(
        mt_task,
        "  /* Discard or make more handlers */\n  return 0;\n",
        "  if (events & MT_DIAG_TICK_EVENT)\n  {\n"
        "    T832Diag_exportPoll();\n"
        "    OsalPortTimers_startTimer(task_id, MT_DIAG_TICK_EVENT, 1000u);\n"
        "    return (events ^ MT_DIAG_TICK_EVENT);\n"
        "  }\n\n"
        "  /* Discard or make more handlers */\n  return 0;\n",
        "diag.mt_task.export_tick",
    )

    # Command receive / dispatch / completion are separate observations.
    mtc = mt / "mt.c"
    include_after(ex, mtc, '#include "mt.h"\n', "t832_diag.h", "diag.mt.include")
    ex.replace(
        mtc,
        "  mtProcessMsg_t func;\n  uint8_t rsp[MT_RPC_FRAME_HDR_SZ];\n\n",
        "  mtProcessMsg_t func;\n  uint8_t rsp[MT_RPC_FRAME_HDR_SZ];\n\n"
        "  T832Diag_commandRx(pBuf[MT_RPC_POS_CMD0], pBuf[MT_RPC_POS_CMD1]);\n",
        "diag.command.rx",
    )
    ex.replace(
        mtc,
        "      /* execute processing function */\n      rsp[0] = (*func)(pBuf);\n",
        "      /* execute processing function */\n"
        "      T832Diag_commandDispatch(pBuf[MT_RPC_POS_CMD0], pBuf[MT_RPC_POS_CMD1]);\n"
        "      T832Diag_afDispatch(pBuf[MT_RPC_POS_CMD0], pBuf[MT_RPC_POS_CMD1],\n"
        "                          pBuf, pBuf[MT_RPC_POS_LEN]);\n"
        "      rsp[0] = (*func)(pBuf);\n"
        "      T832Diag_commandComplete(pBuf[MT_RPC_POS_CMD0], pBuf[MT_RPC_POS_CMD1], rsp[0]);\n",
        "diag.command.dispatch_complete",
    )
    ex.replace(mtc,
        "                                                                  MT_RPC_FRAME_HDR_SZ, rsp);\n"
        "  }\n}\n",
        "                                                                  MT_RPC_FRAME_HDR_SZ, rsp);\n"
        "  }\n  T832Diag_commandEnd();\n}\n", "diag.command.end_scope")

    # startupFromApp stages bracket the exact BDB call and SRSP queue attempt.
    zdo = mt / "mt_zdo.c"
    include_after(ex, zdo, '#include "mt_zdo.h"\n', "t832_diag.h", "diag.zdo.include")
    include_after(ex, zdo, '#include "bdb_interface.h"\n', "bdb.h", "diag.zdo.bdb_include")
    include_after(ex, zdo, '#include "bdb.h"\n', "nwk.h", "diag.zdo.nwk_include")
    ex.replace(
        zdo,
        "  pBuf += MT_RPC_FRAME_HDR_SZ;\n\n  if(ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE)\n",
        "  pBuf += MT_RPC_FRAME_HDR_SZ;\n"
        "  T832Diag_startup(1u, cmd0, cmd1);\n"
        "  T832Diag_networkState(bdbAttributes.bdbNodeIsOnANetwork, _NIB.nwkState);\n\n"
        "  if(ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE)\n",
        "diag.startup.entry",
    )
    ex.replace(
        zdo,
        "  {\n    bdb_StartCommissioning(BDB_COMMISSIONING_MODE_NWK_FORMATION);\n  }\n",
        "  {\n"
        "    T832Diag_startup(2u, cmd0, cmd1);\n"
        "    bdb_StartCommissioning(BDB_COMMISSIONING_MODE_NWK_FORMATION);\n"
        "    T832Diag_startup(3u, cmd0, cmd1);\n"
        "  }\n",
        "diag.startup.bdb_call",
        count=1,
    )
    ex.replace(
        zdo,
        "  else\n  {\n     retValue = ZFailure;\n  }\n\n"
        "  if (MT_RPC_CMD_SREQ == (cmd0 & MT_RPC_CMD_TYPE_MASK))\n  {\n"
        "    MT_BuildAndSendZToolResponse",
        "  else\n  {\n     retValue = ZFailure;\n  }\n\n"
        "  if (MT_RPC_CMD_SREQ == (cmd0 & MT_RPC_CMD_TYPE_MASK))\n  {\n"
        "    T832Diag_startup(4u, cmd0, cmd1);\n"
        "    MT_BuildAndSendZToolResponse",
        "diag.startup.srsp_queue",
        count=1,
    )

    # Observe BDB message dispatch/return in the Zigbee stack task.
    ztask = api / "zstacktask.c"
    include_after(ex, ztask, '#include "zstacktask.h"\n', "t832_diag.h", "diag.zstack.include")
    ex.replace(
        ztask,
        "    case zstackmsg_CmdIDs_BDB_START_COMMISSIONING_REQ:\n"
        "      resend = processBdbStartCommissioningReq( srcServiceTaskId, pMsg );\n"
        "      break;\n",
        "    case zstackmsg_CmdIDs_BDB_START_COMMISSIONING_REQ:\n"
        "      T832Diag_bdb(1u, srcServiceTaskId);\n"
        "      resend = processBdbStartCommissioningReq( srcServiceTaskId, pMsg );\n"
        "      T832Diag_bdb(2u, resend ? 1u : 0u);\n"
        "      break;\n",
        "diag.bdb.dispatch_return",
    )
    # R12: true ZStack-task progress, distinct from MT-side startup calls.
    # ZStackTaskProcessEvent runs in the Zigbee stack task on every stack
    # event; the hook only timestamps, it never records.
    ex.replace(
        ztask,
        "uint32_t ZStackTaskProcessEvent( uint8_t taskId, uint32_t events )\n"
        "{\n"
        "  zstackmsg_sysResetReq_t *pMsg;\n",
        "uint32_t ZStackTaskProcessEvent( uint8_t taskId, uint32_t events )\n"
        "{\n"
        "  zstackmsg_sysResetReq_t *pMsg;\n"
        "  T832Diag_taskWork(T832_DIAG_WORK_ZSTACK, (uint16_t)events);\n",
        "diag.zstack.progress",
    )
    # R04/R07: NPI-side drop of an MT-accepted frame. RX-side only: the MT
    # command never fired, so no pending flags are involved here.
    ex.replace(
        ztask,
        "        pOsalMsg->msg = OsalPort_malloc ( MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN] );\n"
        "\n"
        "        if(pOsalMsg->msg) {\n"
        "          OsalPort_memcpy(pOsalMsg->msg, pReq, (MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN]) );\n"
        "\n"
        "          OsalPort_msgSend( mtTaskID, (byte *)pOsalMsg );\n"
        "        }\n",
        "        pOsalMsg->msg = OsalPort_malloc ( MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN] );\n"
        "\n"
        "        if(pOsalMsg->msg) {\n"
        "          OsalPort_memcpy(pOsalMsg->msg, pReq, (MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN]) );\n"
        "\n"
        "          OsalPort_msgSend( mtTaskID, (byte *)pOsalMsg );\n"
        "        }\n"
        "        else {\n"
        "          T832Diag_npiAllocFailed(2u,\n"
        "              (uint16_t)(MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN]),\n"
        "              pReq[MT_RPC_POS_CMD0], pReq[MT_RPC_POS_CMD1],\n"
        "              pReq[MT_RPC_POS_LEN]);\n"
        "        }\n",
        "diag.zstack.rx_alloc_fail",
    )

    # Observe queueing/allocation independently from physical UART completion.
    # The payload pointer lets the recorder correlate AF confirms and read
    # the SRSP AF status byte; NULL payloads are guarded in the recorder.
    client = npi / "npi_client_mt.c"
    include_after(ex, client, '#include "mt_rpc.h"\n', "t832_diag.h", "diag.npi_client.include")
    ex.replace(
        client,
        "    if(pRspMsg != NULL)\n    {\n",
        "    if(pRspMsg != NULL)\n    {\n"
        "        T832Diag_responseQueued(cmdType, cmdId, dataLen, pData);\n",
        "diag.response.queue",
    )
    ex.replace(
        client,
        "        OsalPort_msgSend(npiTaskID, pRspMsg);\n    }\n\n    return;\n",
        "        OsalPort_msgSend(npiTaskID, pRspMsg);\n"
        "    }\n"
        "    else\n"
        "    {\n"
        "        T832Diag_responseAllocFailed(cmdType, cmdId, (uint16_t)(dataLen + MTRPC_FRAME_HDR_SZ));\n"
        "    }\n\n"
        "    return;\n",
        "diag.response.alloc_fail",
    )

    # NPI task: the central RX-overflow trap, TX-queue dequeue ownership,
    # per-wakeup task progress, RX-path allocation refusals, and the TX-path
    # allocation/framing refusals in NPITask_sendToHost/NPITask_processStackMsg
    # (S01: the old site-1 hook sat in NPITask_sendBufToStack, which allocates
    # an inbound MT message and is RX, not TX). The trap itself is preserved;
    # only fixed-write records precede it. NPI_SREQRSP is not defined in the
    # ZNP build, so no sync-queue/watchdog sites exist to patch (proven by
    # linked-image audit; CI asserts their absence).
    ntask = npi / "npi_task.c"
    include_after(ex, ntask, '#include "npi_client.h"\n', "t832_diag.h", "diag.npi_task.include")
    ex.replace(
        ntask,
        "    else\n"
        "    {\n"
        "        // Trap here for pending buffer overflow. If NPI_FLOW_CTRL is\n"
        "        // enabled, increase size of RxBuf to handle larger frames from host.\n"
        "        for(;;);\n"
        "    }\n",
        "    else\n"
        "    {\n"
        "        // Trap here for pending buffer overflow. If NPI_FLOW_CTRL is\n"
        "        // enabled, increase size of RxBuf to handle larger frames from host.\n"
        "        T832Diag_npiTrap((uint16_t)size, NPIRxBuf_GetRxBufAvail());\n"
        "        for(;;);\n"
        "    }\n",
        "diag.npi_task.rx_trap",
    )
    ex.replace(
        ntask,
        "    recPtr = Queue_dequeue(npiTxQueue);\n"
        "\n"
        "    if (recPtr != NULL)\n"
        "    {\n"
        "        NPITL_writeTL(recPtr->npiMsg->pBuf, recPtr->npiMsg->pBufSize);\n",
        "    recPtr = Queue_dequeue(npiTxQueue);\n"
        "\n"
        "    if (recPtr != NULL)\n"
        "    {\n"
        "        T832Diag_npiTxDequeue((recPtr->npiMsg->pBuf)[0],\n"
        "                              (recPtr->npiMsg->pBuf)[2],\n"
        "                              (recPtr->npiMsg->pBuf)[3],\n"
        "                              (recPtr->npiMsg->pBuf)[1]);\n"
        "        NPITL_writeTL(recPtr->npiMsg->pBuf, recPtr->npiMsg->pBufSize);\n",
        "diag.npi_task.tx_dequeue",
    )
    ex.replace(
        ntask,
        "        pOsalMsg->msg = OsalPort_malloc( MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN] );\n"
        "\n"
        "        if(pOsalMsg->msg) {\n"
        "\n"
        "          memcpy(pOsalMsg->msg, pReq, (MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN]) );\n"
        "\n"
        "          msgStatus = OsalPort_msgSend( MTServiceTaskID, (byte *)pOsalMsg );\n"
        "        }\n",
        "        pOsalMsg->msg = OsalPort_malloc( MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN] );\n"
        "\n"
        "        if(pOsalMsg->msg) {\n"
        "\n"
        "          memcpy(pOsalMsg->msg, pReq, (MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN]) );\n"
        "\n"
        "          msgStatus = OsalPort_msgSend( MTServiceTaskID, (byte *)pOsalMsg );\n"
        "        }\n"
        "        else {\n"
        "          T832Diag_npiAllocFailed(2u,\n"
        "              (uint16_t)(MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN]),\n"
        "              pReq[MT_RPC_POS_CMD0], pReq[MT_RPC_POS_CMD1],\n"
        "              pReq[MT_RPC_POS_LEN]);\n"
        "        }\n",
        "diag.npi_task.rx_alloc_fail",
    )
    ex.replace(
        ntask,
        "    pOsalMsg = (mtOSALSerialData_t *)OsalPort_msgAllocate( sizeof ( mtOSALSerialData_t ) );\n"
        "\n"
        "    if (pOsalMsg)\n",
        "    pOsalMsg = (mtOSALSerialData_t *)OsalPort_msgAllocate( sizeof ( mtOSALSerialData_t ) );\n"
        "\n"
        "    if (pOsalMsg == NULL) {\n"
        "        T832Diag_npiAllocFailed(2u,\n"
        "            (uint16_t)sizeof(mtOSALSerialData_t),\n"
        "            pReq[MT_RPC_POS_CMD0], pReq[MT_RPC_POS_CMD1],\n"
        "            pReq[MT_RPC_POS_LEN]);\n"
        "    }\n"
        "\n"
        "    if (pOsalMsg)\n",
        "diag.npi_task.rx_msg_alloc_fail",
    )
    ex.replace(
        ntask,
        "        /* Wait for response message */\n"
        "        Semaphore_pend(npiSemHandle, BIOS_WAIT_FOREVER);\n",
        "        /* Wait for response message */\n"
        "        Semaphore_pend(npiSemHandle, BIOS_WAIT_FOREVER);\n"
        "        T832Diag_npiTaskWake();\n",
        "diag.npi_task.wake",
    )
    # App-originated TX enters the ownership FIFO here: this site is inside
    # NPITask_sendToHost (npi_task.c), where the NPI task packages a message
    # handed up from the application and queues it for the UART. The anchor
    # is unique to that function (the other recPtr->npiMsg store uses
    # `if(pNPIMsg != NULL)` without spaces and without the recPtr check).
    # S01: the real outgoing failures (framing refusal, queue-record refusal,
    # unsupported type) are hooked with an else/default that only records;
    # SDK allocation/free behavior is unchanged.
    ex.replace(
        ntask,
        "    if ( pNPIMsg != NULL && recPtr != NULL )\n"
        "    {\n"
        "        recPtr->npiMsg = pNPIMsg;\n",
        "    if ( pNPIMsg != NULL && recPtr != NULL )\n"
        "    {\n"
        "        recPtr->npiMsg = pNPIMsg;\n"
        "        T832Diag_npiTxQueuedOther(pMsg[MT_RPC_POS_CMD0],\n"
        "                                  pMsg[MT_RPC_POS_CMD1],\n"
        "                                  pMsg[MT_RPC_POS_LEN]);\n",
        "diag.npi_task.send_to_host",
    )
    ex.replace(
        ntask,
        "            default:\n"
        "            {\n"
        "                //error\n"
        "                break;\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "\n"
        "    OsalPort_leaveCS(key);\n",
        "            default:\n"
        "            {\n"
        "                //error\n"
        "                /* R4-F01 owned: QueuedOther above already stored\n"
        "                 * this frame (push before switch/default). */\n"
        "                T832Diag_npiTxRefusedOwned(3u, pMsg[MT_RPC_POS_CMD0],\n"
        "                                           pMsg[MT_RPC_POS_CMD1],\n"
        "                                           pMsg[MT_RPC_POS_LEN]);\n"
        "                break;\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    else\n"
        "    {\n"
        "        T832Diag_npiTxRefused((uint8_t)(pNPIMsg == NULL ? 1u : 2u),\n"
        "                              pMsg[MT_RPC_POS_CMD0],\n"
        "                              pMsg[MT_RPC_POS_CMD1],\n"
        "                              pMsg[MT_RPC_POS_LEN]);\n"
        "    }\n"
        "\n"
        "    OsalPort_leaveCS(key);\n",
        "diag.npi_task.send_to_host_refuse",
    )
    ex.replace(
        ntask,
        "                default:\n"
        "                {\n"
        "                    /* Fail - unsupported message type */\n"
        "                    OsalPort_free(recPtr);\n",
        "                default:\n"
        "                {\n"
        "                    /* Fail - unsupported message type */\n"
        "                    T832Diag_npiTxRefused(6u, pMsg[MT_RPC_POS_CMD0],\n"
        "                                          pMsg[MT_RPC_POS_CMD1],\n"
        "                                          pMsg[MT_RPC_POS_LEN]);\n"
        "                    OsalPort_free(recPtr);\n",
        "diag.npi_task.stack_msg_unsupported",
    )
    ex.replace(
        ntask,
        "        else\n"
        "        {\n"
        "            /* Fail - couldn't get queue record */\n"
        "          OsalPort_msgDeallocate(pNPIMsg->pBuf);\n"
        "          OsalPort_free(pNPIMsg);\n"
        "        }\n"
        "    }\n"
        "}\n",
        "        else\n"
        "        {\n"
        "            /* Fail - couldn't get queue record */\n"
        "          T832Diag_npiTxRefused(5u, pMsg[MT_RPC_POS_CMD0],\n"
        "                                pMsg[MT_RPC_POS_CMD1],\n"
        "                                pMsg[MT_RPC_POS_LEN]);\n"
        "          OsalPort_msgDeallocate(pNPIMsg->pBuf);\n"
        "          OsalPort_free(pNPIMsg);\n"
        "        }\n"
        "    }\n"
        "    else\n"
        "    {\n"
        "        T832Diag_npiTxRefused(4u, pMsg[MT_RPC_POS_CMD0],\n"
        "                              pMsg[MT_RPC_POS_CMD1],\n"
        "                              pMsg[MT_RPC_POS_LEN]);\n"
        "    }\n"
        "}\n",
        "diag.npi_task.stack_msg_refuse",
    )

    # UART: effective config, RX progress/overflow, write start/rejection and
    # true end-of-wire completion. KCTRL's TX_FINISHED behavior is preserved.
    uart = npi / "npi_tl_uart.c"
    include_after(ex, uart, '#include "npi_tl_uart.h"\n', "t832_diag.h", "diag.uart.include")
    ex.replace(uart, "    params.eventMask |= UART2_EVENT_TX_FINISHED;\n",
               "    params.eventMask |= UART2_EVENT_TX_FINISHED | UART2_EVENT_TX_BEGIN |\n"
               "        UART2_EVENT_OVERRUN | UART2_EVENT_BREAK | UART2_EVENT_PARITY | UART2_EVENT_FRAMING;\n",
               "diag.uart.public_event_mask")
    ex.replace(
        uart,
        "    uartHandle = UART2_open(CONFIG_DISPLAY_UART, &params);\n",
        "    uartHandle = UART2_open(CONFIG_DISPLAY_UART, &params);\n"
        "    T832Diag_uartConfigured(params.baudRate, NPI_FLOW_CTRL);\n",
        "diag.uart.config",
    )
    ex.replace(
        uart,
        "    TransportTxLen = len;\n\n#if (NPI_FLOW_CTRL == 1)\n",
        "    TransportTxLen = len;\n"
        "    T832Diag_uartTxStart(len);\n\n"
        "#if (NPI_FLOW_CTRL == 1)\n",
        "diag.uart.tx_start",
    )
    ex.replace(
        uart,
        "    if(UART2_write(uartHandle, TransportTxBuf, TransportTxLen, NULL) != UART2_STATUS_SUCCESS )\n"
        "    {\n"
        "      TransportTxLen = 0;\n"
        "    }\n",
        "    {\n"
        "      int_fast16_t writeStatus = UART2_write(uartHandle, TransportTxBuf, TransportTxLen, NULL);\n"
        "      if(writeStatus != UART2_STATUS_SUCCESS)\n"
        "      {\n"
        "        T832Diag_uartWriteRejected(TransportTxLen, (int16_t)writeStatus);\n"
        "        TransportTxLen = 0;\n"
        "      }\n"
        "      else { T832Diag_uartEvent(1u, TransportTxLen, (int16_t)writeStatus); }\n"
        "    }\n",
        "diag.uart.write_reject",
    )
    ex.replace(
        uart,
        "static void NPITLUART_readCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)\n{\n",
        "static void NPITLUART_readCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)\n{\n"
        "    T832Diag_uartEvent(5u, (uint16_t)size, (int16_t)status);\n",
        "diag.uart.rx_progress",
    )
    ex.replace(
        uart,
        "        if (size != NPITLUART_readIsrBuf(size))\n        {\n",
        "        uint16_t copied = NPITLUART_readIsrBuf(size);\n"
        "        T832Diag_uartRx(copied, TransportRxLen);\n"
        "        if (size != copied)\n        {\n"
        "            T832Diag_uartRxOverflow((uint16_t)size, TransportRxLen);\n",
        "diag.uart.rx_overflow",
    )
    ex.replace(
        uart,
        "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)\n{\n",
        "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)\n{\n"
        "    T832Diag_uartEvent(2u, (uint16_t)size, (int16_t)status);\n",
        "diag.uart.write_callback",
    )
    ex.replace(
        uart,
        "    if (event == UART2_EVENT_TX_FINISHED)\n    {\n"
        "        uint32_t key = OsalPort_enterCS();\n",
        "    if (event == UART2_EVENT_TX_FINISHED)\n    {\n"
        "        T832Diag_uartTxFinished(TransportTxLen);\n"
        "        uint32_t key = OsalPort_enterCS();\n",
        "diag.uart.tx_finished",
    )
    # TX_BEGIN is a public UART2 event; preserve KCTRL's event path.
    ex.replace(uart, "    if (event == UART2_EVENT_TX_FINISHED)\n",
               "    if (event & (UART2_EVENT_OVERRUN | UART2_EVENT_BREAK | UART2_EVENT_PARITY | UART2_EVENT_FRAMING))\n"
               "        T832Diag_uartError(event);\n"
               "    if (event == UART2_EVENT_TX_BEGIN) { T832Diag_uartEvent(3u, TransportTxLen, 0); }\n"
               "    if (event == UART2_EVENT_TX_FINISHED)\n", "diag.uart.tx_begin")

    # Fatal RAM-only hooks run before the unchanged original spin paths.
    # Standalone header resolves from the kernel source directory while the
    # SDK archive is built, without importing ZStack into the kernel.
    kernel = sdk / "kernel/tirtos7/packages/ti/sysbios"
    for directory in (kernel / "runtime", kernel / "family/arm/v8m"):
        shutil.copy2(HERE / "t832_fatal.h", directory / "t832_fatal.h")
    error = kernel / "runtime/Error.c"
    ex.replace(error, "#include <ti/sysbios/runtime/Error.h>\n",
               '#include <ti/sysbios/runtime/Error.h>\n#include "t832_fatal.h"\n',
               "diag.fatal.error_include")
    ex.replace(error, "    eb->a1 = a1;\n",
               "    eb->a1 = a1;\n"
               "    if (Error_policy_D == Error_SPIN)\n"
               "        T832Diag_fatalError((uintptr_t)id, (uintptr_t)a0, (uintptr_t)a1);\n",
               "diag.fatal.before_error_spin")
    hwi = kernel / "family/arm/v8m/Hwi.c"
    ex.replace(hwi, "void Hwi_excHandler(unsigned int *excStack, unsigned int lr)\n{\n",
               '#include "t832_fatal.h"\n'
               "void Hwi_excHandler(unsigned int *excStack, unsigned int lr)\n{\n"
               "    T832Diag_fatalException(excStack, lr, (uint32_t)BIOS_module->threadType,\n"
               "        Hwi_nvic.ICSR, Hwi_nvic.MMFSR, Hwi_nvic.BFSR, Hwi_nvic.UFSR,\n"
               "        Hwi_nvic.HFSR, Hwi_nvic.DFSR, Hwi_nvic.MMAR, Hwi_nvic.BFAR, Hwi_nvic.AFSR);\n",
               "diag.fatal.before_exception_spin")

    ex.replace(ntask,
               "    Task_construct(&npiTaskStruct, NPITask_Fxn, &npiTaskParams, NULL);\n",
               "    Task_construct(&npiTaskStruct, NPITask_Fxn, &npiTaskParams, NULL);\n"
               "    T832Diag_registerTask(1u, (uintptr_t)Task_handle(&npiTaskStruct));\n",
               "diag.tasks.npi_handle")
    ex.append(ztask, '#include "t832_diag_nwk.inc"', "diag.nwk.sampler")
    ex.replace(ztask,
               "  T832Diag_taskWork(T832_DIAG_WORK_ZSTACK, (uint16_t)events);\n",
               "  T832Diag_taskWork(T832_DIAG_WORK_ZSTACK, (uint16_t)events);\n"
               "  T832Diag_registerTask(2u, (uintptr_t)Task_self());\n"
               "  T832Diag_sampleNwk();\n", "diag.nwk.task_context")
    include_after(ex, ztask, '#include "t832_diag.h"\n', "ti/sysbios/knl/Task.h",
                  "diag.tasks.zstack_include")
    ex.replace(ntask, "Queue_enqueue(npiTxQueue, &recPtr->_elem);\n",
               "Queue_enqueue(npiTxQueue, &recPtr->_elem);\n"
               "                T832Diag_npiQueueAccepted(pNPIMsg->pBuf[2], pNPIMsg->pBuf[3], pNPIMsg->pBuf[1]);\n",
               "diag.pipeline.npi_queue_accepted", count=2)

    # NV compaction begin/end/failure/duration, recovery reformat entry, and
    # init/recovery action breadcrumbs. Hooks only record; erase/reformat
    # policy (NVOCMP_RECOVER_FROM_COMPACT_FAILURE) is unchanged.
    nv = sdk / "source/ti/common/nv/nvocmp.c"
    ex.replace(
        nv,
        '#include "nvocmp.h"\n',
        '#include "nvocmp.h"\n'
        "\n"
        "extern void T832Diag_nvEvent(uint8_t stage, uint16_t b, uint16_t c);\n"
        "extern void T832Diag_nvInit(uint8_t action);\n",
        "diag.nv.decls",
    )
    ex.replace(
        nv,
        "    pNvHandle->compactInfo.xSrcEOffset = 0;\n"
        "    status = NVOCMP_compact(pNvHandle);\n",
        "    pNvHandle->compactInfo.xSrcEOffset = 0;\n"
        "    T832Diag_nvEvent(1u, nBytes, 0u);\n"
        "    status = NVOCMP_compact(pNvHandle);\n"
        "    T832Diag_nvEvent(status == NVOCMP_COMPACT_FAILURE ? 3u : 2u,"
        " (uint16_t)status, 0u);\n",
        "diag.nv.compact_site_4sp",
    )
    ex.replace(
        nv,
        "  pNvHandle->compactInfo.xSrcSOffset = pNvHandle->pageInfo[srcPg].offset;\n"
        "  status = NVOCMP_compact(pNvHandle);\n",
        "  pNvHandle->compactInfo.xSrcSOffset = pNvHandle->pageInfo[srcPg].offset;\n"
        "  T832Diag_nvEvent(1u, nBytes, 0u);\n"
        "  status = NVOCMP_compact(pNvHandle);\n"
        "  T832Diag_nvEvent(status == NVOCMP_COMPACT_FAILURE ? 3u : 2u,"
        " (uint16_t)status, 0u);\n",
        "diag.nv.compact_site_2sp",
    )
    ex.replace(
        nv,
        "#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE",
        "#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE\n"
        "        T832Diag_nvEvent(4u, NVOCMP_NVSIZE, 0u);",
        "diag.nv.reformat_entry",
        count=2,
    )
    ex.replace(
        nv,
        "  gAction = action;\n",
        "  gAction = action;\n  T832Diag_nvInit((uint8_t)action);\n",
        "diag.nv.init_action",
        count=3,
    )
    ex.replace(
        nv,
        "        NVOCMP_initNv(&NVOCMP_nvHandle);\n",
        "        NVOCMP_initNv(&NVOCMP_nvHandle);\n"
        "        T832Diag_nvEvent(5u, (uint16_t)NVOCMP_getFreeNvApi(),\n"
        "            (uint16_t)(((uint16_t)NVOCMP_nvHandle.actPage << 8) |\n"
        "                       (uint16_t)NVOCMP_nvHandle.tailPage));\n",
        "diag.nv.capacity_snapshot",
    )
    ex.replace(
        nv,
        "          // Failure means there\'s no place to put this item\n"
        "          NVOCMP_ALERT(false, \"Out of NV.\")\n"
        "          err = (NVOCMP_failW != NVINTF_SUCCESS) ?\n",
        "          // Failure means there\'s no place to put this item\n"
        "          T832Diag_nvEvent(6u, (uint16_t)NVOCMP_getFreeNvApi(),\n"
        "              (uint16_t)(((uint16_t)pNvHandle->actPage << 8) |\n"
        "                         (uint16_t)pNvHandle->tailPage));\n"
        "          NVOCMP_ALERT(false, \"Out of NV.\")\n"
        "          err = (NVOCMP_failW != NVINTF_SUCCESS) ?\n",
        "diag.nv.out_of_space_snapshot",
    )

    return {
        "variant": VARIANT,
        "control": control_evidence,
        "diagnostic_edits": ex.edits,
        "copied_runtime": [
            {"path": str(path.relative_to(sdk)).replace("\\", "/"),
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in (mt / "t832_diag.h", mt / "t832_diag_impl.inc",
                         mt / "t832_diag_r5.inc", mt / "t832_diag_nwk.inc",
                         mt / "t832_fatal.h", kernel / "runtime/t832_fatal.h",
                         kernel / "family/arm/v8m/t832_fatal.h")
        ],
        "diagnostic_identity": {"sys_version_revision": 8320002,
                                "debug_build_id": int(build_id, 16)},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdk", type=Path, required=True)
    ap.add_argument("--examples", type=Path, required=True)
    ap.add_argument("--control-manifest", type=Path, default=HERE / "manifest.json")
    ap.add_argument("--evidence", type=Path)
    args = ap.parse_args()
    evidence = apply_diag(
        args.sdk.resolve(), args.examples.resolve(), args.control_manifest.resolve()
    )
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
