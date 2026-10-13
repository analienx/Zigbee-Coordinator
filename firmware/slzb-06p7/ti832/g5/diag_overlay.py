#!/usr/bin/env python3
"""Offline P7 G5 native DIAG overlay for the pinned TI SDK (NOT_FLASHABLE).

In the g3/g4 fail-closed style: every insertion is an exact-anchor,
count==1 replacement on the pinned SDK/examples checkouts, applied
only to mutable CI checkouts. It inserts bounded p7_diag_record /
p7_diag_record_isr callsites, copies the flight-recorder sources into
the SDK startup directory (already on the ZNP include path), and adds
one linked file entry to the ZNP projectspec. It never alters NV
control flow: the NV-restore callsite only *reads* the already-decided
networkStateNV value after the restore decision, and never touches the
wipe/restore branches. Endpoint 0xF0 stays DISABLED; no MT SYS handler
is added. Tick is the constant 0 (bounded, no clock dependency); the
snapshot decoder accepts non-regressing zero ticks.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

SDK_SHA = "6499c3f53fc5fb5806213be695450a7b43fbaf3d"
EXAMPLES_SHA = "87ff5b638b632050228a7504f35cf3b95581c278"
CANDIDATE = "G5_CRASHDIAG_NATIVE_DIAG_NOT_FLASHABLE"
INC = '#include "p7_crashdiag.h" /* P7DIAG */\n'
R = "p7_diag_record"
RI = "p7_diag_record_isr"

# (sdk-relative file, anchor, replacement, callsite id)
PATCHES = [
 ("source/ti/zstack/startup/main.c",
  '#include "ti_zstack_config.h"\n',
  '#include "ti_zstack_config.h"\n' + INC, "main_include"),
 ("source/ti/zstack/startup/main.c",
  "int main()\n{\n",
  "int main()\n{\n    p7_diag_init(1, 0, 0); /* P7DIAG:boot_main */\n", "boot_main"),
 ("source/ti/zstack/stack/zdo/zd_app.c",
  '#include "zd_app.h"\n',
  '#include "zd_app.h"\n' + INC, "zdo_include"),
 ("source/ti/zstack/stack/zdo/zd_app.c",
  "uint8_t ZDOInitDeviceEx( uint16_t startDelay, uint8_t mode)\n{\n",
  "uint8_t ZDOInitDeviceEx( uint16_t startDelay, uint8_t mode)\n{\n"
  f"  {R}(P7D_ZDO_INIT_ENTER, (uint16_t)mode, 0); /* P7DIAG:zdo_enter */\n"
  f"  {R}(P7D_NV_READ_BEGIN, 0, 0); /* P7DIAG:nv_read_begin */\n", "zdo_enter"),
 ("source/ti/zstack/stack/zdo/zd_app.c",
  "  // Initialize the security for type of device\n",
  "  if ( networkStateNV == ZDO_INITDEV_RESTORED_NETWORK_STATE ) { "
  f"{R}(P7D_NV_RESTORED, (uint16_t)networkStateNV, 0); }} /* P7DIAG:nv_decision */\n"
  "  else if ( networkStateNV == ZDO_INITDEV_NEW_NETWORK_STATE ) { "
  f"{R}(P7D_NV_NEW, (uint16_t)networkStateNV, 0); }}\n"
  "  else { "
  f"{R}(P7D_NV_AMBIGUOUS, (uint16_t)networkStateNV, 0); }}\n"
  "  // Initialize the security for type of device\n", "nv_decision"),
 ("source/ti/zstack/stack/zdo/zd_app.c",
  "  NLME_SetBroadcastFilter( ZDO_Config_Node_Descriptor.CapabilityFlags );\n\n  return ( networkStateNV );",
  "  NLME_SetBroadcastFilter( ZDO_Config_Node_Descriptor.CapabilityFlags );\n\n"
  f"  {R}(P7D_ZDO_INIT_EXIT, (uint16_t)networkStateNV, 0); /* P7DIAG:zdo_exit */\n"
  "  return ( networkStateNV );", "zdo_exit"),
 ("source/ti/zstack/mt/mt_zdo.c",
  '#include "mt_zdo.h"\n',
  '#include "mt_zdo.h"\n' + INC, "mtzdo_include"),
 ("source/ti/zstack/mt/mt_zdo.c",
  "static void MT_ZdoStartupFromApp(uint8_t *pBuf)\n{\n  uint8_t cmd0, cmd1, retValue;\n  retValue = ZSuccess;\n",
  "static void MT_ZdoStartupFromApp(uint8_t *pBuf)\n{\n  uint8_t cmd0, cmd1, retValue;\n  retValue = ZSuccess;\n"
  f"  {R}(P7D_MT_RX, 0, 0); /* P7DIAG:startup_from_app_rx */\n", "startup_from_app_rx"),
 ("source/ti/zstack/mt/mt_zdo.c",
  "    MT_BuildAndSendZToolResponse(((uint8_t)MT_RPC_CMD_SRSP|(uint8_t)MT_RPC_SYS_ZDO), cmd1,1, &retValue);\n",
  "    MT_BuildAndSendZToolResponse(((uint8_t)MT_RPC_CMD_SRSP|(uint8_t)MT_RPC_SYS_ZDO), cmd1,1, &retValue);\n"
  f"    {R}(P7D_SRSP_QUEUED, (uint16_t)retValue, 0); /* P7DIAG:srsp_queued */\n", "srsp_queued"),
 ("source/ti/zstack/mt/mt_task.c",
  '#include "mt_task.h"\n',
  '#include "mt_task.h"\n' + INC, "mttask_include"),
 ("source/ti/zstack/mt/mt_task.c",
  "MT_ProcessIncoming(msg_ptr);",
  f"{R}(P7D_ZDO_DISPATCH, 0, 0); /* P7DIAG:mt_dispatch */\n          MT_ProcessIncoming(msg_ptr);", "mt_dispatch"),
 ("source/ti/zstack/npi/npi_task.c",
  '#include "npi_task.h"\n',
  '#include "npi_task.h"\n' + INC, "npitask_include"),
 ("source/ti/zstack/npi/npi_task.c",
  "                    Queue_enqueue(npiSyncTxQueue, &recPtr->_elem);\n",
  "                    Queue_enqueue(npiSyncTxQueue, &recPtr->_elem);\n"
  f"                    {R}(P7D_NPI_Q_ACCEPT, 1, 0); /* P7DIAG:npi_q_accept_sync */\n", "npi_q_accept_sync"),
 ("source/ti/zstack/npi/npi_task.c",
  "                    Queue_enqueue(npiTxQueue, &recPtr->_elem);\n",
  "                    Queue_enqueue(npiTxQueue, &recPtr->_elem);\n"
  f"                    {R}(P7D_NPI_Q_ACCEPT, 2, 0); /* P7DIAG:npi_q_accept_async */\n", "npi_q_accept_async"),
 ("source/ti/zstack/npi/npi_task.c",
  "                    /* Fail - unsupported message type */\n",
  "                    /* Fail - unsupported message type */\n"
  f"                    {R}(P7D_NPI_Q_REJECT, 3, 0); /* P7DIAG:npi_q_reject_type */\n", "npi_q_reject_type"),
 ("source/ti/zstack/npi/npi_task.c",
  "            /* Fail - couldn't get queue record */\n",
  "            /* Fail - couldn't get queue record */\n"
  f"            {R}(P7D_NPI_Q_REJECT, 4, 0); /* P7DIAG:npi_q_reject_alloc */\n", "npi_q_reject_alloc"),
 ("source/ti/zstack/npi/npi_task.c",
  "        // Trap here for pending buffer overflow.",
  f"        {RI}(P7D_OVERFLOW, 0, 0); /* P7DIAG:npi_rx_overflow */\n"
  "        // Trap here for pending buffer overflow.", "npi_rx_overflow"),
 ("source/ti/zstack/npi/npi_tl_uart.c",
  '#include "npi_tl_uart.h"\n',
  '#include "npi_tl_uart.h"\n' + INC, "uart_include"),
 ("source/ti/zstack/npi/npi_tl_uart.c",
  "    if(UART2_write(uartHandle, TransportTxBuf, TransportTxLen, NULL) != UART2_STATUS_SUCCESS )\n    {\n      TransportTxLen = 0;\n    }",
  "    if(UART2_write(uartHandle, TransportTxBuf, TransportTxLen, NULL) != UART2_STATUS_SUCCESS )\n    {\n"
  f"      {R}(P7D_UART_REJECTED, 0, 0); /* P7DIAG:uart_write_rejected */\n"
  "      TransportTxLen = 0;\n    }\n    else\n    {\n"
  f"      {R}(P7D_UART_ACCEPTED, (uint16_t)TransportTxLen, 0); /* P7DIAG:uart_write_accepted */\n" + "    }", "uart_write_accepted"),
 ("source/ti/zstack/npi/npi_tl_uart.c",
  "        if ( UART2_write(uartHandle, TransportTxBuf, TransportTxLen) != UART2_STATUS_SUCCESS )\n        {\n          TxActive = FALSE;\n          TransportTxLen = 0;\n        }",
  "        if ( UART2_write(uartHandle, TransportTxBuf, TransportTxLen) != UART2_STATUS_SUCCESS )\n        {\n"
  f"          {R}(P7D_UART_REJECTED, 1, 0); /* P7DIAG:uart_write_rejected_fc */\n"
  "          TxActive = FALSE;\n          TransportTxLen = 0;\n        }\n        else\n        {\n"
  f"          {R}(P7D_UART_ACCEPTED, (uint16_t)TransportTxLen, 0); /* P7DIAG:uart_write_accepted_fc */\n" + "        }", "uart_write_accepted_fc"),
 ("source/ti/zstack/npi/npi_tl_uart.c",
  "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)\n{\n    uint32_t key;",
  "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)\n{\n"
  f"    {RI}(P7D_UART_FIFO_LOADED, (uint16_t)size, 0); /* P7DIAG:uart_fifo_loaded - CR7: TI SDK 8.32 UART2 write callback = bytes in HW FIFO, NOT TX-pin completion; physical wire completion is UART2_EVENT_TX_FINISHED (not subscribed here) and stays UNKNOWN */\n"
  "    uint32_t key;", "uart_fifo_loaded"),
 ("source/ti/zstack/npi/npi_tl_uart.c",
  "        if (size != NPITLUART_readIsrBuf(size))\n        {\n            // Buffer overflow imminent. Cancel read and pass to higher layers",
  "        if (size != NPITLUART_readIsrBuf(size))\n        {\n"
  f"            {RI}(P7D_OVERFLOW, 1, 0); /* P7DIAG:uart_read_overflow */\n"
  "            // Buffer overflow imminent. Cancel read and pass to higher layers", "uart_read_overflow"),
 ("source/ti/zstack/npi/npi_frame_mt.c",
  '#include "npi_frame.h"\n',
  '#include "npi_frame.h"\n' + INC, "frame_include"),
 ("source/ti/zstack/npi/npi_frame_mt.c",
  "                    state = NPIFRAMEMT_SOP_STATE;\n                    return;",
  f"                    {R}(P7D_PARSE_ERR, (uint16_t)LEN_Token, 0); /* P7DIAG:frame_alloc_fail */\n"
  "                    state = NPIFRAMEMT_SOP_STATE;\n                    return;", "frame_alloc_fail"),
 ("source/ti/zstack/npi/npi_frame_mt.c",
  "                    /* deallocate the msg */\n                    OsalPort_msgDeallocate(pMsg);",
  f"                    {R}(P7D_FCS_ERR, (uint16_t)LEN_Token, 0); /* P7DIAG:frame_fcs_err */\n"
  "                    /* deallocate the msg */\n                    OsalPort_msgDeallocate(pMsg);", "frame_fcs_err"),
]
PROJECTSPEC = "examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec"
DIAG_FILE_ENTRY = ('        <file path="${COM_TI_SIMPLELINK_CC13XX_CC26XX_SDK_INSTALL_DIR}'
  '/source/ti/zstack/startup/p7_crashdiag.c" openOnCreation="false" excludeFromBuild="false"'
  ' action="link" targetDirectory="Application/StartUp">\n        </file>\n')

def must(v: bool, m: str) -> None:
    if not v: raise ValueError(m)

def apply_patches(texts: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    out = dict(texts); done = []
    for rel, anchor, repl, cid in PATCHES:
        must(rel in out, "INPUT_MISSING_" + rel)
        must(out[rel].count(anchor) == 1, f"ANCHOR_NOT_UNIQUE_{cid}:{out[rel].count(anchor)}")
        must("P7DIAG:" + cid not in out[rel] and repl not in out[rel], "ALREADY_PATCHED_" + cid)
        out[rel] = out[rel].replace(anchor, repl, 1)
        must(out[rel].count("P7DIAG") >= 1, "INSERT_MISSING_" + cid)
        done.append(cid)
    return out, done

def patch_projectspec(text: str) -> str:
    must("p7_crashdiag.c" not in text, "PROJECTSPEC_ALREADY_PATCHED")
    anchor = "source/ti/zstack/startup/main.c\""
    must(text.count(anchor) == 1, "PROJECTSPEC_MAIN_ANCHOR_NOT_UNIQUE")
    idx = text.index(anchor)
    end = text.index("</file>", idx) + len("</file>")
    return text[:end] + "\n" + DIAG_FILE_ENTRY.rstrip("\n") + text[end:]

def apply(sdk: Path, examples: Path, g5: Path, out: Path) -> dict:
    files = sorted({rel for rel, _, _, _ in PATCHES})
    texts, inputs = {}, {}
    for rel in files:
        f = sdk / rel
        must(f.is_file(), "INPUT_MISSING_" + rel)
        data = f.read_bytes(); inputs[rel] = data
        texts[rel] = data.decode("utf-8")
    patched, callsites = apply_patches(texts)
    spec_file = examples / PROJECTSPEC
    must(spec_file.is_file(), "INPUT_MISSING_projectspec")
    spec_in = spec_file.read_bytes()
    spec_out = patch_projectspec(spec_in.decode("utf-8"))
    for rel, text in patched.items():
        (sdk / rel).write_bytes(text.encode("utf-8"))
    spec_file.write_bytes(spec_out.encode("utf-8"))
    for name in ("p7_crashdiag.c", "p7_crashdiag.h"):
        src = g5 / name
        must(src.is_file(), "INPUT_MISSING_" + name)
        (sdk / "source/ti/zstack/startup" / name).write_bytes(src.read_bytes())
    manifest = {"qualification": CANDIDATE, "sdk_sha": SDK_SHA, "examples_sha": EXAMPLES_SHA,
      "runtime_qualified": False, "hardware_qualified": False, "flash_authorized": False,
      "mt_endpoint_enabled": False, "nv_control_flow_altered": False,
      "callsites": callsites,
      "files": {rel: {"input_sha256": hashlib.sha256(inputs[rel]).hexdigest(),
                      "patched_sha256": hashlib.sha256(patched[rel].encode()).hexdigest()} for rel in files},
      "projectspec": {"input_sha256": hashlib.sha256(spec_in).hexdigest(),
                      "patched_sha256": hashlib.sha256(spec_out.encode()).hexdigest()}}
    out.mkdir(parents=True, exist_ok=True)
    (out / "DIAG-OVERLAY-MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest

def selftest() -> None:
    texts: dict[str, str] = {}
    for rel, anchor, _, _ in PATCHES:
        texts.setdefault(rel, "")
        must(anchor not in texts[rel], "FIXTURE_ANCHOR_DUP_" + rel)
        texts[rel] += "/* fixture */\n" + anchor + "/* tail */\n"
    patched, done = apply_patches(texts)
    must(len(done) == len(PATCHES), "CALLSITE_COUNT")
    for _, _, repl, cid in PATCHES:
        must(any(repl in t for t in patched.values()), "REPL_MISSING_" + cid)
    try: apply_patches(patched)
    except ValueError: pass
    else: raise AssertionError("DOUBLE_APPLY_ACCEPTED")
    try: apply_patches({rel: "no anchors here" for rel in texts})
    except ValueError: pass
    else: raise AssertionError("MISSING_ANCHOR_ACCEPTED")
    spec = ('<file path="${X}/source/ti/zstack/startup/main.c" action="link" '
            'targetDirectory="Application/StartUp">\n        </file>\n<file path="other">\n</file>\n')
    out = patch_projectspec(spec)
    must(out.count("p7_crashdiag.c") == 1 and out.index("p7_crashdiag.c") > out.index("main.c"), "PROJECTSPEC_INSERT")
    try: patch_projectspec(out)
    except ValueError: pass
    else: raise AssertionError("PROJECTSPEC_DOUBLE_ACCEPTED")
    print(f"PASS P7 G5 diag overlay; {len(done)} callsites, fail-closed anchors")

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--sdk", type=Path); p.add_argument("--examples", type=Path)
    p.add_argument("--g5", type=Path); p.add_argument("--out", type=Path)
    p.add_argument("--selftest", action="store_true"); a = p.parse_args()
    if a.selftest: selftest()
    if a.sdk or a.examples or a.g5 or a.out:
        must(bool(a.sdk and a.examples and a.g5 and a.out), "REQUIRE_ALL_INPUTS")
        print(json.dumps(apply(a.sdk, a.examples, a.g5, a.out), indent=2, sort_keys=True))

if __name__ == "__main__": main()
