#!/usr/bin/env python3
"""Task ownership delta after G6. Exact anchors; hosted execution only."""
import argparse
import hashlib
import json
from pathlib import Path
import g7_transport_overlay as lower
from g6_overlay import replace, function, TASK


def patch(texts):
    out = lower.patch(texts)
    task = out[TASK]
    task = replace(task, "void NPITask_inititializeTask(void);\n",
                   'void NPITask_inititializeTask(void);\n#include "p7_g7_task.inc"\n', "g7_task_include")
    task = replace(task, "    // create a Tx Queue instance\n    npiTxQueue = Queue_create(NULL, NULL);\n",
                   "    /* G7 TX lanes are statically constructed after semaphore init. */\n", "g7_queue_init")
    task = replace(task, "    npiSemHandle = Semaphore_handle(&structSem);\n",
                   "    npiSemHandle = Semaphore_handle(&structSem);\n    p7_g7_init();\n", "g7_timer_init")
    task = replace(task, "                             MRDY_ISR_EVENT_FLAG | TRANSPORT_RX_ISR_EVENT_FLAG;",
                   "                             MRDY_ISR_EVENT_FLAG | TRANSPORT_RX_ISR_EVENT_FLAG | p7_g7_isr_event;", "g7_capture")
    task = replace(task, "            TRANSPORT_RX_ISR_EVENT_FLAG = 0;",
                   "            TRANSPORT_RX_ISR_EVENT_FLAG = 0;\n            p7_g7_isr_event = 0;", "g7_clear")
    # Default profile does NOT enable TI's legacy sync transaction watchdog.
    start = "            // An ASYNC message is ready to send to the Host\n"
    end = "            // The Transport Layer has received some bytes\n"
    if task.count(start) != 1 or task.count(end) != 1:
        raise ValueError("G7_TX_EVENT_ANCHORS")
    a, b = task.index(start), task.index(end)
    block = task[a:b]
    if "NPITask_ProcessTXQ();" not in block or "Semaphore_post(npiSemHandle);" not in block:
        raise ValueError("G7_TX_EVENT_PREDECESSOR")
    task = replace(task, block, "", "g7_no_busy_repost")
    process = function(task, "NPITask_process")
    a = process.index("            // The last transmission to the host has completed.")
    old_done = process[a:process.rindex("        }\n    }\n}")]
    if "Queue_empty(npiTxQueue)" not in old_done:
        raise ValueError("G7_DONE_PREDECESSOR")
    task = replace(task, old_done, "            p7_g7_service(); /* RX handled before bounded TX pass */\n", "g7_service")
    old = function(task, "NPITask_sendToHost")
    task = replace(task, old, "void NPITask_sendToHost(uint8_t *pMsg)\n{\n"
                   "    p7_g7_enqueue(NPIFrame_frameMsg(pMsg));\n}", "g7_public_enqueue")
    old = function(task, "NPITask_processStackMsg")
    anchor = "    pNPIMsg = NPIFrame_frameMsg(pMsg);"
    if old.count(anchor) != 1 or "P7DIAG:npi_q_accept_async" not in old:
        raise ValueError("G7_STACK_PREDECESSOR")
    new = old[:old.index(anchor)] + "    pNPIMsg = NPIFrame_frameMsg(pMsg);\n    p7_g7_enqueue(pNPIMsg);\n}"
    task = replace(task, old, new, "g7_stack_enqueue")
    old = function(task, "NPITask_ProcessTXQ")
    task = replace(task, old, "", "g7_remove_old_free")
    task = replace(task, "static void NPITask_ProcessTXQ(void);\n", "", "g7_remove_old_prototype")
    task = replace(task, "static Queue_Handle npiTxQueue;\n", "", "g7_remove_old_queue")
    out[TASK] = task
    return out


def apply(sdk, examples, output):
    paths = (TASK, lower.TL, lower.UART)
    original = {p: (sdk / p).read_text() for p in paths}
    patched = patch(original)
    g7 = Path(__file__).resolve().parent
    startup = sdk / "source/ti/zstack/startup"
    import diag_overlay as diag
    spec = examples / diag.PROJECTSPEC
    text = spec.read_text()
    anchor = diag.DIAG_FILE_ENTRY.replace("p7_crashdiag.c", "p7_g6.c")
    entry = anchor.replace("p7_g6.c", "p7_tx_policy.c")
    text = replace(text, anchor, anchor + entry, "g7_projectspec")
    # Validate every input before first write; sources copied only to CI SDK.
    copies = {name: (g7 / name).read_bytes() for name in
              ("p7_g7_task.inc", "p7_g7_transport.h", "p7_tx_policy.h", "p7_tx_policy.c")}
    for p, source in patched.items(): (sdk / p).write_text(source)
    for name, data in copies.items(): (startup / name).write_bytes(data)
    spec.write_text(text)
    output.mkdir(parents=True, exist_ok=True)
    manifest = {"qualification": "G7_SOURCE_OVERLAY_NOT_FLASHABLE", "runtime_qualified": False,
                "hardware_qualified": False, "flash_authorized": False,
                "linked_sources_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in copies.items()},
                "projectspec_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "files": {p: {"input_sha256": hashlib.sha256(original[p].encode()).hexdigest(),
                              "patched_sha256": hashlib.sha256(source.encode()).hexdigest()}
                          for p, source in patched.items()}}
    (output / "G7-OVERLAY-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("sdk", "examples", "out"): parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.sdk, args.examples, args.out), indent=2))
