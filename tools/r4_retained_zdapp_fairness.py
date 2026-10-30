#!/usr/bin/env python3
"""V48: service the *already queued* B1 retained ZDApp INIT/START event.

V47 physically proved NPI4->6 restores command reception (105 B1E1 reads),
but BDB returned with ZDO_NETWORK_INIT pending while the TI service dispatcher
ran >4000 other service events. TI's fixed-index first-ready selection can
indefinitely starve ZDApp behind earlier continuously ready services.

Change only the existing Stack task scheduler selection while B1's guarded
retained attempt is running and exactly one ZDApp INIT/START bit is pending.
Never synthesize, retry or re-post an event, change network state, NV or UART.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from r4_uart_tx_liveness import once, TI_SHA

STACK="source/ti/zstack/startup/zstackstartup.c"
MARKER="B4_V48_RETAINED_ZDAPP_DISPATCH_FAIRNESS"

BEFORE="""      uint8_t idx = 0;

     // copy the priority-based round-robin scheduler from OSAL
      do {
        if (*(pTasksEvents[idx]))  // Task is highest priority that is ready.
        {
          break;
        }
      } while (++idx < zstackTasksCnt);"""

AFTER="""      uint8_t idx = 0;

      /* B4_V48_RETAINED_ZDAPP_DISPATCH_FAIRNESS
       * When B1 already POSTED retained INIT/START, do not let endlessly
       * ready, lower-index services starve its existing ZDApp dispatcher.
       * This is selection, not dispatch: the original CS/clear/call/merge
       * and semaphore credit logic below remain strictly unchanged.
       */
      if (b1_retained_attempt_active() &&
          (zdAppServiceEvents & (ZDO_NETWORK_INIT | ZDO_NETWORK_START)))
      {
        for (idx=0; idx<zstackTasksCnt; ++idx)
          if (pTasksEvents[idx] == &zdAppServiceEvents) break;
      }
      else
      {
        // Original priority-based first-ready selection for all other work.
        do {
          if (*(pTasksEvents[idx]))
          {
            break;
          }
        } while (++idx < zstackTasksCnt);
      }"""


def apply(sdk):
    sdk=Path(sdk)
    p=sdk/STACK
    if p.is_symlink() or not p.is_file():
        raise ValueError("V48_EXACT_NATIVE_STACK_REQUIRED")
    s=p.read_text()
    if MARKER in s:raise ValueError("V48_ALREADY_APPLIED")
    if ("B4_F2_V6_OWNED_STAGE" not in (sdk/"source/ti/zstack/npi/npi_task.c").read_text() or
        "b1_evidence_bind_pending(&zdAppServiceEvents)" not in s or
        "b1_evidence_dispatch(idx, events)" not in s or
        "if (events != 0u) Semaphore_post(stackSemHandle);" not in s or
        "B1_RETAINED_STARTUP_EVENT" not in (sdk/"source/ti/zstack/stack/zdo/zd_app.c").read_text()):
        raise ValueError("V48_REQUIRES_EXACT_B1_V47_COMPOSED_SCHEDULER")
    # Do not accept a subtly changed or absent ready service selection.
    native=subprocess.check_output(['git','-C',str(sdk),'show',TI_SHA+':'+STACK])
    if b"static void stackTaskFxn" not in native:
        raise ValueError("V48_TI_SCHEDULER_NOT_PINNED")
    updated=once(s,BEFORE,AFTER,"V48_B1_READY_SELECTION")
    if (updated.count(MARKER)!=1 or
        updated.count("b1_evidence_dispatch(idx, events)")!=1 or
        updated.count("Semaphore_post(stackSemHandle);")!=1):
        raise ValueError("V48_REVIEWED_DISPATCH_BODY_CHANGED")
    p.write_text(updated,encoding="utf-8",newline="")
    return {"schema":"p7u-v48-retained-zdapp-fairness-v1",
        "source_before_sha256":hashlib.sha256(s.encode()).hexdigest(),
        "source_modified_sha256":hashlib.sha256(updated.encode()).hexdigest(),
        "only_prioritize_already_posted_bits":[1,2],
        "guard":"B1_RETAINED_ATTEMPT_RUNNING",
        "other_task_priority_unchanged":True,
        "no_new_event_or_nv_or_formation":True,
        "hardware_accepted":False,"flash_authorized":False}


if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--sdk",type=Path,required=True)
    ap.add_argument("--receipt",type=Path,required=True)
    args=ap.parse_args()
    if args.receipt.exists():raise ValueError("V48_RECEIPT_EXISTS")
    result=apply(args.sdk)
    args.receipt.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result))
