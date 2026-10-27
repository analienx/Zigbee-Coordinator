#!/usr/bin/env python3
"""Compile/exercise the exact composed TI C functions, including negative mutants.

Runs ONLY on an isolated CI source checkout. No serial, USB, hardware, NV, or RF.
"""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile

from r4_uart_tx_liveness import TL, UART, extract

def _c(tl_func, abort_func, uart_func):
    return r"""
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
typedef unsigned short uint16;
typedef unsigned char uint8;
typedef void *UART2_Handle;
typedef void (*TxCallback)(int);
#define NPI_FLOW_CTRL 0
#define UART2_STATUS_SUCCESS 0
#define B1_ERROR_UART_WRITE 17
#define TRUE true
#define FALSE false
#define NPI_MAX_FRAG_SIZE 16
static volatile bool npiTxActive = false;
static uint8_t npiTxBuf[512];
static uint16 npiTxBufLen = 0;
static uint8_t *msgFrag = NULL;
static uint16 msgFragLen = 0;
static unsigned txPktCount = 0;
static int lower_response = 0, task_notifications = 0, user_completions = 0;
static int physical_uart_failure_latch = 0;
static bool b1_management_transport_unavailable(void) { return physical_uart_failure_latch != 0; }
static void b1_management_transport_failed(int e) {
 if (e == B1_ERROR_UART_WRITE) physical_uart_failure_latch++;
}
static void b1_startup_tx_result(uint16_t size, int submitted) {
 (void)size;
 (void)submitted;
}
static uint16 TransportTxLen = 0;
static void (*npiTransmitCB)(int,int) = NULL;
static void sent_task(int count) { (void)count; task_notifications++; }
static TxCallback taskTxCB = sent_task;
static uint32_t OsalPort_enterCS(void) { return 0; }
static void OsalPort_leaveCS(uint32_t key) { (void)key; }
static bool NPITL_checkNpiBusy(void) { return npiTxActive; }
static uint16 transportWrite(uint16 len) {
 // Model the real UART transport precondition: accepted writes retain TX len.
 TransportTxLen = lower_response ? len : 0;
 return TransportTxLen;
}
static void complete_callback(int rx, int tx) {
 (void)rx;
 if (tx) { user_completions++; npiTxActive = false; }
}
""" + tl_func + "\n" + abort_func + "\n" + uart_func + r"""
int main(void) {
 uint8_t b[40]={0};
 npiTransmitCB = complete_callback;
 // A rejected UART2_write cannot leave NPI permanently busy.
 lower_response = 0;
 if (NPITL_writeTL(b,12) != 0) return 10;
 if (npiTxActive || msgFragLen || msgFrag || npiTxBufLen) return 11;
 lower_response = 1;
 if (NPITL_writeTL(b,12) != 12 || !npiTxActive) return 12;
 NPITLUART_writeCallBack(NULL,NULL,12,NULL,UART2_STATUS_SUCCESS);
 if (npiTxActive || user_completions != 1) return 13;
 // Fragment failure and subsequent accepted TX are exercised BEFORE B1 HOLD.
 lower_response = 0;
 if (NPITL_writeTL(b,32) != 0) return 16;
 if (npiTxActive || msgFragLen || msgFrag || npiTxBufLen) return 17;
 lower_response = 1;
 if (NPITL_writeTL(b,12) != 12) return 18;
 NPITLUART_writeCallBack(NULL,NULL,12,NULL,UART2_STATUS_SUCCESS);
 if (npiTxActive || user_completions != 2) return 19;
 // Genuine async UART failure must preserve B1 physical HOLD, never
 // fake a TX success, yet clear stale NPI busy state at the early return.
 if (NPITL_writeTL(b,12) != 12 || !npiTxActive) return 14;
 NPITLUART_writeCallBack(NULL,NULL,12,NULL,4);
 if (npiTxActive || user_completions != 2 ||
     task_notifications != 1 || physical_uart_failure_latch != 1) return 15;
 printf("NPI_UART_TX_EXACT_C_LIVENESS_PASS\n");
 return 0;
}
"""


def _b1_gate_c(actual_uart_write):
    # This second independent C fixture compiles the *actual composed*
    # NPITLUART_writeTransport function, not a Python approximation of HOLD.
    return r"""
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
typedef unsigned short uint16;
typedef unsigned char uint8;
typedef void *UART2_Handle;
#define NPI_FLOW_CTRL 0
#define UART2_STATUS_SUCCESS 0
#define B1_ERROR_UART_WRITE 17
static UART2_Handle uartHandle = NULL;
static uint8_t TransportTxBuf[256];
static uint16 TransportTxLen;
static bool hold = false;
static int physical_uart_write_attempts = 0;
static uint32_t OsalPort_enterCS(void) { return 0; }
static void OsalPort_leaveCS(uint32_t key) { (void)key; }
static bool b1_management_transport_unavailable(void) { return hold; }
static void b1_management_transport_failed(int err) { (void)err; hold = true; }
static void b1_startup_tx_submit(const uint8_t *p, uint16 len) {
 (void)p; (void)len;
}
static void b1_startup_tx_accepted(uint16 len, int ok) {
 (void)len; (void)ok;
}
static int_fast16_t UART2_write(UART2_Handle h, void *p, size_t len, void *arg) {
 (void)h; (void)p; (void)len; (void)arg;
 physical_uart_write_attempts++;
 return UART2_STATUS_SUCCESS;
}
""" + actual_uart_write + r"""
int main(void) {
 if (NPITLUART_writeTransport(12) != 12 || physical_uart_write_attempts != 1)
   return 31;
 hold = true; /* B1 physical HOLD after a completed callback error. */
 if (NPITLUART_writeTransport(12) != 0 || physical_uart_write_attempts != 1)
   return 32; /* stale callback cannot race any NEW accepted UART write */
 puts("B1_HOLD_REAL_UART_SUBMISSION_GUARD_PASS");
 return 0;
}
"""

def exercise(sdk):
    sdk=Path(sdk)
    tl=(sdk/TL).read_text()
    uart=(sdk/UART).read_text()
    writer=extract(tl,"uint16 NPITL_writeTL(uint8 *buf, uint16 len)")
    abort=extract(tl,"void NPITL_abortFailedTx(void)")
    callback=extract(uart,"static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)")
    tx_writer=extract(uart,"uint16 NPITLUART_writeTransport(uint16 len)")
    cc=shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:raise RuntimeError("NATIVE_C_COMPILER_REQUIRED")
    def run(label,source):
        with tempfile.TemporaryDirectory(prefix="p7u-v43-c-") as tmp:
            path=Path(tmp)
            inp=path/"actual.c"
            exe=path/"actual"
            inp.write_text(source)
            compile=subprocess.run([cc,"-std=c11","-Wall","-Wextra",
                "-Wno-unused-variable","-Wno-unused-function",
                "-Wno-unused-parameter",str(inp),"-o",str(exe)],
                text=True,capture_output=True,timeout=30)
            if compile.returncode:
                raise RuntimeError("C_COMPILE_FAILED_"+label+": "+compile.stderr[-1400:])
            done=subprocess.run([str(exe)],text=True,capture_output=True,timeout=10)
            return done.returncode,done.stdout
    status, out=run("POSITIVE",_c(writer,abort,callback))
    if status != 0 or "NPI_UART_TX_EXACT_C_LIVENESS_PASS" not in out:
        raise RuntimeError("REAL_C_LIVENESS_FAILED "+str(status))
    marker="    if (len == 0u)\n"
    if writer.count(marker)!=1:raise RuntimeError("IMMEDIATE_FAILURE_CHECK_ABSENT")
    i=writer.index(marker)
    openbrace=writer.index("{",i);depth=0;end=None
    for pos in range(openbrace,len(writer)):
        if writer[pos]=="{":depth+=1
        elif writer[pos]=="}":
            depth-=1
            if depth==0:end=pos+1;break
    if end is None:raise RuntimeError("C_MUTANT_SCAN")
    mutant_writer=writer[:i]+writer[end:]
    rc,_=run("NEGATIVE_STUCK_BUSY",_c(mutant_writer,abort,callback))
    if rc==0:raise RuntimeError("FAILED_TO_CATCH_STUCK_BUSY_MUTANT")
    failed_branch="    if (status != UART2_STATUS_SUCCESS || size != TransportTxLen ||"
    if callback.count(failed_branch)!=1:
        raise RuntimeError("B1_PHYSICAL_UART_ERROR_GATE_MISSING")
    mut_callback=callback.replace(failed_branch,
        "    if (status == UART2_STATUS_SUCCESS || size != TransportTxLen ||",1)
    rc,_=run("NEGATIVE_INVERTED_B1_STATUS",_c(writer,abort,mut_callback))
    if rc==0:raise RuntimeError("FAILED_TO_CATCH_INVERTED_B1_STATUS_MUTANT")
    unwind="        NPITL_abortFailedTx(); /* preserve B1 HOLD; no false TX completion */"
    if callback.count(unwind)!=1:raise RuntimeError("B1_ABORT_UNWIND_MISSING")
    rc,_=run("NEGATIVE_MISSING_B1_ABORT",_c(writer,abort,callback.replace(unwind,"",1)))
    if rc==0:raise RuntimeError("FAILED_TO_CATCH_MISSING_B1_ABORT_MUTANT")
    # The B1 callback enters physical HOLD *before* our error unwind. Prove
    # from actual accepted TI C that no new physical write can start afterward.
    gate_rc,gate_out=run("B1_HOLD_GATE",_b1_gate_c(tx_writer))
    if gate_rc!=0 or "B1_HOLD_REAL_UART_SUBMISSION_GUARD_PASS" not in gate_out:
        raise RuntimeError("B1_HOLD_NOT_ACTUALLY_GATING_UART_WRITES")
    anchor="if (b1_management_transport_unavailable())"
    if tx_writer.count(anchor)!=1:
        raise RuntimeError("B1_HOLD_GATE_SOURCE_DRIFT")
    gate_mutant=tx_writer.replace(anchor,"if (0)",1)
    gate_mutant_rc,_=run("NEGATIVE_B1_HOLD_BYPASS",_b1_gate_c(gate_mutant))
    if gate_mutant_rc==0:
        raise RuntimeError("B1_HOLD_GATE_MUTANT_NOT_REJECTED")
    return {"status":"PASS_ACTUAL_TI_COMPOSED_C_POSITIVE_AND_FOUR_MUTANTS",
            "cases":["immediate_rejection_unwedges","accepted_write_completes",
                     "asynchronous_failure_does_not_fake_success",
                     "failed_fragment_clears_dangling_remainder",
                     "next_write_remains_possible"],
            "negative_mutants":["stuck_busy","inverted_b1_status","missing_b1_abort","b1_hold_bypass"],
            "stale_callback_guard":"B1_HOLD_PREVENTS_NEW_UART_SUBMISSION_AFTER_ERROR",
            "hardware_access":False}

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",required=True)
    print(json.dumps(exercise(p.parse_args().sdk),sort_keys=True))
