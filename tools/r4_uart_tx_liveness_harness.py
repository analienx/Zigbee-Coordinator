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
#define NPI_MAX_FRAG_SIZE 16
static volatile bool npiTxActive = false;
static uint8_t npiTxBuf[512];
static uint16 npiTxBufLen = 0;
static uint8_t *msgFrag = NULL;
static uint16 msgFragLen = 0;
static unsigned txPktCount = 0;
static int lower_response = 0, task_notifications = 0, user_completions = 0;
static uint16 TransportTxLen = 0;
static void (*npiTransmitCB)(int,int) = NULL;
static void sent_task(int count) { (void)count; task_notifications++; }
static TxCallback taskTxCB = sent_task;
static uint32_t OsalPort_enterCS(void) { return 0; }
static void OsalPort_leaveCS(uint32_t key) { (void)key; }
static bool NPITL_checkNpiBusy(void) { return npiTxActive; }
static uint16 transportWrite(uint16 len) { return lower_response ? len : 0; }
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
 // Asynchronous failure must NOT be reported as successful completion.
 if (NPITL_writeTL(b,12) != 12 || !npiTxActive) return 14;
 NPITLUART_writeCallBack(NULL,NULL,12,NULL,4);
 if (npiTxActive || user_completions != 1 || task_notifications != 1) return 15;
 // Fragmented, synchronously rejected transmissions must not retain
 // dangling pointers to a caller-owned message.
 lower_response = 0;
 if (NPITL_writeTL(b,32) != 0) return 16;
 if (npiTxActive || msgFragLen || msgFrag || npiTxBufLen) return 17;
 lower_response = 1;
 if (NPITL_writeTL(b,12) != 12) return 18;
 printf("NPI_UART_TX_EXACT_C_LIVENESS_PASS\n");
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
    failed_branch="""    if (status != UART2_STATUS_SUCCESS)"""
    if callback.count(failed_branch)!=1:raise RuntimeError("ASYNC_STATUS_TEST_ABSENT")
    mut_callback=callback.replace("    if (status != UART2_STATUS_SUCCESS)",
        "    if (status == UART2_STATUS_SUCCESS)",1)
    rc,_=run("NEGATIVE_FALSE_TX",_c(writer,abort,mut_callback))
    if rc==0:raise RuntimeError("FAILED_TO_CATCH_FALSE_TX_MUTANT")
    return {"status":"PASS_ACTUAL_TI_COMPOSED_C_POSITIVE_AND_TWO_MUTANTS",
            "cases":["immediate_rejection_unwedges","accepted_write_completes",
                     "asynchronous_failure_does_not_fake_success",
                     "failed_fragment_clears_dangling_remainder",
                     "next_write_remains_possible"],
            "negative_mutants":["stuck_busy","inverted_callback_status"],
            "hardware_access":False}

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",required=True)
    print(json.dumps(exercise(p.parse_args().sdk),sort_keys=True))
