#!/usr/bin/env python3
"""HOSTED ONLY: actual pinned UART dispatch + NPI transport body regression.

Lower-layer acceptance only; test_task covers the composed task owner separately.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G7 = ROOT / "firmware/slzb-06p7/ti832/g7"
sys.path.insert(0, str(G7))
import g7_transport_overlay as g

COMMON = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#define NPI_USE_UART 1
#define NPI_FLOW_CTRL 0
#define NPI_MAX_FRAG_SIZE NPI_TL_BUF_SIZE
#include "p7_g7_transport.h"
typedef uint8_t uint8; typedef uint16_t uint16;
#define TRUE true
#define FALSE false
#define UART2_Mode_BLOCKING 0
#define UART2_Mode_CALLBACK 1
#define UART2_Mode_NONBLOCKING 2
#define UART2_WAIT_FOREVER 0xffffffffu
#define SemaphoreP_NO_WAIT 0
#define SemaphoreP_OK 0
#define Log_printf(...) ((void)0)
typedef struct {
    struct { bool opened; int writeMode; bool writeTimedOut,txCancelled; } state;
    bool writeInUse;
    const void *writeBuf;
    size_t writeSize,writeCount,bytesWritten;
    int_fast16_t txStatus;
    int writeSem;
} UART2_Object;
typedef struct { int placeholder; } UART2_HWAttrs;
typedef struct { UART2_Object *object; const UART2_HWAttrs *hwAttrs; } UART2_Config;
typedef UART2_Config *UART2_Handle;
static UART2_Object object;
static UART2_HWAttrs attrs;
static UART2_Config config = { &object, &attrs };
static UART2_Handle uartHandle;
static int osal_depth,hwi_depth,dma_calls,driver_calls,late_status,unknown_status,tx_callbacks;
static uint8 npiTxBuf[NPI_TL_BUF_SIZE];
static uint8 *TransportTxBuf = npiTxBuf;
static uint16 TransportTxLen,npiTxBufLen,npiRxBufHead,npiRxBufTail,msgFragLen;
static uint8 *msgFrag;
static bool npiTxActive;
static uint32_t txPktCount;
static void (*taskRxCB)(uint16);
static void (*taskTxCB)(uint16);
static p7_submit_result_t p7_uart_result,p7_tl_result;
static bool HwiP_interruptsEnabled(void) { return hwi_depth==0; }
static uintptr_t HwiP_disable(void) { return (uintptr_t)hwi_depth++; }
static void HwiP_restore(uintptr_t key) { assert(hwi_depth==(int)key+1); --hwi_depth; }
/* Actual OsalPort CS disables HwiP; preserve that coupling in the host boundary. */
static uint32_t OsalPort_enterCS(void) { osal_depth++;return (uint32_t)HwiP_disable(); }
static void OsalPort_leaveCS(uint32_t key) { assert(osal_depth>0);--osal_depth;HwiP_restore(key); }
static int SemaphoreP_pend(int *sem,uint32_t timeout) { (void)sem;(void)timeout;return SemaphoreP_OK; }
static void UART2Support_enableTx(const UART2_HWAttrs *hw) { (void)hw;assert(hwi_depth); }
static void UART2Support_dmaStartTx(UART2_Handle handle) {
    assert(hwi_depth);dma_calls++;
    if(late_status==UART2_STATUS_ECANCELLED) handle->object->state.txCancelled=true;
    if(late_status==UART2_STATUS_ETIMEOUT) handle->object->state.writeTimedOut=true;
}
static void UART2Support_dmaStopTx(UART2_Handle handle) { (void)handle; }
static int_fast16_t UART2_writePolling(UART2_Handle h,const void *b,size_t n,size_t *w) {
    (void)h;(void)b;(void)n;(void)w;assert(!"unexpected polling path");return -11;
}
static int_fast16_t UART2_writeTimeoutNonblocking(UART2_Handle h,const void *b,size_t n,size_t *w,uint32_t t) {
    (void)h;(void)b;(void)n;(void)w;(void)t;assert(!"unexpected nonblocking path");return -11;
}
int_fast16_t UART2_writeTimeout(UART2_Handle,const void *,size_t,size_t *,uint32_t);
int_fast16_t UART2_writeTimeoutBlocking(UART2_Handle,const void *,size_t,size_t *,uint32_t);
static int NPITL_checkNpiBusy(void) { return npiTxActive; }
uint16 NPITL_writeTL(uint8 *,uint16);
'''

ADAPTER = r'''
static int_fast16_t driver_call(UART2_Handle handle,const void *buf,size_t len,size_t *written) {
    driver_calls++;
    int_fast16_t result=UART2_write(handle,buf,len,written);
    /* Unknown/future result is injected only AFTER the genuine submission. */
    return unknown_status ? unknown_status : result;
}
#define UART2_write driver_call
#define transportWrite NPITLUART_writeTransport
static void completed(uint16 len) { assert(len);tx_callbacks++; }
static void reset(void) {
    memset(&object,0,sizeof(object));object.state.opened=true;
    object.state.writeMode=UART2_Mode_CALLBACK;uartHandle=&config;
    dma_calls=driver_calls=late_status=unknown_status=tx_callbacks=0;
    npiTxActive=false;TransportTxLen=npiTxBufLen=msgFragLen=0;msgFrag=NULL;
    TransportTxBuf=npiTxBuf;taskTxCB=completed;taskRxCB=NULL;
    assert(!osal_depth&&!hwi_depth);
}
'''

PRE = r'''
int main(void) {
    uint8 frame[4]={0xfe,0,0x61,1}; reset();object.writeInUse=true;
    assert(NPITL_writeTL(frame,4)==0);
    assert(driver_calls==1 && dma_calls==0);
    assert(!npiTxActive); /* exact original stuck-busy negative control */
    return 0;
}
'''

POST = r'''
int main(void) {
    uint8 frame[NPI_TL_BUF_SIZE+1];memset(frame,0x5a,sizeof(frame));
    for(int i=0;i<512;i++) {
        reset();object.writeInUse=true;
        assert(NPITL_writeTL(frame,4)==0);
        assert(p7_g7_tl_outcome()==P7_SUBMIT_REJECTED);
        assert(!npiTxActive && driver_calls==1 && dma_calls==0);
        object.writeInUse=false;
        assert(NPITL_writeTL(frame,4)==4);
        assert(p7_g7_tl_outcome()==P7_SUBMIT_ACCEPTED);
        assert(npiTxActive && driver_calls==2 && dma_calls==1);
        assert(!memcmp(npiTxBuf,frame,4));
        assert(NPITL_writeTL(frame,4)==0);
        assert(p7_g7_tl_outcome()==P7_SUBMIT_BUSY);
        assert(npiTxActive && driver_calls==2 && dma_calls==1);
        NPITL_transmissionCallBack(0,4);
        assert(!npiTxActive && tx_callbacks==1);
        assert(!osal_depth&&!hwi_depth);
    }
    reset();object.state.opened=false;
    assert(NPITL_writeTL(frame,4)==0);
    assert(p7_g7_tl_outcome()==P7_SUBMIT_REJECTED);
    assert(!npiTxActive && dma_calls==0 && driver_calls==1);
    for(int mode=0;mode<4;mode++) {
        reset();
        if(mode==0)late_status=UART2_STATUS_ECANCELLED;
        if(mode==1)late_status=UART2_STATUS_ETIMEOUT;
        if(mode==2)unknown_status=UART2_STATUS_EFAIL;
        if(mode==3)unknown_status=7;
        assert(NPITL_writeTL(frame,4)==4);
        assert(p7_g7_tl_outcome()==P7_SUBMIT_AMBIGUOUS);
        assert(npiTxActive && dma_calls==1 && driver_calls==1);
        assert(NPITL_writeTL(frame,4)==0);
        assert(p7_g7_tl_outcome()==P7_SUBMIT_BUSY);
        assert(npiTxActive && dma_calls==1 && driver_calls==1);
        NPITL_transmissionCallBack(0,4);
        assert(!npiTxActive && tx_callbacks==1);
    }
    reset();
    assert(NPITL_writeTL(NULL,4)==0);
    assert(NPITL_writeTL(frame,0)==0);
    assert(NPITL_writeTL(frame,NPI_TL_BUF_SIZE+1)==0);
    assert(p7_g7_tl_outcome()==P7_SUBMIT_INVALID);
    assert(!npiTxActive && driver_calls==0 && dma_calls==0);
    uartHandle=NULL;
    assert(NPITL_writeTL(frame,4)==0);
    assert(p7_g7_tl_outcome()==P7_SUBMIT_INVALID);
    assert(!npiTxActive && driver_calls==0);
    puts("PASS actual pinned UART callback dispatch + lower TL: 512 reject/submit/completion cycles, busy, late and unknown outcomes, invalid input");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    texts = {rel: (args.sdk / rel).read_text() for rel in (g.TL, g.UART)}
    patched = g.patch(texts)
    config = (args.sdk / "source/ti/zstack/npi/npi_config.h").read_text()
    match = re.search(r"#\s*define\s+NPI_TL_BUF_SIZE\s+(\d+)", config)
    assert match and int(match[1]) == 270, "PINNED_BUFFER_GEOMETRY_CHANGED"
    header = (args.sdk / "source/ti/drivers/UART2.h").read_text()
    constants = "\n".join(re.findall(r"^#define UART2_STATUS_\w+ .+$", header, re.M))
    assert "params.writeMode = UART2_Mode_CALLBACK;" in texts[g.UART]
    mode_enum = header[header.index("UART2_Mode_BLOCKING,"):header.index("UART2_Mode_POLLING =")]
    assert re.findall(r"^\s*UART2_Mode_(BLOCKING|CALLBACK|NONBLOCKING),\s*$", mode_enum, re.M) == ["BLOCKING", "CALLBACK", "NONBLOCKING"]
    driver_blob = (args.sdk / "source/ti/drivers/UART2.c").read_text()
    driver = driver_blob.replace("int_fast16_t __attribute__((weak))\n", "int_fast16_t ")
    driver_bodies = "\n".join(g.function(driver, name) for name in (
        "UART2_write", "UART2_writeTimeout", "UART2_writeTimeoutBlocking"))
    results = []
    for name, source, test in [("pre_busy", texts, PRE), ("post_boundary", patched, POST)]:
        getters = ""
        if name.startswith("post"):
            getters = g.function(source[g.UART], "p7_g7_uart_outcome") + "\n" + g.function(source[g.TL], "p7_g7_tl_outcome")
        c = args.out / (name + ".c")
        binary = args.out / name
        c.write_text(constants + "\n" + COMMON + "\n" + driver_bodies + "\n" + ADAPTER + "\n" +
                     g.function(source[g.UART], "NPITLUART_writeTransport") + "\n" +
                     g.function(source[g.TL], "NPITL_writeTL") + "\n" +
                     g.function(source[g.TL], "NPITL_transmissionCallBack") + "\n" + getters + "\n" + test)
        subprocess.run(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-function", "-Wno-unused-variable",
                        "-DNPI_TL_BUF_SIZE=" + match[1], "-I", str(G7), str(c), "-o", str(binary)], check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        (args.out / (name + ".log")).write_text(result.stdout + result.stderr)
        if name.startswith("pre"):
            assert result.returncode != 0 and "Assertion `!npiTxActive' failed" in result.stderr, result.stderr
        else:
            assert result.returncode == 0, result.stderr
            print(result.stdout, end="")
        results.append({"name": name, "returncode": result.returncode})
    (args.out / "transport-source-evidence.json").write_text(json.dumps({
        "results": results, "sdk_sha": "6499c3f53fc5fb5806213be695450a7b43fbaf3d",
        "source_sha256": {rel: hashlib.sha256(text.encode()).hexdigest() for rel, text in texts.items()},
        "driver_sha256": hashlib.sha256(driver_blob.encode()).hexdigest(),
        "task_ownership_retry_fairness_qualified": False,
        "runtime_qualified": False, "flash_authorized": False}, indent=2) + "\n")


if __name__ == "__main__":
    main()
