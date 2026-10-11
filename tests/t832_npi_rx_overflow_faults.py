#!/usr/bin/env python3
"""Compile actual pinned-TI NPI callback, parser reset and ring discard.

Deliberately discard corrupted frame; never emit a partial host command.
No serial device, radio or network access.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile
from t832_npi_ownership_faults import function

PREFIX=r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t uint8;
typedef uint16_t uint16;
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);exit(8);}}while(0)
#define NPIFRAMEMT_SOP_STATE 0
#define NPIFRAMEMT_DATA_STATE 4
#define NPITASK_TRANSPORT_RX_EVENT 2
static uint8_t state, LEN_Token, FSC_Token, tempDataLen, *pMsg;
static uint16 RxBufHead,RxBufTail;
static volatile uint32_t npiRxOverflowEvents,npiRxOverflowDiscardedBytes;
static volatile uint8_t npiRxOverflowPending;
static uint16_t available=50,rx_seen,tl_available,sem_posts;
static uint16_t TRANSPORT_RX_ISR_EVENT_FLAG;
static int npiSemHandle;
static int live;
static uint8_t *os_alloc(size_t n) {uint8_t*p=calloc(1,n);CHECK(p);live++;return p;}
static void OsalPort_msgDeallocate(void *p){CHECK(live>0&&p);free(p);live--;}
static uint16 NPIRxBuf_GetRxBufAvail(void){return available;}
static uint16 NPIRxBuf_Read(uint16 n){rx_seen+=n;RxBufTail+=n;return n;}
static uint16 NPITL_readTL(uint8_t *p,uint16 n) {
  uint16 m=n<tl_available?n:tl_available;
  for(uint16 i=0;i<m;i++)p[i]=0xaa;
  tl_available-=m;
  return m;
}
static void Semaphore_post(int h){(void)h;sem_posts++;}
"""
TEST=r"""
int main(void) {
 for(int i=0;i<256;i++) {
  CHECK(live==0);
  rx_seen=sem_posts=0;available=12;tl_available=75;
  state=NPIFRAMEMT_DATA_STATE;LEN_Token=35;FSC_Token=42;tempDataLen=17;
  pMsg=os_alloc(38);RxBufHead=5;RxBufTail=10;npiRxOverflowPending=0;
  NPITask_transportRXCallBack(75);
  CHECK(npiRxOverflowPending==1);
  CHECK(tl_available==0 && rx_seen==0 && sem_posts==1);
  CHECK(npiRxOverflowDiscardedBytes==(uint32_t)(i*92+75));
  // The next ISR callback before task recovery is also discarded.
  tl_available=17;available=500;
  NPITask_transportRXCallBack(17);
  CHECK(tl_available==0&&rx_seen==0&&npiRxOverflowPending==1);
  CHECK(npiRxOverflowDiscardedBytes==(uint32_t)(i+1)*92);
  // In NPI task: discard old buffer and parser ownership, then clear flag.
  NPIFrame_resetOnOverflow();
  NPIRxBuf_DiscardAll();
  npiRxOverflowPending=0;
  CHECK(live==0&&pMsg==NULL&&state==NPIFRAMEMT_SOP_STATE);
  CHECK(RxBufHead==RxBufTail&&LEN_Token==0&&tempDataLen==0);
  tl_available=10;
  NPITask_transportRXCallBack(10);
  CHECK(rx_seen==10 && npiRxOverflowPending==0);
  // Handler is idempotent and must never free completed/owned frames twice.
  NPIFrame_resetOnOverflow();
  CHECK(pMsg==NULL&&live==0);
 }
 puts("PASS native NPI RX overflow: 256 rounds of discard/resync and zero leaks");
 return 0;
}
"""
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    a=p.parse_args()
    n=(a.sdk/"source/ti/zstack/npi/npi_task.c").read_text()
    f=(a.sdk/"source/ti/zstack/npi/npi_frame_mt.c").read_text()
    rx=(a.sdk/"source/ti/zstack/npi/npi_rxbuf.c").read_text()
    loop=function(n,"static void NPITask_process(void)\n")
    assert "NPIFrame_resetOnOverflow();" in loop
    assert "NPIRxBuf_DiscardAll();" in loop
    assert "npiRxOverflowPending = 0;" in loop
    parser=function(f,"void NPIFrame_collectFrameData(void)\n")
    assert "pMsg = NULL; // Ownership transferred or freed at FCS." in parser
    bodies=[
        function(n,"static void NPITask_transportRXCallBack(int size)\n"),
        function(f,"void NPIFrame_resetOnOverflow(void)\n"),
        function(rx,"void NPIRxBuf_DiscardAll(void)\n")
    ]
    with tempfile.TemporaryDirectory() as d:
        c=Path(d)/"rx.c";exe=Path(d)/"rx"
        c.write_text(PREFIX+"\n\n".join(bodies)+TEST)
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                        "-o",str(exe),str(c)],check=True)
        subprocess.run([str(exe)],check=True)
if __name__=="__main__":
    main()
