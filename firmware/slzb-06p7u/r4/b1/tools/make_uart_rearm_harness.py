"""Actual TI8.33 UART read-completion body, with synthetic ISR and UART2.

Checks that a lost-byte callback cannot rearm UART reads after NPI latches
HOLD_TRANSPORT. Existing healthy receive/re-arm control must still work.
"""
from pathlib import Path
import argparse
from patch_zdapp import extract_function

PREAMBLE=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "b1_management.h"
#define NPI_FLOW_CTRL 0
#define NPI_TL_BUF_SIZE 80u
#define UART_ISR_BUF_SIZE 32u
#define UART2_STATUS_SUCCESS 0
typedef void* UART2_Handle;
static uint32_t cs_depth;
static int uart_sentinel, uart_reads, notifications, copied, force_short;
static UART2_Handle uartHandle=&uart_sentinel;
static uint8_t isrRxBuf[UART_ISR_BUF_SIZE];
static uint16_t TransportRxLen, TransportTxLen;
uintptr_t b1_management_test_disable(void) {return 7u;}
void b1_management_test_restore(uintptr_t key) {assert(key==7u);}
static uint32_t OsalPort_enterCS(void) {++cs_depth;return cs_depth;}
static void OsalPort_leaveCS(uint32_t key) {assert(cs_depth==key);--cs_depth;}
static uint16_t NPITLUART_readIsrBuf(size_t n)
{
    ++copied;
    return (uint16_t)(force_short ? n-1 : n);
}
static int UART2_read(UART2_Handle h,void *b,size_t n,void *arg)
{
    assert(h==uartHandle && b==isrRxBuf && n==UART_ISR_BUF_SIZE && arg==NULL);
    ++uart_reads;return UART2_STATUS_SUCCESS;
}
static void notify(uint16_t rx,uint16_t tx)
{
    (void)tx; ++notifications;
    if(rx==NPI_TL_BUF_SIZE) b1_management_transport_failed(B1_ERROR_NPI_RX_OVERFLOW);
}
static void (*npiTransmitCB)(uint16_t,uint16_t)=notify;
'''

MAIN=r'''
int main(int argc,char **argv)
{
    assert(argc==2);
    if(strcmp(argv[1],"healthy")==0)
    {
        NPITLUART_readCallBack(uartHandle,isrRxBuf,4,NULL,UART2_STATUS_SUCCESS);
        assert(copied==1 && notifications==1 && uart_reads==1 && !cs_depth);
        assert(!b1_management_transport_unavailable());
        puts("B1_ACTUAL_UART_HEALTHY_REARM_PASS");
    }
    else if(strcmp(argv[1],"overflow")==0)
    {
        force_short=1;
        NPITLUART_readCallBack(uartHandle,isrRxBuf,4,NULL,UART2_STATUS_SUCCESS);
        assert(copied==1 && notifications>=1 && uart_reads==0 && !cs_depth);
        assert(b1_management_transport_unavailable());
        NPITLUART_readCallBack(uartHandle,isrRxBuf,4,NULL,UART2_STATUS_SUCCESS);
        assert(copied==1 && uart_reads==0 && !cs_depth);
        puts("B1_ACTUAL_UART_LOST_BYTE_NO_REARM_PASS");
    }
    else if(strcmp(argv[1],"preheld")==0)
    {
        b1_management_transport_failed(B1_ERROR_NPI_RX_OVERFLOW);
        NPITLUART_readCallBack(uartHandle,isrRxBuf,4,NULL,UART2_STATUS_SUCCESS);
        assert(copied==0 && notifications==0 && uart_reads==0 && !cs_depth);
        puts("B1_ACTUAL_UART_PREHELD_NO_READ_PASS");
    }
    else return 2;
    return 0;
}
'''


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--source',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    source=args.source.read_text(encoding='utf-8')
    body=extract_function(source,
        "static void NPITLUART_readCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)")
    if "b1_management_transport_unavailable()" not in body:
        raise RuntimeError("B1_UART_REARM_GUARD_MISSING")
    args.output.write_text(PREAMBLE+body+MAIN,encoding='utf-8')
    print("B1_ACTUAL_TI_UART_RX_CALLBACK_BODY_EXTRACTED")

if __name__=='__main__':
    main()
