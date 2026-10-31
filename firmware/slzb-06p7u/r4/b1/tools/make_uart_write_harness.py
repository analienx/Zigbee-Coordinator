"""Compile actual TI8.33 UART TX source, never synthetic completion logic.

Verifies callback status and immediate write submission. Host GPIO/UART only
stubs; physical serial and Zigbee RF remain NOT_MEASURED.
"""
import argparse
from pathlib import Path
from patch_zdapp import extract_function

PREAMBLE = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "b1_management.h"
#define NPI_FLOW_CTRL 0
#define UART2_STATUS_SUCCESS 0
typedef uint16_t uint16;
typedef void *UART2_Handle;
static unsigned osal_depth, callback_count, write_calls, fail_write;
static uint16_t last_callback_rx, last_callback_tx;
static uint8_t txbuf[80];
static int fake_uart;
static UART2_Handle uartHandle=&fake_uart;
static uint16_t TransportTxLen;
static uint8_t *TransportTxBuf=txbuf;
uintptr_t b1_management_test_disable(void) {return 99u;}
void b1_management_test_restore(uintptr_t key) {assert(key==99u);}
static uint32_t OsalPort_enterCS(void) {assert(osal_depth==0u); osal_depth=1u;return 7u;}
static void OsalPort_leaveCS(uint32_t key) {assert(key==7u && osal_depth==1u);osal_depth=0u;}
static int_fast16_t UART2_write(UART2_Handle handle,const void *buf,size_t len,void *ptr)
{
    assert(handle==uartHandle && buf==TransportTxBuf && len==TransportTxLen && ptr==NULL);
    ++write_calls;
    return fail_write?-1:UART2_STATUS_SUCCESS;
}
static void callback(uint16_t rx,uint16_t tx)
{++callback_count;last_callback_rx=rx;last_callback_tx=tx;}
static void (*npiTransmitCB)(uint16_t,uint16_t)=callback;
'''

MAIN = r'''
int main(int argc,char **argv)
{
    assert(argc==2);
    const char *s=argv[1];
    if(strcmp(s,"healthy")==0)
    {
        assert(NPITLUART_writeTransport(4u)==4u);
        assert(write_calls==1u && callback_count==0u);
        NPITLUART_writeCallBack(uartHandle,txbuf,4u,NULL,UART2_STATUS_SUCCESS);
        assert(callback_count==1u && last_callback_rx==0u && last_callback_tx==4u);
        assert(!b1_management_transport_unavailable());
        puts("B1_ACTUAL_UART_TX_HEALTHY_COMPLETE_PASS");
    }
    else if(strcmp(s,"failed_completion")==0)
    {
        assert(NPITLUART_writeTransport(4u)==4u);
        NPITLUART_writeCallBack(uartHandle,txbuf,2u,NULL,-14);
        assert(callback_count==0u && b1_management_transport_unavailable());
        assert(!b1_management_nv_security_hold_active());
        assert(NPITLUART_writeTransport(4u)==0u && write_calls==1u);
        assert(callback_count==0u);
        puts("B1_ACTUAL_UART_TX_FAILED_CALLBACK_NO_FALSE_RECEIPT_PASS");
    }
    else if(strcmp(s,"short_success")==0)
    {
        assert(NPITLUART_writeTransport(4u)==4u);
        NPITLUART_writeCallBack(uartHandle,txbuf,2u,NULL,UART2_STATUS_SUCCESS);
        assert(callback_count==0u && write_calls==1u);
        assert(b1_management_transport_unavailable());
        assert(!b1_management_nv_security_hold_active());
        assert(NPITLUART_writeTransport(4u)==0u && write_calls==1u);
        puts("B1_ACTUAL_UART_TX_SHORT_COMPLETION_NO_FALSE_RECEIPT_PASS");
    }
    else if(strcmp(s,"failed_submit")==0)
    {
        fail_write=1u;
        assert(NPITLUART_writeTransport(4u)==0u);
        assert(callback_count==0u && write_calls==1u);
        assert(b1_management_transport_unavailable());
        assert(!b1_management_nv_security_hold_active());
        fail_write=0u;
        assert(NPITLUART_writeTransport(4u)==0u && write_calls==1u);
        puts("B1_ACTUAL_UART_TX_FAILED_SUBMISSION_STICKY_PASS");
    }
    else if(strcmp(s,"preheld")==0)
    {
        b1_management_transport_failed(B1_ERROR_NPI_RX_OVERFLOW);
        assert(NPITLUART_writeTransport(4u)==0u && write_calls==0u);
        NPITLUART_writeCallBack(uartHandle,txbuf,4u,NULL,UART2_STATUS_SUCCESS);
        assert(callback_count==0u && b1_management_transport_unavailable());
        assert(!b1_management_nv_security_hold_active());
        puts("B1_ACTUAL_UART_TX_PREHELD_NO_WRITE_PASS");
    }
    else return 2;
    assert(osal_depth==0u);
    return 0;
}
'''

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    source=args.source.read_text(encoding="utf-8")
    callback=extract_function(source,
        "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)")
    writer=extract_function(source,
        "uint16 NPITLUART_writeTransport(uint16 len)")
    if "B1_ERROR_UART_WRITE" not in callback or "B1_ERROR_UART_WRITE" not in writer:
        raise RuntimeError("B1_UART_TX_FAIL_CLOSED_PATCH_NOT_LINKED")
    args.output.write_text(PREAMBLE+callback+"\n"+writer+"\n"+MAIN,encoding="utf-8")
    print("B1_ACTUAL_TI_UART_TX_CALLBACK_AND_WRITE_SOURCE_EXTRACTED")

if __name__=="__main__":
    main()
