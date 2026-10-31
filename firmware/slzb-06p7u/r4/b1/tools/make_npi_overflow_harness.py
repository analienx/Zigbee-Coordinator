"""Compile the REAL patched TI RX callback against a no-radio, no-USB host shim.

This catches the stock TI's for(;;) ISR trap after bytes are lost. The
transport is irrecoverable within a boot: we must not parse bytes or promise
SYS F1 replies after an overflow. No production UART is accessed.
"""
import argparse
from pathlib import Path
from patch_zdapp import extract_function

PREAMBLE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "b1_management.h"
#define B1_MANAGEMENT_HOST 1
#define NPITASK_TRANSPORT_RX_EVENT 0x10u
static unsigned irq_depth, reads, posts, bytes_read;
static int avail = 16;
static unsigned TRANSPORT_RX_ISR_EVENT_FLAG;
static unsigned npi_semaphore;
static void *npiSemHandle = &npi_semaphore;
uintptr_t b1_management_test_disable(void)
{
    assert(!irq_depth); irq_depth=1; return 0xFFu;
}
void b1_management_test_restore(uintptr_t key)
{
    assert(irq_depth==1 && key==0xFFu); irq_depth=0;
}
static int NPIRxBuf_GetRxBufAvail(void) {return avail;}
static void NPIRxBuf_Read(int size) {assert(size>0 && size<avail); ++reads; bytes_read+=(unsigned)size;}
static void Semaphore_post(void *s) {assert(s==npiSemHandle); ++posts;}
'''

MAIN = r'''
int main(int argc, char **argv)
{
    assert(argc==2);
    if (strcmp(argv[1],"healthy")==0)
    {
        NPITask_transportRXCallBack(4);
        assert(reads==1 && bytes_read==4 && posts==1);
        assert(TRANSPORT_RX_ISR_EVENT_FLAG == NPITASK_TRANSPORT_RX_EVENT);
        assert(!b1_management_transport_unavailable());
        puts("B1_REAL_TI_RX_HEALTHY_CONTROL_PASS");
    }
    else if (strcmp(argv[1],"overflow")==0)
    {
        /* TI's strict < available condition: equality is overflow. */
        NPITask_transportRXCallBack(avail);
        assert(reads==0 && posts==0);
        assert(b1_management_transport_unavailable());
        assert(b1_management_get_hold_active());
        NPITask_transportRXCallBack(1);
        assert(reads==0 && posts==0); /* no silent recovery/restart */
        puts("B1_REAL_TI_RX_OVERFLOW_STICKY_NO_SPIN_PASS");
    }
    else if (strcmp(argv[1],"oversize")==0)
    {
        NPITask_transportRXCallBack(avail+1);
        assert(reads==0 && posts==0 && b1_management_transport_unavailable());
        puts("B1_REAL_TI_RX_OVERSIZE_NO_SPIN_PASS");
    }
    else if (strcmp(argv[1],"negative")==0)
    {
        NPITask_transportRXCallBack(-1);
        assert(reads==0 && posts==0 && b1_management_transport_unavailable());
        puts("B1_REAL_TI_RX_NEGATIVE_LENGTH_HOLD_PASS");
    }
    else if (strcmp(argv[1],"empty")==0)
    {
        NPITask_transportRXCallBack(0);
        assert(reads==0 && posts==0 && !b1_management_transport_unavailable());
        puts("B1_REAL_TI_RX_EMPTY_NOOP_PASS");
    }
    else return 2;
    return 0;
}
'''


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    source=a.source.read_text(encoding='utf-8')
    body=extract_function(source,'static void NPITask_transportRXCallBack(int size)')
    if 'for(;;)' in body or 'b1_management_transport_unavailable()' not in body:
        raise RuntimeError('UNSAFE_TI_RX_TRAP_OR_MISSING_TRANSPORT_HOLD')
    a.output.write_text(PREAMBLE+body+MAIN,encoding='utf-8')
    print('B1_LINKED_NPI_RX_ISR_BODY_EXTRACTED')


if __name__=='__main__':
    main()
