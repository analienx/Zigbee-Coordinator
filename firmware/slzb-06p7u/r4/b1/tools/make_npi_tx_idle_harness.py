"""Compile exact patched TI NPI TX_READY event section with a mocked UART.

NPI_FLOW_CTRL=0, NPI_SREQRSP disabled. No hardware or alternate serial owner.
An actual busy UART must not cause a priority-4 self-post storm; existing
TX_DONE wakes and progresses the queue. Error/transport HOLD never transmits.
"""
from pathlib import Path
import argparse
PREAMBLE=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define NPITASK_TX_READY_EVENT 0x0010u
#define NPI_FLOW_CTRL 0
static uint32_t npiServiceTaskEvents;
static unsigned pending, transmitted, posts;
static bool busy, hold;
static int queue_object, semaphore_object;
static void *npiTxQueue=&queue_object, *npiSemHandle=&semaphore_object;
static bool Queue_empty(void *q) {
    assert(q==npiTxQueue);
    return pending==0;
}
static bool NPITL_checkNpiBusy(void) {return busy;}
static bool b1_management_transport_unavailable(void) {return hold;}
static void Semaphore_post(void *s) {
    assert(s==npiSemHandle);
    ++posts;
}
static void NPITask_ProcessTXQ(void) {
    assert(!busy && !hold && pending>0);
    --pending;
    ++transmitted;
    busy=true; /* UART accepts one frame asynchronously */
}
'''
MAIN=r'''
int main(int argc,char **argv) {
    assert(argc==2);
    npiServiceTaskEvents=NPITASK_TX_READY_EVENT;
    if(strcmp(argv[1],"busy")==0) {
        pending=2;busy=true;
        for(int i=0;i<1000;i++) cycle();
        assert(posts==0 && transmitted==0 && pending==2);
        assert(npiServiceTaskEvents & NPITASK_TX_READY_EVENT);
        puts("B1_ACTUAL_NPI_BUSY_U2_TX_NO_PRIORITY_SPIN_PASS");
    } else if(strcmp(argv[1],"tx_done")==0) {
        pending=2;busy=true;
        cycle();assert(posts==0);
        busy=false;Semaphore_post(npiSemHandle); /* real TX_DONE callback */
        cycle();assert(transmitted==1 && pending==1 && posts==1 && busy);
        busy=false;Semaphore_post(npiSemHandle); /* second TX_DONE */
        cycle();assert(transmitted==2 && pending==0 && posts==2);
        assert(!(npiServiceTaskEvents & NPITASK_TX_READY_EVENT));
        puts("B1_ACTUAL_NPI_TX_DONE_REARMS_PENDING_SRSP_PASS");
    } else if(strcmp(argv[1],"idle")==0) {
        pending=1;busy=false;
        cycle();assert(transmitted==1 && pending==0 && posts==0);
        assert(!(npiServiceTaskEvents & NPITASK_TX_READY_EVENT));
        puts("B1_ACTUAL_NPI_SINGLE_QUEUED_SRSP_NO_BUSY_LOOP_PASS");
    } else if(strcmp(argv[1],"hold")==0) {
        pending=3;busy=false;hold=true;
        for(int i=0;i<500;i++)cycle();
        assert(posts==0 && transmitted==0 && pending==3);
        assert(npiServiceTaskEvents & NPITASK_TX_READY_EVENT);
        puts("B1_ACTUAL_NPI_STICKY_TRANSPORT_HOLD_NO_SPIN_PASS");
    } else return 2;
    return 0;
}
'''
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--source",type=Path,required=True)
 p.add_argument("--output",type=Path,required=True)
 a=p.parse_args()
 text=a.source.read_text(encoding="utf8")
 beginning="            // An ASYNC message is ready to send to the Host\n"
 ending="            // The Transport Layer has received some bytes\n"
 if text.count(beginning)!=1 or text.count(ending)!=1:raise RuntimeError("PINNED_NPI_EVENT_SECTION_DRIFT")
 body=text.split(beginning,1)[1].split(ending,1)[0]
 assert "NPITASK_TX_READY_EVENT" in body and "NPITask_ProcessTXQ();" in body
 assert "!b1_management_transport_unavailable()" in body
 assert "else if (!NPITL_checkNpiBusy()" in body
 source=PREAMBLE+"\nstatic void cycle(void)\n{\n"+beginning+body+"}\n"+MAIN
 a.output.write_text(source,encoding="utf8")
 print("B1_REAL_NPI_UART_BUSY_SCHEDULER_EXTRACTED")
if __name__=="__main__":main()
