/* Tests invoke ACTUAL extracted TI zd_sec_mgr.c function bodies.
 * Mock only OSAL backend and memory allocation.
 */
#include "b3_security_stub.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

const uint16_t gZDSECMGR_ENTRY_MAX = 2;
const uint16_t gZDSECMGR_TC_DEVICE_MAX = 2;
APSME_ApsLinkKeyRAMEntry_t ApsLinkKeyRAMEntry[2];
APSME_TCLinkKeyRAMEntry_t TCLinkKeyRAMEntry[2];
static unsigned reads, writes;
static uint8_t read_result=SUCCESS,write_result=SUCCESS;
static bool allocation_fails=false;
void *OsalPort_malloc(size_t n) { return allocation_fails ? NULL : calloc(1,n); }
void OsalPort_free(void *p) { free(p); }
uint8_t osal_nv_read_ex(uint16_t id,uint16_t subid,uint16_t ofs,uint16_t len,void *data) {
    (void)id; (void)subid; (void)ofs;
    reads++;
    if(read_result!=SUCCESS) return read_result;
    memset(data,0,len);
    return SUCCESS;
}
uint8_t osal_nv_write_ex(uint16_t id,uint16_t subid,uint16_t len,void *data) {
    (void)id; (void)subid; (void)len; (void)data;
    writes++;
    return write_result;
}
extern void ZDSecMgrSaveApsLinkKey(void);
extern void ZDSecMgrSaveTCLinkKey(void);
static void check(bool tc, int read_rc, int write_rc, int expect_pending, int expect_writes) {
    reads=0; writes=0;
    read_result=read_rc; write_result=write_rc;
    memset(ApsLinkKeyRAMEntry,0,sizeof(ApsLinkKeyRAMEntry));
    memset(TCLinkKeyRAMEntry,0,sizeof(TCLinkKeyRAMEntry));
    if(tc) {
        TCLinkKeyRAMEntry[0].pendingFlag=TRUE;
        TCLinkKeyRAMEntry[0].txFrmCntr=123;
        ZDSecMgrSaveTCLinkKey();
        assert(TCLinkKeyRAMEntry[0].pendingFlag==expect_pending);
        assert(TCLinkKeyRAMEntry[1].pendingFlag==FALSE);
    } else {
        ApsLinkKeyRAMEntry[0].pendingFlag=TRUE;
        ApsLinkKeyRAMEntry[0].txFrmCntr=123;
        ZDSecMgrSaveApsLinkKey();
        assert(ApsLinkKeyRAMEntry[0].pendingFlag==expect_pending);
        assert(ApsLinkKeyRAMEntry[1].pendingFlag==FALSE);
    }
    assert(reads == 1);
    assert(writes == (unsigned)expect_writes);
}
int main(void) {
    for(int kind=0; kind<2;kind++) {
        check(kind,SUCCESS,SUCCESS,FALSE,1); /* positive */
        check(kind,SUCCESS,NV_OPER_FAILED,TRUE,1); /* failed persistence */
        check(kind,NV_OPER_FAILED,SUCCESS,TRUE,0); /* read rejected */
        allocation_fails=true;
        reads=0; writes=0;
        if(kind) {
            TCLinkKeyRAMEntry[0].pendingFlag=TRUE;
            ZDSecMgrSaveTCLinkKey();
            assert(TCLinkKeyRAMEntry[0].pendingFlag==TRUE);
        } else {
            ApsLinkKeyRAMEntry[0].pendingFlag=TRUE;
            ZDSecMgrSaveApsLinkKey();
            assert(ApsLinkKeyRAMEntry[0].pendingFlag==TRUE);
        }
        assert(reads==0 && writes==0);
        allocation_fails=false;
    }
    puts("B3_ACTUAL_TI_SECURITY_CHECKPOINT_PENDING_FAILURE_HARNESS_PASS");
    return 0;
}
