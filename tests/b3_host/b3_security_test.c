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
static bool allocation_fails=false, corrupt_success=false, fail_readback=false;
static APSME_ApsLinkKeyNVEntry_t persisted_aps[2];
static APSME_TCLinkKeyNVEntry_t persisted_tc[2];
void *OsalPort_malloc(size_t n) { return allocation_fails ? NULL : calloc(1,n); }
void OsalPort_free(void *p) { free(p); }
uint8_t osal_nv_read_ex(uint16_t id,uint16_t subid,uint16_t ofs,uint16_t len,void *data) {
    (void)ofs;
    reads++;
    if(read_result!=SUCCESS || (fail_readback && writes != 0)) return NV_OPER_FAILED;
    if(subid >= 2 || len != sizeof(APSME_ApsLinkKeyNVEntry_t)) return NV_OPER_FAILED;
    if(id == ZCD_NV_EX_APS_KEY_DATA_TABLE) memcpy(data,&persisted_aps[subid],len);
    else if(id == ZCD_NV_EX_TCLK_TABLE) memcpy(data,&persisted_tc[subid],len);
    else return NV_OPER_FAILED;
    return SUCCESS;
}
uint8_t osal_nv_write_ex(uint16_t id,uint16_t subid,uint16_t len,void *data) {
    writes++;
    if(write_result!=SUCCESS) return write_result;
    if(subid>=2 || len!=sizeof(APSME_ApsLinkKeyNVEntry_t)) return NV_OPER_FAILED;
    if(id==ZCD_NV_EX_APS_KEY_DATA_TABLE) {
        memcpy(&persisted_aps[subid],data,len);
        if(corrupt_success) persisted_aps[subid].txFrmCntr ^= 1u;
    } else if(id==ZCD_NV_EX_TCLK_TABLE) {
        memcpy(&persisted_tc[subid],data,len);
        if(corrupt_success) persisted_tc[subid].txFrmCntr ^= 1u;
    } else return NV_OPER_FAILED;
    return SUCCESS;
}
extern void ZDSecMgrSaveApsLinkKey(void);
extern void ZDSecMgrSaveTCLinkKey(void);
static void check(bool tc, int read_rc, int write_rc, int corrupt,
                  int readback_error, int expect_pending, int expect_writes) {
    reads=0; writes=0;
    corrupt_success=corrupt; fail_readback=readback_error;
    read_result=read_rc; write_result=write_rc;
    memset(persisted_aps,0,sizeof(persisted_aps));
    memset(persisted_tc,0,sizeof(persisted_tc));
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
    assert(reads == (unsigned)(read_rc==SUCCESS ? (write_rc==SUCCESS ? 2 : 1) : 1));
    assert(writes == (unsigned)expect_writes);
}
int main(void) {
    for(int kind=0; kind<2;kind++) {
        check(kind,SUCCESS,SUCCESS,FALSE,FALSE,FALSE,1); /* readback positive */
        check(kind,SUCCESS,NV_OPER_FAILED,FALSE,FALSE,TRUE,1);
        check(kind,NV_OPER_FAILED,SUCCESS,FALSE,FALSE,TRUE,0);
        check(kind,SUCCESS,SUCCESS,TRUE,FALSE,TRUE,1); /* lie: write succeeded, media corrupted */
        check(kind,SUCCESS,SUCCESS,FALSE,TRUE,TRUE,1); /* readback refuses */
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
    puts("B3_TI_APS_TCLK_READBACK_CORRUPT_SUCCESS_AND_FAILURE_HARNESS_PASS");
    return 0;
}
