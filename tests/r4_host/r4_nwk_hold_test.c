/* Genuine fused TI C function linked with real B1 admission/management C.
 * Mock only synthetic SSP/NV and IRQ primitives. One scenario per process
 * because sticky B1 HOLD must never be reset by a test fixture in one boot.
 */
#include "b3_nwk_stub.h"
#include "b1_management.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

extern int b1_nv_runtime_hold_active(void);
extern void ZDApp_SaveNwkKey(void);
b3_nib_t _NIB;
uint8_t gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES=3u;
uint32_t nwkFrameCounter, nwkFrameCounterChanges=9u;
uint8_t FrameCounterUpdated;
static nwkSecMaterialDesc_t rows[3];
static nwkActiveKeyItems savedKey;
static int table_write_count,key_write_count;
static int table_read_error,table_write_error,table_corrupt_success;
static int key_write_error,key_read_error,key_corrupt_success;
static unsigned irq_enter,irq_exit;
static uint32_t sspCounter=2000u;

uintptr_t b1_management_test_disable(void) { ++irq_enter;return 123u; }
void b1_management_test_restore(uintptr_t v) { assert(v==123u);++irq_exit; }

void SSP_ReadNwkActiveKey(nwkActiveKeyItems *key)
{
    memset(key,0,sizeof(*key));
    memset(key->key,0x42,sizeof(key->key)); /* synthetic/non-secret only */
    key->frameCounter=sspCounter;
}
uint8_t osal_nv_read_ex(uint16_t id,uint16_t row,uint16_t off,uint16_t len,void *dst)
{
    assert(id==ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE && off==0u);
    if(table_read_error || row>=3u || len!=sizeof(rows[0]))return NV_OPER_FAILED;
    memcpy(dst,&rows[row],len);return SUCCESS;
}
uint8_t osal_nv_write_ex(uint16_t id,uint16_t row,uint16_t len,void *data)
{
    assert(id==ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE);
    ++table_write_count;
    if(table_write_error || row>=3u || len!=sizeof(rows[0]))return NV_OPER_FAILED;
    memcpy(&rows[row],data,len);
    if(table_corrupt_success)rows[row].FrameCounter^=1u;
    return SUCCESS;
}
uint8_t osal_nv_write(uint16_t id,uint16_t len,void *data)
{
    assert(id==ZCD_NV_NWKKEY);
    ++key_write_count;
    if(key_write_error || len!=sizeof(savedKey))return NV_OPER_FAILED;
    memcpy(&savedKey,data,len);
    if(key_corrupt_success)savedKey.frameCounter^=1u;
    return SUCCESS;
}
uint8_t osal_nv_read(uint16_t id,uint16_t offset,uint16_t len,void *dst)
{
    assert(id==ZCD_NV_NWKKEY && offset==0u);
    if(key_read_error || len!=sizeof(savedKey))return NV_OPER_FAILED;
    memcpy(dst,&savedKey,len);return SUCCESS;
}
int main(int argc,char **argv)
{
    assert(argc==2);
    memset(&_NIB,0xA1,sizeof(_NIB));
    memcpy(rows[1].extendedPanID,_NIB.extendedPANID,Z_EXTADDR_LEN);
    rows[1].FrameCounter=1000u;
    memset(rows[2].extendedPanID,0xFF,Z_EXTADDR_LEN);
    rows[2].FrameCounter=999u;
    const char *s=argv[1];
    if(strcmp(s,"backend-write-fail")==0)table_write_error=1;
    else if(strcmp(s,"backend-read-fail")==0)table_read_error=1;
    else if(strcmp(s,"table-corrupt-success")==0)table_corrupt_success=1;
    else if(strcmp(s,"key-write-fail")==0)key_write_error=1;
    else if(strcmp(s,"key-read-fail")==0)key_read_error=1;
    else if(strcmp(s,"key-corrupt-success")==0)key_corrupt_success=1;
    else if(strcmp(s,"counter-rollback")==0)rows[1].FrameCounter=2500u;
    else if(strcmp(s,"generic-rollback")==0) {
        memset(rows[1].extendedPanID,0,Z_EXTADDR_LEN);
        rows[2].FrameCounter=2500u;
    }
    else if(strcmp(s,"healthy")!=0)assert(!"unknown case");

    assert(!b1_nv_runtime_hold_active());
    assert(!b1_management_get_hold_active());
    ZDApp_SaveNwkKey();

    if(strcmp(s,"healthy")==0) {
        assert(rows[1].FrameCounter==2000u);
        assert(key_write_count==1 && savedKey.frameCounter==2000u);
        assert(nwkFrameCounterChanges==0u);
        assert(!b1_nv_runtime_hold_active());
        assert(!b1_management_get_hold_active());
    } else {
        /* An error must never clear pending checkpoint or admit new secured RF.
         * ROM and previously queued MAC activity are NOT tested here. */
        assert(nwkFrameCounterChanges==9u);
        assert(b1_management_get_hold_active());
        assert(b1_nv_runtime_hold_active());
        assert(!b1_management_network_ready());
        const int table_before=table_write_count,key_before=key_write_count;
        ZDApp_SaveNwkKey();
        assert(table_write_count==table_before && key_write_count==key_before);
        if(strcmp(s,"counter-rollback")==0) {
            assert(rows[1].FrameCounter==2500u);
            assert(table_write_count==0 && key_write_count==0);
        }
        if(strcmp(s,"generic-rollback")==0) {
            assert(rows[2].FrameCounter==2500u);
            assert(table_write_count==0 && key_write_count==0);
        }
    }
    assert(irq_enter==irq_exit);
    printf("FUSED_ACTUAL_TI_NWK_C_B1_STICKY_HOLD_CASE_PASS %s physical=false\n",s);
    return 0;
}
