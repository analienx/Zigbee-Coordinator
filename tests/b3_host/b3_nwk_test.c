/* The production function bodies come from the exact TI zd_app.c donor overlay. */
#include "b3_nwk_stub.h"
#include <assert.h>
#include <stdio.h>

b3_nib_t _NIB;
uint8_t gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES=3;
uint32_t nwkFrameCounter;
uint32_t nwkFrameCounterChanges;
uint8_t FrameCounterUpdated;
static nwkSecMaterialDesc_t rows[3];
static int read_fail, table_write_fail, key_write_fail, reads, table_writes, key_writes;
static uint32_t tx_counter;
void ZDApp_SaveNwkKey(void);
void ZDApp_RestoreNwkSecMaterial(void);

void SSP_ReadNwkActiveKey(nwkActiveKeyItems *key) {
    memset(key, 0x55, sizeof(*key));
    key->frameCounter = tx_counter;
}
uint8_t osal_nv_read_ex(uint16_t id,uint16_t row,uint16_t ofs,uint16_t len,void *buf) {
    (void)id;(void)ofs;
    ++reads;
    if (read_fail || row>=3 || len!=sizeof(rows[0])) return NV_OPER_FAILED;
    memcpy(buf,&rows[row],len);
    return SUCCESS;
}
uint8_t osal_nv_write_ex(uint16_t id,uint16_t row,uint16_t len,void *buf) {
    (void)id;
    ++table_writes;
    if (table_write_fail || row>=3 || len!=sizeof(rows[0])) return NV_OPER_FAILED;
    memcpy(&rows[row],buf,len);
    return SUCCESS;
}
uint8_t osal_nv_write(uint16_t id,uint16_t len,void *buf) {
    (void)id;(void)buf;
    ++key_writes;
    if (key_write_fail || len!=sizeof(nwkActiveKeyItems)) return NV_OPER_FAILED;
    return SUCCESS;
}
static void reset(void) {
    memset(rows, 0, sizeof(rows));
    memset(&_NIB, 0xA5, sizeof(_NIB));
    memcpy(rows[1].extendedPanID,_NIB.extendedPANID,Z_EXTADDR_LEN);
    memset(rows[2].extendedPanID,0xFF,Z_EXTADDR_LEN);
    rows[1].FrameCounter=100;
    rows[2].FrameCounter=99;
    read_fail=table_write_fail=key_write_fail=reads=table_writes=key_writes=0;
    gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES=3;
    tx_counter=2000;
    nwkFrameCounter=4;
    nwkFrameCounterChanges=9;
    FrameCounterUpdated=FALSE;
}
int main(void) {
    reset();
    ZDApp_SaveNwkKey();
    assert(nwkFrameCounterChanges==0 && table_writes==1 && key_writes==1);
    assert(rows[1].FrameCounter==2000);
    reset(); table_write_fail=1;
    ZDApp_SaveNwkKey();
    assert(nwkFrameCounterChanges==9 && key_writes==0);
    reset(); key_write_fail=1;
    ZDApp_SaveNwkKey();
    assert(nwkFrameCounterChanges==9 && key_writes==1);
    reset(); read_fail=1;
    ZDApp_SaveNwkKey();
    assert(nwkFrameCounterChanges==9 && table_writes==0 && key_writes==0);
    reset(); memset(rows[1].extendedPanID,0,Z_EXTADDR_LEN);
    ZDApp_SaveNwkKey();
    assert(rows[2].FrameCounter==2000 && nwkFrameCounterChanges==0);
    reset();
    ZDApp_RestoreNwkSecMaterial();
    assert(FrameCounterUpdated==TRUE && nwkFrameCounter==1350);
    assert(rows[1].FrameCounter==1350 && nwkFrameCounterChanges==0);
    reset(); table_write_fail=1;
    ZDApp_RestoreNwkSecMaterial();
    assert(FrameCounterUpdated==FALSE && nwkFrameCounter==4 && nwkFrameCounterChanges==9);
    reset(); read_fail=1;
    ZDApp_RestoreNwkSecMaterial();
    assert(FrameCounterUpdated==FALSE && nwkFrameCounter==4 && table_writes==0);
    reset(); rows[1].FrameCounter=0xFFFFFFFEu;
    ZDApp_RestoreNwkSecMaterial();
    assert(FrameCounterUpdated==FALSE && nwkFrameCounter==4 && table_writes==0);
    reset(); FrameCounterUpdated=TRUE;
    ZDApp_RestoreNwkSecMaterial();
    assert(nwkFrameCounter==4 && table_writes==0);
    puts("B3_ACTUAL_TI_NWK_COUNTER_REJECT_OVERFLOW_AND_COMMIT_ORDER_PASS");
    return 0;
}
