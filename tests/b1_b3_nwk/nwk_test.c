/* Only persistence backend mocked, not the actual B1+B3 TI C function body. */
#include "nwk_stub.h"
#include <assert.h>
#include <stdio.h>
b1_nib_t _NIB;
uint8_t gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES=3u;
uint32_t nwkFrameCounterChanges;
static nwkSecMaterialDesc_t rows[3];
static nwkActiveKeyItems key_store;
static uint32_t tx_counter;
static unsigned holds, tableWrites, keyWrites, tableReads, keyReads;
static int hold_active, fail_table_read, fail_table_write;
static int corrupt_table, fail_key_write, corrupt_key, fail_key_read;
uint8_t OsalPort_memcmp(const void *a,const void *b,uint16_t n) {
    return memcmp(a,b,n)==0 ? TRUE : FALSE;
}
void *OsalPort_memcpy(void *a,const void *b,uint16_t n) {return memcpy(a,b,n);}
int b1_nv_runtime_hold_active(void) {return hold_active;}
void b1_security_runtime_hold_latch(void) {++holds;hold_active=1;}
void SSP_ReadNwkActiveKey(nwkActiveKeyItems *value) {
    memset(value,0,sizeof(*value));
    value->frameCounter=tx_counter;
    memset(value->key,0x55,sizeof(value->key));
}
uint8_t osal_nv_read_ex(uint16_t sys,uint16_t index,uint16_t off,uint16_t len,void *out) {
    assert(sys==ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE && off==0);
    ++tableReads;
    if(fail_table_read || index>=3 || len!=sizeof(rows[0])) return 1;
    memcpy(out,&rows[index],len); return SUCCESS;
}
uint8_t osal_nv_write_ex(uint16_t sys,uint16_t index,uint16_t len,void *in) {
    assert(sys==ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE);
    ++tableWrites;
    if(fail_table_write || index>=3 || len!=sizeof(rows[0])) return 1;
    memcpy(&rows[index],in,len);
    if(corrupt_table) rows[index].FrameCounter ^= 1u;
    return SUCCESS;
}
uint8_t osal_nv_read(uint16_t id,uint16_t off,uint16_t len,void *out) {
    assert(id==ZCD_NV_NWKKEY && off==0);
    ++keyReads;
    if(fail_key_read || len!=sizeof(key_store)) return 1;
    memcpy(out,&key_store,len);
    return SUCCESS;
}
uint8_t osal_nv_write(uint16_t id,uint16_t len,void *in) {
    assert(id==ZCD_NV_NWKKEY);
    ++keyWrites;
    if(fail_key_write || len!=sizeof(key_store)) return 1;
    memcpy(&key_store,in,len);
    if(corrupt_key) key_store.frameCounter ^= 1u;
    return SUCCESS;
}
extern void ZDApp_SaveNwkKey(void);
static void reset(void) {
    memset(&_NIB,0xA5,sizeof(_NIB));memset(rows,0,sizeof(rows));
    memcpy(rows[1].extendedPanID,_NIB.extendedPANID,8);
    memset(rows[2].extendedPanID,0xFF,8);
    rows[1].FrameCounter=100; rows[2].FrameCounter=99;
    memset(&key_store,0,sizeof(key_store));
    tx_counter=2000;gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES=3;
    nwkFrameCounterChanges=16;
    holds=tableWrites=keyWrites=tableReads=keyReads=0;
    hold_active=fail_table_read=fail_table_write=corrupt_table=0;
    fail_key_write=corrupt_key=fail_key_read=0;
}
int main(void) {
    reset();ZDApp_SaveNwkKey();
    assert(holds==0 && nwkFrameCounterChanges==0 && rows[1].FrameCounter==2000);
    assert(tableWrites==1 && keyWrites==1 && keyReads==1);
    reset();hold_active=1;ZDApp_SaveNwkKey();
    assert(tableReads==0 && tableWrites==0 && keyWrites==0);
    reset();fail_table_read=1;ZDApp_SaveNwkKey();
    assert(holds==1 && nwkFrameCounterChanges==16 && keyWrites==0);
    reset();corrupt_table=1;ZDApp_SaveNwkKey();
    assert(holds==1 && nwkFrameCounterChanges==16 && keyWrites==0);
    reset();fail_table_write=1;ZDApp_SaveNwkKey();
    assert(holds==1 && nwkFrameCounterChanges==16 && keyWrites==0);
    reset();rows[1].FrameCounter=3000;ZDApp_SaveNwkKey();
    assert(holds==1 && tableWrites==0 && keyWrites==0);
    reset();corrupt_key=1;ZDApp_SaveNwkKey();
    assert(holds==1 && keyWrites==1 && nwkFrameCounterChanges==16);
    reset();fail_key_read=1;ZDApp_SaveNwkKey();
    assert(holds==1 && keyWrites==1 && nwkFrameCounterChanges==16);
    reset();fail_key_write=1;ZDApp_SaveNwkKey();
    assert(holds==1 && keyWrites==1 && nwkFrameCounterChanges==16);
    reset();gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES=0;ZDApp_SaveNwkKey();
    assert(holds==1 && tableWrites==0 && keyWrites==0);
    reset();memset(rows[1].extendedPanID,0,8);ZDApp_SaveNwkKey();
    assert(holds==0 && rows[2].FrameCounter==2000 && keyWrites==1);
    reset();memset(rows[1].extendedPanID,0,8);
    memset(rows[2].extendedPanID,0xA1,8);ZDApp_SaveNwkKey();
    assert(holds==1 && keyWrites==0);
    puts("B1_B3_REAL_TI_NWK_SAVE_HOLD_READBACK_ROLLBACK_AND_GENERIC_PASS");
    return 0;
}
