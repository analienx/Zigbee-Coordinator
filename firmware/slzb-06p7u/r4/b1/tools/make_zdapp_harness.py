"""C fault matrix for exact patched TI8.33 ZDApp NWK key/counter restore functions.

Compiles function bodies extracted from SHA-pinned SDK after B1 overlay.
Only synthetic key bytes and fake NV rows; no hardware, ROM, RF, HA or MQTT.
"""
import argparse
from pathlib import Path
from patch_zdapp import extract_function

PREAMBLE = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "b1_admission.h"
/* Boundary bridge; management-domain classification is tested separately. */
void b1_security_runtime_hold_latch(void) { b1_nv_runtime_hold_latch(); }

#define Z_EXTADDR_LEN 8
#define SEC_KEY_LEN 16
#define TRUE 1
#define FALSE 0
#define ZSUCCESS 0
#define ZCD_NV_NWKKEY 9
#define ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE 14
#define gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES 4
#define MAX_NWK_FRAMECOUNTER_CHANGES 100u
#define NWK_FRAMECOUNTER_CHANGES_RESTORE_DELTA 25u
typedef struct { uint8_t extendedPanID[8]; uint32_t FrameCounter; } nwkSecMaterialDesc_t;
typedef struct {
    struct { uint8_t key[SEC_KEY_LEN]; } active;
    uint32_t frameCounter;
} nwkActiveKeyItems;
typedef struct { uint8_t extendedPANID[8]; } NibMock;
static NibMock _NIB;
static uint8_t FrameCounterUpdated = FALSE;
static uint32_t nwkFrameCounter, nwkFrameCounterChanges;
static nwkSecMaterialDesc_t fake_rows[4];
static uint8_t row_present[4];
static nwkActiveKeyItems fake_key;
static uint8_t key_present, failure_write, failure_read, corrupt_readback;
static uint32_t rows_read, rows_written;
static uint8_t OsalPort_memcmp(const void *a, const void *b, size_t len)
{
    return memcmp(a, b, len) == 0;
}
static uint8_t osal_nv_read_ex(uint16_t id, uint16_t idx, uint16_t offset,
                               uint16_t len, void *target)
{
    assert(id == ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE);
    assert(idx < 4 && offset == 0 && len == sizeof(nwkSecMaterialDesc_t));
    ++rows_read;
    if (!row_present[idx] || failure_read) return 1;
    memcpy(target, &fake_rows[idx], len);
    if (corrupt_readback && rows_written)
        ((nwkSecMaterialDesc_t *)target)->FrameCounter -= 1u;
    return ZSUCCESS;
}
static uint8_t osal_nv_write_ex(uint16_t id, uint16_t idx,
                                uint16_t len, void *value)
{
    assert(id == ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE);
    assert(idx < 4 && len == sizeof(nwkSecMaterialDesc_t));
    ++rows_written;
    if (failure_write) return 1;
    memcpy(&fake_rows[idx], value, len);
    row_present[idx] = 1;
    return ZSUCCESS;
}
static uint8_t osal_nv_read(uint16_t id, uint16_t offset,
                            uint16_t len, void *dst)
{
    assert(id == ZCD_NV_NWKKEY && offset == 0 &&
           len == sizeof(nwkActiveKeyItems));
    if (!key_present) return 1;
    memcpy(dst, &fake_key, len);
    return ZSUCCESS;
}
static uint8_t fake_flash[B1_NV2_REGION_SIZE];
static int_fast16_t read_flash(void *ctx, uint32_t off, uint8_t *dst, uint32_t len)
{
    (void)ctx;
    assert(off + len <= sizeof(fake_flash));
    memcpy(dst, fake_flash + off, len);
    return 0;
}
static void existing(void)
{
    memset(fake_flash, 0xFF, sizeof(fake_flash));
    fake_flash[0] = 0x7Cu; fake_flash[1] = 1;
    fake_flash[2] = 0x0Fu; fake_flash[3] = 0x96u;
    fake_flash[7] = fake_flash[11] = fake_flash[15] = 0x96u;
    fake_flash[8192] = 0xFEu; fake_flash[8193] = 2;
    fake_flash[8194] = 0x0Fu; fake_flash[8195] = 0x96u;
    fake_flash[8199] = fake_flash[8203] = fake_flash[8207] = 0x96u;
    assert(b1_nv_probe(read_flash, NULL, false).code == B1_NV2_HEADER_CANDIDATE);
    assert(b1_nv_existing_header_candidate());
}
static void setup(void)
{
    for (unsigned i=0; i<8; ++i) _NIB.extendedPANID[i] = (uint8_t)(0x20+i);
    key_present=TRUE;
    fake_key.active.key[0]=0x55;
    row_present[0]=TRUE;
    memcpy(fake_rows[0].extendedPanID,_NIB.extendedPANID,8);
    fake_rows[0].FrameCounter=1000;
    nwkFrameCounterChanges=77;
}
"""

TESTMAIN = r"""
int main(int argc, char **argv)
{
    assert(argc == 2);
    const char *scenario = argv[1];
    setup();
    if (strcmp(scenario,"new_empty")==0) {
        key_present = FALSE;
        row_present[0] = FALSE;
        assert(ZDApp_RestoreNwkKey(TRUE) == FALSE);
        assert(!b1_nv_runtime_hold_active());
        assert(rows_written==0 && !FrameCounterUpdated);
    } else {
        existing();
        if (strcmp(scenario,"positive")==0) {
            assert(ZDApp_RestoreNwkKey(TRUE)==TRUE);
            assert(fake_rows[0].FrameCounter==1125u);
            assert(nwkFrameCounter==1125u && FrameCounterUpdated);
            assert(nwkFrameCounterChanges==0);
            assert(rows_written==1 && !b1_nv_runtime_hold_active());
            assert(ZDApp_RestoreNwkKey(TRUE)==TRUE);
            assert(rows_written==1); /* no repeated reserve write */
        } else if (strcmp(scenario,"two_reboots")==0) {
            uint8_t original_pan[8];
            memcpy(original_pan,fake_rows[0].extendedPanID,sizeof(original_pan));
            assert(ZDApp_RestoreNwkKey(TRUE)==TRUE);
            assert(fake_rows[0].FrameCounter==1125u && nwkFrameCounter==1125u);
            assert(rows_written==1u && FrameCounterUpdated);
            /* Reboot resets ONLY RAM: persisted material, identity and counter
             * are kept in synthetic NV and read through actual donor code. */
            FrameCounterUpdated=FALSE;
            nwkFrameCounter=0u;
            nwkFrameCounterChanges=71u;
            assert(ZDApp_RestoreNwkKey(TRUE)==TRUE);
            assert(rows_written==2u);
            assert(fake_rows[0].FrameCounter==1250u);
            assert(nwkFrameCounter==1250u && FrameCounterUpdated);
            assert(nwkFrameCounterChanges==0u);
            assert(memcmp(original_pan,fake_rows[0].extendedPanID,8u)==0);
            assert(!b1_nv_runtime_hold_active());
            puts("B1_N13_TWO_REBOOTS_MONOTONIC_NWK_COUNTER_AND_IDENTITY_PASS");
        } else if (strcmp(scenario,"generic")==0) {
            row_present[0]=FALSE;
            row_present[3]=TRUE;
            memset(fake_rows[3].extendedPanID,0xFF,8);
            fake_rows[3].FrameCounter=500u;
            assert(ZDApp_RestoreNwkKey(TRUE)==TRUE);
            assert(fake_rows[3].FrameCounter==625u);
            assert(nwkFrameCounter==625u && !b1_nv_runtime_hold_active());
        } else if (strcmp(scenario,"missing_key")==0) {
            key_present=FALSE;
            assert(ZDApp_RestoreNwkKey(TRUE)==FALSE);
            assert(b1_nv_runtime_hold_active());
            assert(rows_written==0 && !FrameCounterUpdated && nwkFrameCounter==0);
        } else if (strcmp(scenario,"wrong_generic_identity")==0) {
            row_present[0]=FALSE;
            row_present[3]=TRUE;
            memset(fake_rows[3].extendedPanID,0x33,8);
            fake_rows[3].FrameCounter=500u;
            assert(ZDApp_RestoreNwkKey(TRUE)==FALSE);
            assert(b1_nv_runtime_hold_active());
            assert(rows_written==0 && !FrameCounterUpdated && nwkFrameCounter==0);
        } else if (strcmp(scenario,"zero_key")==0) {
            memset(&fake_key,0,sizeof(fake_key));
            assert(ZDApp_RestoreNwkKey(TRUE)==FALSE);
            assert(b1_nv_runtime_hold_active());
            assert(rows_written==0 && !FrameCounterUpdated);
        } else if (strcmp(scenario,"missing_row")==0) {
            row_present[0]=FALSE;
            assert(ZDApp_RestoreNwkKey(TRUE)==FALSE);
            assert(b1_nv_runtime_hold_active());
            assert(rows_written==0 && !FrameCounterUpdated);
        } else if (strcmp(scenario,"overflow")==0) {
            fake_rows[0].FrameCounter=UINT32_MAX-1;
            assert(ZDApp_RestoreNwkKey(TRUE)==FALSE);
            assert(b1_nv_runtime_hold_active());
            assert(rows_written==0 && !FrameCounterUpdated && nwkFrameCounter==0);
        } else if (strcmp(scenario,"write_fail")==0) {
            failure_write=TRUE;
            assert(ZDApp_RestoreNwkKey(TRUE)==FALSE);
            assert(b1_nv_runtime_hold_active());
            assert(rows_written==1 && !FrameCounterUpdated && nwkFrameCounter==0);
            assert(fake_rows[0].FrameCounter==1000u);
        } else if (strcmp(scenario,"readback")==0) {
            corrupt_readback=TRUE;
            assert(ZDApp_RestoreNwkKey(TRUE)==FALSE);
            assert(b1_nv_runtime_hold_active());
            assert(rows_written==1 && !FrameCounterUpdated && nwkFrameCounter==0);
        } else if (strcmp(scenario,"read_fail")==0) {
            failure_read=TRUE;
            assert(ZDApp_RestoreNwkKey(TRUE)==FALSE);
            assert(b1_nv_runtime_hold_active());
            assert(rows_written==0 && !FrameCounterUpdated && nwkFrameCounter==0);
        } else {
            fprintf(stderr,"Unknown scenario %s\n",scenario);
            return 2;
        }
    }
    printf("B1_ZDAPP_COUNTER_KEY_RESTORE_SOURCE_FAULT_PASS %s\n",scenario);
    return 0;
}
"""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    contents = a.source.read_text(encoding="utf-8")
    functions = [
        extract_function(contents, "void ZDApp_RestoreNwkSecMaterial(void)"),
        extract_function(contents, "uint8_t ZDApp_RestoreNwkKey( uint8_t incrFrmCnt )")
    ]
    if any("b1_security_runtime_hold_latch()" not in func for func in functions):
        raise RuntimeError("ZDAPP_REAL_SECURITY_HOLD_NOT_COMPILED")
    a.output.write_text(PREAMBLE + "\n\n".join(functions) + TESTMAIN,
                        encoding="utf-8")
    print("B1_LINKED_ZDAPP_RESTORE_FUNCTIONS_EXTRACTED")


if __name__ == "__main__":
    main()
