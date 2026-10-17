/* Actual TI NVOCMP API (SDK 8.33), synthetic page-file backend.
 * POSITIVE CONTROL and explicit failure observation; no hardware proof.
 */
#include "nvocmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
extern void b3_flash_receipt(void);
static const NVINTF_itemID_t ids[] = {
    {NVINTF_SYSID_ZSTACK, 10, 0},
    {NVINTF_SYSID_ZSTACK, 10, 1},
    {NVINTF_SYSID_ZSTACK, 10, 2},
    {NVINTF_SYSID_ZSTACK, 10, 3}
};
static void die(const char *why, int status) {
    fprintf(stderr,"B3_DRIVER_FAIL %s status=%d\n",why,status);
    b3_flash_receipt();
    exit(99);
}
static uint8_t check(const char *name, const NVINTF_nvFuncts_t *f,
                     unsigned char value, bool required) {
    unsigned char out[32]={0};
    uint8_t rc=f->readItem(ids[0],0,sizeof(out),out);
    if (required && (rc != NVINTF_SUCCESS || out[0] != value)) die(name,rc);
    return rc;
}
int main(int argc, char **argv) {
    if (argc!=2) die("argument",argc);
    NVINTF_nvFuncts_t api={0};
    NVOCMP_loadApiPtrs(&api);
    if (!api.initNV || !api.createItem || !api.updateItem || !api.readItem ||
        !api.compactNV) die("no_api",0);
    uint8_t rc=api.initNV(NULL);
    if (rc != NVINTF_SUCCESS) die("init",rc);
    unsigned char data[32],more[32];
    memset(data,0x11,sizeof(data));
    memset(more,0x22,sizeof(more));
    if (!strcmp(argv[1],"seed")) {
        for (size_t k=0;k<sizeof(ids)/sizeof(ids[0]);k++) {
            data[0]=0x11;
            rc=api.createItem(ids[k],sizeof(data),data);
            if(rc!=NVINTF_SUCCESS) die("seed",rc);
        }
        check("seed_read",&api,0x11,true);
    } else if (!strcmp(argv[1],"verify")) {
        check("reboot_read",&api,0x11,true);
        for(size_t k=1;k<sizeof(ids)/sizeof(ids[0]);k++) {
            unsigned char out[32]={0};
            rc=api.readItem(ids[k],0,sizeof(out),out);
            if(rc!=NVINTF_SUCCESS || out[0]!=0x11) die("missing_backup_key",rc);
        }
    } else if (!strcmp(argv[1],"update")) {
        check("pre_update",&api,0x11,true);
        rc=api.updateItem(ids[0],sizeof(more),more);
        if(rc!=NVINTF_SUCCESS) die("update",rc);
        check("post_update",&api,0x22,true);
    } else if (!strcmp(argv[1],"verify_update")) {
        check("reboot_updated",&api,0x22,true);
    } else if (!strcmp(argv[1],"compact")) {
        check("pre_compact",&api,0x11,true);
        rc=api.compactNV(0);
        if(rc!=NVINTF_SUCCESS) die("compact",rc);
        check("post_compact",&api,0x11,true);
    } else if (!strcmp(argv[1],"fail_update")) {
        check("pre_injected_update",&api,0x11,true);
        rc=api.updateItem(ids[0],sizeof(more),more);
        if (rc==NVINTF_SUCCESS) die("SILENT_WRITE_FAILURE",rc);
        puts("B3_INJECTED_WRITE_REJECTED");
    } else if (!strcmp(argv[1],"fail_compact")) {
        check("pre_injected_compact",&api,0x11,true);
        rc=api.compactNV(0);
        if (rc==NVINTF_SUCCESS) die("SILENT_COMPACT_FAILURE",rc);
        puts("B3_INJECTED_COMPACT_REJECTED");
    } else die("unknown_mode",0);
    b3_flash_receipt();
    puts("B3_REAL_TI_NVOCMP_HOST_CASE_PASS");
    return 0;
}
