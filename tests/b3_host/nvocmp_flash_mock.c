/* Flash-level fault injection for *actual pinned TI nvocmp.c* host build.
 * Never load actual NV or backup bytes. Every operation saved to synthetic file.
 * One-time environment-bound fault injection; no infinite retry allowed.
 */
#include "nv_linux.h"
#include <errno.h>
#include <limits.h>
#define B3_SECTOR 8192
#ifndef NVOCMP_NVPAGES
#error "Specify NVOCMP_NVPAGES explicitly"
#endif
#if NVOCMP_NVPAGES != 2 && NVOCMP_NVPAGES != 3 && NVOCMP_NVPAGES != 5
#error "B3 only accepts experimental NV2/NV3/NV5 mock profiles"
#endif
#define B3_SIZE (B3_SECTOR * NVOCMP_NVPAGES)
static uint8_t flash[B3_SIZE];
static const char *file_path;
static unsigned long op_number, reads, writes, erases;
static unsigned long inject_op, inject_read;
static int inject_mode; /* 1 pre-write fail, 2 partial mutation fail */
static bool readonly_mode;
static int persist(void) {
    FILE *f = fopen(file_path, "wb");
    if (!f) return -1;
    if (fwrite(flash, 1, sizeof(flash), f) != sizeof(flash)) { fclose(f); return -1; }
    return fclose(f);
}
static void load(void) {
    file_path = getenv("B3_SYNTHETIC_FLASH");
    if (!file_path || !*file_path) { fprintf(stderr,"Missing B3_SYNTHETIC_FLASH\n"); exit(90); }
    FILE *f = fopen(file_path, "rb");
    if (!f) { memset(flash, 0xff, sizeof(flash)); return; }
    if (fread(flash, 1, sizeof(flash), f) != sizeof(flash) || fgetc(f) != EOF) {
        fprintf(stderr,"Invalid simulated flash geometry\n"); exit(91);
    }
    fclose(f);
}
static int bounds(uint8_t pg, uint16_t off, uint16_t length) {
    return pg < NVOCMP_NVPAGES && off <= B3_SECTOR &&
           length <= B3_SECTOR - off;
}
void NV_LINUX_init(void) {
    load();
    const char *p = getenv("B3_FAULT_NUMBER");
    inject_op = p ? strtoul(p, NULL, 10) : 0;
    p = getenv("B3_FAIL_READ_NUMBER");
    inject_read = p ? strtoul(p, NULL, 10) : 0;
    p = getenv("B3_FAULT_MODE");
    inject_mode = p ? atoi(p) : 1;
    p = getenv("B3_READONLY_REBOOT");
    readonly_mode = p && strcmp(p,"1")==0;
}
void NV_LINUX_save(void) { /* every operation is already flash-persistent */ }
int NV_LINUX_read(uint8_t pg, uint16_t off, void *dest, uint16_t length) {
    reads++;
    if (inject_read && reads == inject_read) return -1;
    if (!bounds(pg,off,length)) { fprintf(stderr,"B3_READ_OOB\n"); exit(92); }
    if (length && !dest) return -1;
    memcpy(dest, flash + pg*B3_SECTOR + off, length);
    return 0;
}
int NV_LINUX_write(uint8_t pg, uint16_t off, uint8_t *src, uint16_t length) {
    writes++; op_number++;
    if (readonly_mode) { fprintf(stderr,"B3_REBOOT_WRITE_BLOCKED op=%lu\n",op_number); return -1; }
    if (!bounds(pg,off,length) || (length && !src)) { fprintf(stderr,"B3_WRITE_OOB\n"); exit(93); }
    if (inject_op == op_number && inject_mode == 1) return -1;
    uint8_t *dst = flash + pg*B3_SECTOR + off;
    size_t limit = (inject_op == op_number && inject_mode == 2) ? length/2 : length;
    for (size_t i=0;i<limit;i++) {
        if ((uint8_t)(~dst[i]) & src[i]) { fprintf(stderr,"B3_FLASH_ZERO_TO_ONE\n"); return -1; }
        dst[i] &= src[i];
    }
    if (persist()) return -1;
    if (inject_op == op_number && inject_mode == 2) return -1;
    return 0;
}
int NV_LINUX_erase(uint8_t pg) {
    erases++; op_number++;
    fprintf(stderr,"B3_ERASE_AT op=%lu pg=%u\n",op_number,pg);
    if (readonly_mode) { fprintf(stderr,"B3_REBOOT_ERASE_BLOCKED op=%lu\n",op_number); return -1; }
    if (!bounds(pg,0,B3_SECTOR)) { fprintf(stderr,"B3_ERASE_OOB\n"); exit(94); }
    if (inject_op == op_number && inject_mode == 1) return -1;
    size_t bytes=(inject_op == op_number && inject_mode == 2) ? B3_SECTOR/2 : B3_SECTOR;
    memset(flash+pg*B3_SECTOR,0xff,bytes);
    if (persist()) return -1;
    if (inject_op == op_number && inject_mode == 2) return -1;
    return 0;
}
void b3_flash_receipt(void) {
    printf("B3_NVS_SIM pages=%d reads=%lu writes=%lu erases=%lu ops=%lu fault_op=%lu read_fault=%lu\n",
           NVOCMP_NVPAGES,reads,writes,erases,op_number,inject_op,inject_read);
}
