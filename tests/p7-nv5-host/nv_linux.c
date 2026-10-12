/* Physical NOR flash simulation for the actual TI nvocmp.c under NV_LINUX.
 * This is NOT a simulator of Zigbee protocol or device-side flash controller.
 * Persistent file contains synthetic bytes only; no Zigbee real keys.
 */
#define _POSIX_C_SOURCE 200809L
#include "nv_linux.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static uint8_t flash_bytes[P7_FLASH_SIZE];
static const char *flash_file;
static uint64_t writes, erases;
static void fatal(const char *s) {
    fprintf(stderr,"NV5_HOST_BACKEND_FATAL %s errno=%d\n",s,errno);
    exit(90);
}
static void persist(void) {
    int fd;
    size_t done=0;
    if (!flash_file || !*flash_file) fatal("NV_FILE_UNSET");
    fd=open(flash_file,O_WRONLY|O_CREAT|O_TRUNC,0600);
    if (fd<0) fatal("OPEN_FLASH");
    while(done<P7_FLASH_SIZE) {
        ssize_t n=write(fd,flash_bytes+done,P7_FLASH_SIZE-done);
        if(n<=0) fatal("WRITE_FLASH");
        done+=(size_t)n;
    }
    if(fsync(fd)!=0) fatal("FSYNC_FLASH");
    if(close(fd)!=0) fatal("CLOSE_FLASH");
}
void NV_LINUX_init(void) {
    flash_file=getenv("P7_NV_FILE");
    if(!flash_file || !*flash_file) fatal("MISSING_P7_NV_FILE");
    FILE *f=fopen(flash_file,"rb");
    if(!f) {
        if(errno!=ENOENT) fatal("OPEN_EXISTING_FLASH");
        memset(flash_bytes,0xFF,sizeof(flash_bytes));
        persist();
        return;
    }
    if(fread(flash_bytes,1,sizeof(flash_bytes),f)!=sizeof(flash_bytes) ||
       fgetc(f)!=EOF) fatal("BAD_EXISTING_FLASH_SIZE");
    if(fclose(f)!=0) fatal("CLOSE_EXISTING_FLASH");
}
void NV_LINUX_save(void) {persist();}
static size_t location(uint8_t pg,uint16_t off,uint16_t length) {
    if(pg>=P7_SECTORS || off>=P7_SECTOR_SIZE ||
       (uint32_t)off+length>P7_SECTOR_SIZE) fatal("REGION_OVERLAP");
    return (size_t)pg*P7_SECTOR_SIZE+off;
}
void NV_LINUX_read(uint8_t page,uint16_t offset,uint8_t *dst,uint16_t length) {
    size_t addr=location(page,offset,length);
    memcpy(dst,flash_bytes+addr,length);
}
/* Deterministic host-only abrupt process termination after exactly N-th
 * underlying NV operation. Persist one partial flash transaction before
 * _exit(77). Never run against physical flash or real network state.
 */
static int inject_at(const char *operation,uint64_t ordinal) {
    const char *kind=getenv("P7_FAULT_OP"), *at=getenv("P7_FAULT_AFTER");
    if(!kind && !at) return 0;
    if(!kind || !at || !*kind || !*at) fatal("INCOMPLETE_FAULT_CONFIG");
    char *end;
    errno=0;
    unsigned long n=strtoul(at,&end,10);
    if(errno || !end || *end || n==0 || n>1000000u) fatal("BAD_FAULT_INDEX");
    if(strcmp(kind,"write") && strcmp(kind,"erase")) fatal("BAD_FAULT_MODE");
    return strcmp(kind,operation)==0 && ordinal==(uint64_t)n;
}
static void crash_after_partial(const char *operation,uint64_t ordinal) {
    persist();
    fprintf(stderr,"P7_EXPECTED_SIMULATED_POWER_LOSS op=%s operation=%llu\n",
            operation,(unsigned long long)ordinal);
    fflush(stderr);
    _exit(77);
}
int_fast16_t NV_LINUX_write(uint8_t pg,uint16_t off,uint8_t *src,uint16_t len) {
    size_t addr=location(pg,off,len);
    for(size_t i=0;i<len;i++) {
        /* A NOR flash write may turn ones to zeros but NEVER zeros to ones. */
        if((src[i] & (uint8_t)~flash_bytes[addr+i])!=0) {
            fprintf(stderr,"NOR_REPROGRAM_WITHOUT_ERASE addr=%zu old=%02x new=%02x\n",
                    addr+i,flash_bytes[addr+i],src[i]);
            return -1;
        }
    }
    if(inject_at("write",writes+1)) {
        /* Half the bytes of one NVS write may have been programmed. */
        size_t n=len>1 ? len/2 : len;
        for(size_t i=0;i<n;i++) flash_bytes[addr+i]&=src[i];
        crash_after_partial("write",writes+1);
    }
    for(size_t i=0;i<len;i++) flash_bytes[addr+i]&=src[i];
    writes++;
    persist();
    return 0;
}
int_fast16_t NV_LINUX_erase(uint8_t pg) {
    size_t addr=location(pg,0,P7_SECTOR_SIZE);
    if(inject_at("erase",erases+1)) {
        memset(flash_bytes+addr,0xFF,P7_SECTOR_SIZE/2);
        crash_after_partial("erase",erases+1);
    }
    memset(flash_bytes+addr,0xFF,P7_SECTOR_SIZE);
    erases++;
    persist();
    return 0;
}
