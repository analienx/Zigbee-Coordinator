#define _POSIX_C_SOURCE 200809L
#include "nv_linux.h"
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#define PAGE 2048u
static uint8_t flash[NVOCMP_NVPAGES*PAGE];
static int fd=-1;
static unsigned cut;
unsigned nv_lab_operations;
static void bounds(uint8_t pg,uint16_t off,uint16_t len) {
    if(pg>=NVOCMP_NVPAGES || (unsigned)off+len>PAGE)abort();
}
static void persist(void) {
    if(pwrite(fd,flash,sizeof(flash),0)!=(ssize_t)sizeof(flash) || fsync(fd))abort();
}
static void boundary(void) {
    persist();
    if(cut && ++nv_lab_operations==cut)_exit(77);
    if(!cut)++nv_lab_operations;
}
void NV_LINUX_init(void) {
    const char *name=getenv("NVLAB_IMAGE");if(!name)abort();
    fd=open(name,O_RDWR|O_CREAT,0600);if(fd<0)abort();
    struct stat s;if(fstat(fd,&s))abort();
    if(!s.st_size){memset(flash,255,sizeof(flash));persist();}
    else if(s.st_size!=(off_t)sizeof(flash) || pread(fd,flash,sizeof(flash),0)!=(ssize_t)sizeof(flash))abort();
    const char *v=getenv("NVLAB_CUT_OP");cut=v?(unsigned)strtoul(v,NULL,10):0;
}
void NV_LINUX_save(void) {persist();}
void NV_LINUX_read(uint8_t pg,uint16_t off,uint8_t *buf,uint16_t len) {
    bounds(pg,off,len);memcpy(buf,flash+(size_t)pg*PAGE+off,len);
}
int_fast16_t NV_LINUX_write(uint8_t pg,uint16_t off,uint8_t *buf,uint16_t len) {
    bounds(pg,off,len);uint8_t *dst=flash+(size_t)pg*PAGE+off;
    for(unsigned i=0;i<len;i++)if((dst[i]&buf[i])!=buf[i])return -1;
    for(unsigned i=0;i<len;i++)dst[i]&=buf[i];boundary();return 0;
}
int_fast16_t NV_LINUX_erase(uint8_t pg) {
    bounds(pg,0,PAGE);memset(flash+(size_t)pg*PAGE,255,PAGE);boundary();return 0;
}
