/* Linux flash backend only. The algorithm is the unmodified pinned TI source. */
#ifndef T832_NV_LINUX_H
#define T832_NV_LINUX_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef void *NVS_Handle;
typedef struct {size_t sectorSize,regionSize;} NVS_Attrs;
#define NVS_HANDLE ((NVS_Handle)1)
#define NVOCMP_FLASHACCESS(err) ((void)(err));
#define NVOCMP_ALERT(cond,message) ((void)(cond));
#ifdef NVOCMP_EXCEPTION
#undef NVOCMP_EXCEPTION
#endif
#define NVOCMP_EXCEPTION(pg,err) fprintf(stderr,"NV exception: status=%u\n",(unsigned)(err));
#ifdef NVLAB_EMBEDDED_ASSERT
#define NVOCMP_ASSERT(cond,message) ((void)(cond));
#else
#define NVOCMP_ASSERT(cond,message) do {if(!(cond)){fprintf(stderr,"NV invariant: %s\n",message);exit(80);}} while(0);
#endif
void NV_LINUX_init(void);
void NV_LINUX_save(void);
void NV_LINUX_read(uint8_t pg,uint16_t off,uint8_t *buf,uint16_t len);
int_fast16_t NV_LINUX_write(uint8_t pg,uint16_t off,uint8_t *buf,uint16_t len);
int_fast16_t NV_LINUX_erase(uint8_t pg);
extern unsigned nv_lab_operations;
extern unsigned nv_lab_read_calls, nv_lab_read_bytes;
#endif
