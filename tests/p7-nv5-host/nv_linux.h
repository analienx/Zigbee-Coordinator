/* Simulation-only POSIX NVS adapter for pinned TI NVOCMP.c host tests.
 * Neither this shim nor its flash image may be used on physical coordinators.
 */
#ifndef P7_NV_LINUX_H
#define P7_NV_LINUX_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
typedef void *NVS_Handle;
typedef struct {
    size_t sectorSize;
    size_t regionSize;
} NVS_Attrs;
#define NVS_HANDLE ((NVS_Handle)(uintptr_t)0x1)
/* TI's NVOCMP macro invocations OMIT the trailing semicolon.
 * The actual pinned NV_LINUX branch defines ASSERT1 via NVOCMP_ASSERT,
 * but does not itself define NVOCMP_ASSERT or NVOCMP_ALERT.
 * Supply valid host-only diagnostics with terminators. */
#define NVOCMP_ASSERT(cond,message) do { \
    if(!(cond)) {fprintf(stderr,"HOST_NV_ASSERT %s\n",(message));abort();} \
} while(0);
#define NVOCMP_ALERT(cond,message) do { \
    if(!(cond)) fprintf(stderr,"HOST_NV_ALERT %s\n",(message)); \
} while(0);
#define NVOCMP_FLASHACCESS(err) do { (void)(err); } while(0);
#define P7_SECTORS 5
#define P7_SECTOR_SIZE 8192u
#define P7_FLASH_SIZE (P7_SECTORS * P7_SECTOR_SIZE)
void NV_LINUX_init(void);
void NV_LINUX_save(void);
void NV_LINUX_read(uint8_t page,uint16_t offset,uint8_t *buf,uint16_t length);
int_fast16_t NV_LINUX_write(uint8_t page,uint16_t offset,uint8_t *buf,uint16_t length);
int_fast16_t NV_LINUX_erase(uint8_t page);
#endif
