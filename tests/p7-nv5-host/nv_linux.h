/* Simulation-only POSIX NVS adapter for pinned TI NVOCMP.c host tests.
 * Neither this shim nor its flash image may be used on physical coordinators.
 */
#ifndef P7_NV_LINUX_H
#define P7_NV_LINUX_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef void *NVS_Handle;
typedef struct {
    size_t sectorSize;
    size_t regionSize;
} NVS_Attrs;
#define NVS_HANDLE ((NVS_Handle)(uintptr_t)0x1)
#define NVOCMP_FLASHACCESS(err) ((void)(err))
#define P7_SECTORS 5
#define P7_SECTOR_SIZE 8192u
#define P7_FLASH_SIZE (P7_SECTORS * P7_SECTOR_SIZE)
void NV_LINUX_init(void);
void NV_LINUX_save(void);
void NV_LINUX_read(uint8_t page,uint16_t offset,uint8_t *buf,uint16_t length);
int_fast16_t NV_LINUX_write(uint8_t page,uint16_t offset,uint8_t *buf,uint16_t length);
int_fast16_t NV_LINUX_erase(uint8_t page);
#endif
