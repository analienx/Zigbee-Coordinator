/* Synthetic flash backend ONLY. Included by real TI nvocmp.c under NV_LINUX.
 * Nothing here touches a serial port, real radio, or private backup.
 */
#ifndef B3_NV_LINUX_H
#define B3_NV_LINUX_H
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef void *NVS_Handle;
typedef struct { uint32_t sectorSize, regionSize; } NVS_Attrs;
#define NVS_HANDLE ((NVS_Handle)(uintptr_t)1)
#define NVOCMP_FLASHACCESS(err) ((void)(err));
#define NVOCMP_ASSERT(cond, text) do { if (!(cond)) fprintf(stderr, "B3 TI assert: %s\n", text); } while (0);
#define NVOCMP_ALERT(cond, text) ((void)0);
void NV_LINUX_init(void);
void NV_LINUX_save(void);
int NV_LINUX_read(uint8_t pg, uint16_t off, void *buffer, uint16_t len);
int NV_LINUX_write(uint8_t pg, uint16_t off, uint8_t *buffer, uint16_t len);
int NV_LINUX_erase(uint8_t pg);
#endif
