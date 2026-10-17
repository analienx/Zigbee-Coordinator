/* Test-only aliases for two extracted TI security persistence functions.
 * No keys, identity, serial transport or radio control.
 */
#ifndef B3_SECURITY_STUB_H
#define B3_SECURITY_STUB_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define TRUE 1
#define FALSE 0
#define SUCCESS 0
#define NV_OPER_FAILED 11
#define ZCD_NV_EX_APS_KEY_DATA_TABLE 150
#define ZCD_NV_EX_TCLK_TABLE 151
typedef struct { uint32_t txFrmCntr,rxFrmCntr; uint8_t pendingFlag; } APSME_ApsLinkKeyRAMEntry_t;
typedef struct { uint32_t txFrmCntr,rxFrmCntr; uint8_t pendingFlag; } APSME_TCLinkKeyRAMEntry_t;
typedef struct { uint32_t txFrmCntr,rxFrmCntr; uint8_t reserved[12]; } APSME_ApsLinkKeyNVEntry_t;
typedef struct { uint32_t txFrmCntr,rxFrmCntr; uint8_t reserved[12]; } APSME_TCLinkKeyNVEntry_t;
extern const uint16_t gZDSECMGR_ENTRY_MAX;
extern const uint16_t gZDSECMGR_TC_DEVICE_MAX;
extern APSME_ApsLinkKeyRAMEntry_t ApsLinkKeyRAMEntry[];
extern APSME_TCLinkKeyRAMEntry_t TCLinkKeyRAMEntry[];
static inline uint8_t OsalPort_memcmp(const void *a,const void *b,uint16_t len) {
    return memcmp(a,b,len)==0;
}
void *OsalPort_malloc(size_t size);
void OsalPort_free(void *ptr);
uint8_t osal_nv_read_ex(uint16_t id,uint16_t subid,uint16_t ofs,uint16_t len,void *data);
uint8_t osal_nv_write_ex(uint16_t id,uint16_t subid,uint16_t len,void *data);
#endif
