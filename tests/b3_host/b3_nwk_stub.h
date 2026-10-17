#ifndef B3_NWK_STUB_H
#define B3_NWK_STUB_H
#include <stdint.h>
#include <string.h>
#define TRUE 1
#define FALSE 0
#define SUCCESS 0
#define NV_OPER_FAILED 1
#define Z_EXTADDR_LEN 8
#define ZCD_NV_NWKKEY 0x0062
#define ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE 0x0063
#define MAX_NWK_FRAMECOUNTER_CHANGES 1000
#define NWK_FRAMECOUNTER_CHANGES_RESTORE_DELTA 250
typedef struct { uint8_t key[16]; uint32_t frameCounter; } nwkActiveKeyItems;
typedef struct { uint8_t extendedPanID[Z_EXTADDR_LEN]; uint32_t FrameCounter; } nwkSecMaterialDesc_t;
typedef struct { uint8_t extendedPANID[Z_EXTADDR_LEN]; } b3_nib_t;
extern b3_nib_t _NIB;
extern uint8_t gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES;
extern uint32_t nwkFrameCounter;
extern uint32_t nwkFrameCounterChanges;
extern uint8_t FrameCounterUpdated;
void SSP_ReadNwkActiveKey(nwkActiveKeyItems *key);
uint8_t osal_nv_write(uint16_t id, uint16_t len, void *buf);
uint8_t osal_nv_read(uint16_t id, uint16_t offset, uint16_t len, void *buf);
uint8_t osal_nv_read_ex(uint16_t sysid, uint16_t subid, uint16_t off, uint16_t len, void *buf);
uint8_t osal_nv_write_ex(uint16_t sysid, uint16_t subid, uint16_t len, void *buf);
static inline uint8_t OsalPort_memcmp(const void *a, const void *b, uint16_t len) {
    return (memcmp(a,b,len)==0) ? TRUE : FALSE;
}
#endif
