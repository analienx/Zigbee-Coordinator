#ifndef B1_B3_NWK_STUB_H
#define B1_B3_NWK_STUB_H
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#define SUCCESS 0u
#define TRUE 1u
#define FALSE 0u
#define Z_EXTADDR_LEN 8u
#define ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE 0x0050u
#define ZCD_NV_NWKKEY 0x0051u
typedef struct {uint8_t extendedPanID[8]; uint32_t FrameCounter;} nwkSecMaterialDesc_t;
typedef struct {uint8_t key[16]; uint32_t frameCounter;} nwkActiveKeyItems;
typedef struct {uint8_t extendedPANID[8];} b1_nib_t;
extern b1_nib_t _NIB;
extern uint8_t gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES;
extern uint32_t nwkFrameCounterChanges;
void SSP_ReadNwkActiveKey(nwkActiveKeyItems *);
uint8_t osal_nv_read_ex(uint16_t,uint16_t,uint16_t,uint16_t,void *);
uint8_t osal_nv_write_ex(uint16_t,uint16_t,uint16_t,void *);
uint8_t osal_nv_read(uint16_t,uint16_t,uint16_t,void *);
uint8_t osal_nv_write(uint16_t,uint16_t,void *);
uint8_t OsalPort_memcmp(const void *,const void *,uint16_t);
void *OsalPort_memcpy(void *,const void *,uint16_t);
int b1_nv_runtime_hold_active(void);
void b1_security_runtime_hold_latch(void);
#endif
