#ifndef B3_OSAL_NV_H
#define B3_OSAL_NV_H
#include <stdint.h>
#include <stddef.h>
#define SUCCESS 0
#define NV_OPER_FAILED 11
#define NV_ITEM_UNINIT 12
#define NV_BAD_ITEM_LEN 13
#define NVINTF_SUCCESS 0
#define NVINTF_FAILURE 1
#define NVINTF_NOTFOUND 2
#define NVINTF_SYSID_ZSTACK 9
#define ZCD_NV_EX_LEGACY 77
typedef struct {
    uint16_t systemID, itemID, subID;
} NVINTF_itemID_t;
typedef struct {
    uint8_t (*initNV)(void *);
    uint8_t (*createItem)(NVINTF_itemID_t, uint32_t, void *);
    uint32_t (*getItemLen)(NVINTF_itemID_t);
    uint8_t (*updateItem)(NVINTF_itemID_t, uint16_t, void *);
    uint8_t (*readItem)(NVINTF_itemID_t, uint16_t, uint16_t, void *);
    uint8_t (*readContItem)(NVINTF_itemID_t, uint16_t, uint16_t,
                             void *, uint16_t, uint16_t, void *, uint16_t *);
    uint8_t (*deleteItem)(NVINTF_itemID_t);
} B3NVFuncs;
typedef struct { B3NVFuncs nvFps; } zstack_Config_t;
#endif
