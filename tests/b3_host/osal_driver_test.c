/* Actual pinned TI osal_nv.c linked as separate translation unit; no reimplementation. */
#include "osal_nv.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

zstack_Config_t *pZStackCfg;
extern uint8_t osal_nv_write_ex(uint16_t, uint16_t, uint16_t, void *);
extern uint8_t osal_nv_read_ex(uint16_t, uint16_t, uint16_t, uint16_t, void *);
extern uint8_t osal_nv_item_init_ex(uint16_t, uint16_t, uint16_t, void *);
extern uint8_t osal_nv_delete_ex(uint16_t, uint16_t, uint16_t);
static uint8_t result;
static uint8_t update(NVINTF_itemID_t i, uint16_t l, void *p)
{ (void)i; (void)l; (void)p; return result; }
static uint8_t read_(NVINTF_itemID_t i, uint16_t off, uint16_t l, void *p)
{ (void)i; (void)off; (void)l; (void)p; return result; }
static uint8_t create_(NVINTF_itemID_t i, uint32_t l, void *p)
{ (void)i; (void)l; (void)p; return result; }
static uint8_t delete_(NVINTF_itemID_t i)
{ (void)i; return result; }
static uint32_t length_(NVINTF_itemID_t i)
{ (void)i; return 4; }

int main(void)
{
    uint8_t buf[4] = {0};
    zstack_Config_t cfg = {0};
    pZStackCfg = 0;
    assert(osal_nv_write_ex(2, 3, 4, buf) == NV_OPER_FAILED);
    assert(osal_nv_read_ex(2, 3, 0, 4, buf) == NV_OPER_FAILED);
    assert(osal_nv_delete_ex(2, 3, 4) == NV_OPER_FAILED);

    pZStackCfg = &cfg;
    assert(osal_nv_write_ex(2, 3, 4, buf) == NV_OPER_FAILED);
    assert(osal_nv_read_ex(2, 3, 0, 4, buf) == NV_OPER_FAILED);
    assert(osal_nv_delete_ex(2, 3, 4) == NV_OPER_FAILED);

    cfg.nvFps.updateItem = update;
    cfg.nvFps.readItem = read_;
    cfg.nvFps.createItem = create_;
    cfg.nvFps.deleteItem = delete_;
    cfg.nvFps.getItemLen = length_;

    result = NVINTF_SUCCESS;
    assert(osal_nv_write_ex(2, 3, 4, buf) == SUCCESS);
    assert(osal_nv_read_ex(2, 3, 0, 4, buf) == SUCCESS);
    assert(osal_nv_delete_ex(2, 3, 4) == SUCCESS);

    result = NVINTF_NOTFOUND;
    assert(osal_nv_write_ex(2, 3, 4, buf) == NV_ITEM_UNINIT);
    assert(osal_nv_read_ex(2, 3, 0, 4, buf) == NV_OPER_FAILED);
    assert(osal_nv_item_init_ex(2, 3, 4, buf) == SUCCESS); /* matching existing length */

    result = 99; /* Unknown future or transport backend failure -> fail closed */
    assert(osal_nv_write_ex(2, 3, 4, buf) == NV_OPER_FAILED);
    assert(osal_nv_read_ex(2, 3, 0, 4, buf) == NV_OPER_FAILED);
    assert(osal_nv_delete_ex(2, 3, 4) == NV_OPER_FAILED);

    cfg.nvFps.getItemLen = 0;
    result = NVINTF_FAILURE;
    assert(osal_nv_item_init_ex(2, 3, 4, buf) == NV_OPER_FAILED);
    puts("B3 actual TI OSAL function-body harness PASS: missing, success, not-found and unknown status");
    return 0;
}
