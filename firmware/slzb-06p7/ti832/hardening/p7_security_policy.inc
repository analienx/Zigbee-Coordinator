/* Included in zd_sec_mgr.c. Raw NVINTF callbacks, no secret-bearing diagnostics. */
#include "zstackconfig.h"
#include "p7_security.h"
extern zstack_Config_t *pZStackCfg;
static volatile uint8_t p7_security_fault;
__attribute__((noinline)) uint8_t p7_security_persistence_ok(void)
{
    if (!p7_nv_persistence_ok()) p7_security_fault = TRUE;
    return p7_security_fault == FALSE;
}
void p7_security_latch_failure(void)
{
    p7_security_fault = TRUE;
}
static void p7_security_clear(void *buffer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)buffer;
    while (length--) *bytes++ = 0; /* do not optimize away key-buffer clearing */
}
static uint8_t p7_security_read(uint16_t section, uint16_t slot,
                                uint16_t length, void *buffer)
{
    NVINTF_itemID_t id;
    id.systemID = NVINTF_SYSID_ZSTACK;
    id.itemID = section;
    id.subID = slot;
    if (!p7_security_persistence_ok() || !pZStackCfg ||
        !pZStackCfg->nvFps.getItemLen || !pZStackCfg->nvFps.readItem ||
        pZStackCfg->nvFps.getItemLen(id) != length ||
        pZStackCfg->nvFps.readItem(id, 0, length, buffer) != NVINTF_SUCCESS)
    {
        p7_security_latch_failure();
        return FALSE;
    }
    return TRUE;
}
static uint8_t p7_security_commit(uint16_t section, uint16_t slot,
                                  uint16_t length, void *buffer)
{
    NVINTF_itemID_t id;
    void *readback;
    uint8_t passed = FALSE;
    id.systemID = NVINTF_SYSID_ZSTACK;
    id.itemID = section;
    id.subID = slot;
    if (!p7_security_persistence_ok() || !pZStackCfg ||
        !pZStackCfg->nvFps.getItemLen || !pZStackCfg->nvFps.updateItem ||
        !pZStackCfg->nvFps.readItem || pZStackCfg->nvFps.getItemLen(id) != length)
    {
        p7_security_latch_failure();
        return FALSE;
    }
    readback = OsalPort_malloc(length);
    if (readback == NULL)
    {
        p7_security_latch_failure();
        return FALSE;
    }
    if (pZStackCfg->nvFps.updateItem(id, length, buffer) == NVINTF_SUCCESS &&
        pZStackCfg->nvFps.readItem(id, 0, length, readback) == NVINTF_SUCCESS &&
        OsalPort_memcmp(buffer, readback, length)) passed = TRUE;
    p7_security_clear(readback, length);
    OsalPort_free(readback);
    if (!passed) p7_security_latch_failure();
    return passed;
}
