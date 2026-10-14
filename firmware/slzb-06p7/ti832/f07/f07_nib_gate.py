#!/usr/bin/env python3
"""F07 slice 1: gate coordinator-ready state on a synchronous NIB NV readback.

Pinned TI SDK 8.32 zd_app.c only. NOT full F07 durability, not flashable.
Fail closed on missing NV backend/item, write, read, allocation or mismatch.
This intentionally does NOT alter the separate restoration/wipe decision path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ZDO_PATH = "source/ti/zstack/stack/zdo/zd_app.c"

FUNCTION_ANCHOR = "void ZDApp_NetworkStartEvt( void )\n{"
STATE_ANCHOR = (
    "      //save NIB to NV before child joins if NV_RESTORE is defined\n"
    "      ZDApp_NwkWriteNVRequest();\n"
    "      ZDApp_ChangeState( DEV_ZB_COORD );"
)

GATE = """#if defined(NV_RESTORE)
#include "zstackconfig.h" /* P7 F07: real configured NV backend type */
extern zstack_Config_t *pZStackCfg;
/* F07 slice 1: a void AddrMgrWriteNVRequest is not a durable NIB ack.
 * A missing NV backend may cause osal_nv_write() to report false SUCCESS;
 * require item length and a complete readback before coordinator-ready.
 * Full key/counter/table restoration is a SEPARATE unimplemented gate.
 */
__attribute__((noinline)) static uint8_t p7_f07_commit_nib_before_ready(void)
{
    nwkIB_t *readback;
    uint8_t passed = FALSE;
    NVINTF_itemID_t id;
    /* TI osal_nv_write_ex() may report SUCCESS when updateItem is NULL.
     * A valid item/readback alone is therefore not proof of a write.
     */
    if (pZStackCfg == NULL ||
        pZStackCfg->nvFps.getItemLen == 0 ||
        pZStackCfg->nvFps.updateItem == 0 ||
        pZStackCfg->nvFps.readItem == 0)
    {
        return FALSE;
    }
    id.systemID = NVINTF_SYSID_ZSTACK;
    id.itemID = ZCD_NV_EX_LEGACY;
    id.subID = ZCD_NV_NIB;
    if (pZStackCfg->nvFps.getItemLen(id) != sizeof(nwkIB_t))
    {
        return FALSE;
    }
    readback = (nwkIB_t *)OsalPort_malloc(sizeof(nwkIB_t));
    if (readback == NULL)
    {
        return FALSE;
    }
    /* Use raw NVINTF outcome: osal_nv_read_ex() mistakenly classifies
     * NVINTF_NOTFOUND (10) as success; it only rejects NVINTF_FAILURE (1).
     * The real backend's SUCCESS=0 is the only acceptable outcome.
     */
    if (pZStackCfg->nvFps.updateItem(id, sizeof(nwkIB_t), &_NIB) == NVINTF_SUCCESS &&
        pZStackCfg->nvFps.readItem(id, 0, sizeof(nwkIB_t), readback) == NVINTF_SUCCESS &&
        OsalPort_memcmp(readback, &_NIB, sizeof(nwkIB_t)))
    {
        passed = TRUE;
    }
    OsalPort_free(readback);
    return passed;
}
#endif /* NV_RESTORE: P7_F07_SLICE1 */
"""

GUARDED_STATE = (
    "      // F07 slice 1: do not claim coordinator-ready after failed NIB NV commit.\n"
    "#if defined(NV_RESTORE)\n"
    "      if (!p7_f07_commit_nib_before_ready())\n"
    "      {\n"
    "          return; /* remain DEV_COORD_STARTING; fail closed, no new ready */\n"
    "      }\n"
    "#endif\n"
    "      ZDApp_NwkWriteNVRequest(); /* Address-manager request remains async */\n"
    "      ZDApp_ChangeState( DEV_ZB_COORD );"
)


def patch(source: str) -> str:
    if (source.count(FUNCTION_ANCHOR) != 1 or
            source.count(STATE_ANCHOR) != 1):
        raise ValueError("F07_PINNED_SOURCE_ANCHORS_NOT_UNIQUE")
    if "p7_f07_commit_nib_before_ready" in source or "P7_F07_SLICE1" in source:
        raise ValueError("F07_ALREADY_PATCHED")
    if source.count('#include "osal_nv.h"') != 1:
        raise ValueError("F07_REQUIRED_OSAL_NV_API_MISSING")
    if source.count("ZDApp_ChangeState( DEV_ZB_COORD );") != 1:
        raise ValueError("F07_COORDINATOR_STATE_ANCHOR_NOT_UNIQUE")
    return (source.replace(FUNCTION_ANCHOR,
                           GATE + "\n" + FUNCTION_ANCHOR, 1)
                  .replace(STATE_ANCHOR, GUARDED_STATE, 1))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    a = parser.parse_args()
    target = a.sdk / ZDO_PATH
    before = target.read_text(encoding="utf8")
    after = patch(before)
    target.write_text(after, encoding="utf8")
    record = {
        "qualification": "F07_SYNC_NIB_SOURCE_ONLY_NOT_FLASHABLE",
        "scope": "F07_SLICE1_NIB_ONLY",
        "target": ZDO_PATH,
        "source_sha256_before": hashlib.sha256(before.encode()).hexdigest(),
        "source_sha256_after": hashlib.sha256(after.encode()).hexdigest(),
        "coordinator_state_guard": "NO_DEV_ZB_COORD_BEFORE_NIB_WRITE_AND_READBACK",
        "key_table_counter_restore_guard": "NOT_IMPLEMENTED",
        "nonblank_nv_discriminator": "NOT_IMPLEMENTED",
        "async_addr_manager_completion_guard": "NOT_IMPLEMENTED",
        "hardware_qualified": False,
        "flash_authorized": False,
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf8")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
