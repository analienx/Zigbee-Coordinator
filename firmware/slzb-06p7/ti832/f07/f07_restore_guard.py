#!/usr/bin/env python3
"""F07 slice 2: refuse implicit reset when a requested NV restore fails.

Applies only to exact pinned TI8.32 zd_app.c after the separate F07 slice1.
Explicit user-requested new-network path is left unchanged. Never flash this.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SOURCE="source/ti/zstack/stack/zdo/zd_app.c"
ANCHOR="  if ( networkStateNV == ZDO_INITDEV_RESTORED_NETWORK_STATE )\n  {\n    networkStateNV = ZDApp_RestoreNetworkState();"
RESTORE_ANCHOR=(
    "    runtimeChannel = (uint32_t) (1L << _NIB.nwkLogicalChannel);\n"
    "  }\n  else\n  {\n    // Wipe out the network state in NV"
)
HELPER=r'''#if defined(NV_RESTORE)
/* F07 slice2 is inserted BEFORE slice1's later NIB gate in zd_app.c.
 * Its own early declaration is required by the authentic native compiler.
 */
#include "zstackconfig.h"
extern zstack_Config_t *pZStackCfg;
/* F07 slice 2: preflight a requested existing-network restore before
 * NLME_InitNV() may create/replace records. This is not a complete
 * key-table/frame-counter validation and is not a blank-NV detector.
 */
__attribute__((noinline)) static uint8_t p7_f07_nv_restore_preflight(void)
{
    nwkIB_t *copy;
    uint8_t readable;
    NVINTF_itemID_t id;
    if (pZStackCfg == NULL ||
        pZStackCfg->nvFps.getItemLen == 0 ||
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
    copy = (nwkIB_t *)OsalPort_malloc(sizeof(nwkIB_t));
    if (copy == NULL)
    {
        return FALSE;
    }
    /* osal_nv_read_ex() can convert NVINTF_NOTFOUND to false SUCCESS. */
    readable = (pZStackCfg->nvFps.readItem(id, 0, sizeof(nwkIB_t), copy) == NVINTF_SUCCESS);
    OsalPort_free(copy);
    return readable;
}
#endif /* P7_F07_RESTORE_PREFLIGHT */
'''

ENTRY=(
    "  if ( networkStateNV == ZDO_INITDEV_RESTORED_NETWORK_STATE )\n"
    "  {\n"
    "    /* P7 F07: a requested restore must never silently become a new network. */\n"
    "    if (!p7_f07_nv_restore_preflight())\n"
    "    {\n"
    "      devState = DEV_HOLD;\n"
    "      return ZDO_INITDEV_LEAVE_NOT_STARTED;\n"
    "    }\n"
    "    networkStateNV = ZDApp_RestoreNetworkState();\n"
    "    /* Check the RAW restore result before Touchlink may rewrite NEW to RESTORED. */\n"
    "    if (networkStateNV != ZDO_INITDEV_RESTORED_NETWORK_STATE)\n"
    "    {\n"
    "      devState = DEV_HOLD;\n"
    "      return ZDO_INITDEV_LEAVE_NOT_STARTED;\n"
    "    }"
)

EXIT=RESTORE_ANCHOR  # Original Touchlink branch remains, but cannot mask failed restore.

def patch(source: str) -> str:
    if source.count(ANCHOR)!=1 or source.count(RESTORE_ANCHOR)!=1:
        raise ValueError("F07_RESTORE_PINNED_ANCHOR_CHANGED")
    if "P7_F07_RESTORE_PREFLIGHT" in source:
        raise ValueError("F07_RESTORE_ALREADY_APPLIED")
    # The backend type/extern comes from slice 1. F07 slice 2 must not
    # silently apply to vanilla TI ZNP without the accepted NIB guard.
    if ("p7_f07_commit_nib_before_ready" not in source or
            'extern zstack_Config_t *pZStackCfg;' not in source):
        raise ValueError("F07_SLICE1_BACKEND_GATE_REQUIRED")
    if source.count("    NLME_SetDefaultNV();")!=1 or source.count("    ZDSecMgrClearNVKeyValues();")!=1:
        raise ValueError("F07_DESTRUCTIVE_PATH_ANCHOR_CHANGED")
    marker="uint8_t ZDOInitDeviceEx( uint16_t startDelay, uint8_t mode)\n{"
    if source.count(marker)!=1:
        raise ValueError("F07_STARTUP_FUNCTION_CHANGED")
    result=source.replace(marker,HELPER+"\n"+marker,1)
    result=result.replace(ANCHOR,ENTRY,1).replace(RESTORE_ANCHOR,EXIT,1)
    return result

def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    path=a.sdk/SOURCE
    before=path.read_text(encoding="utf8")
    after=patch(before)
    path.write_text(after,encoding="utf8")
    record={
        "qualification":"F07_RESTORE_PRECHECK_SOURCE_ONLY_NOT_FLASHABLE",
        "source_sha256_before":hashlib.sha256(before.encode()).hexdigest(),
        "source_sha256_after":hashlib.sha256(after.encode()).hexdigest(),
        "requested_restore_requires":"NIB_SIZE_AND_READABLE_BEFORE_NLME_INITNV",
        "restore_failure":"DEV_HOLD_PLUS_LEAVE_NOT_STARTED_NO_NWK_RESET",
        "explicit_new_network_start":"UNCHANGED_REQUIRES_SEPARATE_PROVISIONING_POLICY",
        "security_counter_monotonicity":"NOT_PROVEN",
        "all_NWKV_sec_tables":"NOT_PROVEN",
        "hardware_qualified":False,"flash_authorized":False,
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(record,indent=2)+"\n",encoding="utf8")
    print(json.dumps(record,sort_keys=True))

if __name__=="__main__":
    main()
