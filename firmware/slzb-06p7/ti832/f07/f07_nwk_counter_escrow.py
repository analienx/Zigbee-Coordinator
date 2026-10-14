#!/usr/bin/env python3
"""F07 slice 3: fail-closed coordinator NWK frame-counter escrow on restore.

This is *NOT* power-loss proof. Uses pinned TI SDK8.32 actual NVINTF callbacks,
key+security-material records, monotone addition and readback before returning
restored to the caller. Existing network, HA and radios are untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SOURCE = "source/ti/zstack/stack/zdo/zd_app.c"
FUNCTION_ANCHOR = "uint8_t ZDApp_RestoreNetworkState( void )\n{"
CALLSITE = (
    "    if ( ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE )\n"
    "    {\n"
    "      ZDApp_RestoreNwkKey( TRUE );\n"
    "    }"
)
REPLACEMENT = (
    "    if ( ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE )\n"
    "    {\n"
    "      /* F07: do not resume a coordinator on unchecked security state. */\n"
    "      if (!p7_f07_nwk_counter_escrow() || !ZDApp_RestoreNwkKey( TRUE ))\n"
    "      {\n"
    "        return ZDO_INITDEV_NEW_NETWORK_STATE; /* outer F07 guard holds */\n"
    "      }\n"
    "    }"
)
HELPER = r'''/* P7 F07 security escrow: exact existing-network slot only.
 * Never generate new NWK keys, reset the counter or silently pick a
 * generic fallback from a different network.
 */
__attribute__((noinline)) static uint8_t p7_f07_nwk_counter_escrow(void)
{
    NVINTF_itemID_t id;
    nwkActiveKeyItems key = {0};
    nwkSecMaterialDesc_t current = {0};
    nwkSecMaterialDesc_t selected = {0};
    nwkSecMaterialDesc_t check = {0};
    uint8_t index = 0;
    uint8_t found = FALSE;
    uint8_t success = FALSE;
    uint8_t i;
    uint32_t floor;
    const uint32_t a = (uint32_t)MAX_NWK_FRAMECOUNTER_CHANGES;
    const uint32_t b = (uint32_t)NWK_FRAMECOUNTER_CHANGES_RESTORE_DELTA;
    const uint32_t delta = a + b;

    if (pZStackCfg == NULL ||
        pZStackCfg->nvFps.getItemLen == 0 ||
        pZStackCfg->nvFps.readItem == 0 ||
        pZStackCfg->nvFps.updateItem == 0 ||
        FrameCounterUpdated ||
        delta < a || delta < b || delta == 0)
    {
        goto cleanup;
    }
    if (OsalPort_isBufSet(_NIB.extendedPANID, 0, Z_EXTADDR_LEN) ||
        OsalPort_isBufSet(_NIB.extendedPANID, 0xFF, Z_EXTADDR_LEN))
    {
        goto cleanup;
    }
    id.systemID = NVINTF_SYSID_ZSTACK;
    id.itemID = ZCD_NV_EX_LEGACY;
    id.subID = ZCD_NV_NWKKEY;
    if (pZStackCfg->nvFps.getItemLen(id) != sizeof(key) ||
        pZStackCfg->nvFps.readItem(id, 0, sizeof(key), &key) != NVINTF_SUCCESS ||
        OsalPort_isBufSet(key.active.key, 0, SEC_KEY_LEN))
    {
        goto cleanup;
    }

    id.itemID = ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE;
    for (i = 0; i < gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES; i++)
    {
        id.subID = i;
        /* Absent slots may be empty, but unreadable *present* slots are
         * corrupt/ambiguous; never treat NVINTF_NOTFOUND as success.
         */
        uint32_t len = pZStackCfg->nvFps.getItemLen(id);
        if (len == 0)
        {
            continue;
        }
        if (len != sizeof(current) ||
            pZStackCfg->nvFps.readItem(id, 0, sizeof(current), &current) != NVINTF_SUCCESS)
        {
            goto cleanup;
        }
        if (OsalPort_memcmp(_NIB.extendedPANID, current.extendedPanID, Z_EXTADDR_LEN))
        {
            if (found)
            {
                goto cleanup; /* duplicate network security records */
            }
            found = TRUE;
            index = i;
            selected = current;
        }
    }
    if (!found)
    {
        goto cleanup; /* never fall back to generic counter silently */
    }
    floor = selected.FrameCounter;
    if (key.frameCounter > floor)
    {
        floor = key.frameCounter;
    }
    if (nwkFrameCounter > floor)
    {
        floor = nwkFrameCounter;
    }
    if (floor > UINT32_MAX - delta)
    {
        goto cleanup; /* refuse wrap/replay */
    }
    selected.FrameCounter = floor + delta;
    id.subID = index;
    if (pZStackCfg->nvFps.updateItem(id, sizeof(selected), &selected) != NVINTF_SUCCESS ||
        pZStackCfg->nvFps.readItem(id, 0, sizeof(check), &check) != NVINTF_SUCCESS ||
        !OsalPort_memcmp(&selected, &check, sizeof(selected)))
    {
        goto cleanup;
    }
    /* Publish RAM counter only after the exact persisted row has read back.
     * FrameCounterUpdated suppresses TI's second unchecked increment.
     */
    nwkFrameCounter = selected.FrameCounter;
    FrameCounterUpdated = TRUE;
    nwkFrameCounterChanges = 0;
    success = TRUE;

cleanup:
    memset(&key, 0, sizeof(key));
    memset(&current, 0, sizeof(current));
    memset(&selected, 0, sizeof(selected));
    memset(&check, 0, sizeof(check));
    return success;
}
'''


def patch(source: str) -> str:
    if source.count(FUNCTION_ANCHOR)!=1 or source.count(CALLSITE)!=1:
        raise ValueError("F07_COUNTER_PINNED_CALLSITE_NOT_UNIQUE")
    if "p7_f07_nwk_counter_escrow" in source:
        raise ValueError("F07_COUNTER_ALREADY_PATCHED")
    if ("p7_f07_nv_restore_preflight" not in source or
            "p7_f07_commit_nib_before_ready" not in source or
            'extern zstack_Config_t *pZStackCfg;' not in source):
        raise ValueError("F07_SECURITY_REQUIRES_EARLIER_F07_SLICES")
    if source.count("void ZDApp_RestoreNwkSecMaterial(void)")!=1:
        raise ValueError("F07_SECURITY_RESTORE_API_CHANGED")
    return source.replace(FUNCTION_ANCHOR, HELPER+"\n"+FUNCTION_ANCHOR,1).replace(
        CALLSITE,REPLACEMENT,1)


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
        "qualification":"F07_NWK_SECURITY_COUNTER_ESCROW_SOURCE_ONLY_NOT_FLASHABLE",
        "target":SOURCE,
        "before_sha256":hashlib.sha256(before.encode()).hexdigest(),
        "after_sha256":hashlib.sha256(after.encode()).hexdigest(),
        "guards":"raw_NVINTF_success_exact_existing_network_monotonic_counter_readback",
        "restore_failure":"outer_F07_DEV_HOLD_no_implicit_new_network",
        "linked_native_proof":"PENDING",
        "powercut_persistence":"UNPROVEN",
        "nwk_aps_tclk_all_states_covered":False,
        "flash_authorized":False,
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(record,indent=2)+"\n",encoding="utf8")
    print(json.dumps(record,sort_keys=True))


if __name__=="__main__":
    main()
