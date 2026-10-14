#!/usr/bin/env python3
"""F07 slice 4: coordinator-only checked periodic NWK security checkpoint.

Pinned SDK8.32 zd_app.c overlay. Source/native evidence only; NOT FLASHABLE.
A successful NVINTF readback does not prove durability after a power cut.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SOURCE = "source/ti/zstack/stack/zdo/zd_app.c"
START = "void ZDApp_SaveNwkKey( void )\n{"
END = "/*********************************************************************\n * @fn      ZDApp_ForceConcentratorChange()"
REQUIRE = (
    "  SSP_ReadNwkActiveKey( &keyItems );",
    "  osal_nv_write( ZCD_NV_NWKKEY, sizeof( nwkActiveKeyItems ),",
    "  nwkFrameCounterChanges = 0;",
)

REPLACEMENT = r'''/* F07: bounded, coordinator-only NWK checkpoint; never fall back to
 * a generic security-material row or zero the change counter on NV failure.
 * Does not certify atomic durability, RF quiescence, or key rotation.
 */
static uint8_t p7_f07_nwk_checkpoint_fault = FALSE;

__attribute__((noinline)) static uint8_t p7_f07_nwk_checkpoint(void)
{
    NVINTF_itemID_t id;
    nwkActiveKeyItems active = {0};
    nwkActiveKeyItems oldKey = {0};
    nwkActiveKeyItems readKey = {0};
    nwkSecMaterialDesc_t row = {0};
    nwkSecMaterialDesc_t selected = {0};
    nwkSecMaterialDesc_t readRow = {0};
    uint8_t found = FALSE;
    uint8_t slot = 0;
    uint8_t i;
    uint8_t ok = FALSE;
    uint32_t live;

    if (p7_f07_nwk_checkpoint_fault ||
        pZStackCfg == NULL ||
        pZStackCfg->nvFps.getItemLen == NULL ||
        pZStackCfg->nvFps.readItem == NULL ||
        pZStackCfg->nvFps.updateItem == NULL)
    {
        goto done;
    }
    if (OsalPort_isBufSet(_NIB.extendedPANID, 0, Z_EXTADDR_LEN) ||
        OsalPort_isBufSet(_NIB.extendedPANID, 0xFF, Z_EXTADDR_LEN))
    {
        goto done;
    }

    SSP_ReadNwkActiveKey(&active);
    if (OsalPort_isBufSet(active.active.key, 0, SEC_KEY_LEN))
    {
        goto done;
    }

    id.systemID = NVINTF_SYSID_ZSTACK;
    id.itemID = ZCD_NV_EX_LEGACY;
    id.subID = ZCD_NV_NWKKEY;
    if (pZStackCfg->nvFps.getItemLen(id) != sizeof(oldKey) ||
        pZStackCfg->nvFps.readItem(id, 0, sizeof(oldKey), &oldKey) != NVINTF_SUCCESS ||
        OsalPort_isBufSet(oldKey.active.key, 0, SEC_KEY_LEN) ||
        !OsalPort_memcmp(active.active.key, oldKey.active.key, SEC_KEY_LEN))
    {
        goto done; /* unexpected key rotation requires distinct policy */
    }

    id.itemID = ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE;
    for (i = 0; i < gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES; ++i)
    {
        uint32_t len;
        id.subID = i;
        len = pZStackCfg->nvFps.getItemLen(id);
        if (len == 0)
        {
            continue;
        }
        if (len != sizeof(row) ||
            pZStackCfg->nvFps.readItem(id, 0, sizeof(row), &row) != NVINTF_SUCCESS)
        {
            goto done;
        }
        if (OsalPort_memcmp(row.extendedPanID, _NIB.extendedPANID, Z_EXTADDR_LEN))
        {
            if (found)
            {
                goto done; /* duplicate network material */
            }
            found = TRUE;
            slot = i;
            selected = row;
        }
    }
    if (!found)
    {
        goto done; /* never overwrite generic or unrelated network slot */
    }

    live = active.frameCounter;
    if (nwkFrameCounter > live)
    {
        live = nwkFrameCounter;
    }
    /* Never lower an earlier persisted floor, or continue dangerously near wrap.
     * This checkpoint intentionally cannot repair a live counter rollback.
     */
    if (live < oldKey.frameCounter ||
        live < selected.FrameCounter ||
        live > UINT32_MAX - (uint32_t)MAX_NWK_FRAMECOUNTER_CHANGES)
    {
        goto done;
    }
    active.frameCounter = live;
    selected.FrameCounter = live;

    /* Preserve a monotone material floor even if the later key write fails.
     * An ambiguous update/readback always freezes further coordinator traffic.
     */
    id.subID = slot;
    if (pZStackCfg->nvFps.updateItem(id, sizeof(selected), &selected) != NVINTF_SUCCESS ||
        pZStackCfg->nvFps.readItem(id, 0, sizeof(readRow), &readRow) != NVINTF_SUCCESS ||
        !OsalPort_memcmp(&selected, &readRow, sizeof(selected)))
    {
        goto done;
    }

    id.itemID = ZCD_NV_EX_LEGACY;
    id.subID = ZCD_NV_NWKKEY;
    if (pZStackCfg->nvFps.updateItem(id, sizeof(active), &active) != NVINTF_SUCCESS ||
        pZStackCfg->nvFps.readItem(id, 0, sizeof(readKey), &readKey) != NVINTF_SUCCESS ||
        !OsalPort_memcmp(&active, &readKey, sizeof(active)))
    {
        goto done;
    }
    nwkFrameCounterChanges = 0; /* only after BOTH verified */
    ok = TRUE;

done:
    if (!ok)
    {
        p7_f07_nwk_checkpoint_fault = TRUE; /* sticky until hard reset */
    }
    memset(&active, 0, sizeof(active));
    memset(&oldKey, 0, sizeof(oldKey));
    memset(&readKey, 0, sizeof(readKey));
    memset(&row, 0, sizeof(row));
    memset(&selected, 0, sizeof(selected));
    memset(&readRow, 0, sizeof(readRow));
    return ok;
}

void ZDApp_SaveNwkKey( void )
{
    if (ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE)
    {
        if (!p7_f07_nwk_checkpoint())
        {
            /* Do not let a failed checkpoint silently continue transmission.
             * Real in-flight TX/RF quiescence still requires hardware proof.
             */
            ZDApp_PauseNwk();
            ZDApp_ChangeState(DEV_HOLD);
        }
        return;
    }

    /* Other Zigbee roles: original SDK behavior, not covered by F07 slice 4. */
    P7_F07_LEGACY_NONCOORDINATOR_BODY
}

'''

def patch(source: str) -> str:
    if source.count(START) != 1 or source.count(END) != 1:
        raise ValueError("F07_CHECKPOINT_PINNED_FUNCTION_ANCHORS_CHANGED")
    if "p7_f07_nwk_counter_escrow" not in source or "p7_f07_nwk_checkpoint" in source:
        raise ValueError("F07_CHECKPOINT_COMPOSITION_INVALID")
    first = source.index(START)
    last = source.index(END, first)
    old_body = source[first:last]
    if any(token not in old_body for token in REQUIRE):
        raise ValueError("F07_CHECKPOINT_ORIGINAL_TI_BODY_CHANGED")
    # Preserve TI's non-coordinator semantics verbatim and target only a P7U ZC.
    original_inside = old_body[old_body.index("{") + 1:old_body.rfind("}")]
    if original_inside.count("nwkFrameCounterChanges = 0;") != 1:
        raise ValueError("F07_CHECKPOINT_LEGACY_COUNTER_AMBIGUOUS")
    replacement = REPLACEMENT.replace("P7_F07_LEGACY_NONCOORDINATOR_BODY",
                                      original_inside.rstrip())
    return source[:first] + replacement + source[last:]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sdk", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    path = args.sdk / SOURCE
    before = path.read_text(encoding="utf8")
    after = patch(before)
    path.write_text(after, encoding="utf8")
    record = {
        "qualification": "F07_NWK_CHECKPOINT_SOURCE_ONLY_NOT_FLASHABLE",
        "target": SOURCE,
        "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
        "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
        "failed_checkpoint": "sticky_latch_APS_hold_radio_rx_off_DEV_HOLD",
        "powercut_atomicity_verified": False,
        "runtime_traffic_quiescence_verified": False,
        "other_roles_hardened": False,
        "key_rotation_qualified": False,
        "flash_authorized": False,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf8")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
