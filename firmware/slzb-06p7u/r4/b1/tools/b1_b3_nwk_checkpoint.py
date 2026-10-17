"""Narrow B1+B3 integration: exact TI ZDApp NWK-key save, no other overlays.

This is NOT a complete B1/B3 merge. B1 retains exclusive authority over
restoration/NVOCMP/APS/TCLK and sticky HOLD; this composes B3's missing
save-side verified counter material + key checkpoint with that authority.
"""
from patch_zdapp import extract_function, replace_once

SIG = "void ZDApp_SaveNwkKey( void )"
REPLACEMENT = r'''void ZDApp_SaveNwkKey( void )
{
  nwkActiveKeyItems keyItems = {0};
  nwkActiveKeyItems persistedKey = {0};
  nwkSecMaterialDesc_t row = {0};
  nwkSecMaterialDesc_t verify = {0};
  uint8_t genericPan[Z_EXTADDR_LEN];
  uint8_t found = FALSE;
  uint8_t i = 0u;
  uint8_t index = 0u;

  if (b1_nv_runtime_hold_active()) return;
  if (gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES == 0u)
  {
    b1_security_runtime_hold_latch();
    return;
  }
  SSP_ReadNwkActiveKey(&keyItems);
  memset(genericPan, 0xFF, sizeof(genericPan));
  for (i = 0u; i < gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES; ++i)
  {
    if (osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, i, 0,
                        sizeof(row), &row) != SUCCESS)
    {
      goto b1_b3_failed;
    }
    if (OsalPort_memcmp(_NIB.extendedPANID, row.extendedPanID, Z_EXTADDR_LEN))
    {
      found = TRUE;
      index = i;
      break;
    }
  }
  if (!found)
  {
    /* Retain B3's donor generic slot fallback, but only when it really
     * contains the erased generic PAN sentinel. Never overwrite a
     * different network's security material without explicit migration. */
    if (!OsalPort_memcmp(row.extendedPanID, genericPan, Z_EXTADDR_LEN))
      goto b1_b3_failed;
    index = (uint8_t)(gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES - 1u);
    OsalPort_memcpy(row.extendedPanID, genericPan, Z_EXTADDR_LEN);
  }

  /* No key may roll back an already persisted floor for this identity. */
  if (keyItems.frameCounter < row.FrameCounter) goto b1_b3_failed;
  row.FrameCounter = keyItems.frameCounter;
  if (osal_nv_write_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, index,
                       sizeof(row), &row) != SUCCESS ||
      osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, index, 0,
                      sizeof(verify), &verify) != SUCCESS ||
      !OsalPort_memcmp(&row, &verify, sizeof(row)))
    goto b1_b3_failed;

  /* The NWK key snapshot is not atomic with the material-table row.
   * Any failure latches sticky B1 HOLD; never claim completed checkpoint. */
  if (osal_nv_write(ZCD_NV_NWKKEY, sizeof(keyItems), &keyItems) != SUCCESS ||
      osal_nv_read(ZCD_NV_NWKKEY, 0, sizeof(persistedKey),
                   &persistedKey) != SUCCESS ||
      !OsalPort_memcmp(&keyItems, &persistedKey, sizeof(keyItems)))
    goto b1_b3_failed;

  nwkFrameCounterChanges = 0;
  goto b1_b3_done;

b1_b3_failed:
  b1_security_runtime_hold_latch();
b1_b3_done:
  memset(&row, 0, sizeof(row));
  memset(&verify, 0, sizeof(verify));
  memset(&keyItems, 0, sizeof(keyItems));
  memset(&persistedKey, 0, sizeof(persistedKey));
}'''

def patch(source: str) -> str:
    # Require B1's *actual* checked restoration and sticky security policy
    # before this B3 contribution can be attached.
    if (source.count("void ZDApp_RestoreNwkSecMaterial(void)") != 1 or
            "b1_security_runtime_hold_latch();" not in source or
            "b1_nv_runtime_hold_active()" not in source or
            "readback.FrameCounter != newCounter" not in source):
        raise RuntimeError("B1_B3_NOT_PATCHED_WITH_CHECKED_RESTORE_AND_HOLD")
    old = extract_function(source, SIG)
    for token in ("SSP_ReadNwkActiveKey", "nwkFrameCounterChanges = 0;",
                  "osal_nv_write_ex", "ZCD_NV_NWKKEY"):
        if token not in old:
            raise RuntimeError("B1_B3_ORIGINAL_SAVE_SOURCE_DRIFT " + token)
    if old.count("b1_b3_failed") or source.count("b1_b3_failed"):
        raise RuntimeError("B1_B3_DUPLICATE_OR_ALREADY_APPLIED")
    return replace_once(source, old, REPLACEMENT,
                        "narrow B1+B3 network security save checkpoint")
