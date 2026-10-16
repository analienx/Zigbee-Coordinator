"""Fail-closed TI 8.33 linked ZDApp NV security/counter restore (B1 N12/N13).

Called only after exact upstream zd_app.c git-blob SHA validation in apply_b1.
Actual TI function bodies are replaced, preserving public signatures.
No direct flash, serial, radio, HA or device operations.
"""


def extract_function(source: str, signature: str) -> str:
    needle = signature + "\n{"
    if source.count(needle) != 1:
        raise RuntimeError("ZDAPP_FUNCTION_NOT_UNIQUE " + signature)
    start = source.index(needle)
    opening = start + len(signature) + 1
    depth = 0
    for i in range(opening, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
    raise RuntimeError("ZDAPP_UNTERMINATED " + signature)


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if source.count(old) != 1:
        raise RuntimeError("ZDAPP_SOURCE_DRIFT " + label + " count=" +
                           str(source.count(old)))
    return source.replace(old, new, 1)


RESTORE_COUNTER = r"""void ZDApp_RestoreNwkSecMaterial(void)
{
  nwkSecMaterialDesc_t saved = {0};
  nwkSecMaterialDesc_t generic = {0};
  nwkSecMaterialDesc_t readback = {0};
  uint8_t slot = 0;
  uint8_t found = FALSE;
  uint8_t genericFound = FALSE;
  uint8_t i;
  uint32_t reserve;
  uint32_t newCounter;

  if (b1_nv_runtime_hold_active() || FrameCounterUpdated)
  {
    return;
  }

  /* A populated existing NV header pair must never advance its counter
   * while the mandatory NWK key is absent or all zero. Key bytes never
   * appear in diagnostics and are wiped on all paths. */
  if (b1_nv_existing_header_candidate())
  {
    nwkActiveKeyItems keyItems = {0};
    uint8_t nullKey[SEC_KEY_LEN] = {0};
    uint8_t status = osal_nv_read(ZCD_NV_NWKKEY, 0, sizeof(keyItems), &keyItems);
    uint8_t valid = status == ZSUCCESS &&
                    !OsalPort_memcmp(keyItems.active.key, nullKey, SEC_KEY_LEN);
    memset(&keyItems, 0, sizeof(keyItems));
    if (!valid)
    {
      b1_nv_runtime_hold_latch();
      return;
    }
  }

  /* Missing optional entries are allowed. Any actual failed backend read
   * is separately latched by NVOCMP and must end restoration immediately. */
  for (i = 0; i < gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES; i++)
  {
    nwkSecMaterialDesc_t row = {0};
    uint8_t status = osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE,
                                     i, 0, sizeof(row), &row);
    if (status != ZSUCCESS)
    {
      if (b1_nv_runtime_hold_active()) return;
      continue;
    }

    if (i == gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES - 1 &&
        row.FrameCounter != 0)
    {
      uint8_t genericID[Z_EXTADDR_LEN];
      memset(genericID, 0xFF, sizeof(genericID));
      if (OsalPort_memcmp(row.extendedPanID, genericID, sizeof(genericID)))
      {
        generic = row;
        genericFound = TRUE;
      }
    }
    if (OsalPort_memcmp(_NIB.extendedPANID, row.extendedPanID,
                        Z_EXTADDR_LEN))
    {
      saved = row;
      slot = i;
      found = TRUE;
      break;
    }
  }

  if (!found && genericFound)
  {
    saved = generic;
    slot = gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES - 1;
    found = TRUE;
  }

  if (!found || (b1_nv_existing_header_candidate() &&
                 saved.FrameCounter == 0u))
  {
    /* A restored populated NV2 must not invent a zero-counter key row.
     * Truly authorized factory-new state remains exempt. */
    if (b1_nv_existing_header_candidate()) b1_nv_runtime_hold_latch();
    return;
  }

  reserve = (uint32_t)MAX_NWK_FRAMECOUNTER_CHANGES +
            (uint32_t)NWK_FRAMECOUNTER_CHANGES_RESTORE_DELTA;
  if (reserve == 0u || saved.FrameCounter > UINT32_MAX - reserve)
  {
    b1_nv_runtime_hold_latch();
    return;
  }
  newCounter = saved.FrameCounter + reserve;

  /* Commit, then read back exact identity and counter. Only after both
   * succeed can RAM counter/FrameCounterUpdated be published. */
  saved.FrameCounter = newCounter;
  if (osal_nv_write_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE,
                       slot, sizeof(saved), &saved) != ZSUCCESS)
  {
    b1_nv_runtime_hold_latch();
    return;
  }
  if (osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE,
                      slot, 0, sizeof(readback), &readback) != ZSUCCESS ||
      readback.FrameCounter != newCounter ||
      !OsalPort_memcmp(saved.extendedPanID, readback.extendedPanID,
                       Z_EXTADDR_LEN))
  {
    b1_nv_runtime_hold_latch();
    return;
  }

  nwkFrameCounter = newCounter;
  FrameCounterUpdated = TRUE;
  nwkFrameCounterChanges = 0;
}"""


def patch(source: str) -> str:
    source = replace_once(
        source, '#include "zcomdef.h"',
        '#include "zcomdef.h"\n'
        '/* R4-B1 source-linked fault policy; no second serial owner. */\n'
        'extern void b1_nv_runtime_hold_latch(void);\n'
        'extern int b1_nv_runtime_hold_active(void);\n'
        'extern int b1_nv_existing_header_candidate(void);',
        "ZDApp security declarations")

    old_counter = extract_function(source, "void ZDApp_RestoreNwkSecMaterial(void)")
    source = replace_once(source, old_counter, RESTORE_COUNTER,
                          "counter checked persist/readback")

    key_signature = "uint8_t ZDApp_RestoreNwkKey( uint8_t incrFrmCnt )"
    old_key = extract_function(source, key_signature)
    new_key = r"""uint8_t ZDApp_RestoreNwkKey( uint8_t incrFrmCnt )
{
  nwkActiveKeyItems keyItems = {0};
  uint8_t nullKey[SEC_KEY_LEN] = {0};
  uint8_t ret = FALSE;

  /* Never publish a frame counter if the mandatory key is absent. */
  if (b1_nv_runtime_hold_active()) return FALSE;
  if (osal_nv_read(ZCD_NV_NWKKEY, 0, sizeof(keyItems), &keyItems) == ZSUCCESS)
  {
    if (!OsalPort_memcmp(keyItems.active.key, nullKey, SEC_KEY_LEN))
    {
      ret = TRUE;
    }
  }
  memset(&keyItems, 0, sizeof(keyItems));
  if (ret != TRUE)
  {
    if (b1_nv_existing_header_candidate()) b1_nv_runtime_hold_latch();
    return FALSE;
  }
  ZDApp_RestoreNwkSecMaterial();
  if (b1_nv_runtime_hold_active()) return FALSE;
  return TRUE;
}"""
    source = replace_once(source, old_key, new_key, "key before counter")

    # A persistence fault in these paths is a security-domain failure.
    source = source.replace('b1_nv_runtime_hold_latch()',
                            'b1_security_runtime_hold_latch()')
    source = source.replace('extern void b1_nv_runtime_hold_latch(void);',
                            'extern void b1_security_runtime_hold_latch(void);')
    return source
