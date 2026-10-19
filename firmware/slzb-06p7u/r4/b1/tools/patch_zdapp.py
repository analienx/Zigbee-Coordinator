"""Fail-closed TI 8.33 linked ZDApp NV security material and counter paths.

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
  uint8_t emptyPanID[Z_EXTADDR_LEN] = {0};
  uint8_t genericPanID[Z_EXTADDR_LEN];
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

  memset(genericPanID, 0xFF, sizeof(genericPanID));
  if (gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES == 0 ||
      OsalPort_memcmp(_NIB.extendedPANID, emptyPanID, Z_EXTADDR_LEN) ||
      OsalPort_memcmp(_NIB.extendedPANID, genericPanID, Z_EXTADDR_LEN))
  {
    /* A formed network with an invalid identity must not restore the
     * generic key's counter under a synthetic current PAN identity. */
    if (b1_nv_existing_header_candidate()) b1_nv_runtime_hold_latch();
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
   * is separately latched by NVOCMP and must end restoration immediately.
   * Always inspect ALL slots before publishing a counter. A later duplicate
   * may have a higher persisted replay floor than the first match. */
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

    if (OsalPort_memcmp(_NIB.extendedPANID, row.extendedPanID,
                        Z_EXTADDR_LEN))
    {
      if (found)
      {
        b1_nv_runtime_hold_latch();
        return;
      }
      saved = row;
      slot = i;
      found = TRUE;
      continue;
    }
    if (OsalPort_memcmp(row.extendedPanID, emptyPanID, Z_EXTADDR_LEN))
    {
      if (row.FrameCounter != 0u)
      {
        /* Counter without identity is a torn/ambiguous material row. */
        b1_nv_runtime_hold_latch();
        return;
      }
      continue;
    }
    if (OsalPort_memcmp(row.extendedPanID, genericPanID, Z_EXTADDR_LEN))
    {
      if (i != gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES - 1 &&
          row.FrameCounter != 0u)
      {
        b1_nv_runtime_hold_latch();
        return;
      }
      if (i == gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES - 1 &&
          row.FrameCounter != 0u)
      {
        generic = row;
        genericFound = TRUE;
      }
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


STORE_MATERIAL = r"""void ZDApp_StoreNwkSecMaterial(void)
{
  nwkSecMaterialDesc_t row = {0};
  nwkSecMaterialDesc_t readback = {0};
  uint8_t emptyPanID[Z_EXTADDR_LEN] = {0};
  uint8_t genericPanID[Z_EXTADDR_LEN];
  uint8_t emptySlot = gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES;
  uint8_t found = FALSE;
  uint8_t genericFound = FALSE;
  uint8_t genericHasCounter = FALSE;
  uint8_t i;

  if (b1_nv_runtime_hold_active()) return;
  memset(genericPanID, 0xFF, sizeof(genericPanID));
  if (gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES == 0 ||
      OsalPort_memcmp(_NIB.extendedPANID, emptyPanID, Z_EXTADDR_LEN) ||
      OsalPort_memcmp(_NIB.extendedPANID, genericPanID, Z_EXTADDR_LEN))
  {
    b1_nv_runtime_hold_latch();
    return;
  }

  /* TI's original loop stops at the first zero-ID slot, even when a later
   * slot already belongs to this PAN with a nonzero replay counter. Scan
   * the ENTIRE bounded table before deciding whether to create a row. */
  for (i = 0; i < gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES; i++)
  {
    memset(&row, 0, sizeof(row));
    if (osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, i, 0,
                        sizeof(row), &row) != ZSUCCESS)
    {
      b1_nv_runtime_hold_latch();
      return;
    }
    if (OsalPort_memcmp(row.extendedPanID, _NIB.extendedPANID,
                        Z_EXTADDR_LEN))
    {
      if (found)
      {
        /* Duplicate identity means restore order could choose a stale floor. */
        b1_nv_runtime_hold_latch();
        return;
      }
      found = TRUE;
    }
    else if (OsalPort_memcmp(row.extendedPanID, emptyPanID,
                            Z_EXTADDR_LEN))
    {
      if (row.FrameCounter != 0u)
      {
        b1_nv_runtime_hold_latch();
        return;
      }
      if (emptySlot == gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES) emptySlot = i;
    }
    else if (i == gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES - 1 &&
             OsalPort_memcmp(row.extendedPanID, genericPanID,
                             Z_EXTADDR_LEN))
    {
      genericFound = TRUE;
      genericHasCounter = (row.FrameCounter != 0u);
    }
  }

  if (found || (genericFound && genericHasCounter)) return;
  if (emptySlot == gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES)
  {
    /* An already initialized generic slot may receive the later SAVE. */
    if (!genericFound) b1_nv_runtime_hold_latch();
    return;
  }

  /* First publication of a PAN identity must be durable before startup or
   * authentication progresses. NEVER zero an existing active counter. */
  memset(&row, 0, sizeof(row));
  memcpy(row.extendedPanID, _NIB.extendedPANID, Z_EXTADDR_LEN);
  if (osal_nv_write_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, emptySlot,
                       sizeof(row), &row) != ZSUCCESS ||
      osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, emptySlot, 0,
                      sizeof(readback), &readback) != ZSUCCESS ||
      !OsalPort_memcmp(&row, &readback, sizeof(row)))
  {
    b1_nv_runtime_hold_latch();
  }
}"""


def patch(source: str) -> str:
    source = replace_once(
        source, '#include "zcomdef.h"',
        '#include "zcomdef.h"\n'
        '/* R4-B1 source-linked fault policy; no second serial owner. */\n'
        'extern void b1_nv_runtime_hold_latch(void);\n'
        'extern int b1_nv_runtime_hold_active(void);\n'
        'extern int b1_nv_existing_header_candidate(void);\n'
        'extern int b1_sec_restored_network_validated(void);\n'
        'extern void b1_management_note_zdo_state(uint8_t coordinator, uint8_t persisted_restore_ok);',
        "ZDApp security declarations")

    old_store = extract_function(source, "void ZDApp_StoreNwkSecMaterial(void)")
    source = replace_once(source, old_store, STORE_MATERIAL,
                          "full-table NWK material STORE and checked identity commit")

    network_sig = "void ZDApp_NetworkStartEvt( void )"
    old_network = extract_function(source, network_sig)
    new_network = replace_once(
        old_network,
        "      ZDApp_NwkWriteNVRequest();\n"
        "      ZDApp_ChangeState( DEV_ZB_COORD );\n\n"
        "      if(bdbCommissioningProcedureState.bdbCommissioningState == BDB_COMMISSIONING_STATE_FORMATION)\n"
        "      {\n"
        "        bdb_nwkFormationAttempt(TRUE);\n"
        "        ZDApp_StoreNwkSecMaterial();",
        "      ZDApp_NwkWriteNVRequest();\n"
        "      /* Security material must be persisted before READY/formation is announced. */\n"
        "      if(bdbCommissioningProcedureState.bdbCommissioningState == BDB_COMMISSIONING_STATE_FORMATION)\n"
        "      {\n"
        "        ZDApp_StoreNwkSecMaterial();\n"
        "        if (b1_nv_runtime_hold_active()) return;\n"
        "      }\n"
        "      ZDApp_ChangeState( DEV_ZB_COORD );\n\n"
        "      if(bdbCommissioningProcedureState.bdbCommissioningState == BDB_COMMISSIONING_STATE_FORMATION)\n"
        "      {\n"
        "        bdb_nwkFormationAttempt(TRUE);",
        "coordinator security STORE before READY and formation report")
    source = replace_once(source, old_network, new_network,
                          "network-formation security STORE fence")

    sec_sig = "uint32_t ZDApp_ProcessSecEvent( uint8_t task_id, uint32_t events )"
    old_events = extract_function(source, sec_sig)
    new_events = replace_once(
        old_events,
        "    ZDApp_StoreNwkSecMaterial();\n\n    ZDApp_DeviceAuthEvt();",
        "    ZDApp_StoreNwkSecMaterial();\n"
        "    if (b1_nv_runtime_hold_active())\n"
        "    {\n"
        "      return (events ^ ZDO_DEVICE_AUTH);\n"
        "    }\n\n"
        "    ZDApp_DeviceAuthEvt();",
        "no authentication progression after failed STORE")
    source = replace_once(source, old_events, new_events,
                          "ZDO security-store event fence")

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

    # Only the actual donor ZDO state transition can attest restored
    # coordinator startup. A queued SYS_PING/NPI response is never sufficient.
    state_sig = "void ZDApp_ChangeState( devStates_t state )"
    old_state = extract_function(source, state_sig)
    new_state = replace_once(
        old_state, "    devState = state;",
        "    devState = state;\n"
        "    b1_management_note_zdo_state((uint8_t)(state == DEV_ZB_COORD),\n"
        "        (uint8_t)(state == DEV_ZB_COORD && FrameCounterUpdated &&\n"
        "                  b1_nv_existing_header_candidate() &&\n"
        "                  b1_sec_restored_network_validated()));",
        "ZDO actual state-change ready attestation")
    source = replace_once(source, old_state, new_state, "actual ZDO callback body")

    # A persistence fault in these paths is a security-domain failure.
    source = source.replace('b1_nv_runtime_hold_latch()',
                            'b1_security_runtime_hold_latch()')
    source = source.replace('extern void b1_nv_runtime_hold_latch(void);',
                            'extern void b1_security_runtime_hold_latch(void);')
    return source
