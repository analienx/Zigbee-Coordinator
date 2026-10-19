"""Scoped TI 8.33 APS/TCLK persistence fixes; exact pins checked by apply_b1.

This does not establish full NIB/stack readiness or cancel queued/ROM RF.
The restored-network precheck executes before zgInit can create defaults.
"""
from patch_zdapp import extract_function, replace_once

SUPPORT = r'''
/* zd_app.c writes ZCD_NV_NIB using sizeof(nwkIB_t); use the native ABI,
 * never a host-guessed byte offset. This helper does not publish _NIB. */
static uint8_t b1_sec_validate_nib(uint8_t onNetwork)
{
  nwkIB_t nib = {0};
  uint8_t zero[Z_EXTADDR_LEN] = {0};
  uint8_t erased[Z_EXTADDR_LEN];
  uint8_t logicalType = ZG_DEVICETYPE_COORDINATOR;
  uint16_t length = osal_nv_item_len(ZCD_NV_NIB);
  uint16_t logicalLength = osal_nv_item_len(ZCD_NV_LOGICAL_TYPE);
  memset(erased, 0xFF, sizeof(erased));
  if (b1_nv_runtime_hold_active()) return FALSE;
  if ((onNetwork && logicalLength != sizeof(logicalType)) ||
      (logicalLength != 0u &&
       (logicalLength != sizeof(logicalType) ||
        osal_nv_read(ZCD_NV_LOGICAL_TYPE, 0, sizeof(logicalType), &logicalType) != SUCCESS ||
        logicalType != ZG_DEVICETYPE_COORDINATOR))) return FALSE;
  if (length == 0u) return !onNetwork && !b1_nv_runtime_hold_active();
  if (length != sizeof(nib) ||
      osal_nv_read(ZCD_NV_NIB, 0, sizeof(nib), &nib) != SUCCESS) return FALSE;
  if (!onNetwork)
  {
    /* ZDOInitDeviceEx's explicit new-state assignments (zd_app.c): the
     * device/coordinator/PAN addresses are invalid before formation. */
    return nib.nwkState == NWK_INIT &&
           nib.nwkDevAddress == INVALID_NODE_ADDR &&
           nib.nwkCoordAddress == INVALID_NODE_ADDR &&
           nib.nwkPanId == 0xFFFFu && nib.nwkKeyLoaded == FALSE &&
           !b1_nv_runtime_hold_active();
  }
  return nib.nwkState == NWK_ROUTER && nib.nwkDevAddress == 0u &&
         nib.nwkPanId != 0xFFFFu && nib.nwkKeyLoaded == TRUE &&
         nib.nwkLogicalChannel >= 11u && nib.nwkLogicalChannel <= 26u &&
         !OsalPort_memcmp(nib.extendedPANID, zero, sizeof(zero)) &&
         !OsalPort_memcmp(nib.extendedPANID, erased, sizeof(erased)) &&
         !b1_nv_runtime_hold_active();
}

/* B1: read-only security checks precede zgInit's default item creation. */
int b1_sec_validate_restored(void)
{
  uint8_t onNetwork = FALSE;
  uint8_t zeroKey[SEC_KEY_LEN] = {0};
  uint8_t seed[SEC_KEY_LEN] = {0};
  uint8_t trustCenter[Z_EXTADDR_LEN] = {0};
  uint8_t zeroAddr[Z_EXTADDR_LEN] = {0};
  nwkActiveKeyItems nwk = {0};
  nwkKeyDesc active = {0};
  nvDeviceListHdr_t hdr = {0};
  uint16_t i;
  uint16_t used = 0;
  uint8_t okay = TRUE;
  b1_sec_existing_network = FALSE;
  if (b1_nv_runtime_hold_active()) return FALSE;
  if (!b1_nv_existing_header_candidate()) return TRUE;
  if (osal_nv_read(ZCD_NV_BDBNODEISONANETWORK, 0, sizeof(onNetwork),
                   &onNetwork) != SUCCESS || onNetwork > TRUE)
  {
    b1_security_runtime_hold_latch();
    return FALSE;
  }
  if (!b1_sec_validate_nib(onNetwork))
  {
    b1_security_runtime_hold_latch();
    return FALSE;
  }
  if (!onNetwork) return TRUE; /* Verified new NIB; APS may be empty. */
  /* Do not publish restored-network validation until ALL APS/TCLK checks
   * finish. The ZDO readiness hook must not see a partial preflight. */
  if (osal_nv_read(ZCD_NV_NWKKEY, 0, sizeof(nwk), &nwk) != SUCCESS ||
      osal_nv_read(ZCD_NV_NWK_ACTIVE_KEY_INFO, 0, sizeof(active), &active) != SUCCESS ||
      OsalPort_memcmp(nwk.active.key, zeroKey, SEC_KEY_LEN) ||
      nwk.active.keySeqNum != active.keySeqNum ||
      !OsalPort_memcmp(nwk.active.key, active.key, SEC_KEY_LEN) ||
      osal_nv_read(ZCD_NV_TCLK_SEED, 0, sizeof(seed), seed) != SUCCESS ||
      OsalPort_memcmp(seed, zeroKey, SEC_KEY_LEN) ||
      osal_nv_read(ZCD_NV_TRUSTCENTER_ADDR, 0, sizeof(trustCenter), trustCenter) != SUCCESS ||
      OsalPort_memcmp(trustCenter, zeroAddr, sizeof(trustCenter)) ||
      osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE, 0, sizeof(hdr), &hdr) != SUCCESS ||
      hdr.numRecs > gZDSECMGR_ENTRY_MAX)
  {
    okay = FALSE;
  }
  memset(&nwk, 0, sizeof(nwk));
  memset(&active, 0, sizeof(active));
  memset(seed, 0, sizeof(seed));
  memset(trustCenter, 0, sizeof(trustCenter));
  /* numRecs == 0 is a legitimate optional empty APS table. Unreferenced
   * APS data rows are not required and are not created on restoration. */
  if (okay && hdr.numRecs != 0)
  {
    for (i = 0; i < gZDSECMGR_ENTRY_MAX; ++i)
    {
      ZDSecMgrEntry_t entry = {0};
      APSME_ApsLinkKeyNVEntry_t key = {0};
      if (osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE,
          (uint16_t)(sizeof(hdr) + i * sizeof(entry)), sizeof(entry), &entry) != SUCCESS)
      {
        okay = FALSE;
        break;
      }
      if (entry.ami == INVALID_NODE_ADDR) continue;
      if (entry.keyNvId >= gZDSECMGR_ENTRY_MAX ||
          osal_nv_read_ex(ZCD_NV_EX_APS_KEY_DATA_TABLE, entry.keyNvId, 0,
                         sizeof(key), &key) != SUCCESS ||
          OsalPort_memcmp(key.key, zeroKey, SEC_KEY_LEN) ||
          key.txFrmCntr > UINT32_MAX - ((uint32_t)MAX_APS_FRAMECOUNTER_CHANGES + 1u))
      {
        okay = FALSE;
      }
      memset(&key, 0, sizeof(key));
      if (!okay) break;
      {
        uint16_t previous;
        for (previous = 0; previous < i; ++previous)
        {
          ZDSecMgrEntry_t other = {0};
          if (osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE,
              (uint16_t)(sizeof(hdr) + previous * sizeof(other)), sizeof(other), &other) != SUCCESS ||
              (other.ami != INVALID_NODE_ADDR &&
               (other.ami == entry.ami || other.keyNvId == entry.keyNvId)))
          {
            okay = FALSE;
            break;
          }
        }
      }
      if (!okay) break;
      ++used;
    }
    if (used != hdr.numRecs) okay = FALSE;
  }
  /* Donor preallocates every TCLK slot. Empty slots are valid; missing
   * storage is not equivalent to a verified empty slot on a restored net. */
  if (okay)
  {
    for (i = 0; i < gZDSECMGR_TC_DEVICE_MAX; ++i)
    {
      APSME_TCLinkKeyNVEntry_t row = {0};
      uint8_t empty[Z_EXTADDR_LEN] = {0};
      if (osal_nv_read_ex(ZCD_NV_EX_TCLK_TABLE, i, 0, sizeof(row), &row) != SUCCESS ||
          row.SeedShift >= SEC_KEY_LEN ||
          (!OsalPort_memcmp(row.extAddr, empty, Z_EXTADDR_LEN) &&
           row.txFrmCntr > UINT32_MAX - ((uint32_t)MAX_TCLK_FRAMECOUNTER_CHANGES + 1u)))
      {
        okay = FALSE;
      }
      memset(&row, 0, sizeof(row));
      if (!okay) break;
    }
  }
  if (!okay || b1_nv_runtime_hold_active())
  {
    b1_security_runtime_hold_latch();
    return FALSE;
  }
  b1_sec_existing_network = TRUE; /* Successful complete preflight only. */
  return TRUE;
}

/* Read-only cached attestation: only a completed restored-network security
 * preflight may set this bit; late backend HOLD always revokes it. Never
 * recompute or create NV records inside an asynchronous ZDO state callback. */
int b1_sec_restored_network_validated(void)
{
  return b1_sec_existing_network && !b1_nv_runtime_hold_active();
}

static uint8_t b1_sec_write_checked(uint16_t table, uint16_t index,
                                    uint16_t len, void *value)
{
  uint8_t verify[sizeof(APSME_TCLinkKeyNVEntry_t) + sizeof(APSME_ApsLinkKeyNVEntry_t)] = {0};
  uint8_t okay = FALSE;
  if (!b1_nv_runtime_hold_active() && len <= sizeof(verify) &&
      osal_nv_write_ex(table, index, len, value) == SUCCESS &&
      osal_nv_read_ex(table, index, 0, len, verify) == SUCCESS &&
      OsalPort_memcmp(value, verify, len)) okay = TRUE;
  memset(verify, 0, sizeof(verify));
  if (!okay) b1_security_runtime_hold_latch();
  return okay;
}
'''

RESTORE_APS = r'''static void ZDSecMgrRestoreFromNV( void )
{
  nvDeviceListHdr_t hdr = {0};
  uint8_t tc[Z_EXTADDR_LEN] = {0};
  uint16_t x;
  if (b1_nv_runtime_hold_active()) return;
  if (ZDSecMgrEntries == NULL ||
      osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE, 0, sizeof(hdr), &hdr) != SUCCESS ||
      hdr.numRecs > gZDSECMGR_ENTRY_MAX ||
      osal_nv_read(ZCD_NV_TRUSTCENTER_ADDR, 0, sizeof(tc), tc) != SUCCESS)
  {
    b1_security_runtime_hold_latch();
    return;
  }
  for (x = 0; hdr.numRecs != 0 && x < gZDSECMGR_ENTRY_MAX; ++x)
  {
    ZDSecMgrEntry_t entry = {0};
    APSME_ApsLinkKeyNVEntry_t key = {0};
    uint8_t zero[SEC_KEY_LEN] = {0};
    if (osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE,
        (uint16_t)(sizeof(hdr) + x * sizeof(entry)), sizeof(entry), &entry) != SUCCESS)
    {
      b1_security_runtime_hold_latch();
      return;
    }
    if (entry.ami == INVALID_NODE_ADDR) continue;
    if (entry.keyNvId >= gZDSECMGR_ENTRY_MAX ||
        osal_nv_read_ex(ZCD_NV_EX_APS_KEY_DATA_TABLE, entry.keyNvId, 0,
                       sizeof(key), &key) != SUCCESS ||
        OsalPort_memcmp(key.key, zero, SEC_KEY_LEN) ||
        key.txFrmCntr > UINT32_MAX - ((uint32_t)MAX_APS_FRAMECOUNTER_CHANGES + 1u))
    {
      memset(&key, 0, sizeof(key));
      b1_security_runtime_hold_latch();
      return;
    }
    key.txFrmCntr += (uint32_t)MAX_APS_FRAMECOUNTER_CHANGES + 1u;
    if (!b1_sec_write_checked(ZCD_NV_EX_APS_KEY_DATA_TABLE, entry.keyNvId,
                              sizeof(key), &key))
    {
      memset(&key, 0, sizeof(key));
      return;
    }
    /* Publish only the exact persisted/read-back row and index. */
    ZDSecMgrEntries[x] = entry;
    ApsLinkKeyRAMEntry[entry.keyNvId].txFrmCntr = key.txFrmCntr;
    ApsLinkKeyRAMEntry[entry.keyNvId].rxFrmCntr = key.rxFrmCntr;
    memset(&key, 0, sizeof(key));
  }
  OsalPort_memcpy(zgApsTrustCenterAddr, tc, sizeof(tc));
}'''

TCLK_INIT = r'''void APSME_TCLinkKeyInit(uint8_t setDefault)
{
  uint16_t i;
  uint8_t empty[Z_EXTADDR_LEN] = {0};
  if (b1_nv_runtime_hold_active()) return;
  if (b1_sec_existing_network && setDefault)
  {
    b1_security_runtime_hold_latch();
    return; /* A startup option cannot clear restored-network security. */
  }
  for (i = 0; i < gZDSECMGR_TC_DEVICE_MAX; ++i)
  {
    APSME_TCLinkKeyNVEntry_t row = {0};
    row.keyAttributes = ZG_DEFAULT_KEY;
    if (!b1_sec_existing_network)
    {
      uint8_t status = osal_nv_item_init_ex(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row);
      if (status == NV_ITEM_UNINIT && !b1_nv_runtime_hold_active()) continue;
      if (status != SUCCESS)
      {
        b1_security_runtime_hold_latch();
        return;
      }
    }
    if (!setDefault)
    {
      if (osal_nv_read_ex(ZCD_NV_EX_TCLK_TABLE, i, 0, sizeof(row), &row) != SUCCESS ||
          row.SeedShift >= SEC_KEY_LEN)
      {
        b1_security_runtime_hold_latch();
        return;
      }
      if (!OsalPort_memcmp(row.extAddr, empty, Z_EXTADDR_LEN))
      {
        if (row.txFrmCntr > UINT32_MAX - ((uint32_t)MAX_TCLK_FRAMECOUNTER_CHANGES + 1u))
        {
          b1_security_runtime_hold_latch();
          return;
        }
        row.txFrmCntr += (uint32_t)MAX_TCLK_FRAMECOUNTER_CHANGES + 1u;
      }
      else continue; /* An unused optional slot needs no persistence write. */
    }
    if (!b1_sec_write_checked(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row)) return;
    TCLinkKeyRAMEntry[i].txFrmCntr = row.txFrmCntr;
    TCLinkKeyRAMEntry[i].rxFrmCntr = row.rxFrmCntr;
    TCLinkKeyRAMEntry[i].entryUsed = !OsalPort_memcmp(row.extAddr, empty, Z_EXTADDR_LEN);
    memset(&row, 0, sizeof(row));
  }
  if (setDefault && !b1_nv_runtime_hold_active()) APSME_EraseICEntry(NULL);
}'''


def checkpoint(name, row_type, ram, table, count):
    return f'''void {name}(void)
{{
  uint16_t i;
  if (b1_nv_runtime_hold_active()) return;
  for (i = 0; i < {count}; ++i)
  {{
    {row_type} row = {{0}};
    if (!{ram}[i].pendingFlag) continue;
    if (osal_nv_read_ex({table}, i, 0, sizeof(row), &row) != SUCCESS ||
        {ram}[i].txFrmCntr < row.txFrmCntr ||
        {ram}[i].rxFrmCntr < row.rxFrmCntr)
    {{
      memset(&row, 0, sizeof(row));
      b1_security_runtime_hold_latch();
      return;
    }}
    row.txFrmCntr = {ram}[i].txFrmCntr;
    row.rxFrmCntr = {ram}[i].rxFrmCntr;
    if (!b1_sec_write_checked({table}, i, sizeof(row), &row))
    {{
      memset(&row, 0, sizeof(row));
      return;
    }}
    {ram}[i].pendingFlag = FALSE;
    memset(&row, 0, sizeof(row));
  }}
}}'''


def patch(source: str) -> str:
    source = replace_once(source, '#include "zcomdef.h"', '#include "zcomdef.h"\n'
        '#include <stdint.h>\n'
        'extern int b1_nv_runtime_hold_active(void);\n'
        'extern int b1_nv_existing_header_candidate(void);\n'
        'extern void b1_security_runtime_hold_latch(void);\n'
        'static uint8_t b1_sec_existing_network;\n'
        'static uint8_t b1_sec_write_checked(uint16_t, uint16_t, uint16_t, void *);',
        'security support declarations')
    replacements = [
        ('static void ZDSecMgrRestoreFromNV( void )', RESTORE_APS),
        ('void APSME_TCLinkKeyInit(uint8_t setDefault)', TCLK_INIT),
        ('void ZDSecMgrSaveApsLinkKey(void)', checkpoint('ZDSecMgrSaveApsLinkKey',
         'APSME_ApsLinkKeyNVEntry_t', 'ApsLinkKeyRAMEntry', 'ZCD_NV_EX_APS_KEY_DATA_TABLE', 'gZDSECMGR_ENTRY_MAX')),
        ('void ZDSecMgrSaveTCLinkKey(void)', checkpoint('ZDSecMgrSaveTCLinkKey',
         'APSME_TCLinkKeyNVEntry_t', 'TCLinkKeyRAMEntry', 'ZCD_NV_EX_TCLK_TABLE', 'gZDSECMGR_TC_DEVICE_MAX')),
    ]
    for signature, replacement in replacements:
        source = replace_once(source, extract_function(source, signature), replacement, signature)
    # TI's original ZDSecMgrEntryInit() silently returns on a failed
    # security-table allocation. The existing ZDSecMgrInit() HOLD check
    # cannot catch that failure unless the callee latches it first.
    entry_sig = 'void ZDSecMgrEntryInit(uint8_t state)'
    entry_body = extract_function(source, entry_sig)
    secured_entry = replace_once(
        entry_body,
        '    if ((ZDSecMgrEntries = OsalPort_malloc(sizeof(ZDSecMgrEntry_t) * gZDSECMGR_ENTRY_MAX)) == NULL)\n'
        '    {\n'
        '      return;\n'
        '    }',
        '    if ((ZDSecMgrEntries = OsalPort_malloc(sizeof(ZDSecMgrEntry_t) * gZDSECMGR_ENTRY_MAX)) == NULL)\n'
        '    {\n'
        '      b1_security_runtime_hold_latch(); /* no uninitialized security table */\n'
        '      return;\n'
        '    }', 'security table allocation must HOLD')
    source = replace_once(source, entry_body, secured_entry,
                          'ZDSecMgrEntryInit allocation failure HOLD')
    # On restored network, validation has checked the mandatory records. Do
    # not run item_init loops that silently create absent zero key/counter rows.
    for signature in ('void ZDSecMgrNwkKeyInit(uint8_t setDefault)',
                      'void ZDSecMgrApsLinkKeyInit(uint8_t setDefault)'):
        source = replace_once(source, signature + '\n{', signature + '\n{\n'
            '  if (b1_nv_runtime_hold_active() || b1_sec_existing_network) return;', signature + ' no replacement')
    source = replace_once(source, 'void ZDSecMgrGenerateSeed(uint8_t SetDefault)\n{',
        'void ZDSecMgrGenerateSeed(uint8_t SetDefault)\n{\n'
        '  if (b1_nv_runtime_hold_active() || b1_sec_existing_network) return;', 'seed no replacement')
    source = replace_once(source, 'uint8_t ZDSecMgrInitNV(void)\n{',
        'uint8_t ZDSecMgrInitNV(void)\n{\n'
        '  if (b1_nv_runtime_hold_active()) return NV_OPER_FAILED;\n'
        '  if (b1_sec_existing_network) return SUCCESS;', 'APS table no replacement')
    source = replace_once(source, '  ZDSecMgrEntryInit(state);',
        '  ZDSecMgrEntryInit(state);\n'
        '  if (b1_nv_runtime_hold_active()) return;', 'security init stop after restore fault')
    source = replace_once(source,
        'ZStatus_t APSME_TCLinkKeyLoad( uint16_t dstAddr, SSP_Info_t* si )\n{',
        'ZStatus_t APSME_TCLinkKeyLoad( uint16_t dstAddr, SSP_Info_t* si )\n{\n'
        '  if (b1_nv_runtime_hold_active()) return ZSecNoKey;', 'runtime TCLK hold')
    load_signature = 'ZStatus_t APSME_TCLinkKeyLoad( uint16_t dstAddr, SSP_Info_t* si )'
    load = extract_function(source, load_signature)
    initialized_load = replace_once(load,
        '  APSME_TCLinkKeyNVEntry_t TCLKDevEntry;',
        '  APSME_TCLinkKeyNVEntry_t TCLKDevEntry = {0};',
        'new TCLK row fully initialized')
    source = replace_once(source, load, initialized_load, 'initialize TCLK load scratch')
    source = replace_once(source, '    if(entryIndex != 0xFFFF)\n    {\n      uint16_t i = entryIndex;',
        '    if(entryIndex != 0xFFFF)\n    {\n'
        '      if (entryIndex >= gZDSECMGR_TC_DEVICE_MAX)\n'
        '      {\n'
        '        b1_security_runtime_hold_latch();\n'
        '        return ZSecNoKey;\n'
        '      }\n'
        '      uint16_t i = entryIndex;', 'runtime TCLK bounds')
    source = replace_once(source,
        '        osal_nv_write_ex(ZCD_NV_EX_TCLK_TABLE, entryIndex,\n'
        '                         sizeof(APSME_TCLinkKeyNVEntry_t),\n'
        '                         &TCLKDevEntry);',
        '        if (!b1_sec_write_checked(ZCD_NV_EX_TCLK_TABLE, entryIndex,\n'
        '                                  sizeof(TCLKDevEntry), &TCLKDevEntry))\n'
        '          return ZSecNoKey;', 'new TCLK persist before publish')
    source = replace_once(source, '      // update link key related fields\n'
        '      si->keyID   = SEC_KEYID_LINK;',
        '      if (TCLinkKeyRAMEntry[i].txFrmCntr == UINT32_MAX)\n'
        '      {\n'
        '        b1_security_runtime_hold_latch();\n'
        '        return ZSecNoKey;\n'
        '      }\n'
        '      // update link key related fields\n'
        '      si->keyID   = SEC_KEYID_LINK;', 'TCLK no wrap before security publish')
    # The ZDO NV event may be delayed; do not issue beyond the reboot counter
    # reservation. Reject before publishing ANY partial SSP_Info security
    # fields, leaving the event loop (not outgoing encryption) to write NV.
    source = replace_once(source,
        '      if(found)\n      {\n        switch(TCLKDevEntry.keyAttributes)',
        '      if(found)\n      {\n'
        '        if (TCLinkKeyRAMEntry[i].pendingFlag)\n'
        '        {\n'
        '          OsalPort_setEvent(ZDAppTaskID, ZDO_TCLK_FRAMECOUNTER_CHANGE);\n'
        '          return ZSecNoKey; /* retry only after verified NV commit */\n'
        '        }\n'
        '        switch(TCLKDevEntry.keyAttributes)',
        'TCLK checkpoint before SSP_Info publication')
    source = replace_once(source,
        '          default:\n            //This should not happen\n          break;',
        '          default:\n'
        '            b1_security_runtime_hold_latch();\n'
        '            return ZSecNoKey;', 'runtime TCLK unknown key attributes')
    source = replace_once(source,
        '    osal_nv_read(ZCD_NV_TCLK_SEED,0,SEC_KEY_LEN,tempKey);',
        '    if (b1_nv_runtime_hold_active() ||\n'
        '        osal_nv_read(ZCD_NV_TCLK_SEED,0,SEC_KEY_LEN,tempKey) != SUCCESS)\n'
        '    {\n'
        '      memset(tempKey, 0, sizeof(tempKey));\n'
        '      memset(key, 0, SEC_KEY_LEN);\n'
        '      b1_security_runtime_hold_latch();\n'
        '      return;\n'
        '    }', 'seed read failure before key derive')
    # Receive-side replay tracking must never wrap its high-water counter.
    # This path is implemented in TI C (unlike the opaque APS/NWK SSP library),
    # and was not protected by the prior transmit-only TCLK load guard.
    sync_sig = 'ZStatus_t APSME_TCLinkKeySync( uint16_t srcAddr, SSP_Info_t* si )'
    sync = extract_function(source, sync_sig)
    sync = replace_once(sync, '{\n  APSME_TCLinkKeyNVEntry_t  TCLKDevEntry;',
        '{\n  if (b1_nv_runtime_hold_active()) return ZSecNoKey;\n'
        '  APSME_TCLinkKeyNVEntry_t  TCLKDevEntry = {0};',
        'TCLK receive rejects security HOLD before lookup')
    sync = replace_once(sync,
        '  if(entryFound && (entryIndex != 0xFFFF))\n  {',
        '  if (entryIndex != 0xFFFF && entryIndex >= gZDSECMGR_TC_DEVICE_MAX)\n'
        '  {\n'
        '    b1_security_runtime_hold_latch();\n'
        '    return ZSecNoKey;\n'
        '  }\n'
        '  if(entryFound && (entryIndex != 0xFFFF))\n  {',
        'TCLK receive bounds before RAM index')
    sync = replace_once(sync,
        '        if ( si->frmCntr >= *tclkRxFrmCntr )',
        '        /* UINT32_MAX + 1 would reset the replay high-water mark.\n'
        '         * Treat a peer at exhaustion as an old frame, not a local NV fault. */\n'
        '        if ( si->frmCntr != UINT32_MAX && si->frmCntr >= *tclkRxFrmCntr )',
        'TCLK receive counter must not wrap')
    sync = replace_once(sync,
        '      default:\n        //This should not happen\n      break;',
        '      default:\n'
        '        b1_security_runtime_hold_latch();\n'
        '        return ZSecNoKey;',
        'TCLK unknown receive attributes fail closed')
    source = replace_once(source, extract_function(source, sync_sig), sync,
                          'replace guarded TCLK receive sync')
    # The APS SSP implementation is linked from TI's library, but its key
    # retrieval boundary is in this source unit. Do not hand out an APS key
    # while the corresponding counter reservation is awaiting durable NV.
    # This covers callers of this function, not cached/ROM-only key paths.
    read_sig = 'ZStatus_t ZDSecMgrReadKeyFromNv(uint16_t keyNvSection, uint16_t keyNvId, void *keyinfo)'
    read = extract_function(source, read_sig)
    read = replace_once(read,
        '{\n  if (keyNvSection == ZCD_NV_EX_LEGACY)',
        '{\n'
        '  if (b1_nv_runtime_hold_active()) return NV_OPER_FAILED;\n'
        '  if (keyNvSection == ZCD_NV_EX_APS_KEY_DATA_TABLE)\n'
        '  {\n'
        '    if (keyNvId >= gZDSECMGR_ENTRY_MAX)\n'
        '    {\n'
        '      b1_security_runtime_hold_latch();\n'
        '      return NV_OPER_FAILED;\n'
        '    }\n'
        '    if (ApsLinkKeyRAMEntry[keyNvId].pendingFlag)\n'
        '    {\n'
        '      OsalPort_setEvent(ZDAppTaskID, ZDO_APS_FRAMECOUNTER_CHANGE);\n'
        '      return NV_OPER_FAILED; /* retry after checked NV persistence */\n'
        '    }\n'
        '  }\n'
        '  if (keyNvSection == ZCD_NV_EX_LEGACY)',
        'APS key read bound to durable reservation')
    source = replace_once(source, extract_function(source, read_sig), read,
                          'replace guarded APS key read')
    return source + '\n' + SUPPORT


def patch_zglobals(source: str) -> str:
    source = replace_once(source, '#include "zcomdef.h"', '#include "zcomdef.h"\n'
        'extern int b1_sec_validate_restored(void);', 'early security precheck declaration')
    return replace_once(source, 'uint8_t zgInit( void )\n{',
        'uint8_t zgInit( void )\n{\n'
        '  if (!b1_sec_validate_restored()) return NV_OPER_FAILED;',
        'security precheck before first item initialization')


def patch_osal_nv(source: str) -> str:
    return replace_once(source,
        'if ( pZStackCfg->nvFps.readItem( nvId, ndx, len, buf ) == NVINTF_FAILURE )',
        'if ( pZStackCfg->nvFps.readItem( nvId, ndx, len, buf ) != NVINTF_SUCCESS )',
        'OSAL read propagates every failed status including NOTFOUND')


def patch_startup(source: str) -> str:
    source = replace_once(source, 'static void stackTaskFxn(UArg a0, UArg a1)\n{',
        'static void stackTaskFxn(UArg a0, UArg a1)\n{\n'
        '    /* Task context: pZStackCfg is bound; NV mutex is initialized.\n'
        '     * Reject incoherent restored state before MAC/stack init. */\n'
        '    if (!b1_sec_validate_restored()) return;', 'pre-MAC security gate')
    source = replace_once(source, '    MT_TaskInit( tmpServiceId );',
        '    if (tmpServiceId >= 15u)\n'
        '    {\n'
        '        b1_management_transport_failed(0x65u);\n'
        '        return;\n'
        '    }\n'
        '    MT_TaskInit( tmpServiceId );\n'
        '    b1_management_note_mt_registered();', 'MT actual registration lifecycle')
    # Header and helper symbols compile within the existing donor source unit.
    return replace_once(source,
        '#include "zstackconfig.h"', '#include "zstackconfig.h"\n'
        'extern int b1_sec_validate_restored(void);\n'
        'extern void b1_management_transport_failed(uint8_t reason);\n'
        'extern void b1_management_note_mt_registered(void);', 'startup security declarations')
