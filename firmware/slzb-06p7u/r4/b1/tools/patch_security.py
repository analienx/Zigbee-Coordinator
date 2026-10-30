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

/* Exactly one live TC slot may own a peer's security counter/key epoch.
 * Duplicate IEEE identities in different NV rows can select different
 * persisted counter floors for the same peer after reboot. Keep only row
 * indices in bounded preflight BSS (1024 bytes), not keys or IEEE values;
 * compare the actual eight-byte identities on every hash collision. */
#define B1_TCLK_PEER_BUCKETS 512u
static uint16_t b1_tclk_peer_slots[B1_TCLK_PEER_BUCKETS];

static uint16_t b1_tclk_peer_bucket(const uint8_t *addr)
{
  uint32_t hash = 2166136261u;
  uint8_t j;
  for (j = 0u; j < Z_EXTADDR_LEN; ++j)
    hash = (hash ^ addr[j]) * 16777619u;
  return (uint16_t)(hash & (B1_TCLK_PEER_BUCKETS - 1u));
}

static uint8_t b1_tclk_unique_peer(uint16_t index, const uint8_t *addr)
{
  uint16_t bucket = b1_tclk_peer_bucket(addr);
  uint16_t probes;
  for (probes = 0u; probes < B1_TCLK_PEER_BUCKETS; ++probes)
  {
    uint16_t previous = b1_tclk_peer_slots[bucket];
    if (previous == 0u)
    {
      b1_tclk_peer_slots[bucket] = (uint16_t)(index + 1u);
      return TRUE;
    }
    else
    {
      APSME_TCLinkKeyNVEntry_t prior = {0};
      uint8_t same;
      if (osal_nv_read_ex(ZCD_NV_EX_TCLK_TABLE, (uint16_t)(previous - 1u), 0,
                          sizeof(prior), &prior) != SUCCESS)
      {
        memset(&prior, 0, sizeof(prior));
        return FALSE;
      }
      same = OsalPort_memcmp(prior.extAddr, addr, Z_EXTADDR_LEN);
      memset(&prior, 0, sizeof(prior));
      if (same) return FALSE;
    }
    bucket = (uint16_t)((bucket + 1u) & (B1_TCLK_PEER_BUCKETS - 1u));
  }
  return FALSE; /* unexpected saturation: never accept ambiguous identity */
}

/* B1: read-only security checks precede zgInit's default item creation. */
int b1_sec_validate_restored(void)
{
  uint8_t onNetwork = FALSE;
  uint8_t zeroKey[SEC_KEY_LEN] = {0};
  uint8_t seed[SEC_KEY_LEN] = {0};
  uint8_t trustCenter[Z_EXTADDR_LEN] = {0};
  uint8_t coordinatorExt[Z_EXTADDR_LEN] = {0};
  uint8_t zeroAddr[Z_EXTADDR_LEN] = {0};
  uint8_t ffAddr[Z_EXTADDR_LEN];
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
  memset(ffAddr, 0xFF, sizeof(ffAddr));
  /* A verified restored coordinator must have a valid local EUI64. This
   * constrains the stock persisted TC=zero representation to its own IEEE. */
  if (osal_nv_read(ZCD_NV_EXTADDR, 0, sizeof(coordinatorExt),
                   coordinatorExt) != SUCCESS ||
      OsalPort_memcmp(coordinatorExt, zeroAddr, sizeof(coordinatorExt)) ||
      OsalPort_memcmp(coordinatorExt, ffAddr, sizeof(coordinatorExt)))
  {
    b1_security_runtime_hold_latch();
    return FALSE;
  }
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
      /* Stock restored coordinator may persist TC=zero. Runtime APS TC is
       * assigned from NLME_GetExtAddr() in TI ZDSecMgrInit(). Never accept
       * an unrelated nonzero TC, and never rewrite persistent TC here. */
      (!OsalPort_memcmp(trustCenter, zeroAddr, sizeof(trustCenter)) &&
       !OsalPort_memcmp(trustCenter, coordinatorExt, sizeof(trustCenter))) ||
      osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE, 0, sizeof(hdr), &hdr) != SUCCESS ||
      hdr.numRecs > gZDSECMGR_ENTRY_MAX)
  {
    okay = FALSE;
  }
  memset(&nwk, 0, sizeof(nwk));
  memset(&active, 0, sizeof(active));
  memset(seed, 0, sizeof(seed));
  memset(trustCenter, 0, sizeof(trustCenter));
  memset(coordinatorExt, 0, sizeof(coordinatorExt));
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
    uint8_t allFF[Z_EXTADDR_LEN];
    memset(allFF, 0xFF, sizeof(allFF));
    if (gZDSECMGR_TC_DEVICE_MAX >= B1_TCLK_PEER_BUCKETS)
    {
      b1_security_runtime_hold_latch();
      return FALSE; /* no silently truncated TC peer-identity index */
    }
    memset(b1_tclk_peer_slots, 0, sizeof(b1_tclk_peer_slots));
    for (i = 0; i < gZDSECMGR_TC_DEVICE_MAX; ++i)
    {
      APSME_TCLinkKeyNVEntry_t row = {0};
      uint8_t empty[Z_EXTADDR_LEN] = {0};
      if (osal_nv_read_ex(ZCD_NV_EX_TCLK_TABLE, i, 0, sizeof(row), &row) != SUCCESS ||
          row.SeedShift >= SEC_KEY_LEN ||
          (!OsalPort_memcmp(row.extAddr, empty, Z_EXTADDR_LEN) &&
           (OsalPort_memcmp(row.extAddr, allFF, Z_EXTADDR_LEN) ||
            row.txFrmCntr > UINT32_MAX - ((uint32_t)MAX_TCLK_FRAMECOUNTER_CHANGES + 1u) ||
            !b1_tclk_unique_peer(i, row.extAddr))))
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

# Device removal is a two-item transaction: make the APS table reference
# disappear atomically first, then scrub its extended key row. On a crash
# between commits the row is merely orphaned; the restored table never points
# at an erased key. No legacy NV item number is derived from an extended row
# index. Any failure latches HOLD before modifying the live RAM entry.
APS_REMOVE_NV = r'''static uint8_t ZDSecMgrUpdateNV( uint16_t index )
{
  uint16_t len = (uint16_t)(sizeof(nvDeviceListHdr_t) +
                             gZDSECMGR_ENTRY_MAX * sizeof(ZDSecMgrEntry_t));
  uint8_t *table = NULL;
  uint8_t *verify = NULL;
  nvDeviceListHdr_t hdr = {0};
  ZDSecMgrEntry_t current = {0};
  ZDSecMgrEntry_t retired = {0};
  uint16_t offset;
  uint8_t okay = FALSE;
  if (b1_nv_runtime_hold_active() || ZDSecMgrEntries == NULL ||
      index >= gZDSECMGR_ENTRY_MAX)
  {
    b1_security_runtime_hold_latch();
    return FALSE;
  }
  table = (uint8_t *)OsalPort_malloc(len);
  verify = (uint8_t *)OsalPort_malloc(len);
  if (table != NULL && verify != NULL &&
      osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE, 0, len, table) == SUCCESS)
  {
    OsalPort_memcpy(&hdr, table, sizeof(hdr));
    offset = (uint16_t)(sizeof(hdr) + index * sizeof(current));
    OsalPort_memcpy(&current, table + offset, sizeof(current));
    if (hdr.numRecs > 0 && hdr.numRecs <= gZDSECMGR_ENTRY_MAX &&
        current.ami != INVALID_NODE_ADDR &&
        current.ami == ZDSecMgrEntries[index].ami &&
        current.keyNvId == ZDSecMgrEntries[index].keyNvId)
    {
      --hdr.numRecs;
      retired = current;
      retired.ami = INVALID_NODE_ADDR;
      retired.keyNvId = SEC_NO_KEY_NV_ID;
      retired.authenticateOption = ZDSecMgr_Not_Authenticated;
      OsalPort_memcpy(table, &hdr, sizeof(hdr));
      OsalPort_memcpy(table + offset, &retired, sizeof(retired));
      if (osal_nv_write(ZCD_NV_APS_LINK_KEY_TABLE, len, table) == SUCCESS &&
          osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE, 0, len, verify) == SUCCESS &&
          OsalPort_memcmp(table, verify, len)) okay = TRUE;
    }
  }
  if (table != NULL) { memset(table, 0, len); OsalPort_free(table); }
  if (verify != NULL) { memset(verify, 0, len); OsalPort_free(verify); }
  if (!okay) b1_security_runtime_hold_latch();
  return okay;
}'''

APS_REMOVE_ENTRY = r'''void ZDSecMgrEntryFree( ZDSecMgrEntry_t* entry )
{
  uint16_t index;
  uint16_t keyIndex;
  APSME_ApsLinkKeyNVEntry_t empty = {0};
  if (b1_nv_runtime_hold_active()) return;
  if (entry == NULL || ZDSecMgrEntries == NULL ||
      ZDSecMgrEntryLookupAMIGetIndex(entry->ami, &index) != ZSuccess ||
      index >= gZDSECMGR_ENTRY_MAX || &ZDSecMgrEntries[index] != entry)
  {
    b1_security_runtime_hold_latch();
    return;
  }
  keyIndex = entry->keyNvId;
  if (keyIndex != SEC_NO_KEY_NV_ID && keyIndex >= gZDSECMGR_ENTRY_MAX)
  {
    b1_security_runtime_hold_latch();
    return;
  }
#if defined ( NV_RESTORE )
  /* One checked full-table commit includes BOTH the retired entry and the
   * decremented count. Never expose a dangling reference to an erased row. */
  if (!ZDSecMgrUpdateNV(index)) return;
#endif
  if (keyIndex != SEC_NO_KEY_NV_ID)
  {
    if (!b1_sec_write_checked(ZCD_NV_EX_APS_KEY_DATA_TABLE, keyIndex,
                              sizeof(empty), &empty)) return;
    memset(&ApsLinkKeyRAMEntry[keyIndex], 0, sizeof(ApsLinkKeyRAMEntry[keyIndex]));
  }
  entry->keyNvId = SEC_NO_KEY_NV_ID;
  entry->ami = INVALID_NODE_ADDR;
  entry->authenticateOption = ZDSecMgr_Not_Authenticated;
}'''

# The stock APS setter silently resets counters even for an identical key,
# creating same-key CCM nonce reuse on repeated Transport-Key delivery. It
# also publishes RAM and the key-table index when the NV write has failed.
# Preserve the existing row index and monotonic counters for the same key;
# for a genuinely different key, publish zero counters only after a verified
# durable write. A pending asynchronous checkpoint is backpressure, not an
# excuse to reuse the old on-flash high-water mark.
APS_LINK_KEY_SET = r'''ZStatus_t ZDSecMgrLinkKeySet( uint8_t* extAddr, uint8_t* key )
{
  ZDSecMgrEntry_t *entry = NULL;
  APSME_ApsLinkKeyNVEntry_t row = {0};
  uint8_t zero[SEC_KEY_LEN] = {0};
  uint16_t index = 0;
  uint16_t keyIndex;
  uint16_t i;
  uint8_t identical;
  if (extAddr == NULL || key == NULL || OsalPort_memcmp(key, zero, SEC_KEY_LEN))
    return ZFailure;
  if (b1_nv_runtime_hold_active()) return ZFailure;
  if (ZDSecMgrEntryLookupExtGetIndex(extAddr, &entry, &index) != ZSuccess ||
      entry == NULL || index >= gZDSECMGR_ENTRY_MAX)
    return ZFailure;
  keyIndex = entry->keyNvId == SEC_NO_KEY_NV_ID ? index : entry->keyNvId;
  if (keyIndex >= gZDSECMGR_ENTRY_MAX)
  {
    b1_security_runtime_hold_latch();
    return ZFailure;
  }
  /* A live entry must never overwrite another entry's security row. */
  for (i = 0; i < gZDSECMGR_ENTRY_MAX; ++i)
  {
    if (i != index && ZDSecMgrEntries[i].ami != INVALID_NODE_ADDR &&
        ZDSecMgrEntries[i].keyNvId == keyIndex)
    {
      b1_security_runtime_hold_latch();
      return ZFailure;
    }
  }
  if (ApsLinkKeyRAMEntry[keyIndex].pendingFlag)
  {
    OsalPort_setEvent(ZDAppTaskID, ZDO_APS_FRAMECOUNTER_CHANGE);
    return ZFailure;
  }
  if (osal_nv_read_ex(ZCD_NV_EX_APS_KEY_DATA_TABLE, keyIndex, 0,
                      sizeof(row), &row) != SUCCESS)
  {
    b1_security_runtime_hold_latch();
    return ZFailure;
  }
  identical = OsalPort_memcmp(row.key, key, SEC_KEY_LEN);
  if (identical)
  {
    /* Never reset a counter under the same key, including after a reboot.
     * RAM may be ahead of the durable reservation between checkpoints. */
    if (row.txFrmCntr < ApsLinkKeyRAMEntry[keyIndex].txFrmCntr)
      row.txFrmCntr = ApsLinkKeyRAMEntry[keyIndex].txFrmCntr;
    if (row.rxFrmCntr < ApsLinkKeyRAMEntry[keyIndex].rxFrmCntr)
      row.rxFrmCntr = ApsLinkKeyRAMEntry[keyIndex].rxFrmCntr;
    if (row.txFrmCntr > UINT32_MAX - ((uint32_t)MAX_APS_FRAMECOUNTER_CHANGES + 1u))
    {
      memset(&row, 0, sizeof(row));
      b1_security_runtime_hold_latch();
      return ZFailure;
    }
  }
  else
  {
    OsalPort_memcpy(row.key, key, SEC_KEY_LEN);
    row.txFrmCntr = 0;
    row.rxFrmCntr = 0;
  }
  if (!b1_sec_write_checked(ZCD_NV_EX_APS_KEY_DATA_TABLE, keyIndex,
                            sizeof(row), &row))
  {
    memset(&row, 0, sizeof(row));
    return ZFailure;
  }
  entry->keyNvId = keyIndex;
  ApsLinkKeyRAMEntry[keyIndex].txFrmCntr = row.txFrmCntr;
  ApsLinkKeyRAMEntry[keyIndex].rxFrmCntr = row.rxFrmCntr;
  ApsLinkKeyRAMEntry[keyIndex].pendingFlag = FALSE;
  memset(&row, 0, sizeof(row));
  return ZSuccess;
}'''

# Both stock installation callers ignore the LinkKeySet result, and the
# stock ZDSecMgrWriteNV silently drops a failed table write. Return failure
# upstream and latch HOLD if either a key or its index metadata fails to
# reach durable, read-back-verified NV.
APS_TABLE_WRITE = r'''static uint8_t ZDSecMgrWriteNV( void )
{
  uint16_t len = (uint16_t)(sizeof(nvDeviceListHdr_t) +
                            gZDSECMGR_ENTRY_MAX * sizeof(ZDSecMgrEntry_t));
  uint8_t *table = NULL;
  uint8_t *verify = NULL;
  nvDeviceListHdr_t hdr = {0};
  uint16_t i;
  uint8_t okay = FALSE;
  if (b1_nv_runtime_hold_active() || ZDSecMgrEntries == NULL ||
      osal_nv_item_len(ZCD_NV_APS_LINK_KEY_TABLE) != len)
    goto done;
  table = (uint8_t *)OsalPort_malloc(len);
  verify = (uint8_t *)OsalPort_malloc(len);
  if (table == NULL || verify == NULL) goto done;
  for (i = 0; i < gZDSECMGR_ENTRY_MAX; ++i)
  {
    ZDSecMgrEntry_t entry = ZDSecMgrEntries[i];
    if (entry.ami != INVALID_NODE_ADDR)
    {
      if (entry.keyNvId >= gZDSECMGR_ENTRY_MAX) goto done;
      ++hdr.numRecs;
    }
    OsalPort_memcpy(table + sizeof(hdr) + i * sizeof(entry), &entry, sizeof(entry));
  }
  OsalPort_memcpy(table, &hdr, sizeof(hdr));
  if (osal_nv_write(ZCD_NV_APS_LINK_KEY_TABLE, len, table) == SUCCESS &&
      osal_nv_read(ZCD_NV_APS_LINK_KEY_TABLE, 0, len, verify) == SUCCESS &&
      OsalPort_memcmp(table, verify, len)) okay = TRUE;
done:
  if (table != NULL) { memset(table, 0, len); OsalPort_free(table); }
  if (verify != NULL) { memset(verify, 0, len); OsalPort_free(verify); }
  if (!okay) b1_security_runtime_hold_latch();
  return okay;
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
        ('void ZDSecMgrEntryFree( ZDSecMgrEntry_t* entry )', APS_REMOVE_ENTRY),
        ('static void ZDSecMgrUpdateNV( uint16_t index )', APS_REMOVE_NV),
        ('ZStatus_t ZDSecMgrLinkKeySet( uint8_t* extAddr, uint8_t* key )', APS_LINK_KEY_SET),
        ('static void ZDSecMgrWriteNV( void )', APS_TABLE_WRITE),
        ('void ZDSecMgrSaveApsLinkKey(void)', checkpoint('ZDSecMgrSaveApsLinkKey',
         'APSME_ApsLinkKeyNVEntry_t', 'ApsLinkKeyRAMEntry', 'ZCD_NV_EX_APS_KEY_DATA_TABLE', 'gZDSECMGR_ENTRY_MAX')),
        ('void ZDSecMgrSaveTCLinkKey(void)', checkpoint('ZDSecMgrSaveTCLinkKey',
         'APSME_TCLinkKeyNVEntry_t', 'TCLinkKeyRAMEntry', 'ZCD_NV_EX_TCLK_TABLE', 'gZDSECMGR_TC_DEVICE_MAX')),
    ]
    for signature, replacement in replacements:
        source = replace_once(source, extract_function(source, signature), replacement, signature)
    source = replace_once(source,
        'static void ZDSecMgrUpdateNV( uint16_t index );',
        'static uint8_t ZDSecMgrUpdateNV( uint16_t index );',
        'checked APS retirement declaration')
    source = replace_once(source,
        'static void ZDSecMgrWriteNV(void);',
        'static uint8_t ZDSecMgrWriteNV(void);',
        'checked APS table writer declaration')
    source = replace_once(source,
        '    ZDSecMgrLinkKeySet( ind->srcExtAddr, ind->key );',
        '    if (ZDSecMgrLinkKeySet(ind->srcExtAddr, ind->key) != ZSuccess) return;',
        'transport-key delivery stops on undurable key')
    source = replace_once(source,
        '  APSME_LinkKeySet( extAddr, key );',
        '  if (APSME_LinkKeySet(extAddr, key) != ZSuccess) return ZFailure;',
        'application-key add propagates NV failure')
    source = replace_once(source,
        '    ZDSecMgrWriteNV();  // Write the control record for the new established link key to NV.',
        '    if (!ZDSecMgrWriteNV()) return; /* missing index must not be published */',
        'transport-key metadata durability')
    source = replace_once(source,
        '  ZDSecMgrWriteNV();  // Write the new established link key to NV.',
        '  if (!ZDSecMgrWriteNV()) return ZFailure;',
        'application-key metadata durability')
    source = replace_once(source,
        '    ZDSecMgrEntryFree( pEntry );',
        '    ZDSecMgrEntryFree( pEntry );\n'
        '    if (b1_nv_runtime_hold_active()) return ZFailure;',
        'device removal must not report success on security HOLD')
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
        'extern int b1_sec_validate_restored(void);\n'
        'extern int b1_nv_runtime_hold_active(void);\n'
        'extern void b1_nv_runtime_hold_latch(void);', 'early security precheck declaration')
    source = replace_once(source, 'uint8_t zgInit( void )\n{',
        'uint8_t zgInit( void )\n{\n'
        '  if (!b1_sec_validate_restored()) return NV_OPER_FAILED;',
        'security precheck before first item initialization')
    original = extract_function(source, 'void zgInitItems( uint8_t setDefault )')
    changed = replace_once(original, '\n{\n', '\n{\n'
        '  if (b1_nv_runtime_hold_active()) return;\n',
        'do not initialize globals after HOLD')
    changed = replace_once(changed,
        '    zgItemInit( zgItemTable[i].id, zgItemTable[i].len, zgItemTable[i].buf, setDefault  );',
        '    uint8_t b1_item_status = zgItemInit( zgItemTable[i].id, zgItemTable[i].len, zgItemTable[i].buf, setDefault  );\n'
        '    if ((b1_item_status != ZSUCCESS && b1_item_status != NV_ITEM_UNINIT) ||\n'
        '        b1_nv_runtime_hold_active())\n'
        '    {\n'
        '      b1_nv_runtime_hold_latch();\n'
        '      return; /* do not publish host callback readiness after failed init */\n'
        '    }', 'preserve initialization failure before runtime callback setup')
    changed = changed[:-1] + (
        '#if defined(ZNP_NPI) && !defined(MT_TASK)\n'
        '  /* Retained R4 uses direct ZDO responses expected by Herdsman.\n'
        '   * Override only this RAM callback switch, after successful item init.\n'
        '   * Preserve NV ZCD_NV_ZDO_DIRECT_CB and every network/security record. */\n'
        '  zgZdoDirectCB = TRUE;\n'
        '#endif\n}')
    return replace_once(source, original, changed, 'ZNP RAM-only direct ZDO callback')


def patch_osal_nv(source: str) -> str:
    from patch_nv_capacity import patch as patch_nv_capacity
    source = replace_once(source,
        'if ( pZStackCfg->nvFps.readItem( nvId, ndx, len, buf ) == NVINTF_FAILURE )',
        'if ( pZStackCfg->nvFps.readItem( nvId, ndx, len, buf ) != NVINTF_SUCCESS )',
        'OSAL read propagates every failed status including NOTFOUND')
    return patch_nv_capacity(source)


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
    # V48: the donor starts each scan at index 0. On retained startup the
    # continuously-ready NWK service (index 2 in the real NPI-enabled build)
    # exhausted thousands of wakeups while ZDApp's INIT bit remained pending.
    # Rotate *selection* among the original service handlers; do not dispatch
    # INIT directly or bypass any ZDApp security/startup gate. One handler is
    # still called per scheduler wake and the donor's critical sections remain.
    source = replace_once(source,
        "    while(1)\n    {\n      /* Block here until TIRTOS task gets an event */",
        "    uint8_t b1_next_service = 0u;\n"
        "    while(1)\n    {\n      /* Block here until TIRTOS task gets an event */",
        "B1 fair dispatch cursor lifetime")
    source = replace_once(source,
        "      uint8_t idx = 0;\n\n"
        "     // copy the priority-based round-robin scheduler from OSAL\n"
        "      do {\n"
        "        if (*(pTasksEvents[idx]))  // Task is highest priority that is ready.\n"
        "        {\n"
        "          break;\n"
        "        }\n"
        "      } while (++idx < zstackTasksCnt);",
        "      uint8_t idx = b1_next_service;\n"
        "      uint8_t b1_scanned = 0u;\n"
        "      while (b1_scanned < zstackTasksCnt)\n"
        "      {\n"
        "        if (*(pTasksEvents[idx])) break;\n"
        "        idx++;\n"
        "        if (idx >= zstackTasksCnt) idx = 0u;\n"
        "        b1_scanned++;\n"
        "      }\n"
        "      if (b1_scanned == zstackTasksCnt) idx = zstackTasksCnt;",
        "B1 fair bounded wraparound service scan")
    source = replace_once(source,
        "      if (idx < zstackTasksCnt)\n      {\n        uint32_t events, key;",
        "      if (idx < zstackTasksCnt)\n      {\n"
        "        b1_next_service = (uint8_t)(idx + 1u);\n"
        "        if (b1_next_service >= zstackTasksCnt) b1_next_service = 0u;\n"
        "        uint32_t events, key;",
        "B1 fair selector advancement before handler")
    # TI 8.33 dispatcher consumes one semaphore credit before selecting a
    # highest-ready service. Returned bits are ORed back, but the donor
    # forgot to restore any credit. A two-bit event can strand the second
    # bit forever with no further external activity. Preserve concurrent
    # OsalPort posts by retaining the donor's same critical-section merge.
    source = replace_once(source,
        "        *(pTasksEvents[idx]) |= events;  // Add back unprocessed events to the current task.\n"
        "        OsalPort_leaveCS(key);",
        "        *(pTasksEvents[idx]) |= events;  // Add back unprocessed events to the current task.\n"
        "        OsalPort_leaveCS(key);\n"
        "        if (events != 0u) Semaphore_post(stackSemHandle);",
        "dispatch returned-bits semaphore credit")
    source = replace_once(source,
        "    pTasksEvents[idx] = &zdAppServiceEvents;\n    idx++;",
        "    pTasksEvents[idx] = &zdAppServiceEvents;\n"
        "    b1_evidence_bind_pending(&zdAppServiceEvents);\n"
        "    idx++;", "bind one original ZDApp event-word owner")
    source = replace_once(source,
        "        events = (zstackTasksArr[idx])( 0U, events );",
        "        b1_evidence_dispatch(idx, events);\n"
        "        events = (zstackTasksArr[idx])( 0U, events );\n"
        "        b1_evidence_dispatch_end(events);",
        "true stack dispatch input and returned masks")
    # Header and helper symbols compile within the existing donor source unit.
    return replace_once(source,
        '#include "zstackconfig.h"', '#include "zstackconfig.h"\n'
        '#include "b1_management.h"\n'
        'extern int b1_sec_validate_restored(void);\n'
        'extern void b1_management_transport_failed(uint8_t reason);\n'
        'extern void b1_management_note_mt_registered(void);', 'startup security declarations')
