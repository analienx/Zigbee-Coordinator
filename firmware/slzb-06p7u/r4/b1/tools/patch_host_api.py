"""Pinned TI ZNP host APS/NWK key API correction (source-only B1 overlay).

The original ZNP API wrote indexed APS keys as *legacy* OSAL NV item IDs,
silently accepted counter rollback, and matched the wrong TCLK address.
Do not let a live host command bypass the durable security-manager setter.
"""

from patch_zdapp import extract_function, replace_once


NWK_SET = r'''static bool processSecNwkKeySetReq( uint8_t srcServiceTaskId, void *pMsg )
{
  zstackmsg_secNwkKeySetReq_t *pPtr = (zstackmsg_secNwkKeySetReq_t *)pMsg;
  nwkKeyDesc active = {0};
  nwkKeyDesc alternate = {0};
  nwkKeyDesc proposed = {0};
  nwkKeyDesc verify = {0};
  nwkActiveKeyItems logical = {0};
  uint8_t zeroKey[SEC_KEY_LEN] = {0};
  uint16_t target;
  nwkKeyDesc *old;
  if (pPtr == NULL) return TRUE;
  pPtr->hdr.status = zstack_ZStatusValues_ZFailure;
  if (pPtr->pReq == NULL)
  {
    pPtr->hdr.status = zstack_ZStatusValues_ZInvalidParameter;
    return TRUE;
  }
  if (b1_nv_runtime_hold_active() || b1_sec_restored_network_validated() ||
      b1_management_network_ready()) return TRUE;
  /* B1-only TI builds still expose a void RNG API. Require the caller's
   * explicit, already generated initial key until checked B3 entropy is
   * available end-to-end; never accept an unchecked random-key fallback. */
  if (!pPtr->pReq->has_key)
  {
    pPtr->hdr.status = zstack_ZStatusValues_ZInvalidParameter;
    return TRUE;
  }

  /* This legacy setter may only populate a wholly virgin security store.
   * Existing formed-network keys must go through a durable staged epoch
   * transition; direct active/alternate replacement can resurrect an old
   * key with reset counters and repeat the same CCM nonce. */
  if (osal_nv_item_len(ZCD_NV_NWK_ACTIVE_KEY_INFO) != sizeof(active) ||
      osal_nv_item_len(ZCD_NV_NWK_ALTERN_KEY_INFO) != sizeof(alternate) ||
      osal_nv_item_len(ZCD_NV_NWKKEY) != sizeof(logical) ||
      osal_nv_read(ZCD_NV_NWK_ACTIVE_KEY_INFO, 0,
                   sizeof(active), &active) != ZSUCCESS ||
      osal_nv_read(ZCD_NV_NWK_ALTERN_KEY_INFO, 0,
                   sizeof(alternate), &alternate) != ZSUCCESS ||
      osal_nv_read(ZCD_NV_NWKKEY, 0,
                   sizeof(logical), &logical) != ZSUCCESS)
  {
    b1_security_runtime_hold_latch();
    goto done;
  }
  target = pPtr->pReq->activeKey ? ZCD_NV_NWK_ACTIVE_KEY_INFO :
                                   ZCD_NV_NWK_ALTERN_KEY_INFO;
  old = pPtr->pReq->activeKey ? &active : &alternate;
  proposed.keySeqNum = pPtr->pReq->seqNum;
  OsalPort_memcpy(proposed.key, pPtr->pReq->key, SEC_KEY_LEN);
  if (OsalPort_memcmp(proposed.key, zeroKey, SEC_KEY_LEN) ||
      OsalPort_isBufSet(proposed.key, 0xFF, SEC_KEY_LEN))
  {
    pPtr->hdr.status = zstack_ZStatusValues_ZInvalidParameter;
    goto done;
  }
  if (old->keySeqNum == proposed.keySeqNum &&
      OsalPort_memcmp(old->key, proposed.key, SEC_KEY_LEN))
  {
    pPtr->hdr.status = zstack_ZStatusValues_ZSuccess; /* No NV mutation. */
    goto done;
  }
  if (!OsalPort_memcmp(active.key, zeroKey, SEC_KEY_LEN) ||
      !OsalPort_memcmp(alternate.key, zeroKey, SEC_KEY_LEN) ||
      !OsalPort_memcmp(logical.active.key, zeroKey, SEC_KEY_LEN) ||
      active.keySeqNum != 0u || alternate.keySeqNum != 0u ||
      logical.active.keySeqNum != 0u || logical.frameCounter != 0u)
    goto done; /* Already keyed: no direct host mutation, even across slots. */

  if (osal_nv_write(target, sizeof(proposed), &proposed) != ZSUCCESS ||
      osal_nv_read(target, 0, sizeof(verify), &verify) != ZSUCCESS ||
      !OsalPort_memcmp(&proposed, &verify, sizeof(proposed)))
  {
    b1_security_runtime_hold_latch();
    goto done;
  }
  pPtr->hdr.status = zstack_ZStatusValues_ZSuccess;
done:
  memset(&active, 0, sizeof(active));
  memset(&alternate, 0, sizeof(alternate));
  memset(&logical, 0, sizeof(logical));
  memset(&proposed, 0, sizeof(proposed));
  memset(&verify, 0, sizeof(verify));
  return TRUE;
}'''


NWK_GET = r'''static bool processSecNwkKeyGetReq( uint8_t srcServiceTaskId, void *pMsg )
{
  zstackmsg_secNwkKeyGetReq_t *pPtr = (zstackmsg_secNwkKeyGetReq_t *)pMsg;
  nwkKeyDesc row = {0};
  uint8_t zeroKey[SEC_KEY_LEN] = {0};
  uint16_t target;
  if (pPtr == NULL) return TRUE;
  pPtr->hdr.status = zstack_ZStatusValues_ZFailure;
  if (pPtr->pRsp != NULL) memset(pPtr->pRsp, 0, sizeof(*pPtr->pRsp));
  if (pPtr->pReq == NULL || pPtr->pRsp == NULL)
  {
    pPtr->hdr.status = zstack_ZStatusValues_ZInvalidParameter;
    return TRUE;
  }
  if (b1_nv_runtime_hold_active()) return TRUE;
  target = pPtr->pReq->activeKey ? ZCD_NV_NWK_ACTIVE_KEY_INFO :
                                   ZCD_NV_NWK_ALTERN_KEY_INFO;
  if (osal_nv_item_len(target) != sizeof(row) ||
      osal_nv_read(target, 0, sizeof(row), &row) != ZSUCCESS)
  {
    b1_security_runtime_hold_latch();
    return TRUE;
  }
  if (!OsalPort_memcmp(row.key, zeroKey, SEC_KEY_LEN) &&
      !OsalPort_isBufSet(row.key, 0xFF, SEC_KEY_LEN))
  {
    pPtr->pRsp->activeKey = pPtr->pReq->activeKey;
    pPtr->pRsp->seqNum = row.keySeqNum;
    OsalPort_memcpy(pPtr->pRsp->key, row.key, SEC_KEY_LEN);
    pPtr->hdr.status = zstack_ZStatusValues_ZSuccess;
  }
  memset(&row, 0, sizeof(row));
  return TRUE;
}'''


GET = r'''static bool processSecApsLinkKeyGetReq( uint8_t srcServiceTaskId, void *pMsg )
{
  zstackmsg_secApsLinkKeyGetReq_t *pPtr =
      (zstackmsg_secApsLinkKeyGetReq_t *)pMsg;
  uint16_t i;
  if (pPtr == NULL) return TRUE;
  pPtr->hdr.status = zstack_ZStatusValues_ZFailure;
  /* Clear any available response even if the request pointer is malformed. */
  if (pPtr->pRsp != NULL)
    memset(pPtr->pRsp, 0, sizeof(*pPtr->pRsp));
  if (pPtr->pReq == NULL || pPtr->pRsp == NULL)
  {
    pPtr->hdr.status = zstack_ZStatusValues_ZInvalidParameter;
    return TRUE;
  }
  if (b1_nv_runtime_hold_active()) return TRUE;
  pPtr->pRsp->tcLinkKey = pPtr->pReq->tcLinkKey;
  OsalPort_memcpy(pPtr->pRsp->ieeeAddr, pPtr->pReq->ieeeAddr, Z_EXTADDR_LEN);
  if (pPtr->pReq->tcLinkKey)
  {
    for (i = 0; i < gZDSECMGR_TC_DEVICE_MAX; ++i)
    {
      APSME_TCLinkKeyNVEntry_t row = {0};
      if (osal_nv_read_ex(ZCD_NV_EX_TCLK_TABLE, i, 0,
                          sizeof(row), &row) != ZSUCCESS)
      {
        b1_security_runtime_hold_latch();
        return TRUE;
      }
      if (!OsalPort_memcmp(pPtr->pReq->ieeeAddr, row.extAddr, Z_EXTADDR_LEN))
        continue;
      if (TCLinkKeyRAMEntry[i].pendingFlag) return TRUE;
      pPtr->pRsp->rxFrmCntr = row.rxFrmCntr;
      pPtr->pRsp->txFrmCntr = row.txFrmCntr;
      pPtr->hdr.status = zstack_ZStatusValues_ZSuccess;
      return TRUE;
    }
  }
  else
  {
    ZDSecMgrEntry_t *entry = NULL;
    APSME_ApsLinkKeyNVEntry_t row = {0};
    if (ZDSecMgrEntryLookupExt(pPtr->pReq->ieeeAddr, &entry) != ZSuccess ||
        entry == NULL || entry->keyNvId >= gZDSECMGR_ENTRY_MAX)
      return TRUE;
    i = entry->keyNvId;
    if (ApsLinkKeyRAMEntry[i].pendingFlag) return TRUE;
    if (osal_nv_read_ex(ZCD_NV_EX_APS_KEY_DATA_TABLE, i, 0,
                        sizeof(row), &row) != ZSUCCESS)
    {
      b1_security_runtime_hold_latch();
      return TRUE;
    }
    pPtr->pRsp->rxFrmCntr = row.rxFrmCntr;
    pPtr->pRsp->txFrmCntr = row.txFrmCntr;
    OsalPort_memcpy(pPtr->pRsp->key, row.key, SEC_KEY_LEN);
    memset(&row, 0, sizeof(row));
    pPtr->hdr.status = zstack_ZStatusValues_ZSuccess;
  }
  return TRUE;
}'''


SET = r'''static bool processSecApsLinkKeySetReq( uint8_t srcServiceTaskId, void *pMsg )
{
  zstackmsg_secApsLinkKeySetReq_t *pPtr =
      (zstackmsg_secApsLinkKeySetReq_t *)pMsg;
  uint16_t i;
  if (pPtr == NULL) return TRUE;
  pPtr->hdr.status = zstack_ZStatusValues_ZFailure;
  if (pPtr->pReq == NULL)
  {
    pPtr->hdr.status = zstack_ZStatusValues_ZInvalidParameter;
    return TRUE;
  }
  if (b1_nv_runtime_hold_active()) return TRUE;
  if (pPtr->pReq->tcLinkKey)
  {
    /* No implicit new TCLK slot/key installation through a counter API.
     * Only an exact existing address can have its floor advanced. */
    for (i = 0; i < gZDSECMGR_TC_DEVICE_MAX; ++i)
    {
      APSME_TCLinkKeyNVEntry_t row = {0};
      APSME_TCLinkKeyNVEntry_t verify = {0};
      if (osal_nv_read_ex(ZCD_NV_EX_TCLK_TABLE, i, 0,
                          sizeof(row), &row) != ZSUCCESS)
      {
        b1_security_runtime_hold_latch();
        return TRUE;
      }
      if (!OsalPort_memcmp(pPtr->pReq->ieeeAddr, row.extAddr, Z_EXTADDR_LEN))
        continue;
      if (TCLinkKeyRAMEntry[i].pendingFlag) return TRUE;
      if (row.txFrmCntr < TCLinkKeyRAMEntry[i].txFrmCntr)
        row.txFrmCntr = TCLinkKeyRAMEntry[i].txFrmCntr;
      if (row.rxFrmCntr < TCLinkKeyRAMEntry[i].rxFrmCntr)
        row.rxFrmCntr = TCLinkKeyRAMEntry[i].rxFrmCntr;
      if (row.txFrmCntr < pPtr->pReq->txFrmCntr)
        row.txFrmCntr = pPtr->pReq->txFrmCntr;
      if (row.rxFrmCntr < pPtr->pReq->rxFrmCntr)
        row.rxFrmCntr = pPtr->pReq->rxFrmCntr;
      if (row.txFrmCntr > UINT32_MAX - ((uint32_t)MAX_TCLK_FRAMECOUNTER_CHANGES + 1u))
      {
        b1_security_runtime_hold_latch();
        return TRUE;
      }
      if (osal_nv_write_ex(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row) != ZSUCCESS ||
          osal_nv_read_ex(ZCD_NV_EX_TCLK_TABLE, i, 0,
                          sizeof(verify), &verify) != ZSUCCESS ||
          !OsalPort_memcmp(&row, &verify, sizeof(row)))
      {
        b1_security_runtime_hold_latch();
        return TRUE;
      }
      TCLinkKeyRAMEntry[i].txFrmCntr = row.txFrmCntr;
      TCLinkKeyRAMEntry[i].rxFrmCntr = row.rxFrmCntr;
      pPtr->hdr.status = zstack_ZStatusValues_ZSuccess;
      return TRUE;
    }
  }
  else
  {
    ZDSecMgrEntry_t *entry = NULL;
    /* Host-supplied raw counters cannot roll a live key backwards. A
     * nonzero counter import requires a separate offline restore protocol. */
    if (pPtr->pReq->txFrmCntr != 0u || pPtr->pReq->rxFrmCntr != 0u)
    {
      pPtr->hdr.status = zstack_ZStatusValues_ZInvalidParameter;
      return TRUE;
    }
    if (ZDSecMgrEntryLookupExt(pPtr->pReq->ieeeAddr, &entry) == ZSuccess)
    {
      pPtr->hdr.status = (zstack_ZStatusValues)
          APSME_LinkKeySet(pPtr->pReq->ieeeAddr, pPtr->pReq->key);
    }
    else
    {
      pPtr->hdr.status = (zstack_ZStatusValues)
          ZDSecMgrAddLinkKey(pPtr->pReq->shortAddr,
                             pPtr->pReq->ieeeAddr, pPtr->pReq->key);
    }
  }
  return TRUE;
}'''


REMOVE = r'''static bool processSecApsLinkKeyRemoveReq( uint8_t srcServiceTaskId, void *pMsg )
{
  zstackmsg_secApsLinkKeyRemoveReq_t *pPtr =
      (zstackmsg_secApsLinkKeyRemoveReq_t *)pMsg;
  ZDSecMgrEntry_t *entry = NULL;
  if (pPtr == NULL) return TRUE;
  pPtr->hdr.status = zstack_ZStatusValues_ZFailure;
  if (pPtr->pReq == NULL)
  {
    pPtr->hdr.status = zstack_ZStatusValues_ZInvalidParameter;
    return TRUE;
  }
  if (b1_nv_runtime_hold_active()) return TRUE;
  if (pPtr->pReq->tcLinkKey)
  {
    /* A live host cannot erase a TCLK peer/counter binding. The upstream
     * handler inverted the peer address match and zeroed the whole row,
     * permitting wrong-peer deletion and later same-key nonce reuse.
     * Safe deprovision requires an offline key/seed epoch transition. */
    return TRUE;
  }
  if (ZDSecMgrEntryLookupExt(pPtr->pReq->ieeeAddr, &entry) != ZSuccess ||
      entry == NULL || entry->keyNvId >= gZDSECMGR_ENTRY_MAX ||
      ApsLinkKeyRAMEntry[entry->keyNvId].pendingFlag)
    return TRUE;
  pPtr->hdr.status = (zstack_ZStatusValues)
      ZDSecMgrDeviceRemoveByExtAddr(pPtr->pReq->ieeeAddr);
  if (b1_nv_runtime_hold_active())
    pPtr->hdr.status = zstack_ZStatusValues_ZFailure;
  return TRUE;
}'''


def patch(source: str) -> str:
    source = replace_once(source, '#include "zd_sec_mgr.h"',
                          '#include "zd_sec_mgr.h"\n#include <stdint.h>\n'
                          'extern int b1_nv_runtime_hold_active(void);\n'
                          'extern void b1_security_runtime_hold_latch(void);\n'
                          'extern int b1_sec_restored_network_validated(void);\n'
                          'extern int b1_management_network_ready(void);',
                          'host API security HOLD declarations')
    for signature, replacement in (
        ('static bool processSecNwkKeySetReq( uint8_t srcServiceTaskId, void *pMsg )', NWK_SET),
        ('static bool processSecNwkKeyGetReq( uint8_t srcServiceTaskId, void *pMsg )', NWK_GET),
        ('static bool processSecApsLinkKeyGetReq( uint8_t srcServiceTaskId, void *pMsg )', GET),
        ('static bool processSecApsLinkKeySetReq( uint8_t srcServiceTaskId, void *pMsg )', SET),
        ('static bool processSecApsLinkKeyRemoveReq( uint8_t srcServiceTaskId, void *pMsg )', REMOVE),
    ):
        source = replace_once(source, extract_function(source, signature),
                              replacement, 'host API ' + signature)
    return source
