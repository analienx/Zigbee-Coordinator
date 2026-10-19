"""Pinned TI ZNP host APS key API correction (source-only B1 overlay).

The original ZNP API wrote indexed APS keys as *legacy* OSAL NV item IDs,
silently accepted counter rollback, and matched the wrong TCLK address.
Do not let a live host command bypass the durable security-manager setter.
"""

from patch_zdapp import extract_function, replace_once


GET = r'''static bool processSecApsLinkKeyGetReq( uint8_t srcServiceTaskId, void *pMsg )
{
  zstackmsg_secApsLinkKeyGetReq_t *pPtr =
      (zstackmsg_secApsLinkKeyGetReq_t *)pMsg;
  uint16_t i;
  if (pPtr == NULL) return TRUE;
  pPtr->hdr.status = zstack_ZStatusValues_ZFailure;
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


def patch(source: str) -> str:
    source = replace_once(source, '#include "zd_sec_mgr.h"',
                          '#include "zd_sec_mgr.h"\n#include <stdint.h>\n'
                          'extern int b1_nv_runtime_hold_active(void);\n'
                          'extern void b1_security_runtime_hold_latch(void);',
                          'host API security HOLD declarations')
    for signature, replacement in (
        ('static bool processSecApsLinkKeyGetReq( uint8_t srcServiceTaskId, void *pMsg )', GET),
        ('static bool processSecApsLinkKeySetReq( uint8_t srcServiceTaskId, void *pMsg )', SET),
    ):
        source = replace_once(source, extract_function(source, signature),
                              replacement, 'host API ' + signature)
    return source
