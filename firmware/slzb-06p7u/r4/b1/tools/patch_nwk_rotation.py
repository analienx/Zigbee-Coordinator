"""Fail-closed coordinator NWK rotation boundary for pinned TI 8.33.

The source-distributed ZDO wrappers do not expose SSP_UpdateNwkKey or
SSP_SwitchNwkKey's durability / counter-epoch behavior. A send, two unrelated
NV writes and a void SSP call cannot form an atomic two-phase transition.
Until the pinned opaque SSP implementation can be audited and a durable journal
integrated, deny coordinator rotation at BOTH public and internal boundaries.
This intentionally does not pretend to implement operational key rotation.
"""

from patch_zdapp import extract_function, replace_once


UPDATE = r'''ZStatus_t ZDSecMgrUpdateNwkKey( uint8_t* key, uint8_t keySeqNum, uint16_t dstAddr )
{
  /* R4-R04: the stock implementation queues a Transport Key and THEN calls
   * void SSP_UpdateNwkKey even when transport failed. Neither that opaque
   * caller nor ZDApp_NVUpdate commits an atomic key+counter epoch. There is
   * no safe rollback after a network peer has received a new key. Do not
   * publish an update, replace the alternate slot, or touch NV here. */
  (void)key;
  (void)keySeqNum;
  (void)dstAddr;
  return ZFailure;
}'''


SWITCH = r'''ZStatus_t ZDSecMgrSwitchNwkKey( uint8_t keySeqNum, uint16_t dstAddr )
{
  /* R4-R04: the stock implementation sets zgSwitchCoordKey and schedules
   * NV persistence even after a failed APSME_SwitchKeyReq. An unjournaled
   * switch may reuse the old key's frame-counter epoch after a power cut.
   * Never signal RF, mutate coordinator flags, or write NV in this state. */
  (void)keySeqNum;
  (void)dstAddr;
  return ZFailure;
}'''


HOST_UPDATE = r'''static bool processSecNwkKeyUpdateReq( uint8_t srcServiceTaskId, void *pMsg )
{
  zstackmsg_secNwkKeyUpdateReq_t *pPtr = (zstackmsg_secNwkKeyUpdateReq_t *)pMsg;
  (void)srcServiceTaskId;
  if (pPtr == NULL) return TRUE;
  pPtr->hdr.status = zstack_ZStatusValues_ZFailure;
  if (pPtr->pReq == NULL)
    pPtr->hdr.status = zstack_ZStatusValues_ZInvalidParameter;
  else if (ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE)
    pPtr->hdr.status = zstack_ZStatusValues_ZUnsupportedMode;
  /* Do not read an unverified alternate key or invoke opaque SSP. */
  return TRUE;
}'''


HOST_SWITCH = r'''static bool processSecNwkKeySwitchReq( uint8_t srcServiceTaskId, void *pMsg )
{
  zstackmsg_secNwkKeySwitchReq_t *pPtr = (zstackmsg_secNwkKeySwitchReq_t *)pMsg;
  (void)srcServiceTaskId;
  if (pPtr == NULL) return TRUE;
  pPtr->hdr.status = zstack_ZStatusValues_ZFailure;
  if (pPtr->pReq == NULL)
    pPtr->hdr.status = zstack_ZStatusValues_ZInvalidParameter;
  else if (ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE)
    pPtr->hdr.status = zstack_ZStatusValues_ZUnsupportedMode;
  /* No queued Switch Key request or coordinator-key index publication. */
  return TRUE;
}'''


def patch_security(source: str) -> str:
    source = replace_once(source, 'static uint8_t b1_sec_existing_network;',
                          'extern int b1_management_network_ready(void);\n'
                          'int b1_sec_restored_network_validated(void);\n'
                          'static uint8_t b1_sec_existing_network;',
                          'declarations for coordinator key-retirement preflight')
    for signature, guarded in (
        ('ZStatus_t ZDSecMgrUpdateNwkKey( uint8_t* key, uint8_t keySeqNum, uint16_t dstAddr )', UPDATE),
        ('ZStatus_t ZDSecMgrSwitchNwkKey( uint8_t keySeqNum, uint16_t dstAddr )', SWITCH),
    ):
        source = replace_once(source, extract_function(source, signature), guarded,
                              'no opaque SSP coordinator key transition: ' + signature)

    # A coordinator is itself the trust center. A received Transport Key or
    # Switch Key must not change its active key via the ordinary joining-device
    # handler. Do not latch HOLD on unauthenticated network noise (DoS), and
    # preserve the non-NWK-key delivery and joining-role implementation.
    source = replace_once(
        source,
        'void ZDSecMgrTransportKeyInd( ZDO_TransportKeyInd_t* ind )\n{',
        'void ZDSecMgrTransportKeyInd( ZDO_TransportKeyInd_t* ind )\n{\n'
        '  if (ind == NULL) { b1_security_runtime_hold_latch(); return; }\n'
        '  if (b1_nv_runtime_hold_active()) return;\n'
        '  if (ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE &&\n'
        '      (ind->keyType == KEY_TYPE_NWK || ind->keyType == 6))\n'
        '    return; /* Only joining nodes accept inbound NWK key updates. */',
        'coordinator unsolicited NWK transport denied before TC address mutation')
    source = replace_once(
        source,
        'void ZDSecMgrSwitchKeyInd( ZDO_SwitchKeyInd_t* ind )\n{',
        'void ZDSecMgrSwitchKeyInd( ZDO_SwitchKeyInd_t* ind )\n{\n'
        '  if (ind == NULL) { b1_security_runtime_hold_latch(); return; }\n'
        '  if (b1_nv_runtime_hold_active()) return;\n'
        '  if (ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE)\n'
        '    return; /* Never trust an unjournaled coordinator key switch. */',
        'coordinator incoming key switch denied before SSP')
    # Stock recovery calls this void function when a state restore is not
    # selected. It blindly zeroes all THREE NV key/counter records. Refuse
    # irreversible rekey/epoch retirement on a formed coordinator. On virgin
    # stores the keys are already zero; avoid needless NV writes entirely.
    source = replace_once(
        source,
        'void ZDSecMgrClearNVKeyValues(void)\n{',
        'void ZDSecMgrClearNVKeyValues(void)\n{\n'
        '  if (ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE)\n'
        '  {\n'
        '    nwkActiveKeyItems committed = {0};\n'
        '    nwkKeyDesc active = {0}, alternate = {0};\n'
        '    uint8_t zeroKey[SEC_KEY_LEN] = {0};\n'
        '    uint16_t keyLen = osal_nv_item_len(ZCD_NV_NWKKEY);\n'
        '    uint16_t activeLen = osal_nv_item_len(ZCD_NV_NWK_ACTIVE_KEY_INFO);\n'
        '    uint16_t altLen = osal_nv_item_len(ZCD_NV_NWK_ALTERN_KEY_INFO);\n'
        '    if (b1_nv_runtime_hold_active()) return;\n'
        '    if (b1_sec_restored_network_validated() ||\n'
        '        b1_management_network_ready() || _NIB.nwkKeyLoaded)\n'
        '      goto unsafe_clear;\n'
        '    if (keyLen == 0u && activeLen == 0u && altLen == 0u) return;\n'
        '    if (keyLen != sizeof(committed) || activeLen != sizeof(active) ||\n'
        '        altLen != sizeof(alternate) ||\n'
        '        osal_nv_read(ZCD_NV_NWKKEY, 0, sizeof(committed), &committed) != SUCCESS ||\n'
        '        osal_nv_read(ZCD_NV_NWK_ACTIVE_KEY_INFO, 0, sizeof(active), &active) != SUCCESS ||\n'
        '        osal_nv_read(ZCD_NV_NWK_ALTERN_KEY_INFO, 0, sizeof(alternate), &alternate) != SUCCESS ||\n'
        '        committed.frameCounter != 0u || committed.active.keySeqNum != 0u ||\n'
        '        active.keySeqNum != 0u || alternate.keySeqNum != 0u ||\n'
        '        !OsalPort_memcmp(committed.active.key, zeroKey, SEC_KEY_LEN) ||\n'
        '        !OsalPort_memcmp(active.key, zeroKey, SEC_KEY_LEN) ||\n'
        '        !OsalPort_memcmp(alternate.key, zeroKey, SEC_KEY_LEN))\n'
        '      goto unsafe_clear;\n'
        '    /* Virgin records have nothing to reset. Do not mutate NV. */\n'
        '    return;\n'
        'unsafe_clear:\n'
        '    b1_security_runtime_hold_latch();\n'
        '    return;\n'
        '  }',
        'coordinator key/counter retirement refuses nonvirgin NV')
    return source


def patch_host_api(source: str) -> str:
    for signature, guarded in (
        ('static bool processSecNwkKeyUpdateReq( uint8_t srcServiceTaskId, void *pMsg )', HOST_UPDATE),
        ('static bool processSecNwkKeySwitchReq( uint8_t srcServiceTaskId, void *pMsg )', HOST_SWITCH),
    ):
        source = replace_once(source, extract_function(source, signature), guarded,
                              'host opaque NWK transition disabled: ' + signature)
    return source
