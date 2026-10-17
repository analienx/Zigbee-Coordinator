#!/usr/bin/env python3
"""Tiny B3 overlays on EXACT TI SDK8.33 bytes, never on installed radios.

Use only in a disposable hosted checkout of pinned TI SDK. Reject donor drift,
duplicate anchors, repeated application and broader writes.
"""
import argparse
import hashlib
import json
from pathlib import Path

PINNED_BLOBS = {
    "source/ti/zstack/osal/osal_nv.c": "65c7667475627989cbe2e3f5fdd46335b50eb660",
    "source/ti/common/nv/nvocmp.c": "01b2b0827d278c10c012b33e5791e53bc5662f10",
    "source/ti/zstack/stack/zdo/zd_sec_mgr.c": "65d7857cc9c62b75419807a8c0d03a62ec1a5574",
    "source/ti/zstack/stack/zdo/zd_sec_mgr.h": "b1ab5fcf490f77f95cd111a13581cb15d198d79c",
    "source/ti/zstack/stack/zdo/zd_app.c": "d67a7798a3e6a8681faddebf5e4b87b4b4c60421",
    "source/ti/zstack/stack/sys/zglobals.c": "0a1d7d2a61a88d1a6bb6e4bc5e359e71e1719024",
    "source/ti/zstack/stack/api/zstacktask.c": "d85758d2274097d2efe7c395e97e394f70fd352e",
}


def blob_id(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def one(source, before, after):
    if source.count(before) != 1:
        raise ValueError("B3 anchor absent/ambiguous: donor changed or overlay repeated")
    return source.replace(before, after, 1)


def osal_changes(source):
    source = one(source,
        "  uint8_t rtrn = SUCCESS;\n  uint8_t status;\n",
        "  uint8_t rtrn = NV_OPER_FAILED;\n  uint8_t status;\n")
    source = one(source,
        "if ( pZStackCfg && pZStackCfg->nvFps.createItem )",
        "if ( pZStackCfg && pZStackCfg->nvFps.createItem && pZStackCfg->nvFps.getItemLen )")
    source = one(source,
        "    }\n  }\n\n  // NV was created\n  return ( NV_ITEM_UNINIT );",
        "    }\n    return ( NV_ITEM_UNINIT );\n  }\n\n  // Missing backend is a failure, never a created record.\n  return ( NV_OPER_FAILED );")
    source = one(source,
        "if ( pZStackCfg->nvFps.createItem( nvId, len, buf ) == NVINTF_FAILURE )",
        "if ( pZStackCfg->nvFps.createItem( nvId, len, buf ) != NVINTF_SUCCESS )")
    source = one(source,
        "if ( pZStackCfg->nvFps.readItem( nvId, ndx, len, buf ) == NVINTF_FAILURE )",
        "if ( pZStackCfg->nvFps.readItem( nvId, ndx, len, buf ) != NVINTF_SUCCESS )")
    source = one(source,
        "  uint8_t ret = SUCCESS;\n\n  if ( pZStackCfg && pZStackCfg->nvFps.deleteItem )",
        "  uint8_t ret = NV_OPER_FAILED;\n\n  if ( pZStackCfg && pZStackCfg->nvFps.deleteItem )")
    source = one(source,
        "  if ( pZStackCfg && pZStackCfg->nvFps.deleteItem )\n  {\n    uint32_t nvLen = 0;",
        "  if ( pZStackCfg && pZStackCfg->nvFps.deleteItem && pZStackCfg->nvFps.getItemLen )\n  {\n    ret = SUCCESS;\n    uint32_t nvLen = 0;")
    source = one(source,
        "else if ( pZStackCfg->nvFps.deleteItem( nvId ) == NVINTF_FAILURE )",
        "else if ( pZStackCfg->nvFps.deleteItem( nvId ) != NVINTF_SUCCESS )")
    return source


def nvocmp_changes(source):
    before = ("        NVOCMP_nvsHandle = NVS_open(NVOCMP_NVS_INDEX, param);\n\n"
              "        // Get NV hardware attributes\n"
              "        NVS_getAttrs(NVOCMP_nvsHandle,&NVOCMP_nvsAttrs);")
    after = ("        NVOCMP_nvsHandle = NVS_open(NVOCMP_NVS_INDEX, param);\n"
             "        if (NVOCMP_nvsHandle == NULL)\n"
             "        {\n"
             "            NVOCMP_failF = NVINTF_FAILURE;\n"
             "            NVOCMP_EXCEPTION(pg, NVINTF_NOTREADY);\n"
             "            return(NVOCMP_failF);\n"
             "        }\n\n"
             "        // Get NV hardware attributes only after successful NVS_open\n"
             "        NVS_getAttrs(NVOCMP_nvsHandle,&NVOCMP_nvsAttrs);")
    source = one(source, before, after)
    prior = ("        // Confirm that the NVS region opened properly\n"
             "        if (NVOCMP_nvsHandle == NULL)\n"
             "        {\n"
             "            NVOCMP_failF = NVINTF_FAILURE;\n"
             "            NVOCMP_ASSERT(false,\"NVS HANDLE IS NULL\")\n"
             "            NVOCMP_EXCEPTION(pg, NVINTF_NOTREADY);\n"
             "            return(NVOCMP_failF);\n"
             "        }\n")
    source = one(source, prior, "")
    source = one(source,
        "        NVOCMP_nvHandle.nvSize = NVOCMP_nvsAttrs.regionSize/NVOCMP_nvsAttrs.sectorSize;\n"
        "        NVOCMP_nvHandle.nvSize = NVOCMP_nvHandle.nvSize > NVOCMP_NVPAGES ? NVOCMP_NVPAGES : NVOCMP_nvHandle.nvSize;\n"
        "        NVOCMP_size = NVOCMP_nvHandle.nvSize;\n\n"
        "        // Confirm NV region has expected characteristics\n"
        "        if (FLASH_PAGE_SIZE != NVOCMP_nvsAttrs.sectorSize ||\n"
        "                (NVOCMP_NVSIZE * FLASH_PAGE_SIZE > NVOCMP_nvsAttrs.regionSize))",
        "        // Validate exact page count BEFORE any division or flash scan.\n"
        "        // A bigger region is not proof that its format is compatible.\n"
        "        if (NVOCMP_nvsAttrs.sectorSize != FLASH_PAGE_SIZE ||\n"
        "            NVOCMP_nvsAttrs.regionSize != (uint32_t)NVOCMP_NVPAGES * FLASH_PAGE_SIZE)")
    source = one(source,
        "        // Initialize force compaction to false",
        "        NVOCMP_nvHandle.nvSize = NVOCMP_NVPAGES;\n"
        "        NVOCMP_size = NVOCMP_NVPAGES;\n\n"
        "        // Initialize force compaction to false")
    # All the modifications below run in the EXACT pinned original TI source.
    # Void NVOCMP_read formerly threw away NVS failure status. A sticky fatal
    # state plus caller-output wipe prevents fake success or mutating damaged NV.
    source = one(source,
        "static inline void NVOCMP_read(uint8_t pg, uint16_t off, uint8_t *pBuf, uint16_t len)\n"
        "{\n"
        "#ifndef NV_LINUX\n"
        "    NVS_read(NVOCMP_nvsHandle, NVOCMP_FLASHOFFSET(pg, off), (uint8_t *)pBuf, len);\n"
        "#else\n"
        "    NV_LINUX_read(pg, off, pBuf, len);\n"
        "#endif\n"
        "}",
        "static inline void NVOCMP_read(uint8_t pg, uint16_t off, uint8_t *pBuf, uint16_t len)\n"
        "{\n"
        "    int_fast16_t status;\n"
        "    if (NVOCMP_failF != NVINTF_SUCCESS || pg >= NVOCMP_NVPAGES ||\n"
        "        off > FLASH_PAGE_SIZE || len > FLASH_PAGE_SIZE - off || pBuf == NULL)\n"
        "    {\n"
        "        NVOCMP_failF = NVINTF_FAILURE;\n"
        "        NVOCMP_failW = NVINTF_FAILURE;\n"
        "        /* Do not memset with an untrusted corrupt size or page. */\n"
        "        if (pBuf != NULL && pg < NVOCMP_NVPAGES &&\n"
        "            off <= FLASH_PAGE_SIZE && len <= FLASH_PAGE_SIZE - off)\n"
        "            memset(pBuf, 0, len);\n"
        "        return;\n"
        "    }\n"
        "#ifndef NV_LINUX\n"
        "    status = NVS_read(NVOCMP_nvsHandle, NVOCMP_FLASHOFFSET(pg, off), (uint8_t *)pBuf, len);\n"
        "#else\n"
        "    status = NV_LINUX_read(pg, off, pBuf, len);\n"
        "#endif\n"
        "    if (status != 0)\n"
        "    {\n"
        "        memset(pBuf, 0, len);\n"
        "        NVOCMP_failF = NVINTF_FAILURE;\n"
        "        NVOCMP_failW = NVINTF_FAILURE;\n"
        "    }\n"
        "}")

    # A rejected data write MUST NOT be followed by a committed-looking
    # record header or an offset advance. This is a real TI NVOCMP defect
    # reproduced in the NV2/3/5 source-compiled crash harness.
    source = one(source,
        "            NVOCMP_failW = NVOCMP_write(dstPg, dstOff,\n"
        "                                        NVOCMP_itemBuffer, iLen);\n"
        "            // Advance to next location",
        "            NVOCMP_failW = NVOCMP_write(dstPg, dstOff,\n"
        "                                        NVOCMP_itemBuffer, iLen);\n"
        "            if (NVOCMP_failW != NVINTF_SUCCESS)\n"
        "            {\n"
        "                NVOCMP_failF = NVINTF_FAILURE;\n"
        "                return;\n"
        "            }\n"
        "            // Advance to next location")
    source = one(source,
        "            NVOCMP_failW = NVOCMP_write(dstPg, dstOff, pBuf, dLen);\n"
        "            // Write header\n"
        "            NVOCMP_failW |= NVOCMP_write(dstPg, hOfs, cHdr, NVOCMP_ITEMHDRLEN);",
        "            NVOCMP_failW = NVOCMP_write(dstPg, dstOff, pBuf, dLen);\n"
        "            if (NVOCMP_failW != NVINTF_SUCCESS)\n"
        "            {\n"
        "                NVOCMP_failF = NVINTF_FAILURE;\n"
        "                return;\n"
        "            }\n"
        "            // Header is the final validity/commit marker.\n"
        "            NVOCMP_failW = NVOCMP_write(dstPg, hOfs, cHdr, NVOCMP_ITEMHDRLEN);\n"
        "            if (NVOCMP_failW != NVINTF_SUCCESS)\n"
        "            {\n"
        "                NVOCMP_failF = NVINTF_FAILURE;\n"
        "                return;\n"
        "            }")

    # After fatal write/read, do not let readItem disguise the I/O error
    # as missing security state (NOTFOUND). Inspect failF in every API.
    source = one(source,
        '    if(NVOCMP_failF == NVINTF_NOTREADY)\n'
        '    {\n'
        '        // NV driver has not been initialized\n'
        '        NVOCMP_ASSERT(false, "Driver uninitialized.")\n'
        '        return(NVINTF_NOTREADY);\n'
        '    }',
        '    if(NVOCMP_failF != NVINTF_SUCCESS)\n'
        '    {\n'
        '        // Fatal storage failure is never equivalent to missing NV.\n'
        '        return(NVOCMP_failF);\n'
        '    }')
    # Stop all further writes, erases and normal NV reads after a hard I/O
    # failure. In-flight RAM is not authority to transmit; B1 must still
    # independently enforce HOLD_SECURITY on caller errors.
    source = one(source,
        "static uint8_t NVOCMP_write(uint8_t dstPg, uint16_t off, uint8_t *pBuf, uint16_t len)\n"
        "{\n"
        "    uint8_t err = NVINTF_SUCCESS;",
        "static uint8_t NVOCMP_write(uint8_t dstPg, uint16_t off, uint8_t *pBuf, uint16_t len)\n"
        "{\n"
        "    if (NVOCMP_failF != NVINTF_SUCCESS) return(NVINTF_FAILURE);\n"
        "    uint8_t err = NVINTF_SUCCESS;")
    # A failed page-state/header write is just as fatal as an item write.
    # Without this, an interrupted NV2 compaction can continue after failed
    # page metadata publication and later lose valid records (fault op 627).
    source = one(source,
        '    NVOCMP_ALERT(NVINTF_LOWPOWER != err, "Voltage check failed.")\n'
        '    if (NVINTF_FAILURE == err)\n'
        '    {\n'
        '        NVOCMP_ALERT(NVINTF_FAILURE != err, "NVS write failure.")\n'
        '    }\n\n'
        '    return(err);\n'
        '}\n\n'
        '/******************************************************************************\n'
        ' * @fn      NVOCMP_erase',
        '    NVOCMP_ALERT(NVINTF_LOWPOWER != err, "Voltage check failed.")\n'
        '    if (NVINTF_FAILURE == err)\n'
        '    {\n'
        '        NVOCMP_ALERT(NVINTF_FAILURE != err, "NVS write failure.")\n'
        '    }\n'
        '    if (err != NVINTF_SUCCESS)\n'
        '    {\n'
        '        NVOCMP_failF = NVINTF_FAILURE;\n'
        '        NVOCMP_failW = NVINTF_FAILURE;\n'
        '    }\n\n'
        '    return(err);\n'
        '}\n\n'
        '/******************************************************************************\n'
        ' * @fn      NVOCMP_erase')
    source = one(source,
        "static uint8_t NVOCMP_erase(NVOCMP_nvHandle_t *pNvHandle, uint8_t dstPg)\n"
        "{\n"
        "    uint8_t err = NVINTF_SUCCESS;",
        "static uint8_t NVOCMP_erase(NVOCMP_nvHandle_t *pNvHandle, uint8_t dstPg)\n"
        "{\n"
        "    if (NVOCMP_failF != NVINTF_SUCCESS) return(NVINTF_FAILURE);\n"
        "    uint8_t err = NVINTF_SUCCESS;")
    # An NVS erase refusal must permanently prevent programming its
    # still-containing NOR page. The original function returns failure but
    # its callers may continue compaction and attempt 0->1 writes into it.
    source = one(source,
        "    NVOCMP_ALERT(NVINTF_LOWPOWER != err, \"Voltage check failed.\")\n"
        "    NVOCMP_ALERT(NVINTF_FAILURE != err, \"NVS erase failure.\")\n\n"
        "    return(err);",
        "    NVOCMP_ALERT(NVINTF_LOWPOWER != err, \"Voltage check failed.\")\n"
        "    NVOCMP_ALERT(NVINTF_FAILURE != err, \"NVS erase failure.\")\n"
        "    if (err != NVINTF_SUCCESS)\n"
        "    {\n"
        "        NVOCMP_failF = NVINTF_FAILURE;\n"
        "        NVOCMP_failW = NVINTF_FAILURE;\n"
        "    }\n\n"
        "    return(err);")
    source = one(source,
        "    // Read Item\n"
        "    if (!err)\n"
        "    {\n"
        "        err = NVOCMP_readItem(&iHdr, ofs, len, pBuf, false);\n"
        "    }\n\n"
        "    NVOCMP_UNLOCK(err);",
        "    // Read Item\n"
        "    if (!err)\n"
        "    {\n"
        "        err = NVOCMP_readItem(&iHdr, ofs, len, pBuf, false);\n"
        "    }\n"
        "    if (NVOCMP_failF != NVINTF_SUCCESS)\n"
        "    {\n"
        "        memset(pBuf, 0, len);\n"
        "        err = NVINTF_FAILURE;\n"
        "    }\n"
        "    NVOCMP_UNLOCK(err);")
    source = one(source,
        "    return(NVOCMP_failW);\n"
        "}\n\n"
        "/******************************************************************************\n"
        " * @fn      NVOCMP_eraseNvApi",
        "    if (NVOCMP_failF != NVINTF_SUCCESS) return(NVINTF_FAILURE);\n"
        "    return(NVOCMP_failW);\n"
        "}\n\n"
        "/******************************************************************************\n"
        " * @fn      NVOCMP_eraseNvApi")
    # NV2 source-retention journal ordering. Never erase the prior
    # authoritative page before the destination's PGCDONE commit succeeds.
    source = one(source, "#if(NVOCMP_NVPAGES > NVOCMP_NVONEP)\n  // clean XSRC pages\n  NVOCMP_failW = NVOCMP_erase(pNvHandle, srcPg);\n#endif\n\n  // mark XDST page as done\n  NVOCMP_writeByte(dstPg, NVOCMP_COMPMODEOFS, NVOCMP_PGCDONE);\n  pNvHandle->pageInfo[dstPg].mode = NVOCMP_PGCDONE;", "// The destination completion marker is the durable handoff: it MUST\n  // be committed successfully BEFORE the last valid source is erased.\n  // The upstream NV2 sequence erased the source first, then wrote this\n  // marker, allowing a failed marker write to lose necessary security rows.\n  NVOCMP_writeByte(dstPg, NVOCMP_COMPMODEOFS, NVOCMP_PGCDONE);\n  if (NVOCMP_failW != NVINTF_SUCCESS)\n  {\n    NVOCMP_failF = NVINTF_FAILURE;\n    return(0);\n  }\n  pNvHandle->pageInfo[dstPg].mode = NVOCMP_PGCDONE;\n\n#if(NVOCMP_NVPAGES > NVOCMP_NVONEP)\n  // Only now may the source be erased: a failed erase leaves a fully\n  // committed destination and is latched by B3 NVOCMP_erase.\n  NVOCMP_failW = NVOCMP_erase(pNvHandle, srcPg);\n  if (NVOCMP_failW != NVINTF_SUCCESS) return(0);\n#endif")
    return source


def security_changes(source):
    # The pinned donor also declares this function locally in zd_sec_mgr.c
    # (near line 280), independently of zd_sec_mgr.h. Update both ABI sites.
    source = one(source,
        "void ZDSecMgrGenerateKeyFromSeed(uint8_t *extAddr, uint8_t shift, uint8_t *key);",
        "ZStatus_t ZDSecMgrGenerateKeyFromSeed(uint8_t *extAddr, uint8_t shift, uint8_t *key);")
    # The actual TI APS/TCLK checkpoint routines used to clear pendingFlag
    # even when the persistence write was rejected. Do not make a failed
    # checkpoint look durable. B1 still owns RF HOLD on failed persistence.
    source = one(source,
        "          // Write the APS link key back to the NV\n"
        "          osal_nv_write_ex(ZCD_NV_EX_APS_KEY_DATA_TABLE, i,\n"
        "                        sizeof(APSME_ApsLinkKeyNVEntry_t),\n"
        "                        pKeyData);\n\n"
        "          // clear the pending write flag\n"
        "          ApsLinkKeyRAMEntry[i].pendingFlag = FALSE;",
        "          // Clear pending ONLY if the actual NV backend accepted the write.\n"
        "          if (osal_nv_write_ex(ZCD_NV_EX_APS_KEY_DATA_TABLE, i,\n"
        "                               sizeof(APSME_ApsLinkKeyNVEntry_t),\n"
        "                               pKeyData) == SUCCESS)\n"
        "          {\n"
        "              ApsLinkKeyRAMEntry[i].pendingFlag = FALSE;\n"
        "          }")
    source = one(source,
        "          // Write the TC link key back to the NV\n"
        "          osal_nv_write_ex(ZCD_NV_EX_TCLK_TABLE, i,\n"
        "                           sizeof(APSME_TCLinkKeyNVEntry_t),\n"
        "                           pKeyData);\n\n"
        "          // clear the pending write flag\n"
        "          TCLinkKeyRAMEntry[i].pendingFlag = FALSE;",
        "          // Clear pending ONLY if the actual NV backend accepted the write.\n"
        "          if (osal_nv_write_ex(ZCD_NV_EX_TCLK_TABLE, i,\n"
        "                               sizeof(APSME_TCLinkKeyNVEntry_t),\n"
        "                               pKeyData) == SUCCESS)\n"
        "          {\n"
        "              TCLinkKeyRAMEntry[i].pendingFlag = FALSE;\n"
        "          }")
    # Pinned source P0: TI TRNG failure branch did NOTHING and still
    # published uninitialized entropy bytes. Change API to a checked status;
    # each original caller must suppress key publication on failure.
    source = one(source, "void ZDSecMgrGenerateRndKey(uint8_t* pKey)\n{\n  extern TRNG_Handle TRNG_handle;\n\n  int_fast16_t result;\n\n  CryptoKey entropyKey;\n  uint8_t entropyBuffer[SEC_KEY_LEN];\n\n  CryptoKeyPlaintext_initBlankKey(&entropyKey, entropyBuffer, SEC_KEY_LEN);\n\n  result = TRNG_generateEntropy(TRNG_handle, &entropyKey);\n\n  if (result != TRNG_STATUS_SUCCESS) {\n      // Handle error\n  }\n\n  OsalPort_memcpy(pKey, &entropyKey.u.plaintext.keyMaterial[0], SEC_KEY_LEN);\n}", "uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey)\n{\n  extern TRNG_Handle TRNG_handle;\n  CryptoKey entropyKey;\n  uint8_t entropyBuffer[SEC_KEY_LEN] = {0};\n  int_fast16_t result;\n\n  // Missing destination, absent driver or TRNG failure must not publish a key.\n  if (pKey == NULL) return ZFailure;\n  memset(pKey, 0, SEC_KEY_LEN);\n  if (TRNG_handle == NULL) return ZFailure;\n\n  CryptoKeyPlaintext_initBlankKey(&entropyKey, entropyBuffer, SEC_KEY_LEN);\n  result = TRNG_generateEntropy(TRNG_handle, &entropyKey);\n  if (result != TRNG_STATUS_SUCCESS)\n  {\n      memset(entropyBuffer, 0, sizeof(entropyBuffer));\n      return ZFailure;\n  }\n  OsalPort_memcpy(pKey, &entropyKey.u.plaintext.keyMaterial[0], SEC_KEY_LEN);\n  memset(entropyBuffer, 0, sizeof(entropyBuffer));\n  return ZSuccess;\n}")
    source = one(source,
        "  ZDSecMgrGenerateRndKey(SeedKey);\n\n  if((SUCCESS == osal_nv_item_init",
        "  if (ZDSecMgrGenerateRndKey(SeedKey) != ZSuccess)\n  {\n    memset(SeedKey, 0, SEC_KEY_LEN);\n    return; // never create or overwrite TC seed with failed entropy\n  }\n\n  if((SUCCESS == osal_nv_item_init")
    source = one(source, "void ZDSecMgrGenerateKeyFromSeed(uint8_t *extAddr, uint8_t shift, uint8_t *key)\n{\n  uint8_t i;\n  uint8_t tempKey[SEC_KEY_LEN];\n  //shift must be less than SEC_KEY_LEN. This is to handle the cases where SeedShift is >= SEC_KEY_LEN.\n  shift &= 0x0F;\n\n  if((key != NULL) && (extAddr != NULL))\n  {\n    //Read the key\n    osal_nv_read(ZCD_NV_TCLK_SEED,0,SEC_KEY_LEN,tempKey);\n\n    //shift the seed\n    OsalPort_memcpy(key, &tempKey[shift], SEC_KEY_LEN - shift);\n    OsalPort_memcpy(&key[SEC_KEY_LEN - shift], tempKey, shift);\n\n    //Create the key from the seed\n    for(i = 0; i < Z_EXTADDR_LEN; i++)\n    {\n      key[i] ^= extAddr[i];\n      key[i+Z_EXTADDR_LEN] ^= extAddr[i];\n    }\n  }\n}", "ZStatus_t ZDSecMgrGenerateKeyFromSeed(uint8_t *extAddr, uint8_t shift, uint8_t *key)\n{\n  uint8_t i;\n  uint8_t tempKey[SEC_KEY_LEN] = {0};\n  // Never turn a failed seed NV read into a newly derived TC transport key.\n  if (key == NULL || extAddr == NULL) return ZFailure;\n  memset(key, 0, SEC_KEY_LEN);\n  if (osal_nv_read(ZCD_NV_TCLK_SEED, 0, SEC_KEY_LEN, tempKey) != SUCCESS)\n  {\n    memset(tempKey, 0, sizeof(tempKey));\n    return ZFailure;\n  }\n  shift &= 0x0F;\n  OsalPort_memcpy(key, &tempKey[shift], SEC_KEY_LEN - shift);\n  OsalPort_memcpy(&key[SEC_KEY_LEN - shift], tempKey, shift);\n  for (i = 0; i < Z_EXTADDR_LEN; i++)\n  {\n    key[i] ^= extAddr[i];\n    key[i + Z_EXTADDR_LEN] ^= extAddr[i];\n  }\n  memset(tempKey, 0, sizeof(tempKey));\n  return ZSuccess;\n}")
    source = one(source, "      ZDSecMgrGenerateKeyFromSeed(TCLKDevEntry.extAddr,TCLKDevEntry.SeedShift,req.key);", "      if (ZDSecMgrGenerateKeyFromSeed(TCLKDevEntry.extAddr,\n                                      TCLKDevEntry.SeedShift, req.key) != ZSuccess)\n      {\n        memset(key, 0, SEC_KEY_LEN);\n        return; // No APSME_TransportKeyReq on unreadable seed\n      }")
    source = one(source, "    // set key data to all 0s if NV read fails\n    memset(&tmpKey, 0x00, sizeof(tmpKey));", "    // Reject unreadable NWK key; zero is NEVER a substitute transport key.\n    memset(&tmpKey, 0x00, sizeof(tmpKey));\n    return ZFailure;")
    return source


def entropy_header_changes(source):
    source = one(source,
        'extern void ZDSecMgrGenerateRndKey(uint8_t* pKey);',
        'extern uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey);')
    return one(source,
        'extern void ZDSecMgrGenerateKeyFromSeed(uint8_t *extAddr, uint8_t shift, uint8_t *key);',
        'extern ZStatus_t ZDSecMgrGenerateKeyFromSeed(uint8_t *extAddr, uint8_t shift, uint8_t *key);')


def entropy_zdapp_changes(source):
    return one(source,
        '        ZDSecMgrGenerateRndKey(tmpKey);\n\n        //Set the nwk key as the default',
        '        if (ZDSecMgrGenerateRndKey(tmpKey) != ZSuccess)\n'
        '        {\n'
        '          memset(tmpKey, 0, SEC_KEY_LEN);\n'
        '          bdb_nwkFormationAttempt(FALSE);\n'
        '          return; // no key publication or network-start event\n'
        '        }\n\n        //Set the nwk key as the default')


def entropy_zglobals_changes(source):
    return one(source,
        '      ZDSecMgrGenerateRndKey(zgPreConfigKey);',
        '      if (ZDSecMgrGenerateRndKey(zgPreConfigKey) != ZSuccess)\n'
        '      {\n'
        '        memset(zgPreConfigKey, 0, SEC_KEY_LEN);\n'
        '        return NV_OPER_FAILED; // refuse writing a fabricated key\n'
        '      }')


def entropy_zstacktask_changes(source):
    return one(source,
        '      ZDSecMgrGenerateRndKey(&nwkKey.key[0]);',
        '      if (ZDSecMgrGenerateRndKey(&nwkKey.key[0]) != ZSuccess)\n'
        '      {\n'
        '        memset(&nwkKey, 0, sizeof(nwkKey));\n'
        '        pPtr->hdr.status = (zstack_ZStatusValues)ZFailure;\n'
        '        return (TRUE); // no OSAL NV write on failed entropy\n'
        '      }')


def b3_replace_function(source, signature, replacement, required):
    """Replace only one exact pinned-TI function. Never touch similarly named callers."""
    if source.count(signature) != 1:
        raise ValueError("B3 function declaration absent or ambiguous: " + signature)
    start = source.index(signature)
    end = source.index("\n}\n", start) + 2
    original = source[start:end]
    if len(original) > 6000:
        raise ValueError("B3 source function boundary unexpected")
    for needle in required:
        if needle not in original:
            raise ValueError("B3 security caller drift: " + needle)
    return one(source, original, replacement)


def nwk_checkpoint_changes(source):
    """Conservative source repair, not a B1 RF hold or key-transaction proof."""
    save = r'''void ZDApp_SaveNwkKey( void )
{
  nwkActiveKeyItems keyItems;
  nwkSecMaterialDesc_t nwkSecMaterialDesc = {0};
  nwkSecMaterialDesc_t persisted = {0};
  nwkActiveKeyItems persistedKey = {0};
  uint8_t found = FALSE;
  uint8_t i;

  SSP_ReadNwkActiveKey( &keyItems );

  // Do not claim a security checkpoint if ANY table read/write was rejected.
  // Keep RAM's pending counter changes so a later controlled retry can see them.
  for( i = 0; i < gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES; i++)
  {
    if (osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, i, 0,
                        sizeof(nwkSecMaterialDesc_t),
                        &nwkSecMaterialDesc) != SUCCESS)
    {
      goto b3_checkpoint_done;
    }
    if (OsalPort_memcmp(_NIB.extendedPANID,
                        nwkSecMaterialDesc.extendedPanID,Z_EXTADDR_LEN))
    {
      nwkSecMaterialDesc.FrameCounter = keyItems.frameCounter;
      found = TRUE;
      if (osal_nv_write_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, i,
                           sizeof(nwkSecMaterialDesc_t),
                           &nwkSecMaterialDesc) != SUCCESS ||
          osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, i, 0,
                          sizeof(persisted), &persisted) != SUCCESS ||
          !OsalPort_memcmp(&persisted, &nwkSecMaterialDesc, sizeof(persisted)))
      {
        goto b3_checkpoint_done;
      }
      break;
    }
  }

  if (!found)
  {
    if (gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES == 0)
    {
      goto b3_checkpoint_done;
    }
    // The last slot is the generic item, NEVER unsigned i-1 on no slots.
    memset(nwkSecMaterialDesc.extendedPanID,0xFF,Z_EXTADDR_LEN);
    nwkSecMaterialDesc.FrameCounter = keyItems.frameCounter;
    if (osal_nv_write_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE,
                         gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES - 1,
                         sizeof(nwkSecMaterialDesc_t),
                         &nwkSecMaterialDesc) != SUCCESS ||
        osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE,
                        gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES - 1, 0,
                        sizeof(persisted), &persisted) != SUCCESS ||
        !OsalPort_memcmp(&persisted, &nwkSecMaterialDesc, sizeof(persisted)))
    {
      goto b3_checkpoint_done;
    }
  }

  // Save key snapshot after counter material: a failure cannot falsely
  // acknowledge both records. This is NOT cross-item atomic key rotation.
  if (osal_nv_write(ZCD_NV_NWKKEY, sizeof(nwkActiveKeyItems),
                    (void *)&keyItems) == SUCCESS &&
      osal_nv_read(ZCD_NV_NWKKEY, 0, sizeof(persistedKey),
                   &persistedKey) == SUCCESS &&
      OsalPort_memcmp(&persistedKey, &keyItems, sizeof(keyItems)))
  {
    nwkFrameCounterChanges = 0;
  }

b3_checkpoint_done:
  memset(&persistedKey, 0, sizeof(persistedKey));
  memset(&keyItems, 0, sizeof(keyItems));
}'''
    source = b3_replace_function(
        source, "void ZDApp_SaveNwkKey( void )", save,
        ["nwkFrameCounterChanges = 0;", "i - 1,", "SSP_ReadNwkActiveKey"])
    restore = r'''void ZDApp_RestoreNwkSecMaterial(void)
{
  uint8_t Found = FALSE;
  uint8_t i;
  nwkSecMaterialDesc_t nwkSecMaterialDesc = {0};
  nwkSecMaterialDesc_t persisted = {0};
  uint8_t UpdateFrameCounter = FALSE;
  const uint32_t reserve = (uint32_t)MAX_NWK_FRAMECOUNTER_CHANGES +
                           (uint32_t)NWK_FRAMECOUNTER_CHANGES_RESTORE_DELTA;

  // Reject absent/corrupt NV instead of comparing a stale/uninitialized row.
  for( i = 0; i < gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES; i++)
  {
    if (osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, i, 0,
                        sizeof(nwkSecMaterialDesc_t),
                        &nwkSecMaterialDesc) != SUCCESS)
    {
      return;
    }
    if (OsalPort_memcmp(_NIB.extendedPANID,
                        nwkSecMaterialDesc.extendedPanID,Z_EXTADDR_LEN))
    {
      UpdateFrameCounter = TRUE;
      Found = TRUE;
      break;
    }
  }

  if (!Found && gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES > 0 &&
      nwkSecMaterialDesc.FrameCounter)
  {
    UpdateFrameCounter = TRUE;
    i = gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES - 1;
  }

  if (UpdateFrameCounter && (!FrameCounterUpdated))
  {
    // Never wrap the TX frame counter for the active key.
    if (reserve == 0 || nwkSecMaterialDesc.FrameCounter > 0xFFFFFFFFUL - reserve)
    {
      return;
    }
    nwkSecMaterialDesc.FrameCounter += reserve;

    // Durable reservation BEFORE publishing either the RAM floor or
    // FrameCounterUpdated. B1 must still gate all encrypted RF sends.
    if (osal_nv_write_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, i,
                         sizeof(nwkSecMaterialDesc_t),
                         &nwkSecMaterialDesc) != SUCCESS ||
        osal_nv_read_ex(ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE, i, 0,
                        sizeof(persisted), &persisted) != SUCCESS ||
        !OsalPort_memcmp(&persisted, &nwkSecMaterialDesc, sizeof(persisted)))
    {
      return; // never publish a floor that NV did not retain byte-for-byte
    }
    nwkFrameCounter = nwkSecMaterialDesc.FrameCounter;
    FrameCounterUpdated = TRUE;
    nwkFrameCounterChanges = 0;
  }
}'''
    source = b3_replace_function(
        source, "void ZDApp_RestoreNwkSecMaterial(void)", restore,
        ["FrameCounterUpdated = TRUE;", "nwkFrameCounter =", "osal_nv_read_ex"])
    return source


def apply(sdk, receipt):
    sdk = Path(sdk).resolve()
    prepared = []
    # Validate all preimages BEFORE writing anything to the scratch checkout.
    for path, expected in PINNED_BLOBS.items():
        target = (sdk / path).resolve()
        if not target.is_relative_to(sdk) or not target.is_file():
            raise ValueError("B3 SDK path missing or outside checkout")
        raw = target.read_bytes()
        if blob_id(raw) != expected:
            raise ValueError("B3 donor git blob mismatch: " + path)
        orig = raw.decode("utf-8")
        changes = {
            "osal_nv.c": osal_changes,
            "nvocmp.c": nvocmp_changes,
            "zd_sec_mgr.c": security_changes,
            "zd_sec_mgr.h": entropy_header_changes,
            "zd_app.c": lambda src: nwk_checkpoint_changes(entropy_zdapp_changes(src)),
            "zglobals.c": entropy_zglobals_changes,
            "zstacktask.c": entropy_zstacktask_changes,
        }
        changed = changes[target.name](orig)
        prepared.append((target, changed.encode("utf-8"), path, expected))
    for target, changed, _, _ in prepared:
        target.write_bytes(changed)
    report = {"schema": "r4-b3-source-overlay-v1",
              "donor_sdk_commit": "3615ad5d3f4f271258d18a2f5ce1785064ff9a58",
              "production_flash_authorized": False, "unresolved": [
                  "NVOCMP read/compaction full negative matrix and actual device power-loss still pending",
                  "osal_nv_init void ABI drops initialization failure",
                  "B1 HOLD_SECURITY integration unimplemented",
                  "per-key reserve-before-send and native B1 hold wiring not proven",
                  "TRNG status checked at all public TI callers, RF blocking on hold still unintegrated",
              "TC seed-derived and NWK key transport read failures now denied in actual TI source; B1 RF gate still unintegrated"],
              "files": [{"path": path, "original_blob_sha1": old,
                         "modified_sha256": hashlib.sha256(raw).hexdigest()}
                        for _, raw, path, old in prepared]}
    if receipt:
        Path(receipt).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", required=True)
    parser.add_argument("--receipt")
    args = parser.parse_args()
    print(json.dumps(apply(args.sdk, args.receipt), sort_keys=True))


if __name__ == "__main__":
    main()
