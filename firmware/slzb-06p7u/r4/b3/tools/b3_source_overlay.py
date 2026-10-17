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
    return source


def entropy_header_changes(source):
    return one(source,
        'extern void ZDSecMgrGenerateRndKey(uint8_t* pKey);',
        'extern uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey);')


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
            "zd_app.c": entropy_zdapp_changes,
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
                  "TRNG status checked at all public TI callers, RF blocking on hold still unintegrated"],
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
