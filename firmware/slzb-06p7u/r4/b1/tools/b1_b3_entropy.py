"""Narrow B3 entropy failure semantics composed with B1 security HOLD.

This changes exactly the TI 8.33 RNG function and four original public
publishers. A failed TRNG must never create/overwrite keys or send secured RF.
No new TRNG owner, no UART/NV/PHY control, no installed-radio interactions.
"""
from patch_zdapp import extract_function, replace_once

RND = r'''uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey)
{
  extern TRNG_Handle TRNG_handle;
  CryptoKey entropyKey;
  uint8_t entropyBuffer[SEC_KEY_LEN] = {0};
  int_fast16_t result;
  if (pKey == NULL)
  {
    b1_security_runtime_hold_latch();
    return ZFailure;
  }
  memset(pKey, 0, SEC_KEY_LEN);
  if (TRNG_handle == NULL)
  {
    b1_security_runtime_hold_latch();
    return ZFailure;
  }
  CryptoKeyPlaintext_initBlankKey(&entropyKey, entropyBuffer, SEC_KEY_LEN);
  result = TRNG_generateEntropy(TRNG_handle, &entropyKey);
  if (result != TRNG_STATUS_SUCCESS)
  {
    memset(entropyBuffer, 0, sizeof(entropyBuffer));
    b1_security_runtime_hold_latch();
    return ZFailure;
  }
  OsalPort_memcpy(pKey, &entropyKey.u.plaintext.keyMaterial[0], SEC_KEY_LEN);
  memset(entropyBuffer, 0, sizeof(entropyBuffer));
  return ZSuccess;
}'''

def compose(security, header, zdapp, zglobals, zstacktask):
    if "b1_security_runtime_hold_latch();" not in security:
        raise RuntimeError("B1_B3_ENTROPY_NO_B1_SECURITY_HOLD")
    old=extract_function(security, "void ZDSecMgrGenerateRndKey(uint8_t* pKey)")
    if "TRNG_generateEntropy(TRNG_handle, &entropyKey)" not in old or (
            "if (result != TRNG_STATUS_SUCCESS)" not in old):
        raise RuntimeError("B1_B3_TRNG_ORIGINAL_TI_DRIFT")
    security=replace_once(security,old,RND,"B1_B3 checked RNG")
    security=replace_once(security,
        "  ZDSecMgrGenerateRndKey(SeedKey);",
        "  if (ZDSecMgrGenerateRndKey(SeedKey) != ZSuccess)\n"
        "  {\n    memset(SeedKey, 0, SEC_KEY_LEN);\n"
        "    return; /* sticky security HOLD already asserted */\n  }",
        "B1_B3 TC seed entropy guard")
    header=replace_once(header,
        "extern void ZDSecMgrGenerateRndKey(uint8_t* pKey);",
        "extern uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey);",
        "B1_B3 checked RNG header")
    zdapp=replace_once(zdapp,
        "        ZDSecMgrGenerateRndKey(tmpKey);\n\n"
        "        //Set the nwk key as the default",
        "        if (ZDSecMgrGenerateRndKey(tmpKey) != ZSuccess)\n"
        "        {\n"
        "          memset(tmpKey, 0, SEC_KEY_LEN);\n"
        "          bdb_nwkFormationAttempt(FALSE);\n"
        "          return; /* no NWK key creation under B1 HOLD */\n"
        "        }\n\n        //Set the nwk key as the default",
        "B1_B3 NWK formation fails on entropy")
    zglobals=replace_once(zglobals,
        "      ZDSecMgrGenerateRndKey(zgPreConfigKey);",
        "      if (ZDSecMgrGenerateRndKey(zgPreConfigKey) != ZSuccess)\n"
        "      {\n        memset(zgPreConfigKey, 0, SEC_KEY_LEN);\n"
        "        return NV_OPER_FAILED; /* B1 security HOLD asserted */\n      }",
        "B1_B3 preconfigured key fails on entropy")
    zstacktask=replace_once(zstacktask,
        "      ZDSecMgrGenerateRndKey(&nwkKey.key[0]);",
        "      if (ZDSecMgrGenerateRndKey(&nwkKey.key[0]) != ZSuccess)\n"
        "      {\n        memset(&nwkKey, 0, sizeof(nwkKey));\n"
        "        pPtr->hdr.status = (zstack_ZStatusValues)ZFailure;\n"
        "        return (TRUE); /* never save uninitialized NWK key */\n      }",
        "B1_B3 zstacktask status reject")
    return security, header, zdapp, zglobals, zstacktask
