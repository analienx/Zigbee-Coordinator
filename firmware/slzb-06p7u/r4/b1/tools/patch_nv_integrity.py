"""Extra fail-closed NV changes applied AFTER the original exact-SHA overlay.

The caller verifies the unmodified 8.33 nvocmp blob before applying overlays.
All replacements here require unique body/anchor preimages. No device access.
"""


def once(text, before, after, label):
    if text.count(before) != 1:
        raise RuntimeError("B1_NV_INTEGRITY_PREIMAGE " + label)
    return text.replace(before, after, 1)


def functions(text, signature):
    marker = signature + "\n{"
    position = 0
    bodies = []
    while True:
        start = text.find(marker, position)
        if start < 0:
            return bodies
        opening = start + len(signature) + 1
        depth = 0
        for end in range(opening, len(text)):
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
                if depth == 0:
                    bodies.append(text[start:end + 1])
                    position = end + 1
                    break
        else:
            raise RuntimeError("B1_NV_INTEGRITY_UNTERMINATED " + signature)


def patch(source):
    source = once(source, "static uint8_t NVOCMP_failW;",
                  "static uint8_t NVOCMP_failW;\n"
                  "static uint8_t b1_nv_initializing; /* forbid resume repair */",
                  "boot repair state")
    source = once(source, "        sem_init(&NVOCMP_gPosixSem, 0 /* ignored */, 1);",
                  "        if (sem_init(&NVOCMP_gPosixSem, 0 /* ignored */, 1) != 0)\n"
                  "        {\n"
                  "            NVOCMP_failF = NVINTF_FAILURE;\n"
                  "            NVOCMP_failW = NVINTF_FAILURE;\n"
                  "            b1_nv_runtime_hold_latch();\n"
                  "            return NVOCMP_failF;\n"
                  "        }", "POSIX semaphore allocation")
    source = once(source, "        NVOCMP_initNv(&NVOCMP_nvHandle);",
                  "        b1_nv_initializing = 1u;\n"
                  "        NVOCMP_initNv(&NVOCMP_nvHandle);\n"
                  "        b1_nv_initializing = 0u;\n"
                  "        if (NVOCMP_failF != NVINTF_SUCCESS || b1_nv_runtime_hold_active())\n"
                  "        {\n"
                  "            NVOCMP_failW = NVINTF_FAILURE;\n"
                  "            return NVINTF_FAILURE;\n"
                  "        }", "fatal init outcome")

    signature = "static inline void NVOCMP_read(uint8_t pg, uint16_t off, uint8_t *pBuf, uint16_t len)"
    body, = functions(source, signature)
    changed = body.replace("\n{\n", "\n{\n"
        "    if (NVOCMP_failF != NVINTF_SUCCESS || b1_nv_runtime_hold_active() ||\n"
        "        pg >= NVOCMP_NVPAGES || off > FLASH_PAGE_SIZE ||\n"
        "        len > FLASH_PAGE_SIZE - off || pBuf == NULL)\n"
        "    {\n"
        "        NVOCMP_failF = NVINTF_FAILURE;\n"
        "        NVOCMP_failW = NVINTF_FAILURE;\n"
        "        b1_nv_runtime_hold_latch();\n"
        "        /* Never overwrite caller RAM with an untrusted oversized len. */\n"
        "        if (pBuf != NULL && pg < NVOCMP_NVPAGES &&\n"
        "            off <= FLASH_PAGE_SIZE && len <= FLASH_PAGE_SIZE - off)\n"
        "            memset(pBuf, 0, len);\n"
        "        return;\n"
        "    }\n", 1)
    source = once(source, body, changed, "bounded real NVS read")

    for signature in (
        "static uint8_t NVOCMP_write(uint8_t dstPg, uint16_t off, uint8_t *pBuf, uint16_t len)",
        "static uint8_t NVOCMP_erase(NVOCMP_nvHandle_t *pNvHandle, uint8_t dstPg)",
    ):
        body, = functions(source, signature)
        extra = (" || off > FLASH_PAGE_SIZE || len > FLASH_PAGE_SIZE - off || pBuf == NULL"
                 if "NVOCMP_write(" in signature else " || pNvHandle == NULL")
        guard = ("    if (NVOCMP_failF != NVINTF_SUCCESS || b1_nv_runtime_hold_active() ||\n"
                 "        dstPg >= NVOCMP_NVPAGES" + extra + " ||\n"
                 "        (b1_nv_initializing && b1_nv_existing_header_candidate()))\n"
                 "    {\n"
                 "        NVOCMP_failF = NVINTF_FAILURE;\n"
                 "        NVOCMP_failW = NVINTF_FAILURE;\n"
                 "        b1_nv_runtime_hold_latch();\n"
                 "        return NVINTF_FAILURE;\n"
                 "    }")
        changed = once(body,
            "    if (NVOCMP_failF != NVINTF_SUCCESS) return NVINTF_FAILURE;",
            guard, "fatal/bounds/resume-write guard")
        changed = changed.replace("if (nvsRes < 0)", "if (nvsRes != NVS_STATUS_SUCCESS)")
        changed = once(changed, "    return(err);",
            "    if (err != NVINTF_SUCCESS)\n"
            "    {\n"
            "        NVOCMP_failF = NVINTF_FAILURE;\n"
            "        NVOCMP_failW = err;\n"
            "        b1_nv_runtime_hold_latch(); /* includes voltage denial */\n"
            "    }\n"
            "    return(err);", "low voltage sticky failure")
        source = once(source, body, changed, signature)

    signature = "static void NVOCMP_readHeader(uint8_t pg, uint16_t ofs, NVOCMP_itemHdr_t *pHdr, bool flag)"
    body, = functions(source, signature)
    changed = body.replace("\n{\n", "\n{\n"
        "    if (NVOCMP_failF != NVINTF_SUCCESS || b1_nv_runtime_hold_active() ||\n"
        "        pg >= NVOCMP_NVPAGES || ofs > FLASH_PAGE_SIZE - NVOCMP_ITEMHDRLEN)\n"
        "    {\n"
        "        memset(pHdr, 0, sizeof(*pHdr));\n"
        "        pHdr->stats = NVOCMP_VALIDIDBIT;\n"
        "        NVOCMP_failF = NVINTF_FAILURE;\n"
        "        NVOCMP_failW = NVINTF_FAILURE;\n"
        "        b1_nv_runtime_hold_latch();\n"
        "        return;\n"
        "    }\n", 1)
    changed = once(changed, "        pHdr->stats |=  NVOCMP_VALIDIDBIT;",
        "        pHdr->stats |= NVOCMP_VALIDIDBIT;\n"
        "        NVOCMP_failF = NVINTF_FAILURE;\n"
        "        NVOCMP_failW = NVINTF_FAILURE;\n"
        "        b1_nv_runtime_hold_latch();", "invalid signature fatal")
    source = once(source, body, changed, "bounded actual header read")

    scan_signature = ("static uint8_t NVOCMP_scanPage(NVOCMP_nvHandle_t *pNvHandle, uint8_t pg,\n"
                      "                               NVOCMP_pageInfo_t *pPageInfo)")
    scan_bodies = functions(source, scan_signature)
    matches = [body for body in scan_bodies if
               "if ((pHdr->version == NVOCMP_VERSION) ||" in body]
    if len(matches) != 1:
        raise RuntimeError("B1_NV_NV2_SCAN_NOT_UNIQUE")
    body = matches[0]
    anchor = "  NVOCMP_read(pg, NVOCMP_PGHDROFS, (uint8_t *)pHdr, NVOCMP_PGHDRLEN);"
    changed = once(body, anchor, anchor + "\n"
        "  if (NVOCMP_failF != NVINTF_SUCCESS ||\n"
        "      (b1_nv_existing_header_candidate() &&\n"
        "      (pHdr->version != NVOCMP_VERSION || pHdr->signature != NVOCMP_SIGNATURE ||\n"
        "      pHdr->cycle == 0u || pHdr->cycle == 0xFFu ||\n"
        "      (pHdr->allActive != NVOCMP_ALLACTIVE && pHdr->allActive != NVOCMP_SOMEINACTIVE) ||\n"
        "      (pHdr->state != NVOCMP_PGACT && pHdr->state != NVOCMP_PGFULL &&\n"
        "       pHdr->state != NVOCMP_PGXDST))))\n"
        "  {\n"
        "      NVOCMP_failF = NVINTF_FAILURE;\n"
        "      NVOCMP_failW = NVINTF_FAILURE;\n"
        "      b1_nv_runtime_hold_latch();\n"
        "      return NVINTF_CORRUPT;\n"
        "  }", "NV2 coherent page header after admission")
    changed = once(changed,
        "if ((pHdr->version == NVOCMP_VERSION) || (pHdr->signature == NVOCMP_SIGNATURE))",
        "if ((pHdr->version == NVOCMP_VERSION) && (pHdr->signature == NVOCMP_SIGNATURE))",
        "NV2 page version and signature")
    source = once(source, body, changed, "actual NV2 page scan")

    # The real NV2 initializer ignores scan/header statuses and would enter
    # compaction even after a fatal read. Stop before recovery/repair branches.
    init_bodies = functions(source, "static void NVOCMP_initNv(NVOCMP_nvHandle_t *pNvHandle)")
    matches = [body for body in init_bodies if "prevactPage" in body]
    if len(matches) != 1:
        raise RuntimeError("B1_NV_TWO_PAGE_INIT_NOT_UNIQUE")
    body = matches[0]
    changed = once(body, "    NVOCMP_scanPage(pNvHandle, pg, pPageInfo);",
        "    if (NVOCMP_scanPage(pNvHandle, pg, pPageInfo) != NVINTF_SUCCESS ||\n"
        "        NVOCMP_failF != NVINTF_SUCCESS || b1_nv_runtime_hold_active()) return;",
        "NV2 stop failed page scan")
    anchor = ("            NVOCMP_readHeader(pNvHandle->actPage, "
              "pNvHandle->actOffset - NVOCMP_ITEMHDRLEN , &iHdr, false);")
    changed = once(changed, anchor, anchor + "\n"
        "            if (NVOCMP_failF != NVINTF_SUCCESS || b1_nv_runtime_hold_active()) return;",
        "NV2 stop failed header scan")
    source = once(source, body, changed, "real NV2 init fault exit")

    signature = ("static int8_t NVOCMP_findItem(NVOCMP_nvHandle_t *pNvHandle, uint8_t pg, uint16_t ofs,\n"
                 "                              NVOCMP_itemHdr_t *pHdr, int8_t flag, NVOCMP_itemInfo_t *pInfo)")
    bodies = functions(source, signature)
    if len(bodies) != 2:
        raise RuntimeError("B1_NV_FIND_VARIANTS_NOT_TWO")
    for body in bodies:
        fast = "NVOCMP_readHeader(p, ofs, &iHdr, true);" in body
        anchor = "          NVOCMP_readHeader(p, ofs, &iHdr, " + ("true" if fast else "false") + ");"
        guard = ("\n          if (NVOCMP_failF != NVINTF_SUCCESS ||\n"
                 "              !(iHdr.stats & NVOCMP_FOLLOWBIT) ||\n"
                 "              iHdr.len == 0u || iHdr.len > ofs - NVOCMP_PGDATAOFS)\n"
                 "          {\n"
                 "              NVOCMP_failF = NVINTF_FAILURE;\n"
                 "              NVOCMP_failW = NVINTF_FAILURE;\n"
                 "              b1_nv_runtime_hold_latch();\n")
        if fast:
            guard += "#ifdef NVOCMP_GPRAM\n              NVOCMP_restoreCache(vm);\n#endif\n"
        guard += ("              return NVINTF_CORRUPT; /* never repair an untrusted row */\n"
                  "          }")
        changed = once(body, anchor, anchor + guard, "bounded item scan")
        source = once(source, body, changed, "fast/slow item scan")

    signature = "static uint8_t NVOCMP_verifyCRC(uint16_t iOfs, uint16_t len, uint8_t crc, uint8_t pg, bool flag)"
    body, = functions(source, signature)
    changed = once(body, "    return(newCRC == crc ? NVINTF_SUCCESS : NVINTF_CORRUPT);",
        "    if (NVOCMP_failF != NVINTF_SUCCESS || newCRC != crc)\n"
        "    {\n"
        "        NVOCMP_failF = NVINTF_FAILURE;\n"
        "        NVOCMP_failW = NVINTF_FAILURE;\n"
        "        b1_nv_runtime_hold_latch();\n"
        "        return NVINTF_CORRUPT;\n"
        "    }\n"
        "    return NVINTF_SUCCESS;", "CRC failure becomes sticky")
    source = once(source, body, changed, "actual CRC failure")
    return source
