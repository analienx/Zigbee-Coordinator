#!/usr/bin/env python3
"""Preserve unknown nonblank NV and validate P7 NVS before recovery writes."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path
from runtime_overlay import replace, function

SOURCE="source/ti/common/nv/nvocmp.c"
NV_FAILURE_OPERATIONS=("voltage_check", "initial_success_not_a_failure",
    "pthread_mutex_attributes", "pthread_mutex_create", "gate_mutex_create",
    "nvs_open", "nvs_geometry", "nvs_region_base", "legacy_geometry_check",
    "legacy_handle_check", "nv_format_precheck", "ambiguous_force_clean",
    "nv2_page_scan", "nvs_read", "nvs_write", "nvs_erase")
GUARD=r'''
/* P7: inspect every page before scanPage is allowed to format even a blank
 * page. An unsupported nonblank page must preserve the entire NV image. */
static uint8_t p7_nv_precheck(void)
{
    uint8_t pg;
    uint8_t destinations = 0, sources = 0, active = 0;
    for (pg = 0; pg < NVOCMP_NVSIZE; ++pg)
    {
        NVOCMP_pageHdr_t header = {0};
        uint16_t off;
        uint8_t probe[32];
        uint8_t blank = 1;
        NVOCMP_read(pg, 0, (uint8_t *)&header, sizeof(header));
        if (NVOCMP_failF != NVINTF_SUCCESS) return NVOCMP_failF;
        if (header.signature == NVOCMP_SIGNATURE && header.version == NVOCMP_VERSION &&
            (header.state == NVOCMP_PGNACT || header.state == NVOCMP_PGXDST ||
             header.state == NVOCMP_PGRDY || header.state == NVOCMP_PGACT ||
             header.state == NVOCMP_PGFULL || header.state == NVOCMP_PGXSRC))
        {
            if (header.state == NVOCMP_PGXDST) ++destinations;
            if (header.state == NVOCMP_PGXSRC) ++sources;
            if (header.state == NVOCMP_PGRDY || header.state == NVOCMP_PGACT ||
                header.state == NVOCMP_PGFULL) ++active;
            continue;
        }
        for (off = 0; off < FLASH_PAGE_SIZE; off += sizeof(probe))
        {
            unsigned i;
            memset(probe, 0, sizeof(probe));
            NVOCMP_read(pg, off, probe, sizeof(probe));
            if (NVOCMP_failF != NVINTF_SUCCESS) return NVOCMP_failF;
            for (i = 0; i < sizeof(probe); ++i) if (probe[i] != 0xFF) blank = 0;
            if (!blank) break;
        }
        if (!blank) return NVINTF_BADVERSION;
    }
    if (NVOCMP_NVPAGES == 2 && (destinations > 1 || sources > 1 || active > 1))
        return NVINTF_CORRUPT;
    return NVINTF_SUCCESS;
}
'''


def patch(source: str, *, sites=None) -> str:
    if "p7_nv_precheck" in source: raise ValueError("NV_HARDENING_ALREADY_PATCHED")
    source=replace(source,
        "    { if (!NVOCMP_voltCheckFptr()) { err = NVINTF_LOWPOWER;}}}",
        "    { if (!NVOCMP_voltCheckFptr()) { err = NVOCMP_failF = NVINTF_LOWPOWER;}}}",
        "nv_voltage_failure_latch")
    source=replace(source,"        NVOCMP_gMutexPri = GateMutexPri_create(&gateParams, NULL);",
        "        NVOCMP_gMutexPri = GateMutexPri_create(&gateParams, NULL);\n"
        "        if (NVOCMP_gMutexPri == NULL)\n"
        "        { NVOCMP_failF = NVOCMP_failW = NVINTF_FAILURE; return NVINTF_FAILURE; }",
        "nv_mutex_before_startup_access")
    source=replace(source,
        "        // Get NV hardware attributes\n        NVS_getAttrs(NVOCMP_nvsHandle,&NVOCMP_nvsAttrs);",
        "        if (NVOCMP_nvsHandle == NULL)\n"
        "        { NVOCMP_failF = NVOCMP_failW = NVINTF_FAILURE; return NVINTF_FAILURE; }\n"
        "        // Get NV hardware attributes only from an opened handle\n"
        "        NVS_getAttrs(NVOCMP_nvsHandle,&NVOCMP_nvsAttrs);",
        "nv_open_before_attrs")
    source=replace(source,"        NVOCMP_nvHandle.nvSize = NVOCMP_nvsAttrs.regionSize/NVOCMP_nvsAttrs.sectorSize;",
        "        if (NVOCMP_nvsAttrs.sectorSize != FLASH_PAGE_SIZE ||\n"
        "            NVOCMP_nvsAttrs.regionSize != FLASH_PAGE_SIZE * NVOCMP_NVPAGES)\n"
        "        { NVOCMP_failF = NVOCMP_failW = NVINTF_FAILURE; return NVINTF_FAILURE; }\n"
        "#ifndef NV_LINUX\n"
        "        if ((uintptr_t)NVOCMP_nvsAttrs.regionBase !=\n"
        "            (uintptr_t)(0xAE000u - FLASH_PAGE_SIZE * NVOCMP_NVPAGES))\n"
        "        { NVOCMP_failF = NVOCMP_failW = NVINTF_FAILURE; return NVINTF_FAILURE; }\n"
        "#endif\n"
        "        NVOCMP_nvHandle.nvSize = NVOCMP_nvsAttrs.regionSize/NVOCMP_nvsAttrs.sectorSize;",
        "nv_geometry_before_division")
    # Declare after the private types/prototypes, before initialization API.
    marker="static uint8_t NVOCMP_initNvApi(void *param)\n{"
    source=replace(source,marker,GUARD+"\n"+marker,"nv_precheck_definition")
    source=replace(source,"        NVOCMP_initNv(&NVOCMP_nvHandle);",
        "        NVOCMP_failW = p7_nv_precheck();\n"
        "        if (NVOCMP_failW != NVINTF_SUCCESS)\n"
        "        { NVOCMP_failF = NVOCMP_failW; return NVOCMP_failW; }\n"
        "        NVOCMP_initNv(&NVOCMP_nvHandle);","nv_precheck_before_writes")
    source=replace(source,
        "  case NVOCMP_FORCE_CLEAN :\n      // Erase All pages before start\n"
        "      for(pg = 0; pg < NVOCMP_NVSIZE; pg++)\n      {\n"
        "        NVOCMP_failW |= NVOCMP_erase(pNvHandle, pg);\n      }\n"
        "      // init should be followed by force clean",
        "  case NVOCMP_FORCE_CLEAN :\n"
        "      NVOCMP_failF = NVOCMP_failW = NVINTF_CORRUPT;\n"
        "      return; /* preserve ambiguous multi-page state for explicit recovery */",
        "nv_no_implicit_force_clean")
    # The two-page variant ignored scan errors. The multi-page variant checks them.
    source=replace(source,"    NVOCMP_scanPage(pNvHandle, pg, pPageInfo);",
        "    status = NVOCMP_scanPage(pNvHandle, pg, pPageInfo);\n"
        "    if (status != NVINTF_SUCCESS)\n"
        "    { NVOCMP_failF = NVOCMP_failW = status; return; }", "nv2_scan_status")
    source=replace(source,
        "    NVS_read(NVOCMP_nvsHandle, NVOCMP_FLASHOFFSET(pg, off), (uint8_t *)pBuf, len);",
        "    if (NVS_read(NVOCMP_nvsHandle, NVOCMP_FLASHOFFSET(pg, off), (uint8_t *)pBuf, len) != NVS_STATUS_SUCCESS)\n"
        "    {\n"
        "        memset(pBuf, 0, len);\n"
        "        NVOCMP_failF = NVOCMP_failW = NVINTF_FAILURE;\n"
        "    }", "nv_read_status")
    # A fatal read/initialization error must not permit later recovery mutations.
    for name in ("NVOCMP_write","NVOCMP_erase"):
        pattern=r"static uint8_t "+name+r"\([^;{]*\)\s*\{"
        matches=list(re.finditer(pattern,source))
        if len(matches)!=1: raise ValueError("NV_MUTATION_FUNCTION_NOT_UNIQUE")
        at=matches[0].end()
        source=source[:at]+"\n    if (NVOCMP_failF != NVINTF_SUCCESS) return NVOCMP_failF;\n"+source[at:]
        old=function(source,name)
        changed=replace(old,"    return(err);",
                        "    if (err != NVINTF_SUCCESS) NVOCMP_failF = err;\n    return(err);",
                        name+"_physical_failure_latch")
        source=replace(source,old,changed,name+"_latch")
    for name in ("NVOCMP_readItemApi","NVOCMP_readContItemApi",
                 "NVOCMP_createItemApi","NVOCMP_updateItemApi","NVOCMP_deleteItemApi",
                 "NVOCMP_writeItemApi","NVOCMP_compactNvApi","NVOCMP_eraseNvApi"):
        old=function(source,name)
        changed=replace(old,"NVOCMP_UNLOCK(err);",
                        "NVOCMP_UNLOCK(NVOCMP_failF != NVINTF_SUCCESS ? NVOCMP_failF : err);",
                        name+"_fatal_read_status")
        source=replace(source,old,changed,name)
    old=function(source,"NVOCMP_initNvApi")
    changed=replace(old,"return(NVOCMP_failW);",
                    "return(NVOCMP_failF != NVINTF_SUCCESS ? NVOCMP_failF : NVOCMP_failW);",
                    "nv_init_fatal_status")
    source=replace(source,old,changed,"nv_init_status")
    old=function(source,"NVOCMP_checkItem")
    changed=replace(old,"if(NVOCMP_failF == NVINTF_NOTREADY)",
                    "if(NVOCMP_failF != NVINTF_SUCCESS)","nv_api_fatal_gate")
    changed=replace(changed,"return(NVINTF_NOTREADY);","return(NVOCMP_failF);","nv_api_fatal_status")
    source=replace(source,old,changed,"nv_check_item_status")
    old=function(source,"NVOCMP_updateItemApi")
    changed=replace(old,"    if(err == NVINTF_SUCCESS)\n    {\n      // Create the new item",
                    "    if(err == NVINTF_SUCCESS)\n    {\n"
                    "      if (iHdr.len != len) { NVOCMP_UNLOCK(NVINTF_BADLENGTH); }\n"
                    "      // Create the new item", "nv_update_buffer_length")
    source=replace(source,old,changed,"nv_update_item_length")
    old=function(source,"NVOCMP_readContItemApi")
    changed=replace(old,"    *pSubId = NVOCMP_INVALIDSUBID;",
                    "    if (pSubId == NULL) return NVINTF_BADPARAM;\n"
                    "    *pSubId = NVOCMP_INVALIDSUBID;", "nv_match_output_pointer")
    changed=replace(changed,"    err = NVOCMP_checkItem(&id, rlen, &iHdr, NVOCMP_FINDSTRICT);",
                    "    if (clen > rlen || coff > rlen - clen) return NVINTF_BADOFFSET;\n"
                    "    err = NVOCMP_checkItem(&id, rlen, &iHdr, NVOCMP_FINDSTRICT);",
                    "nv_match_buffer_bound")
    source=replace(source,old,changed,"nv_match_api_bounds")
    old=function(source,"NVOCMP_doNextApi")
    changed=replace(old,"    // Sanitize inputs",
                    "    if (NVOCMP_failF != NVINTF_SUCCESS) return NVOCMP_failF;\n"
                    "    // Sanitize inputs", "nv_batch_fatal_gate")
    changed=replace(changed,"NVOCMP_UNLOCK(status);",
                    "NVOCMP_UNLOCK(NVOCMP_failF != NVINTF_SUCCESS ? NVOCMP_failF : status);",
                    "nv_batch_fatal_status")
    source=replace(source,old,changed,"nv_batch_status")
    source=replace(source,"          NVOCMP_readHeader(p, ofs, &iHdr, false);",
                   "          NVOCMP_readHeader(p, ofs, &iHdr, false);\n"
                   "          if (NVOCMP_failF != NVINTF_SUCCESS) return NVOCMP_failF;",
                   "nv_find_stops_on_failed_header_read")
    # Numeric-only evidence when a fatal status is assigned, including early
    # initialization before BIOS starts. No clock call, NV read or allocation.
    # Independent driver tests supply the observer macro and still execute the
    # complete real driver; native builds use the existing recorder guard.
    source=replace(source,'#include "ti/common/nv/crc.h"\n',
        '#include "ti/common/nv/crc.h"\n'
        '#ifndef P7_NV_DIAG_FAILURE\n#include "p7_crashdiag.h"\n'
        '#define P7_NV_DIAG_FAILURE(status, site) do { if ((status) != NVINTF_SUCCESS && '
        '(status) != NVINTF_NOTREADY) p7_diag_record(P7D_NV_FAILURE, '
        '((uint16_t)(site) << 8) | (uint8_t)(status), 0); } while (0)\n'
        '#endif\n'
        'static __attribute__((noinline)) uint8_t p7_nv_diag_status(uint8_t status, uint8_t site) { P7_NV_DIAG_FAILURE(status, site); return status; }\n',"nv_failure_observer")
    observations=0
    site_map={}
    def observe(match):
        nonlocal observations
        prefix=source[:match.start()].rsplit("\n",1)[-1]
        if "static uint8_t" in prefix: return match.group(0)
        observations+=1
        definitions=re.findall(r'(?m)^(?:static\s+)?(?:inline\s+)?(?:void|uint8_t|uint16_t|uint32_t|int)\s+'
            r'(NVOCMP_\w+)\s*\([^;{}]*\)\s*\{',source[:match.start()])
        owner=definitions[-1] if definitions else "NVOCMP_FLASHACCESS"
        site_map[observations]={"function_or_macro":owner,
            "operation":NV_FAILURE_OPERATIONS[observations-1],
            "status_expression":" ".join(match.group(1).split())}
        return "NVOCMP_failF = p7_nv_diag_status("+match.group(1).strip()+", "+str(observations)+");"
    source=re.sub(r'\bNVOCMP_failF\s*=(?!=)([^;]+);',observe,source)
    if observations!=16: raise ValueError("NV_FAILURE_ASSIGNMENT_COVERAGE_CHANGED")
    if sites is not None: sites.update(site_map)
    source+="\n__attribute__((noinline)) uint8_t p7_nv_persistence_ok(void) { return NVOCMP_failF == NVINTF_SUCCESS; }\n"
    return source


def apply(sdk:Path,output:Path):
    path=sdk/SOURCE;original=path.read_text();sites={};changed=patch(original,sites=sites)
    path.write_text(changed)
    report={"qualification":"P7_NV_UNKNOWN_FORMAT_PRESERVATION_SOURCE_ONLY",
            "flash_authorized":False,"source":SOURCE,
            "input_sha256":hashlib.sha256(original.encode()).hexdigest(),
            "output_sha256":hashlib.sha256(changed.encode()).hexdigest(),
            "nv_failure_argument":"high byte=site ID; low byte=NVINTF status; timestamp unavailable",
            "nv_failure_sites":sites}
    output.mkdir(parents=True,exist_ok=True)
    (output/"NV-HARDENING-SOURCE.json").write_text(json.dumps(report,indent=2)+"\n")
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();print(json.dumps(apply(a.sdk,a.out),sort_keys=True))
