"""Deterministic source-linked B1 NV safety overlay for pinned TI 8.33.

Only operates on GitHub Actions throwaway SDK checkout. Never opens radio, USB,
HA, Zigbee2MQTT or a real NV device. Abort on any unexpected preimage.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from patch_zdapp import patch as patch_zdapp
from patch_security import patch as patch_security, patch_zglobals, patch_startup, patch_osal_nv
from patch_host_api import patch as patch_host_api
from patch_nv_integrity import patch as patch_nv_integrity
import patch_management
import subprocess

SDK_NV = "source/ti/common/nv/nvocmp.c"
SDK_MAIN = "source/ti/zstack/startup/main.c"
SDK_ZMAC = "source/ti/zstack/zmac/f8w/zmac.c"
SDK_ZDAPP = "source/ti/zstack/stack/zdo/zd_app.c"
SDK_SECURITY = "source/ti/zstack/stack/zdo/zd_sec_mgr.c"
SDK_HOST_API = "source/ti/zstack/stack/api/zstacktask.c"
SDK_ZGLOBALS = "source/ti/zstack/stack/sys/zglobals.c"
SDK_STARTUP = "source/ti/zstack/startup/zstackstartup.c"
SDK_OSAL_NV = "source/ti/zstack/osal/osal_nv.c"
SHA_SECURITY = "65d7857cc9c62b75419807a8c0d03a62ec1a5574"
SHA_HOST_API = "d85758d2274097d2efe7c395e97e394f70fd352e"
SHA_ZGLOBALS = "0a1d7d2a61a88d1a6bb6e4bc5e359e71e1719024"
SHA_STARTUP = "72073f7a90d3de183533e84c3396e239343731e5"
SHA_OSAL_NV = "65c7667475627989cbe2e3f5fdd46335b50eb660"
HERDSMAN_FILE = ".b1-prerequisites/herdsman-definition.ts"
SHA_NV = "01b2b0827d278c10c012b33e5791e53bc5662f10"
SHA_MAIN = "608adc97370be3910a96f5dcc356d0feffb79d70"
SHA_ZMAC = "38edebba04b31a416f64949ef991aa990dd99dba"
SHA_ZDAPP = "d67a7798a3e6a8681faddebf5e4b87b4b4c60421"


def git_blob_sha(text):
    raw = text.encode("utf-8")
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def replace_once(text, before, after, name):
    if text.count(before) != 1:
        raise RuntimeError("%s anchor not unique (got %d)" % (name, text.count(before)))
    return text.replace(before, after, 1)


def overlay(sdk, b1_dir):
    src_nv = sdk / SDK_NV
    src_main = sdk / SDK_MAIN
    src_zmac = sdk / SDK_ZMAC
    src_zdapp = sdk / SDK_ZDAPP
    src_security = sdk / SDK_SECURITY
    src_host_api = sdk / SDK_HOST_API
    src_zglobals = sdk / SDK_ZGLOBALS
    src_startup = sdk / SDK_STARTUP
    src_osal_nv = sdk / SDK_OSAL_NV
    security = src_security.read_text(encoding="utf-8")
    host_api = src_host_api.read_text(encoding="utf-8")
    zglobals = src_zglobals.read_text(encoding="utf-8")
    startup = src_startup.read_text(encoding="utf-8")
    osal_nv = src_osal_nv.read_text(encoding="utf-8")
    source = src_nv.read_text(encoding="utf-8")
    main = src_main.read_text(encoding="utf-8")
    zmac = src_zmac.read_text(encoding="utf-8")
    zdapp = src_zdapp.read_text(encoding="utf-8")
    if (git_blob_sha(source) != SHA_NV or git_blob_sha(main) != SHA_MAIN
            or git_blob_sha(zmac) != SHA_ZMAC
            or git_blob_sha(zdapp) != SHA_ZDAPP
            or git_blob_sha(security) != SHA_SECURITY
            or git_blob_sha(host_api) != SHA_HOST_API
            or git_blob_sha(zglobals) != SHA_ZGLOBALS
            or git_blob_sha(startup) != SHA_STARTUP
            or git_blob_sha(osal_nv) != SHA_OSAL_NV):
        raise RuntimeError("BLOCKED: pinned TI upstream source SHA mismatch; no patch applied")
    if not (b1_dir / "b1_admission.c").is_file() or not (b1_dir / "b1_admission.h").is_file():
        raise RuntimeError("BLOCKED: missing B1 linked admission C/H files")

    management_sources, management_receipt = patch_management.prepare(
        sdk, (sdk / HERDSMAN_FILE).read_text(encoding="utf-8"))
    source_sha = os.environ.get("B1_SOURCE_SHA") or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True).strip()
    if len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha):
        raise RuntimeError("BLOCKED: exact source SHA required for public build digest")
    digest_bytes = ", ".join("0x" + source_sha[i:i + 2] for i in range(0, 8, 2))

    # ZMac wrappers in the pinned projectspec reach the actual MAC request
    # API. Gating this layer covers new APP-origin RF requests after NV faults,
    # but NOT ROM-originated requests or already queued frames.
    zmac = replace_once(
        zmac, '#include "mac_api.h"',
        '#include "mac_api.h"\n'
        'extern int b1_nv_runtime_hold_active(void);',
        "linked ZMac include")
    for signature, refused in (
        ("uint8_t ZMacAssociateReq( ZMacAssociateReq_t *pData )", "MAC_NO_RESOURCES"),
        ("uint8_t ZMacDisassociateReq( ZMacDisassociateReq_t *pData )", "MAC_NO_RESOURCES"),
        ("uint8_t ZMacScanReq( ZMacScanReq_t *pData )", "MAC_NO_RESOURCES"),
        ("uint8_t ZMacStartReq( ZMacStartReq_t *pData )", "MAC_NO_RESOURCES"),
        ("uint8_t ZMacSyncReq( ZMacSyncReq_t *pData )", "MAC_NO_RESOURCES"),
        ("uint8_t ZMacPollReq( ZMacPollReq_t *pData )", "MAC_NO_RESOURCES"),
        ("uint8_t ZMacDataReqSec( ZMacDataReq_t *pData, applySecCB_t secCB )", "MAC_NO_RESOURCES"),
        ("void ZMacSendNoData( uint16_t DstAddr, uint16_t DstPANId )", ""),
    ):
        guard = ("  if (b1_nv_runtime_hold_active()) return " + refused + ";"
                 if refused else "  if (b1_nv_runtime_hold_active()) return;")
        zmac = replace_once(zmac, signature + "\n{",
                            signature + "\n{\n" + guard,
                            "ZMac RF admission " + signature)

    # Compile the actual admission C as part of the SDK's nvocmp.c TU, avoiding
    # any CCS projectspec alias/new compile-unit ambiguity.
    source = replace_once(source, '#include "ti/common/nv/crc.h"',
                          '#include "ti/common/nv/crc.h"\n#ifndef NV_LINUX\n'
                          '#define B1_MANAGEMENT_ENABLED 1\n'
                          '#define B1_BUILD_DIGEST_BYTES ' + digest_bytes + '\n'
                          '#include "b1_management.c"\n'
                          '#include "b1_admission.c" /* B1 source-linked native admission */\n#endif',
                          "NV includes")

    # This callback is in the same TU and uses the existing single TI NVS
    # handle. NVS region base is NOT exposed in NVS_Attrs: board config is
    # independently checked by B0 native generated SysConfig receipt.
    insertion = (
        "#ifndef NV_LINUX\n"
        "static int_fast16_t b1_nv_nvs_read(void *opaque, uint32_t off,\n"
        "                                   uint8_t *data, uint32_t len)\n"
        "{\n"
        "    return NVS_read((NVS_Handle)opaque, off, data, len);\n"
        "}\n"
        "#endif\n\n"
    )
    source = replace_once(source, "static uint8_t NVOCMP_initNvApi(void *param)\n{",
                          insertion + "static uint8_t NVOCMP_initNvApi(void *param)\n{",
                          "NVOCMP init function")

    # TI's priority mutex allocation is unchecked in the ZNP path.
    # A NULL gate would cause NVOCMP_LOCK()/UNLOCK() to fail unpredictably.
    source = replace_once(
        source,
        "        NVOCMP_gMutexPri = GateMutexPri_create(&gateParams, NULL);",
        "        NVOCMP_gMutexPri = GateMutexPri_create(&gateParams, NULL);\n"
        "        if (NVOCMP_gMutexPri == NULL)\n"
        "        {\n"
        "            NVOCMP_failF = NVINTF_FAILURE;\n"
        "            NVOCMP_failW = NVINTF_FAILURE;\n"
        "            return NVOCMP_failF; /* B1 N08: no task gate */\n"
        "        }",
        "NVOCMP mutex allocation failure")

    # The original implementation dereferences NVS_open(NULL) *before* checking.
    # Repair in the real compiled donor body, not a mock or commentary.
    source = replace_once(
        source,
        "        NVOCMP_nvsHandle = NVS_open(NVOCMP_NVS_INDEX, param);\n\n"
        "        // Get NV hardware attributes\n"
        "        NVS_getAttrs(NVOCMP_nvsHandle,&NVOCMP_nvsAttrs);",
        "        NVOCMP_nvsHandle = NVS_open(NVOCMP_NVS_INDEX, param);\n"
        "        if (NVOCMP_nvsHandle == NULL)\n"
        "        {\n"
        "            NVOCMP_failF = NVINTF_FAILURE;\n"
        "            NVOCMP_failW = NVINTF_FAILURE;\n"
        "            return NVOCMP_failF; /* B1 N04: never dereference NULL */\n"
        "        }\n"
        "        // Only now is getAttrs safe.\n"
        "        NVS_getAttrs(NVOCMP_nvsHandle,&NVOCMP_nvsAttrs);",
        "NVS_open NULL-before-getAttrs")

    # Check actual NVS geometry BEFORE the donor divides by sectorSize.
    # The original checks after division; sectorSize=0 can fault first.
    source = replace_once(
        source,
        "        NVOCMP_nvHandle.nvSize = NVOCMP_nvsAttrs.regionSize/NVOCMP_nvsAttrs.sectorSize;",
        "        if (NVOCMP_NVS_INDEX != 0 ||\n"
        "            NVOCMP_NVPAGES != B1_NV2_PAGE_COUNT ||\n"
        "            NVOCMP_nvsAttrs.sectorSize != B1_NV2_PAGE_SIZE ||\n"
        "            NVOCMP_nvsAttrs.regionSize != B1_NV2_REGION_SIZE ||\n"
        "            (uintptr_t)NVOCMP_nvsAttrs.regionBase != (uintptr_t)0xAA000u)\n"
        "        {\n"
        "            NVOCMP_failF = NVINTF_FAILURE;\n"
        "            NVOCMP_failW = NVINTF_FAILURE;\n"
        "            return NVOCMP_failF; /* B1 N03: no divide by zero/CCFG */\n"
        "        }\n"
        "        NVOCMP_nvHandle.nvSize = NVOCMP_nvsAttrs.regionSize/NVOCMP_nvsAttrs.sectorSize;",
        "pre-division exact NV2 address/sector geometry")

    # The late NULL check is now unreachable; remove to ensure the source
    # never claims a NULL handle could survive the geometry calculations.
    source = replace_once(
        source,
        "        // Confirm that the NVS region opened properly\n"
        "        if (NVOCMP_nvsHandle == NULL)\n"
        "        {\n"
        "            NVOCMP_failF = NVINTF_FAILURE;\n"
        "            NVOCMP_ASSERT(false,\"NVS HANDLE IS NULL\")\n"
        "            NVOCMP_EXCEPTION(pg, NVINTF_NOTREADY);\n"
        "            return(NVOCMP_failF);\n"
        "        }\n\n",
        "", "remove dead late NULL check")

    # Region/page check has to run before calling the bounded read-only
    # scanner. No writes, erase, recovery, migration, or key generation can
    # occur in the rejected path. Header candidate is NOT security proof.
    region_anchor = "        // Initialize force compaction to false\n"
    guard = (
        "#ifndef NV_LINUX\n"
        "        if (NVOCMP_NVS_INDEX != 0 ||\n"
        "            NVOCMP_NVPAGES != B1_NV2_PAGE_COUNT ||\n"
        "            NVOCMP_nvsAttrs.sectorSize != B1_NV2_PAGE_SIZE ||\n"
        "            NVOCMP_nvsAttrs.regionSize != B1_NV2_REGION_SIZE)\n"
        "        {\n"
        "            NVOCMP_failF = NVINTF_FAILURE;\n"
        "            NVOCMP_failW = NVINTF_FAILURE;\n"
        "            return NVOCMP_failF; /* B1 N03 */\n"
        "        }\n"
        "        {\n"
        "            b1_nv_probe_result admission = b1_nv_probe(\n"
        "                b1_nv_nvs_read, NVOCMP_nvsHandle,\n"
        "#ifdef B1_FACTORY_BOOT_AUTHORIZED\n"
        "                true);\n"
        "#else\n"
        "                false);\n"
        "#endif\n"
        "            if (admission.code != B1_NV2_HEADER_CANDIDATE &&\n"
        "                admission.code != B1_NV_FACTORY_AUTHORIZED)\n"
        "            {\n"
        "                NVOCMP_failF = NVINTF_FAILURE;\n"
        "                NVOCMP_failW = NVINTF_FAILURE;\n"
        "                return NVOCMP_failF;\n"
        "            }\n"
        "        }\n"
        "#endif /* !NV_LINUX */\n\n"
    )
    source = replace_once(source, region_anchor, guard + region_anchor, "admission before NVOCMP_init")

    # TI originally discarded read failures, so corruption could masquerade
    # as NOTFOUND. Make backend failure fatal and reject later media mutation.
    source = replace_once(
        source,
        "    NVS_read(NVOCMP_nvsHandle, NVOCMP_FLASHOFFSET(pg, off), (uint8_t *)pBuf, len);",
        "    if (NVS_read(NVOCMP_nvsHandle, NVOCMP_FLASHOFFSET(pg, off),\n"
        "                 (uint8_t *)pBuf, len) != NVS_STATUS_SUCCESS)\n"
        "    {\n"
        "        memset(pBuf, 0, len); /* poisoned bytes MUST NOT be trusted */\n"
        "        NVOCMP_failF = NVINTF_FAILURE;\n"
        "        NVOCMP_failW = NVINTF_FAILURE;\n"
        "        b1_nv_runtime_hold_latch();\n"
        "    }",
        "NVOCMP_read real checked backend")

    # A backend read error must also reach the public NV item read status,
    # not just poison the buffer and set a hidden fatal flag.
    source = replace_once(
        source,
        "              NVOCMP_read(iHdr->hpage, dOfs, (uint8_t *)pBuf, len);",
        "              NVOCMP_read(iHdr->hpage, dOfs, (uint8_t *)pBuf, len);\n"
        "              if (NVOCMP_failF != NVINTF_SUCCESS)\n"
        "              {\n"
        "                  err = NVINTF_FAILURE; /* B1 N05: no fake success */\n"
        "              }",
        "NVOCMP item API read failure propagation")

    # Further writes/erases do not reach NVS once any fatal read fault occurs.
    source = replace_once(
        source,
        "static uint8_t NVOCMP_write(uint8_t dstPg, uint16_t off, uint8_t *pBuf, uint16_t len)\n{\n"
        "    uint8_t err = NVINTF_SUCCESS;",
        "static uint8_t NVOCMP_write(uint8_t dstPg, uint16_t off, uint8_t *pBuf, uint16_t len)\n{\n"
        "    if (NVOCMP_failF != NVINTF_SUCCESS) return NVINTF_FAILURE;\n"
        "    uint8_t err = NVINTF_SUCCESS;",
        "no writes after fatal read")

    source = replace_once(
        source,
        "static uint8_t NVOCMP_erase(NVOCMP_nvHandle_t *pNvHandle, uint8_t dstPg)\n{\n"
        "    uint8_t err = NVINTF_SUCCESS;",
        "static uint8_t NVOCMP_erase(NVOCMP_nvHandle_t *pNvHandle, uint8_t dstPg)\n{\n"
        "    if (NVOCMP_failF != NVINTF_SUCCESS) return NVINTF_FAILURE;\n"
        "    uint8_t err = NVINTF_SUCCESS;",
        "no erase after fatal read")

    # Sticky failure of a real NVS mutation must block later media writes
    # and fresh ZMac-origin RF requests even if failW is reset later.
    source = replace_once(
        source,
        "    if (nvsRes < 0)\n"
        "    {\n"
        "        err = NVINTF_FAILURE;\n"
        "    }",
        "    if (nvsRes < 0)\n"
        "    {\n"
        "        err = NVINTF_FAILURE;\n"
        "        NVOCMP_failF = NVINTF_FAILURE;\n"
        "        NVOCMP_failW = NVINTF_FAILURE;\n"
        "        b1_nv_runtime_hold_latch();\n"
        "    }",
        "NVOCMP_write real NVS error latch")
    source = replace_once(
        source,
        "        if (nvsRes < 0)\n"
        "        {\n"
        "          err = NVINTF_FAILURE;\n"
        "        }",
        "        if (nvsRes < 0)\n"
        "        {\n"
        "          err = NVINTF_FAILURE;\n"
        "          NVOCMP_failF = NVINTF_FAILURE;\n"
        "          NVOCMP_failW = NVINTF_FAILURE;\n"
        "          b1_nv_runtime_hold_latch();\n"
        "        }",
        "NVOCMP_erase real NVS error latch")

    # The original app ignores initNV's failure and creates the Zigbee stack.
    # B1 must not do that. This path is deliberately NOT_OBSERVABLE until the
    # native one-owner NPI-without-stack dependency gate is independently proved.
    main = replace_once(
        main,
        "        zstack_user0Cfg.nvFps.initNV(NULL);",
        "        if (zstack_user0Cfg.nvFps.initNV(NULL) != NVINTF_SUCCESS)\n"
        "        {\n"
        "            /* B1 fail-closed: never initialize the network on bad NV.\n"
        "             * No NPI/SYS response can be promised on this path. */\n"
        "            return 1;\n"
        "        }",
        "main failed NV init must not start Zigbee stack")

    # Donor's if(initNV) silently continues if the function pointer is absent.
    # A missing NV driver cannot be treated as factory-new or RF-safe.
    main = replace_once(
        main,
        "        }\n"
        "    }\n\n"
        "#ifdef ZSTACK_GPD",
        "        }\n"
        "    }\n"
        "    else\n"
        "    {\n"
        "        return 1; /* B1 N08: no NV API means no Zigbee startup */\n"
        "    }\n\n"
        "#ifdef ZSTACK_GPD",
        "main absent NV init function fail-closed")

    source = patch_nv_integrity(source)

    # Runtime NWK counter continuity: persist, read back, then publish.
    zdapp = patch_zdapp(zdapp)
    security = patch_security(security)
    host_api = patch_host_api(host_api)
    zglobals = patch_zglobals(zglobals)
    startup = patch_startup(startup)
    osal_nv = patch_osal_nv(osal_nv)

    main = replace_once(main, '#include "nvocmp.h"',
                        '#include "nvocmp.h"\n#include "b1_management.h"', "main management header")
    main = replace_once(main, "            return 1;",
        "            b1_management_hold_nv(B1_ERROR_NV_INIT);\n"
        "#if defined(NPI) && defined(ZNP_NPI)\n"
        "            goto b1_start_npi; /* no stack task, original NPI owner */\n"
        "#else\n            return 1;\n#endif", "boot HOLD original NPI path")
    main = replace_once(main,
        "        return 1; /* B1 N08: no NV API means no Zigbee startup */",
        "        b1_management_hold_nv(B1_ERROR_NV_API);\n"
        "#if defined(NPI) && defined(ZNP_NPI)\n"
        "        goto b1_start_npi;\n#else\n        return 1;\n#endif",
        "absent NV API original NPI path")
    main = replace_once(main, "#ifdef NPI\n    extern void NPITask_createTask(void);",
        "#if defined(NPI) && defined(ZNP_NPI)\nb1_start_npi: ;\n#endif\n"
        "#ifdef NPI\n    extern void NPITask_createTask(void);", "original NPI task label")
    main = replace_once(main,
        "    npiInitializationMutexHandle = Semaphore_handle(&npiInitializationMutex);",
        "    npiInitializationMutexHandle = Semaphore_handle(&npiInitializationMutex);\n"
        "    if (npiInitializationMutexHandle == NULL)\n"
        "    {\n        b1_management_transport_failed(B1_ERROR_NPI_SEMAPHORE);\n"
        "        return 1; /* scheduler has not started */\n    }",
        "boot NPI semaphore failure")
    source = replace_once(source, "            if (admission.code != B1_NV2_HEADER_CANDIDATE &&",
        "            b1_management_note_nv_probe((uint8_t)admission.code);\n"
        "            if (admission.code != B1_NV2_HEADER_CANDIDATE &&", "record NV layout without secrets")
    source = replace_once(source,
        "                return NVOCMP_failF;\n            }\n        }\n#endif /* !NV_LINUX */",
        "                b1_management_hold_nv((uint8_t)admission.code);\n"
        "                return NVOCMP_failF;\n            }\n"
        "            if (admission.code == B1_NV2_HEADER_CANDIDATE)\n"
        "                b1_management_note_nv_candidate();\n"
        "        }\n#endif /* !NV_LINUX */", "NV admission HOLD first error")
    for anchor, reason in (
        ("            return NVOCMP_failF; /* B1 N08: no task gate */", "B1_ERROR_NV_MUTEX"),
        ("            return NVOCMP_failF; /* B1 N04: never dereference NULL */", "B1_ERROR_NV_OPEN"),
        ("            return NVOCMP_failF; /* B1 N03: no divide by zero/CCFG */", "B1_ERROR_NV_GEOMETRY"),
    ):
        source = replace_once(source, anchor,
            "            b1_management_hold_nv(" + reason + ");\n" + anchor, "NV reason " + reason)

    # All preflight validation completed before writing any workspace file.
    (src_nv.parent / "b1_admission.h").write_bytes((b1_dir / "b1_admission.h").read_bytes())
    (src_nv.parent / "b1_admission.c").write_bytes((b1_dir / "b1_admission.c").read_bytes())
    for name in ("b1_management.c", "b1_management.h"):
        (src_nv.parent / name).write_bytes((b1_dir / name).read_bytes())
    for directory in (sdk / "source/ti/zstack/mt", sdk / "source/ti/zstack/npi", src_main.parent):
        (directory / "b1_management.h").write_bytes((b1_dir / "b1_management.h").read_bytes())
    for relative, text in management_sources.items():
        (sdk / relative).write_text(text, encoding="utf-8")
    src_nv.write_text(source, encoding="utf-8")
    src_main.write_text(main, encoding="utf-8")
    src_zmac.write_text(zmac, encoding="utf-8")
    src_zdapp.write_text(zdapp, encoding="utf-8")
    src_security.write_text(security, encoding="utf-8")
    src_host_api.write_text(host_api, encoding="utf-8")
    src_zglobals.write_text(zglobals, encoding="utf-8")
    src_startup.write_text(startup, encoding="utf-8")
    src_osal_nv.write_text(osal_nv, encoding="utf-8")
    return {
        "schema": "r4-b1-admission-overlay-v2",
        "source_sha": source_sha,
        "management": management_receipt,
        "upstream_nv_blob": SHA_NV,
        "upstream_main_blob": SHA_MAIN,
        "upstream_zmac_blob": SHA_ZMAC,
        "upstream_zdapp_blob": SHA_ZDAPP,
        "upstream_security_blob": SHA_SECURITY,
        "upstream_host_api_blob": SHA_HOST_API,
        "upstream_zglobals_blob": SHA_ZGLOBALS,
        "modified_security_sha256": hashlib.sha256(security.encode()).hexdigest(),
        "modified_host_api_sha256": hashlib.sha256(host_api.encode()).hexdigest(),
        "modified_zglobals_sha256": hashlib.sha256(zglobals.encode()).hexdigest(),
        "modified_startup_sha256": hashlib.sha256(startup.encode()).hexdigest(),
        "modified_osal_nv_sha256": hashlib.sha256(osal_nv.encode()).hexdigest(),
        **{"management_source_%d_sha256" % i: hashlib.sha256(text.encode()).hexdigest()
           for i, (relative, text) in enumerate(management_sources.items())},
        "additional_source_bindings": {
            **{"management_source_%d_sha256" % i: relative
               for i, relative in enumerate(management_sources)},
            "modified_security_sha256": SDK_SECURITY,
            "modified_host_api_sha256": SDK_HOST_API,
            "modified_zglobals_sha256": SDK_ZGLOBALS,
            "modified_startup_sha256": SDK_STARTUP,
            "modified_osal_nv_sha256": SDK_OSAL_NV,
        },
        "additional_required_functions": ["b1_sec_validate_restored", "APSME_TCLinkKeyInit",
            "b1_management_mt_filter", "b1_security_runtime_hold_latch",
            "b1_management_npi_initialized",
            "b1_management_note_zdo_state", "b1_sec_restored_network_validated",
            "ZDApp_ChangeState"],
        "modified_zdapp_sha256": hashlib.sha256(zdapp.encode()).hexdigest(),
        "modified_zmac_sha256": hashlib.sha256(zmac.encode()).hexdigest(),
        "modified_nv_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "modified_main_sha256": hashlib.sha256(main.encode()).hexdigest(),
        "mode": "B1_SOURCE_ONLY_NOT_PHYSICALLY_TESTED",
        "preflight": "read only (0x4000), no NVS_write/NVS_erase",
        "factory_boot": "unauthorized by default",
        "hold_transport": "existing NPI task only on early NV HOLD; physical UART/RF NOT_MEASURED",
        "security_and_mac_tx": "NV/security HOLD gates linked ZMac new submissions; restored-security/counter checks source-linked; ROM and queued/in-flight RF NOT_MEASURED"
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdk", type=Path, required=True)
    ap.add_argument("--receipt", type=Path, required=True)
    args = ap.parse_args()
    b1_dir = Path(__file__).resolve().parents[1]
    result = overlay(args.sdk, b1_dir)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
