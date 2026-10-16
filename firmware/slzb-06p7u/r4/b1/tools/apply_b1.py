"""Deterministic source-linked B1 NV safety overlay for pinned TI 8.33.

Only operates on GitHub Actions throwaway SDK checkout. Never opens radio, USB,
HA, Zigbee2MQTT or a real NV device. Abort on any unexpected preimage.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

SDK_NV = "source/ti/common/nv/nvocmp.c"
SDK_MAIN = "source/ti/zstack/startup/main.c"
SHA_NV = "01b2b0827d278c10c012b33e5791e53bc5662f10"
SHA_MAIN = "608adc97370be3910a96f5dcc356d0feffb79d70"


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
    source = src_nv.read_text(encoding="utf-8")
    main = src_main.read_text(encoding="utf-8")
    if git_blob_sha(source) != SHA_NV or git_blob_sha(main) != SHA_MAIN:
        raise RuntimeError("BLOCKED: pinned TI upstream source SHA mismatch; no patch applied")
    if not (b1_dir / "b1_admission.c").is_file() or not (b1_dir / "b1_admission.h").is_file():
        raise RuntimeError("BLOCKED: missing B1 linked admission C/H files")

    # Compile the actual admission C as part of the SDK's nvocmp.c TU, avoiding
    # any CCS projectspec alias/new compile-unit ambiguity.
    source = replace_once(source, '#include "ti/common/nv/crc.h"',
                          '#include "ti/common/nv/crc.h"\n#ifndef NV_LINUX\n#include "b1_admission.c" /* B1 source-linked native admission */\n#endif',
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

    # All preflight validation completed before writing any workspace file.
    (src_nv.parent / "b1_admission.h").write_bytes((b1_dir / "b1_admission.h").read_bytes())
    (src_nv.parent / "b1_admission.c").write_bytes((b1_dir / "b1_admission.c").read_bytes())
    src_nv.write_text(source, encoding="utf-8")
    src_main.write_text(main, encoding="utf-8")
    return {
        "schema": "r4-b1-admission-overlay-v1",
        "upstream_nv_blob": SHA_NV,
        "upstream_main_blob": SHA_MAIN,
        "modified_nv_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "modified_main_sha256": hashlib.sha256(main.encode()).hexdigest(),
        "mode": "B1_SOURCE_ONLY_NOT_PHYSICALLY_TESTED",
        "preflight": "read only (0x4000), no NVS_write/NVS_erase",
        "factory_boot": "unauthorized by default",
        "hold_transport": "NOT_OBSERVABLE pending NPI independent gate",
        "security_and_mac_tx": "BLOCKED_NOT_IMPLEMENTED"
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
