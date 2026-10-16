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
        "  if ( pZStackCfg && pZStackCfg->nvFps.deleteItem )\n  {\n    ret = SUCCESS;\n    uint32_t nvLen = 0;")
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
        changed = osal_changes(orig) if path.endswith("osal_nv.c") else nvocmp_changes(orig)
        prepared.append((target, changed.encode("utf-8"), path, expected))
    for target, changed, _, _ in prepared:
        target.write_bytes(changed)
    report = {"schema": "r4-b3-source-overlay-v1",
              "donor_sdk_commit": "3615ad5d3f4f271258d18a2f5ce1785064ff9a58",
              "production_flash_authorized": False, "unresolved": [
                  "NVOCMP_read ignores NVS_read status",
                  "osal_nv_init void ABI drops initialization failure",
                  "B1 HOLD_SECURITY integration unimplemented",
                  "counter reservation and interrupted compaction not proven"],
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
