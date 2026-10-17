#!/usr/bin/env python3
"""Exact-source TI 8.33 NV3/NV5 hosted-only experimental profile.

Never rewrite firmware images, radio NV, live backup or board. Patch three
pinned *source* inputs in a throwaway GitHub Actions checkout. No guessed
20260310/11 stock compatibility and no automatic installer.
"""
import argparse
import hashlib
import json
from pathlib import Path

PINNED = {
    "linker": ("source/ti/zstack/boards/cc13x2x7_cc26x2x7/"
               "cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd",
               "1e5777c21f354566e6479c3cb7d97bb51637159b"),
    "project": ("examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/"
                "ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec",
                "4d05569e6a4164ce3c1d682b4ee9865f6a1d23be"),
    "syscfg": ("examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/znp.syscfg",
               "463216ecaa895654cbfb85bd3becd838e49ae5bf"),
}
FLASH_LAST = 0xAE000
PAGE_BYTES = 0x2000


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def once(src, old, new):
    if src.count(old) != 1:
        raise ValueError("B3 native source mismatch or repeated profile")
    return src.replace(old, new, 1)


def profile(pages):
    if pages not in (3, 5):
        raise ValueError("NV2 stays the untouched B0 native profile")
    first = FLASH_LAST - pages * PAGE_BYTES
    return dict(pages=pages, flash_app_start=0, flash_app_end=first,
                nv_start=first, nv_size=pages*PAGE_BYTES,
                nv_end=FLASH_LAST, ccfg_start=FLASH_LAST,
                ccfg_end=FLASH_LAST + PAGE_BYTES,
                flash_removed_vs_b0=(pages-2)*PAGE_BYTES)


def prepare(sdk, examples, pages):
    target = profile(pages)
    roots = {"linker": Path(sdk).resolve(),
             "project": Path(examples).resolve(), "syscfg": Path(examples).resolve()}
    prepared = {}
    for kind, (path, expected) in PINNED.items():
        file = (roots[kind] / path).resolve()
        if not file.is_relative_to(roots[kind]) or not file.is_file():
            raise ValueError("B3 file outside pinned source root")
        raw = file.read_bytes()
        if git_blob(raw) != expected:
            raise ValueError("B3 rejected unexpected upstream Git blob: " + kind)
        text = raw.decode("utf-8")
        if kind == "linker":
            text = once(text, "#define FLASH_SIZE              0xAA000",
                        "#define FLASH_SIZE              0x%X" % target["flash_app_end"])
            text = once(text, "#define FLASH_NV_BASE           0xAA000",
                        "#define FLASH_NV_BASE           0x%X" % target["nv_start"])
            text = once(text, "#define FLASH_NV_SIZE           0x4000",
                        "#define FLASH_NV_SIZE           0x%X" % target["nv_size"])
        elif kind == "project":
            text = once(text, "-DNVOCMP_NVPAGES=2",
                        "-DNVOCMP_NVPAGES=%d" % pages)
            text = once(text, "--define=NVOCMP_NVPAGES=2",
                        "--define=NVOCMP_NVPAGES=%d" % pages)
        else:
            text = once(text,
                '    NVS1.internalFlash.regionBase = 0xAA000;\r\n'
                '    NVS1.internalFlash.regionSize = 0x4000;',
                '    NVS1.internalFlash.regionBase = 0x%X;\r\n'
                '    NVS1.internalFlash.regionSize = 0x%X;' %
                    (target["nv_start"],target["nv_size"]))
        prepared[kind] = (file, text.encode("utf-8"), expected)
    # Only write once *all* preimages and source anchors have passed.
    for path, raw, _ in prepared.values():
        path.write_bytes(raw)
    return {
        "schema": "r4-b3-experimental-native-layout-v1",
        "status": "EXPERIMENTAL_NOT_FLASH_READY",
        "native_linker_required": True,
        "source_sdk": "3615ad5d3f4f271258d18a2f5ce1785064ff9a58",
        "source_examples": "87ff5b638b632050228a7504f35cf3b95581c278",
        "geometry": target,
        "fields": {name: {"blob_preimage": original,
                          "modified_sha256": hashlib.sha256(raw).hexdigest()}
                   for name, (_,raw,original) in prepared.items()},
        "flash_authorized": False, "migration_authorized": False}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--sdk",type=Path,required=True)
    parser.add_argument("--examples",type=Path,required=True)
    parser.add_argument("--pages",type=int,choices=(3,5),required=True)
    parser.add_argument("--receipt",type=Path,required=True)
    args=parser.parse_args()
    result=prepare(args.sdk,args.examples,args.pages)
    args.receipt.parent.mkdir(parents=True,exist_ok=True)
    args.receipt.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
