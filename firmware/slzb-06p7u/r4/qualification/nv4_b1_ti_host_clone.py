#!/usr/bin/env python3
"""Compile the real *post-B1/post-NV4 bridge* NVOCMP bodies against RAM NVS.

Both pristine TI git blobs and the exact output hash of the source-only B1/NV4
bridge are mandatory. Production B1 admission.c is compiled in the same C TU;
all host writes/erases/compactions are refused, never redirected to hardware.
No private payloads, IDs, or keys are printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from nv4_ti_host_clone import transform as ti_transform, PREFIXES, git_blob, TI_NV_GIT_BLOB, TI_CRC_GIT_BLOB

# Identical compile-time selections to pinned TI 8.33 with four NV pages.
INDICES = {'static int8_t NVOCMP_findItem(': 1,
           'static uint8_t NVOCMP_scanPage(': 0,
           'static void NVOCMP_initNv(': 0}


def body(source: str, prefix: str, index: int) -> str:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'b1/tools'))
    from make_nv_backend_harness import choose
    return choose(source, prefix, index)


def transform(pristine: bytes, crc: bytes, bridged: bytes,
              expected_sha256: str, *, stock_base: int = 0xA6000) -> str:
    if type(stock_base) is not int or stock_base not in (0xA6000, 0xA4000):
        raise ValueError('B1_NV4_HOST_UNQUALIFIED_BASE')
    if git_blob(pristine) != TI_NV_GIT_BLOB or git_blob(crc) != TI_CRC_GIT_BLOB:
        raise ValueError('B1_NV4_PINNED_TI_OR_CRC_MISMATCH')
    if hashlib.sha256(bridged).hexdigest() != expected_sha256:
        raise ValueError('B1_NV4_BRIDGED_SOURCE_SHA256_MISMATCH')
    post = bridged.decode('utf-8').replace('\r\n', '\n')
    if (post.count('r4_nv4_admit(r4_nv4_nvs_read, NVOCMP_nvsHandle)') != 2 or
            post.count('b1_nv_existing_pair = 1u;') != 1 or
            post.count('NVOCMP_NVPAGES != R4_NV4_PAGES') != 2):
        raise ValueError('B1_NV4_BRIDGE_MARKERS_MISSING')
    pristine_source = pristine.decode('utf-8').replace('\r\n', '\n')
    host = ti_transform(pristine, crc)
    # The pristine RAM emulator predates stock-20260311 and defaults to
    # A6000. Bind its fake NVS attributes to the exact B1 bridge variant.
    old_base = 'a->regionBase=(void *)(uintptr_t)0xA6000u;'
    desired_base = f'a->regionBase=(void *)(uintptr_t)0x{stock_base:05X}u;'
    if host.count(old_base) != 1:
        raise ValueError('B1_NV4_HOST_NVS_REGION_ANCHOR_DRIFT')
    host = host.replace(old_base, desired_base, 1)
    expected_guard = f'(uintptr_t)NVOCMP_nvsAttrs.regionBase != (uintptr_t)0x{stock_base:05X}u'
    if post.count(expected_guard) != 1:
        raise ValueError('B1_NV4_HOST_BRIDGE_REGION_MISMATCH')
    for prefix in PREFIXES:
        index = INDICES.get(prefix, 0)
        old = body(pristine_source, prefix, index)
        new = body(post, prefix, index)
        if host.count(old) != 1:
            raise ValueError('B1_NV4_COMPILED_BODY_NOT_UNIQUE_' + prefix[:28])
        host = host.replace(old, new, 1)
    callback = body(post, 'static int r4_nv4_nvs_read(', 0)
    scratch = (
        'static uint8_t r4_nv4_repair_write_window;\n'
        'static uint8_t r4_nv4_nib_repair_pending;\n'
        'static uint8_t r4_nv4_nib_expected_startup;\n'
        'static uint32_t r4_nv4_nib_source_offset;\n'
        'static uint8_t r4_nv4_nib_data[R4_RECOVER_NIB_LENGTH];'
    )
    if post.count(scratch) != 1 or post.count(
        'static uint8_t r4_nv4_finish_nib_repair(void)') != 1:
        raise ValueError('B1_NV4_RESCUE_FW_MARKERS_MISSING')
    # This legacy RAM clone denies ALL writes and only tests ordinary
    # formed/uncommissioned/ambiguous init. Its maintenance helper is
    # deliberately a HOLD stub; real repair must be tested separately
    # against actual TI writer bodies and the native firmware build.
    addition = ('#include "b1_admission.c" /* B1 real sticky/candidate code */\n'
                '#include "nv4_readonly_admission.c" /* strict 4-page C code */\n'
                '#include "nv4_nib_repair_probe.c" /* read-only rescue gate */\n'
                + callback + '\n' + scratch + '\n'
                'static uint8_t r4_nv4_finish_nib_repair(void)\n'
                '{ return NVINTF_FAILURE; } /* writes prohibited by this clone */\n')
    marker = '#pragma GCC diagnostic push'
    if host.count(marker) != 1:
        raise ValueError('B1_NV4_HOST_PREAMBLE_DRIFT')
    host = host.replace(marker, addition + marker, 1)
    guard = '  good=good && code==NVINTF_SUCCESS && !write_calls && !erase_calls &&'
    if host.count(guard) != 1:
        raise ValueError('B1_NV4_HOST_OUTCOME_GUARD_DRIFT')
    host = host.replace(guard,
                        '  good=good && b1_nv_existing_header_candidate() &&\n'
                        '       !b1_nv_runtime_hold_active();\n' + guard, 1)
    return host


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--nvocmp-source', type=Path, required=True)
    ap.add_argument('--crc-source', type=Path, required=True)
    ap.add_argument('--bridged-source', type=Path, required=True)
    ap.add_argument('--bridge-receipt', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('B1_NV4_HOST_OUTPUT_EXISTS')
    receipt = json.loads(args.bridge_receipt.read_text())
    if (receipt.get('schema') != 'p7u-nv4-b1-source-only-v1' or
            receipt.get('flash_authorized') is not False):
        raise ValueError('B1_NV4_BRIDGE_RECEIPT_INVALID')
    stock_base = int(receipt.get('region_base', ''), 16)
    source = transform(args.nvocmp_source.read_bytes(), args.crc_source.read_bytes(),
                       args.bridged_source.read_bytes(), receipt['source_after_sha256'],
                       stock_base=stock_base)
    args.output.write_text(source, encoding='utf-8')
    print('B1_NV4_REAL_TI_RAM_CLONE_SOURCE_SHA256_' +
          hashlib.sha256(source.encode()).hexdigest())


if __name__ == '__main__':
    main()
