#!/usr/bin/env python3
"""Strict source-only conversion of a PINNED, already-applied B1 NV2 overlay.

The existing P7U NVOCMP v3 four-page network is never factory-formatted here.
Before TI init, run a read-only bounded CRC/layout scan; on success preserve
B1's existing-network signal and prohibit all init-time NV writes. Rejection
retains the B1 sticky HOLD and its existing NPI-without-Zigbee path.

Inputs MUST be disposable *post-B1* SDK files created by the exact-pinned B1
overlay. This code does not operate on hardware, and never authorizes flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from nv4_source_overlay import STOCK_BASE, STOCK_SIZE, STOCK_PAGES


# TI 8.33 nvocmp.c documents this optional flag as erasing/reformatting
# *all* NV pages when compaction encounters an error. It is inadmissible for
# fitted, retained stock NV4: a failed restore must HOLD, not reformat.
DESTRUCTIVE_COMPACTION_DENIAL = (
    '#if defined(NVOCMP_RECOVER_FROM_COMPACT_FAILURE)\n'
    '#error R4_NV4_DESTRUCTIVE_COMPACTION_REFORMAT_FORBIDDEN_PRESERVE_STOCK_NV\n'
    '#endif\n'
)

INCLUDE_FROM = '#include "b1_admission.c" /* B1 source-linked native admission */'
INCLUDE_TO = (INCLUDE_FROM + '\n'
              '#include "nv4_readonly_admission.c" /* stock P7U read-only NV4 */')

PRE_DIVISION_NV2 = (
    'NVOCMP_NVPAGES != B1_NV2_PAGE_COUNT ||\n'
    '            NVOCMP_nvsAttrs.sectorSize != B1_NV2_PAGE_SIZE ||\n'
    '            NVOCMP_nvsAttrs.regionSize != B1_NV2_REGION_SIZE ||\n'
    '            (uintptr_t)NVOCMP_nvsAttrs.regionBase != (uintptr_t)0xAA000u'
)
PRE_DIVISION_NV4 = (
    'NVOCMP_NVPAGES != R4_NV4_PAGES ||\n'
    '            NVOCMP_nvsAttrs.sectorSize != R4_NV4_PAGE_SIZE ||\n'
    '            NVOCMP_nvsAttrs.regionSize != R4_NV4_REGION_SIZE ||\n'
    '            (uintptr_t)NVOCMP_nvsAttrs.regionBase != (uintptr_t)0xA6000u'
)
POST_DIVISION_NV2 = (
    'NVOCMP_NVPAGES != B1_NV2_PAGE_COUNT ||\n'
    '            NVOCMP_nvsAttrs.sectorSize != B1_NV2_PAGE_SIZE ||\n'
    '            NVOCMP_nvsAttrs.regionSize != B1_NV2_REGION_SIZE)'
)
POST_DIVISION_NV4 = (
    'NVOCMP_NVPAGES != R4_NV4_PAGES ||\n'
    '            NVOCMP_nvsAttrs.sectorSize != R4_NV4_PAGE_SIZE ||\n'
    '            NVOCMP_nvsAttrs.regionSize != R4_NV4_REGION_SIZE)'
)

OLD_ADMISSION = '''        {
            b1_nv_probe_result admission = b1_nv_probe(
                b1_nv_nvs_read, NVOCMP_nvsHandle,
#ifdef B1_FACTORY_BOOT_AUTHORIZED
                true);
#else
                false);
#endif
            b1_management_note_nv_probe((uint8_t)admission.code);
            if (admission.code != B1_NV2_HEADER_CANDIDATE &&
                admission.code != B1_NV_FACTORY_AUTHORIZED)
            {
                NVOCMP_failF = NVINTF_FAILURE;
                NVOCMP_failW = NVINTF_FAILURE;
                b1_management_hold_nv((uint8_t)admission.code);
                return NVOCMP_failF;
            }
            if (admission.code == B1_NV2_HEADER_CANDIDATE)
                b1_management_note_nv_candidate();
        }'''

NEW_ADMISSION = '''        {
            /* Existing fitted four-page NV store only. Factory authorization
             * is NOT inherited from B1's two-page provisioning mode. */
            r4_nv4_result admission;
            uint8_t reason = B1_NV_HOLD_UNKNOWN_LAYOUT;
            b1_nv_existing_pair = 0u;
            admission = r4_nv4_admit(r4_nv4_nvs_read, NVOCMP_nvsHandle);
            b1_management_note_nv4((uint32_t)admission.code,
                (uint32_t)admission.semantic_state, admission.reads,
                admission.records, admission.active_records, admission.fault_offset,
                admission.semantic_flags);
            switch (admission.code)
            {
            case R4_NV4_BAD_READER: reason = B1_NV_HOLD_NO_READER; break;
            case R4_NV4_READ_FAILURE: reason = B1_NV_HOLD_READ_FAILED; break;
            case R4_NV4_BAD_PAGE_HEADER: reason = B1_NV_HOLD_UNKNOWN_LAYOUT; break;
            case R4_NV4_UNSAFE_PAGE_STATES: reason = B1_NV_HOLD_MIXED_LAYOUT; break;
            case R4_NV4_BAD_ITEM: reason = B1_NV_HOLD_ITEM_HEADER; break;
            case R4_NV4_BAD_CRC: reason = B1_NV_HOLD_ITEM_CRC; break;
            case R4_NV4_SCAN_LIMIT: reason = B1_NV_HOLD_SCAN_LIMIT; break;
            case R4_NV4_DUPLICATE_ACTIVE_ID: reason = B1_NV_HOLD_MIXED_LAYOUT; break;
            case R4_NV4_INVALID_STATUS: reason = B1_NV_HOLD_ITEM_HEADER; break;
            case R4_NV4_NO_ZSTACK_RECORDS: reason = B1_NV_HOLD_UNKNOWN_LAYOUT; break;
            case R4_NV4_RECOVER_COMPACT_CANDIDATE:
            case R4_NV4_RECOVER_ERASE_CANDIDATE:
                /* Already formed, complete surviving source. The *only*
                 * permitted writes are the pinned TI init journal replay.
                 * Post-init scan below must return a settled formed ring. */
                if (admission.semantic_state == R4_NV4_STATE_FORMED_CANDIDATE)
                {
                    reason = B1_NV2_HEADER_CANDIDATE;
                    r4_nv4_recovery_pending = 1u;
                }
                break;
            case R4_NV4_READONLY_STRUCTURE_ACCEPTED:
                /* A CRC-valid random record cannot stand in for the stock
                 * coordinator's BDB+logical-type+NIB state. This remains a
                 * candidate pending the later native security precheck. */
                if (admission.semantic_state == R4_NV4_STATE_FORMED_CANDIDATE)
                    reason = B1_NV2_HEADER_CANDIDATE;
                else
                    reason = B1_NV_HOLD_MIXED_LAYOUT;
                break;
            default: break;
            }
            b1_management_note_nv_probe(reason);
            if ((admission.code != R4_NV4_READONLY_STRUCTURE_ACCEPTED &&
                 admission.code != R4_NV4_RECOVER_COMPACT_CANDIDATE &&
                 admission.code != R4_NV4_RECOVER_ERASE_CANDIDATE) ||
                reason != B1_NV2_HEADER_CANDIDATE)
            {
                NVOCMP_failF = NVINTF_FAILURE;
                NVOCMP_failW = NVINTF_FAILURE;
                b1_management_hold_nv(reason);
                return NVOCMP_failF;
            }
            b1_nv_existing_pair = 1u; /* B1 retained-NV security path */
            b1_management_note_nv_candidate();
        }'''

READ_CALLBACK = '''static int_fast16_t b1_nv_nvs_read(void *opaque, uint32_t off,
                                   uint8_t *data, uint32_t len)
{
    return NVS_read((NVS_Handle)opaque, off, data, len);
}'''
READ_CALLBACK_NV4 = '''static int r4_nv4_nvs_read(void *opaque, uint32_t off,
                           uint8_t *data, uint32_t len)
{
    return NVS_read((NVS_Handle)opaque, off, data, len) ==
           NVS_STATUS_SUCCESS ? 0 : -1;
}'''

INIT_DECLARATION = "static uint8_t NVOCMP_initNvApi(void *param)\n{"
INIT_RECOVERY_DECLARATION = (INIT_DECLARATION +
    "\n#ifndef NV_LINUX\n"
    "    uint8_t r4_nv4_recovery_pending = 0u;\n"
    "#endif")

INIT_REPAIR_HOOK = """        NVOCMP_initNv(&NVOCMP_nvHandle);"""
INIT_REPAIR_VERIFIED = """        NVOCMP_initNv(&NVOCMP_nvHandle);
#ifndef NV_LINUX
        if (r4_nv4_recovery_pending)
        {
            r4_nv4_result after = r4_nv4_admit(r4_nv4_nvs_read, NVOCMP_nvsHandle);
            /* No stack startup until the TI native transaction committed
             * a settled, formed ring with all records still CRC-valid.
             * Driver errors remain sticky, not merely logged. */
            if (NVOCMP_failF != NVINTF_SUCCESS ||
                NVOCMP_failW != NVINTF_SUCCESS ||
                after.code != R4_NV4_READONLY_STRUCTURE_ACCEPTED ||
                after.semantic_state != R4_NV4_STATE_FORMED_CANDIDATE)
            {
                NVOCMP_failF = NVINTF_FAILURE;
                NVOCMP_failW = NVINTF_FAILURE;
                b1_nv_runtime_hold_latch();
                b1_management_hold_nv(B1_NV_HOLD_MIXED_LAYOUT);
                return NVOCMP_failF;
            }
        }
#endif"""


MULTIPAGE_SCAN = '''    status = NVOCMP_scanPage(pNvHandle, pg, pPageInfo);
    if(status != NVINTF_SUCCESS)
    {
      return;
    }'''
MULTIPAGE_SCAN_CHECKED = '''    status = NVOCMP_scanPage(pNvHandle, pg, pPageInfo);
    if(status != NVINTF_SUCCESS || NVOCMP_failF != NVINTF_SUCCESS ||
       b1_nv_runtime_hold_active())
    {
      NVOCMP_failF = NVINTF_FAILURE;
      NVOCMP_failW = NVINTF_FAILURE;
      b1_nv_runtime_hold_latch();
      return; /* never choose a repair/erase action after scan error */
    }'''


def one(source: str, before: str, after: str, label: str) -> str:
    if source.count(before) != 1 or after in source:
        raise ValueError('R4_NV4_B1_POST_B1_PREIMAGE_' + label)
    return source.replace(before, after, 1)


def transform(source: str, *, stock_base: int = STOCK_BASE) -> str:
    if not isinstance(source, str) or not source:
        raise ValueError('R4_NV4_B1_SOURCE_REQUIRED')
    if not (STOCK_BASE == 0xA6000 and STOCK_SIZE == 0x8000 and STOCK_PAGES == 4):
        raise ValueError('R4_NV4_STOCK_GEOMETRY_DRIFT')
    # Explicit alternative for the exact captured P7U stock 20260311 pages.
    # Never silently infer NV base from a boot image or expand this set.
    if type(stock_base) is not int or stock_base not in (0xA6000, 0xA4000):
        raise ValueError('R4_NV4_UNQUALIFIED_NV_BASE')
    source = source.replace('\r\n', '\n')
    if (DESTRUCTIVE_COMPACTION_DENIAL in source or
            re.search(r'(?m)^\s*#\s*define\s+NVOCMP_RECOVER_FROM_COMPACT_FAILURE\b',
                      source)):
        raise ValueError('R4_NV4_UNSAFE_COMPACTION_RECOVERY_DEFINE')
    if ('/* B1 source-linked native admission */' not in source or
            '/* B1 N03: no divide by zero/CCFG */' not in source or
            'b1_nv_initializing = 1u;' not in source or
            'b1_nv_runtime_hold_latch();' not in source or
            'b1_nv_existing_pair' in source):
        raise ValueError('R4_NV4_B1_REQUIRES_PINNED_B1_APPLIED_SOURCE')
    source = one(source, INCLUDE_FROM, INCLUDE_TO, 'INCLUDE')
    source = one(source, READ_CALLBACK, READ_CALLBACK_NV4, 'READ_CALLBACK')
    expected_pre = PRE_DIVISION_NV4.replace(
        '0xA6000u', f'0x{stock_base:05X}u')
    source = one(source, PRE_DIVISION_NV2, expected_pre, 'PRE_DIVISION')
    source = one(source, POST_DIVISION_NV2, POST_DIVISION_NV4, 'POST_DIVISION')
    source = one(source, OLD_ADMISSION, NEW_ADMISSION, 'ADMISSION')
    source = one(source, INIT_DECLARATION, INIT_RECOVERY_DECLARATION,
                 'RECOVERY_LOCAL')
    source = one(source, INIT_REPAIR_HOOK, INIT_REPAIR_VERIFIED,
                 'POST_NATIVE_REPAIR_VERIFICATION')
    source = one(source, MULTIPAGE_SCAN, MULTIPAGE_SCAN_CHECKED, 'MULTIPAGE_SCAN')
    # The fallback is declared twice in the pinned TI SDK (multi-page and
    # 1/2-page variants). Deny it at both *use sites* as well as before
    # includes, so an included header cannot enable a late destructive path.
    fallback = '#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE'
    if source.count(fallback) != 2:
        raise ValueError('R4_NV4_DESTRUCTIVE_COMPACTION_FALLBACK_SOURCE_DRIFT')
    source = source.replace(fallback, DESTRUCTIVE_COMPACTION_DENIAL + fallback)
    if source.count('NVOCMP_NVPAGES != B1_NV2_PAGE_COUNT') != 0:
        raise ValueError('R4_NV4_B1_LEFTOVER_NATIVE_NV2_GUARD')
    return DESTRUCTIVE_COMPACTION_DENIAL + source


def apply(sdk: Path, c_source: Path, h_source: Path, receipt: Path,
          b1_receipt: Path | None = None, *, stock_base: int = STOCK_BASE) -> dict:
    """Prevalidate all sources, then modify disposable SDK and add NV4 C/H."""
    sdk = sdk.resolve()
    nv = sdk / 'source/ti/common/nv/nvocmp.c'
    dst = [nv, nv.parent/'nv4_readonly_admission.c',
           nv.parent/'nv4_readonly_admission.h', receipt.resolve()]
    if (len({x.resolve() for x in dst}) != 4 or
            receipt.exists() or receipt.is_symlink() or
            any(p.exists() or p.is_symlink() for p in dst[1:3])):
        raise ValueError('R4_NV4_B1_DESTINATION_NOT_DISPOSABLE')
    originals = [nv.read_bytes(), c_source.read_bytes(), h_source.read_bytes()]
    replacement = transform(originals[0].decode('utf-8'),
                            stock_base=stock_base)
    if b'R4_NV4_REGION_SIZE' not in originals[2] or b'r4_nv4_admit' not in originals[1]:
        raise ValueError('R4_NV4_B1_ADMISSION_SOURCES_MISSING')
    prior = None
    if b1_receipt is not None:
        if (b1_receipt.is_symlink() or not b1_receipt.is_file() or
                b1_receipt.resolve() in {p.resolve() for p in dst}):
            raise ValueError('R4_NV4_B1_SOURCE_RECEIPT_ALIAS_OR_MISSING')
        try:
            prior = json.loads(b1_receipt.read_bytes())
        except (ValueError, UnicodeDecodeError):
            raise ValueError('R4_NV4_B1_SOURCE_RECEIPT_INVALID')
        bindings = prior.get('additional_source_bindings')
        if (prior.get('schema') != 'r4-b1-admission-overlay-v2' or
                prior.get('post_b1_b3_b2_b4_source_composition') !=
                'EXPLICIT_SEMANTIC_FUSION_STANDALONE_NATIVE_PENDING' or
                prior.get('nvocmp_compaction_fusion_source') !=
                'B1_HOLD_PLUS_B3_THREE_DONOR_GUARDS' or
                prior.get('modified_nv_sha256') != hashlib.sha256(originals[0]).hexdigest() or
                not isinstance(bindings, dict) or
                'nv4_admission_c_sha256' in bindings or
                'nv4_admission_h_sha256' in bindings):
            raise ValueError('R4_NV4_B1_SOURCE_RECEIPT_PREIMAGE_DRIFT')
        if not all(isinstance(x, str) and isinstance(y, str)
                   for x, y in bindings.items()):
            raise ValueError('R4_NV4_B1_SOURCE_RECEIPT_BINDINGS_INVALID')
    result = {
        'schema': 'p7u-nv4-b1-source-only-v1',
        'destructive_compaction_reformat_if_enabled': 'COMPILE_TIME_ERROR',
        'source_before_sha256': hashlib.sha256(originals[0]).hexdigest(),
        'source_after_sha256': hashlib.sha256(replacement.encode()).hexdigest(),
        'nv4_admission_c_sha256': hashlib.sha256(originals[1]).hexdigest(),
        'nv4_admission_h_sha256': hashlib.sha256(originals[2]).hexdigest(),
        'region_base': f'0x{stock_base:05X}', 'region_size': '0x8000',
        'nv_pages': 4,
        'factory_boot_authorized': False, 'hardware_contact': False,
        'native_linked': False, 'security_counter_continuity_verified': False,
        'flash_authorized': False,
    }
    nv.write_text(replacement, encoding='utf-8', newline='\n')
    dst[1].write_bytes(originals[1])
    dst[2].write_bytes(originals[2])
    if prior is not None:
        prior['modified_nv_sha256'] = result['source_after_sha256']
        prior['nv4_admission_c_sha256'] = result['nv4_admission_c_sha256']
        prior['nv4_admission_h_sha256'] = result['nv4_admission_h_sha256']
        prior['additional_source_bindings']['nv4_admission_c_sha256'] = (
            'source/ti/common/nv/nv4_readonly_admission.c')
        prior['additional_source_bindings']['nv4_admission_h_sha256'] = (
            'source/ti/common/nv/nv4_readonly_admission.h')
        prior['nv4_readonly_bridge_source'] = 'EXACT_PINNED_FOUR_PAGE_B1_ADMISSION'
        prior['nv4_destructive_compaction_reformat_if_enabled'] = 'COMPILE_TIME_ERROR'
        b1_receipt.write_text(json.dumps(prior, indent=2, sort_keys=True) + '\n')
        result['b1_overlay_receipt_bound'] = True
    else:
        result['b1_overlay_receipt_bound'] = False
    receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--admission-c', type=Path,
                        default=Path(__file__).with_name('nv4_readonly_admission.c'))
    parser.add_argument('--admission-h', type=Path,
                        default=Path(__file__).with_name('nv4_readonly_admission.h'))
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--b1-overlay-receipt', type=Path)
    parser.add_argument('--nv-base', choices=('0xA6000', '0xA4000'),
                        default='0xA6000',
                        help='Explicit fitted stock NV geometry; no flash')
    args = parser.parse_args()
    print(json.dumps(apply(args.sdk, args.admission_c, args.admission_h,
                           args.receipt, args.b1_overlay_receipt,
                           stock_base=int(args.nv_base, 16)), sort_keys=True))


if __name__ == '__main__':
    main()
