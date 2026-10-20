"""The NV4 bridge must keep B1's existing-network HOLD and never flash."""
from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT / 'firmware/slzb-06p7u/r4/qualification'
sys.path.insert(0, str(QUAL))
spec = importlib.util.spec_from_file_location('r4_b1_nv4_bridge',
                                             QUAL / 'nv4_b1_bridge.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def post_b1_fixture() -> str:
    return '\n'.join((
        '/* pinned TI source plus exact B1 source overlay */',
        bridge.INCLUDE_FROM,
        '/* B1 N03: no divide by zero/CCFG */',
        'b1_nv_initializing = 1u;',
        'b1_nv_runtime_hold_latch();',
        bridge.READ_CALLBACK,
        bridge.PRE_DIVISION_NV2,
        bridge.POST_DIVISION_NV2,
        bridge.OLD_ADMISSION,
        bridge.MULTIPAGE_SCAN,
        '#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE',
        '/* pinned TI multi-page destructive branch */',
        '#endif',
        '#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE',
        '/* pinned TI two-page destructive branch */',
        '#endif',
    ))


class Nv4B1BridgeTests(unittest.TestCase):
    def test_existing_network_integration_preserves_hold(self):
        source = bridge.transform(post_b1_fixture())
        self.assertIn('r4_nv4_admit(r4_nv4_nvs_read, NVOCMP_nvsHandle)', source)
        self.assertIn('b1_nv_existing_pair = 1u;', source)
        self.assertIn('b1_nv_existing_pair = 0u;', source)
        self.assertIn('b1_management_note_nv_candidate()', source)
        self.assertIn('b1_management_hold_nv(reason)', source)
        self.assertIn('b1_nv_runtime_hold_active()', source)
        self.assertIn('B1_NV_HOLD_ITEM_CRC', source)
        self.assertIn('R4_NV4_NO_ZSTACK_RECORDS: reason = B1_NV_HOLD_UNKNOWN_LAYOUT', source)
        self.assertIn('admission.semantic_state == R4_NV4_STATE_UNCOMMISSIONED_CANDIDATE', source)
        self.assertIn('admission.semantic_state == R4_NV4_STATE_FORMED_CANDIDATE', source)
        self.assertIn('reason != B1_NV2_HEADER_CANDIDATE', source)
        self.assertIn('NVOCMP_failF != NVINTF_SUCCESS', source)
        self.assertIn('NVOCMP_NVPAGES != R4_NV4_PAGES', source)
        self.assertIn('NVOCMP_nvsAttrs.regionSize != R4_NV4_REGION_SIZE', source)
        self.assertIn('0xA6000u', source)
        self.assertNotIn('NVOCMP_NVPAGES != B1_NV2_PAGE_COUNT', source)
        self.assertNotIn('#ifdef B1_FACTORY_BOOT_AUTHORIZED', source)
        self.assertTrue(source.startswith(bridge.DESTRUCTIVE_COMPACTION_DENIAL))
        self.assertEqual(source.count(bridge.DESTRUCTIVE_COMPACTION_DENIAL), 3)

    def test_current_stock_20260311_explicit_nv_base(self):
        source = bridge.transform(post_b1_fixture(), stock_base=0xA4000)
        self.assertIn('0xA4000u', source)
        self.assertNotIn('0xA6000u', source)
        self.assertIn('r4_nv4_admit', source)
        self.assertIn('B1_NV_HOLD_SCAN_LIMIT', source)
        with self.assertRaisesRegex(ValueError, 'UNQUALIFIED_NV_BASE'):
            bridge.transform(post_b1_fixture(), stock_base=0xA0000)

    def test_current_stock_20260311_bridge_receipt_is_explicit(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            nv = root / 'source/ti/common/nv/nvocmp.c'
            nv.parent.mkdir(parents=True)
            nv.write_text(post_b1_fixture())
            report = bridge.apply(root, QUAL / 'nv4_readonly_admission.c',
                                  QUAL / 'nv4_readonly_admission.h',
                                  root / 'bridge.json', stock_base=0xA4000)
            self.assertEqual(report['region_base'], '0xA4000')
            self.assertIn('0xA4000u', nv.read_text())
            self.assertNotIn('0xA6000u', nv.read_text())
            self.assertFalse(report['flash_authorized'])

    @unittest.skipUnless(shutil.which('gcc'), 'host C compiler required')
    def test_stock_nv4_compiler_rejects_lossy_ti_compaction_fallback(self):
        guarded = bridge.transform(post_b1_fixture())
        data = (guarded[:len(bridge.DESTRUCTIVE_COMPACTION_DENIAL)] +
                'int main(void) { return 0; }\n').encode()
        ordinary = subprocess.run(
            ['gcc', '-x', 'c', '-fsyntax-only', '-'],
            input=data, capture_output=True)
        dangerous = subprocess.run(
            ['gcc', '-DNVOCMP_RECOVER_FROM_COMPACT_FAILURE=1',
             '-x', 'c', '-fsyntax-only', '-'],
            input=data, capture_output=True)
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        self.assertNotEqual(dangerous.returncode, 0)
        self.assertIn(b'R4_NV4_DESTRUCTIVE_COMPACTION_REFORMAT_FORBIDDEN',
                      dangerous.stderr)

    def test_checked_source_cannot_define_lossy_compaction_recovery_late(self):
        for injection in ('#define NVOCMP_RECOVER_FROM_COMPACT_FAILURE 1',
                          ' #  define\tNVOCMP_RECOVER_FROM_COMPACT_FAILURE'):
            with self.subTest(injection=injection), self.assertRaisesRegex(
                    ValueError, 'UNSAFE_COMPACTION_RECOVERY_DEFINE'):
                bridge.transform(post_b1_fixture() + '\n' + injection)

    def test_malformed_or_missing_destructive_fallback_is_rejected(self):
        original = post_b1_fixture()
        for mutant in (
                original.replace('#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE',
                                 '#if 0', 1),
                original.replace('#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE',
                                 '#if 0'),
                original + '\n#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE'):
            with self.subTest(size=len(mutant)), self.assertRaisesRegex(
                    ValueError, 'FALLBACK_SOURCE_DRIFT'):
                bridge.transform(mutant)

    def test_missing_or_duplicate_anchors_hold(self):
        source = post_b1_fixture()
        with self.assertRaisesRegex(ValueError, 'REQUIRES_PINNED_B1'):
            bridge.transform(source.replace(bridge.INCLUDE_FROM, 'MISSING'))
        with self.assertRaisesRegex(ValueError, 'PREIMAGE_PRE_DIVISION'):
            bridge.transform(source + '\n' + bridge.PRE_DIVISION_NV2)
        with self.assertRaisesRegex(ValueError, 'PREIMAGE_ADMISSION'):
            bridge.transform(source.replace('B1_FACTORY_BOOT_AUTHORIZED', 'OTHER'))
        with self.assertRaisesRegex(ValueError, 'REQUIRES_PINNED_B1'):
            bridge.transform('unmodified upstream')
        with self.assertRaisesRegex(ValueError, 'UNSAFE_COMPACTION_RECOVERY_DEFINE'):
            bridge.transform(bridge.transform(source))

    def test_disposable_prevalidation_no_partial_changes(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            nv = root / 'source/ti/common/nv/nvocmp.c'
            nv.parent.mkdir(parents=True)
            nv.write_text('not B1')
            receipt = root / 'result.json'
            original = nv.read_bytes()
            with self.assertRaisesRegex(ValueError, 'REQUIRES_PINNED_B1'):
                bridge.apply(root, QUAL / 'nv4_readonly_admission.c',
                             QUAL / 'nv4_readonly_admission.h', receipt)
            self.assertEqual(nv.read_bytes(), original)
            self.assertFalse(receipt.exists())
            self.assertFalse((nv.parent / 'nv4_readonly_admission.c').exists())

    def test_full_composite_b1_binding_is_exact_and_single_use(self):
        def digest(data):
            return hashlib.sha256(data).hexdigest()

        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            nv = root / 'source/ti/common/nv/nvocmp.c'
            nv.parent.mkdir(parents=True)
            nv.write_text(post_b1_fixture())
            raw = nv.read_bytes()
            original = {
                'schema': 'r4-b1-admission-overlay-v2',
                'post_b1_b3_b2_b4_source_composition':
                'EXPLICIT_SEMANTIC_FUSION_STANDALONE_NATIVE_PENDING',
                'nvocmp_compaction_fusion_source': 'B1_HOLD_PLUS_B3_THREE_DONOR_GUARDS',
                'modified_nv_sha256': digest(raw),
                'additional_source_bindings': {},
            }
            prior = root/'b1.json'
            prior.write_text(json.dumps(original))
            out = root/'bridge.json'
            result = bridge.apply(root, QUAL/'nv4_readonly_admission.c',
                                  QUAL/'nv4_readonly_admission.h', out,
                                  b1_receipt=prior)
            bound = json.loads(prior.read_text())
            self.assertTrue(result['b1_overlay_receipt_bound'])
            self.assertEqual(result['source_before_sha256'], digest(raw))
            self.assertEqual(result['source_after_sha256'], digest(nv.read_bytes()))
            self.assertEqual(bound['modified_nv_sha256'], result['source_after_sha256'])
            for kind in ('c', 'h'):
                self.assertEqual(bound[f'nv4_admission_{kind}_sha256'],
                                 result[f'nv4_admission_{kind}_sha256'])
            self.assertEqual(bound['nv4_readonly_bridge_source'],
                             'EXACT_PINNED_FOUR_PAGE_B1_ADMISSION')
            self.assertFalse(result['flash_authorized'])
            self.assertEqual(result['destructive_compaction_reformat_if_enabled'],
                             'COMPILE_TIME_ERROR')
            self.assertEqual(bound['nv4_destructive_compaction_reformat_if_enabled'],
                             'COMPILE_TIME_ERROR')

        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            nv = root/'source/ti/common/nv/nvocmp.c'
            nv.parent.mkdir(parents=True)
            nv.write_text(post_b1_fixture())
            prior = root/'b1.json'
            original['modified_nv_sha256'] = '0'*64
            prior.write_text(json.dumps(original))
            saved = nv.read_bytes()
            with self.assertRaisesRegex(ValueError, 'SOURCE_RECEIPT_PREIMAGE_DRIFT'):
                bridge.apply(root, QUAL/'nv4_readonly_admission.c',
                             QUAL/'nv4_readonly_admission.h',
                             root/'bridge.json', b1_receipt=prior)
            self.assertEqual(nv.read_bytes(), saved)
            self.assertFalse((root/'bridge.json').exists())
            self.assertFalse((nv.parent/'nv4_readonly_admission.c').exists())

    def test_successful_source_only_application(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            nv = root / 'source/ti/common/nv/nvocmp.c'
            nv.parent.mkdir(parents=True)
            nv.write_text(post_b1_fixture())
            report = bridge.apply(root, QUAL / 'nv4_readonly_admission.c',
                                  QUAL / 'nv4_readonly_admission.h',
                                  root / 'bridge.json')
            self.assertEqual(report['nv_pages'], 4)
            self.assertFalse(report['flash_authorized'])
            self.assertFalse(report['factory_boot_authorized'])
            self.assertFalse(report['native_linked'])
            self.assertIn('r4_nv4_admit', nv.read_text())
            with self.assertRaisesRegex(ValueError, 'DESTINATION_NOT_DISPOSABLE'):
                bridge.apply(root, QUAL / 'nv4_readonly_admission.c',
                             QUAL / 'nv4_readonly_admission.h', root / 'bridge.json')


if __name__ == '__main__':
    unittest.main()
