"""Hosted tests for the Q4 trial-bundle checker. All fixtures are
synthetic fills invented in-test; no real NV data is used or needed.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import check_trial_bundle as c


def rec(kind, a=0, b=0, d=0):
    return {'kind_name': kind, 'a': a, 'b': b, 'c': d}


class TrialBundleTest(unittest.TestCase):
    def bundle(self, tmp, pre=None, post=None, boot=None, records=None,
               expected=(3,), manifest=None):
        root = Path(tmp) / 'bundle'
        root.mkdir()
        pre = b'\xff' * c.NV_IMAGE_SIZE if pre is None else pre
        p3 = bytearray(pre)
        p3[3 * c.PAGE:4 * c.PAGE] = b'\xaa' * c.PAGE
        post = bytes(p3) if post is None else post
        b3 = bytearray(post)
        b3[0:16] = b'\x7c' + b'\x01' * 15
        boot = bytes(b3) if boot is None else boot
        records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
                   rec('NV_RESULT', 9, 0, 0)] if records is None else records
        blobs = {'pre-nv.bin': pre, 'post-program-nv.bin': post,
                 'post-boot-nv.bin': boot,
                 'records.json': (json.dumps(records) + '\n').encode()}
        files = {}
        for name, data in blobs.items():
            (root / name).write_bytes(data)
            files[name] = {'file': name, 'sha256': hashlib.sha256(data).hexdigest(),
                           'size': len(data)}
        doc = {'schema': c.SCHEMA, 'plan_version': '1.0.0',
               'candidate_sha': '0' * 40,
               'meta': {'operator': 'synthetic', 'tools': ['none'],
                        'hex_sha256': '1' * 64, 'capture_window_s': 120},
               'files': {'pre_nv': files['pre-nv.bin'],
                         'post_program_nv': files['post-program-nv.bin'],
                         'post_boot_nv': files['post-boot-nv.bin'],
                         'records': files['records.json']},
               'ranges': {'expected_changed_pages': list(expected)},
               'network_state': {'preserved': True,
                                 'note': 'synthetic: bytes identical'}}
        if manifest:
            doc.update(manifest)
        (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
        return root

    def test_good_bundle_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = c.check_bundle(self.bundle(tmp))
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['program_diff_pages'], [3])
        self.assertEqual(result['boot_diff_pages'], [0])
        self.assertEqual(result['latch'],
                         {'status': 0, 'page': 0, 'site': 0, 'raw': 0})
        self.assertEqual(result['init_action'], 0)

    def test_latched_reject_decodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 12),
                       rec('NV_RESULT', 9, (12 << 8) | 3, (8 << 8) | 7)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['latch'],
                         {'status': 12, 'page': 3, 'site': 8, 'raw': 7})

    def test_bad_schema_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = c.check_bundle(self.bundle(tmp, manifest={'schema': 'x'}))
        self.assertFalse(result['ok'])
        self.assertIn('schema', result['errors'][0]['error'])

    def test_tampered_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            with open(root / 'pre-nv.bin', 'r+b') as fh:
                fh.write(b'\x00')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        self.assertTrue(any('sha256' in e['error'] for e in result['errors']))

    def test_missing_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            (root / 'post-boot-nv.bin').unlink()
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])

    def test_short_image_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            short = b'\xff' * (c.NV_IMAGE_SIZE - 1)
            root = self.bundle(tmp, pre=short)
            doc = json.loads((root / 'manifest.json').read_text())
            doc['files']['pre_nv']['sha256'] = hashlib.sha256(short).hexdigest()
            doc['files']['pre_nv']['size'] = len(short)
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        self.assertTrue(any('geometry' in e['error'] for e in result['errors']))

    def test_diff_outside_claimed_ranges_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = c.check_bundle(self.bundle(tmp, expected=(5,)))
        self.assertFalse(result['ok'])
        self.assertTrue(any('outside claimed' in e['error']
                            for e in result['errors']))

    def test_missing_records_rejected(self):
        for drop in ('BOOT', 7, 9):
            with self.subTest(drop=drop), tempfile.TemporaryDirectory() as tmp:
                records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
                           rec('NV_RESULT', 9, 0, 0)]
                if drop == 'BOOT':
                    records = records[1:]
                else:
                    records = [r for r in records if r.get('a') != drop]
                result = c.check_bundle(self.bundle(tmp, records=records))
            self.assertFalse(result['ok'], drop)

    def test_a9_out_of_range_rejected(self):
        bad = [((7 << 8) | 0, 0),  # unknown status
               ((12 << 8) | 15, 0),  # page 15, not 0xFF
               (0, (40 << 8) | 0)]  # site 40
        for b, d in bad:
            with self.subTest(b=b, c=d), tempfile.TemporaryDirectory() as tmp:
                records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
                           rec('NV_RESULT', 9, b, d)]
                result = c.check_bundle(self.bundle(tmp, records=records))
            self.assertFalse(result['ok'], (b, d))

    def test_a7_action_out_of_range_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 7, 7, 0),
                       rec('NV_RESULT', 9, 0, 0)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])

    def test_second_a9_bad_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
                       rec('NV_RESULT', 9, 0, 0),
                       rec('NV_RESULT', 9, (7 << 8) | 15, (40 << 8) | 99)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])

    def test_second_a7_bad_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
                       rec('NV_RESULT', 7, 99, 0),
                       rec('NV_RESULT', 9, 0, 0)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])

    def test_a7_first_failure_not_u16_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 99999),
                       rec('NV_RESULT', 9, 0, 0)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])
        self.assertTrue(any('u16' in e['error'] for e in result['errors']))

    def test_a9_not_u16_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
                       rec('NV_RESULT', 9, 65536, 0)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])
        self.assertTrue(any('u16' in e['error'] for e in result['errors']))

    def test_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            outside = Path(tmp) / 'outside.bin'
            outside.write_bytes(b'\xff' * c.NV_IMAGE_SIZE)
            doc = json.loads((root / 'manifest.json').read_text())
            doc['files']['pre_nv']['file'] = '../outside.bin'
            doc['files']['pre_nv']['sha256'] = hashlib.sha256(
                outside.read_bytes()).hexdigest()
            doc['files']['pre_nv']['size'] = len(outside.read_bytes())
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        self.assertTrue(any('escapes' in e['error'] for e in result['errors']))

    def test_meta_and_pins_enforced(self):
        good_meta = {'operator': 's', 'tools': ['n'],
                     'hex_sha256': '1' * 64, 'capture_window_s': 120}
        variants = [
            {'meta': {**good_meta, 'operator': ''}},
            {'meta': {**good_meta, 'hex_sha256': 'zz'}},
            {'meta': {**good_meta, 'capture_window_s': 30}},
            {'meta': {**good_meta, 'tools': 'n'}},
            {'meta': 'operator-name-string'},
            {'ranges': 'expected-pages-string'},
            {'ranges': {'expected_changed_pages': 3}},
            {'ranges': {'expected_changed_pages': [3],
                        'boot_allowed_pages': 0}},
            {'candidate_sha': 'TBD'},
            {'plan_version': '9.9.9'},
        ]
        for override in variants:
            with self.subTest(override=override), \
                    tempfile.TemporaryDirectory() as tmp:
                result = c.check_bundle(self.bundle(tmp, manifest=override))
            self.assertFalse(result['ok'], override)

    def test_duplicate_boot_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
                       rec('NV_RESULT', 9, 0, 0), rec('BOOT'),
                       rec('NV_RESULT', 7, 0, 0), rec('NV_RESULT', 9, 0, 0)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])
        self.assertTrue(any('multiple BOOT' in e['error']
                            for e in result['errors']))

    def test_boot_not_first_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('NV_RESULT', 9, 0, 0), rec('NV_RESULT', 7, 0, 0),
                       rec('BOOT')]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])
        self.assertTrue(any('BOOT not first' in e['error']
                            for e in result['errors']))

    def test_a9_without_preceding_a7_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 9, 0, 0),
                       rec('NV_RESULT', 7, 0, 0), rec('NV_RESULT', 9, 0, 0)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])
        self.assertTrue(any('preceding a7' in e['error']
                            for e in result['errors']))

    def test_a7_without_following_a9_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
                       rec('NV_RESULT', 9, 0, 0), rec('NV_RESULT', 7, 0, 0)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])
        self.assertTrue(any('following a9' in e['error']
                            for e in result['errors']))

    def test_multi_poll_order_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
                       rec('NV_RESULT', 9, 0, 0), rec('NV_RESULT', 7, 0, 0),
                       rec('NV_RESULT', 9, 0, 0)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertTrue(result['ok'], result)

    def test_malformed_record_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), None, rec('NV_RESULT', 7, 0, 0),
                       rec('NV_RESULT', 9, 0, 0)]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])
        self.assertTrue(any('malformed' in e['error']
                            for e in result['errors']))

    def test_network_state_required_and_gated(self):
        variants = [
            {'network_state': {'preserved': False, 'note': 'loss seen'}},
            {'network_state': {'preserved': 'yes', 'note': 'x'}},
            {'network_state': {'preserved': True, 'note': '  '}},
            {'network_state': 'compared-ok'},
        ]
        for override in variants:
            with self.subTest(override=override), \
                    tempfile.TemporaryDirectory() as tmp:
                result = c.check_bundle(self.bundle(tmp, manifest=override))
            self.assertFalse(result['ok'], override)
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            doc = json.loads((root / 'manifest.json').read_text())
            del doc['network_state']
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])

    def test_claim_slack_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp, manifest={'ranges':
                               {'expected_changed_pages': [3, 4]}})
            result = c.check_bundle(root)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['claim_slack_pages'], [4])

    def test_checker_micro_branches_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            (root / 'manifest.json').unlink()
            self.assertFalse(c.check_bundle(root)['ok'])
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            (root / 'records.json').write_text(json.dumps({'x': 1}) + '\n')
            doc = json.loads((root / 'manifest.json').read_text())
            data = (root / 'records.json').read_bytes()
            doc['files']['records']['sha256'] = hashlib.sha256(data).hexdigest()
            doc['files']['records']['size'] = len(data)
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        with tempfile.TemporaryDirectory() as tmp:
            records = [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
                       {'kind_name': 'NV_RESULT', 'a': 9, 'b': 'x', 'c': 0}]
            result = c.check_bundle(self.bundle(tmp, records=records))
        self.assertFalse(result['ok'])
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            doc = json.loads((root / 'manifest.json').read_text())
            del doc['files']['pre_nv']
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            doc = json.loads((root / 'manifest.json').read_text())
            doc['files']['pre_nv']['size'] += 1
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        self.assertTrue(any('size mismatch' in e['error']
                            for e in result['errors']))
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp, manifest={'ranges': {}})
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        with tempfile.TemporaryDirectory() as tmp:
            meta = {'operator': 's', 'tools': ['n'],
                    'hex_sha256': '1' * 64, 'capture_window_s': 120}
            del meta['tools']
            root = self.bundle(tmp, manifest={'meta': meta})
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])

    def test_files_shape_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp, manifest={'files': ['pre_nv']})
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        self.assertTrue(any('not an object' in e['error']
                            for e in result['errors']))
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            doc = json.loads((root / 'manifest.json').read_text())
            doc['files']['pre_nv'] = 'pre-nv.bin'
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            doc = json.loads((root / 'manifest.json').read_text())
            doc['files']['pre_nv']['file'] = 7
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            doc = json.loads((root / 'manifest.json').read_text())
            del doc['files']['pre_nv']['size']
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        self.assertTrue(any('size pin missing' in e['error']
                            for e in result['errors']))

    def test_boot_allowlist_optional_but_gated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            doc = json.loads((root / 'manifest.json').read_text())
            doc['ranges']['boot_allowed_pages'] = [0]
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            self.assertTrue(c.check_bundle(root)['ok'])
            doc['ranges']['boot_allowed_pages'] = [5]
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        self.assertTrue(any('allowlist' in e['error'] for e in result['errors']))


    def test_nv_result_pairs_are_exactly_one_to_one(self):
        bad_streams = [
            [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
             rec('NV_RESULT', 7, 0, 0), rec('NV_RESULT', 9, 0, 0)],
            [rec('BOOT'), rec('NV_RESULT', 7, 0, 0),
             rec('NV_RESULT', 9, 0, 0), rec('NV_RESULT', 9, 0, 0)],
        ]
        for records in bad_streams:
            with self.subTest(codes=[r.get('a') for r in records[1:]]), \
                    tempfile.TemporaryDirectory() as tmp:
                result = c.check_bundle(self.bundle(tmp, records=records))
            self.assertFalse(result['ok'])
            self.assertTrue(any('exact a7/a9 pairs' in e['error']
                                for e in result['errors']))

    def test_required_roles_cannot_alias_one_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.bundle(tmp)
            doc = json.loads((root / 'manifest.json').read_text())
            doc['files']['pre_nv'] = dict(doc['files']['post_program_nv'])
            (root / 'manifest.json').write_text(json.dumps(doc) + '\n')
            result = c.check_bundle(root)
        self.assertFalse(result['ok'])
        self.assertTrue(any('alias' in e['error'] for e in result['errors']))

    def test_page_lists_require_unique_integer_ids_0_to_14(self):
        variants = [
            {'ranges': {'expected_changed_pages': [3, 3]}},
            {'ranges': {'expected_changed_pages': [15]}},
            {'ranges': {'expected_changed_pages': [True]}},
            {'ranges': {'expected_changed_pages': [3],
                        'boot_allowed_pages': [0, 0]}},
            {'ranges': {'expected_changed_pages': [3],
                        'boot_allowed_pages': [-1]}},
        ]
        for override in variants:
            with self.subTest(override=override), \
                    tempfile.TemporaryDirectory() as tmp:
                result = c.check_bundle(self.bundle(tmp, manifest=override))
            self.assertFalse(result['ok'], override)

    def test_unknown_or_non_u16_nv_result_subtype_rejected(self):
        bad = [
            {'kind_name': 'NV_RESULT', 'a': 8, 'b': 0, 'c': 0},
            {'kind_name': 'NV_RESULT', 'a': '7', 'b': 0, 'c': 0},
            {'kind_name': 'NV_RESULT', 'a': 7, 'b': -1, 'c': 0},
            {'kind_name': 'NV_RESULT', 'a': 9, 'b': 0, 'c': 65536},
        ]
        for record in bad:
            with self.subTest(record=record), tempfile.TemporaryDirectory() as tmp:
                records = [rec('BOOT'), record, rec('NV_RESULT', 7, 0, 0),
                           rec('NV_RESULT', 9, 0, 0)]
                result = c.check_bundle(self.bundle(tmp, records=records))
            self.assertFalse(result['ok'])

    def test_meta_tools_entries_must_be_non_empty_strings(self):
        for tools in ([''], ['   '], [1], ['ok', '']):
            with self.subTest(tools=tools), tempfile.TemporaryDirectory() as tmp:
                meta = {'operator': 's', 'tools': tools,
                        'hex_sha256': '1' * 64, 'capture_window_s': 120}
                result = c.check_bundle(self.bundle(tmp, manifest={'meta': meta}))
            self.assertFalse(result['ok'])


if __name__ == '__main__':
    unittest.main()
