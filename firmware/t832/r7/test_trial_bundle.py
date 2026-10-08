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
               'files': {'pre_nv': files['pre-nv.bin'],
                         'post_program_nv': files['post-program-nv.bin'],
                         'post_boot_nv': files['post-boot-nv.bin'],
                         'records': files['records.json']},
               'ranges': {'expected_changed_pages': list(expected)}}
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


if __name__ == '__main__':
    unittest.main()
