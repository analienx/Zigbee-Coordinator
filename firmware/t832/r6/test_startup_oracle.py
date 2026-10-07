"""Hosted pure-python oracle invariants for the R10 startup corpus.

No SDK, no probe, no flash backend: locks the state-count oracle, the
compact-preflight mirror, and the F5 check()-only evidence discipline.
"""
import re
import unittest
from pathlib import Path

import verify_startup_guard as v

PAGE = v.PAGE


def page(state=0xFF, verbyte=0x0F, sig=0x96, compact=None, data=None):
    hdr = bytes((state, 0x01, verbyte, sig))
    cmp_ = b'\xff\xff\xff\x96' * 3 if compact is None else compact
    body = b'\xff' * (PAGE - 16) if data is None else data
    return hdr + cmp_ + body


def image(pages):
    check_pages = list(pages) + [page()] * (15 - len(pages))
    return b''.join(check_pages[:15])


def item_data(length):
    b3 = ((length & 0x3F) << 2) & 0xFF
    b4 = (length >> 6) & 0x3F
    hdr = bytes((0x04, 0x21, 0x00, b3, b4, 0x42, 0x96))
    return hdr + bytes([0xAA]) * length + b'\xff' * (PAGE - 16 - 7 - length)


class OracleCorpusTest(unittest.TestCase):
    def test_verifier_uses_no_bare_assert(self):
        text = (Path(__file__).resolve().parent / 'verify_startup_guard.py').read_text()
        bare = [n for n, line in enumerate(text.splitlines(), 1)
                if re.match(r'\s*assert\s+', line)]
        self.assertEqual(bare, [])

    def test_corpus_declared_and_tagged(self):
        self.assertTrue(v.REJECT_CASES)
        self.assertTrue(v.ADMIT_CASES)
        self.assertEqual(len(set(v.REJECT_CASES)), len(v.REJECT_CASES))
        self.assertEqual(len(set(v.ADMIT_CASES)), len(v.ADMIT_CASES))
        self.assertFalse(set(v.REJECT_CASES) & set(v.ADMIT_CASES))
        for name in list(v.REJECT_CASES) + list(v.ADMIT_CASES):
            self.assertIn(name, v.EXPECTED_TAG)
        self.assertEqual(v.CORPUS_VERSION, 'enumerated-v2')

    def test_enumeration_partitions(self):
        fam = v.enumerate_topology()
        self.assertEqual(fam['total'], 15504)
        self.assertEqual(sum(fam['families'].values()), 15504)
        self.assertEqual(fam['families']['admit_init'], 1)

    def test_find_end_mirrors_driver(self):
        self.assertEqual(v.find_end(b'\xff' * PAGE), 1)
        self.assertEqual(v.find_end(page()), 16)
        self.assertEqual(v.find_end(page(data=item_data(116))), 16 + 7 + 116)

    def test_boundary_walk(self):
        body = item_data(5)
        self.assertTrue(v.on_boundary(body, 16))
        self.assertTrue(v.on_boundary(body, 16 + 7 + 5))
        self.assertFalse(v.on_boundary(body, 16 + 7 + 4))
        self.assertFalse(v.on_boundary(body, 15))
        self.assertFalse(v.on_boundary(body, 2049))

    def test_oracle_init_and_lone(self):
        self.assertEqual(v.oracle_decision(image([])), ('ADMIT', 'ADMIT_INIT'))
        lone = image([page(0x7E, 0x0C)])
        self.assertEqual(v.oracle_decision(lone), ('REJECT', 'TOPO_LONE_OR_EMPTY'))

    def test_oracle_multi_act_admitted_with_proof(self):
        twin = image([page(0x7C), page(0x7C)] + [page()] * 12 + [page(0xFE)])
        self.assertEqual(v.oracle_decision(twin), ('ADMIT', 'ADMIT_RESUME_DIRECT'))

    def test_oracle_dup_recovery_rejected(self):
        two_xdst = image([page(0x7C), page(0xFE)] + [page()] * 12 + [page(0xFE)])
        self.assertEqual(v.oracle_decision(two_xdst), ('REJECT', 'TOPO_DUP_XDST'))

    def test_oracle_legacy_fail_closed(self):
        legacy = bytes((0xA5, 0x01, 0x02, 0x96)) + b'\xff\xff\xff\x96' * 3
        legacy += b'\x00' * 20 + b'\xff' * (PAGE - 16 - 20)
        mixed = image([page(0x7C), legacy] + [page()] * 12 + [page(0xFE)])
        self.assertEqual(v.oracle_decision(mixed), ('REJECT', 'LEGACY'))

    def test_oracle_compact_null_range_rejected(self):
        dst = (bytes((0x7C, 0x01, 0x0F, 0x96))
               + bytes((0xFF, 0xFF, 0xFE, 0x96))
               + b'\xff\xff\xff\x96' * 2
               + b'\xff' * (PAGE - 16))
        img = image([dst] + [page()] * 13 + [page(0x78)])
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'CMP_ERASE_RANGE_NULL'))

    def test_oracle_compact_torn_sig_rejected(self):
        bad = (bytes((0x7C, 0x01, 0x0F, 0x96))
               + b'\xff\xff\xff\x96'
               + bytes((0x10, 0x00, 0x00, 0x97))
               + b'\xff\xff\xff\x96'
               + b'\xff' * (PAGE - 16))
        img = image([bad] + [page()] * 13 + [page(0xFE)])
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'CMP_SIG'))

    def test_oracle_unknown_topology_latched(self):
        full = image([page(0x78)] * 15)
        self.assertEqual(v.oracle_decision(full), ('REJECT', 'DRIVER_UNKNOWN_LATCH'))


if __name__ == '__main__':
    unittest.main()
