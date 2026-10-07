"""Hosted pure-python oracle invariants for the R10 startup corpus.

No SDK, no probe, no flash backend: locks the state-count policy mirror,
the compact-preflight mirror, and the F5 check()-only evidence discipline.
These lock the Python case-construction rules, not the driver itself.
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
    # Data-first layout with the HDRLE header encoding the driver reads.
    b3 = (length >> 6) & 0x3F
    b4 = ((length & 0x3F) << 2) & 0xFF
    hdr = bytes((0x04, 0x21, 0x00, b3, b4, 0x42, 0x96))
    return bytes([0xAA]) * length + hdr + b'\xff' * (PAGE - 16 - 7 - length)


def live_item(sysid, itemid, subid, length, fill=0xAA):
    # One live (active, valid-signature) item with an explicit ID. CRC byte
    # is zeroed: the Python proof compares length and payload bytes only (C
    # additionally requires both CRCs valid), and these pages never reach
    # the driver probe.
    b0 = ((sysid & 0x3F) << 2) | ((itemid >> 8) & 0x03)
    b1 = itemid & 0xFF
    b2 = (subid >> 2) & 0xFF
    b3 = ((subid & 0x03) << 6) | ((length >> 6) & 0x3F)
    b4 = ((length & 0x3F) << 2) & 0xFF
    hdr = bytes((b0, b1, b2, b3, b4, 0x42, 0x96))
    return bytes((fill,)) * length + hdr


def padded(*blobs):
    body = b''.join(blobs)
    return body + b'\xff' * (PAGE - 16 - len(body))


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

    def test_hdr_len_matches_driver_vector(self):
        # Seed item header bytes produced by the pinned driver (len 116).
        self.assertEqual(v.hdr_len(0x01, 0xD0), 116)

    def test_boundary_walk_two_items(self):
        two = item_data(5)[:12] + item_data(3)[:10] + b'\xff' * (PAGE - 16 - 22)
        body = page(data=two)
        self.assertTrue(v.on_boundary(body, 16, 38))
        self.assertTrue(v.on_boundary(body, 28, 38))
        self.assertTrue(v.on_boundary(body, 38, 38))
        self.assertFalse(v.on_boundary(body, 30, 38))

    def test_boundary_walk(self):
        body = page(data=item_data(5))
        self.assertTrue(v.on_boundary(body, 16, 28))
        self.assertTrue(v.on_boundary(body, 28, 28))
        self.assertFalse(v.on_boundary(body, 27, 28))
        self.assertFalse(v.on_boundary(body, 15, 28))
        self.assertFalse(v.on_boundary(body, 2049, 2048))

    def test_oracle_init_and_lone(self):
        self.assertEqual(v.oracle_decision(image([])), ('ADMIT', 'ADMIT_INIT'))
        lone = image([page(0x7E, 0x0C)])
        self.assertEqual(v.oracle_decision(lone), ('REJECT', 'TOPO_LONE_OR_EMPTY'))

    def test_oracle_agreeing_twins_admitted(self):
        # F8: twins whose shared live IDs all agree are admitted; resume
        # dedups the older copy and the image converges to single-live.
        a = page(0x7C, data=padded(live_item(1, 33, 0, 5)))
        b = page(0x7C, data=padded(live_item(1, 33, 0, 5)))
        img = image([a, b] + [page()] * 12 + [page(0xFE)])
        self.assertEqual(v.oracle_decision(img), ('ADMIT', 'ADMIT_RESUME_DIRECT'))

    def test_oracle_partitioned_act_admitted(self):
        # F8: the lab-population shape (disjoint live IDs per ACT page).
        ids = [(1, 6, 106), (1, 6, 212), (1, 4, 40)]
        acts = [page(0x7C, data=padded(live_item(s, i, u, 12))) for s, i, u in ids]
        img = image(acts + [page()] * 11 + [page(0xFE)])
        self.assertEqual(v.oracle_decision(img), ('ADMIT', 'ADMIT_RESUME_DIRECT'))

    def test_oracle_same_page_agree_admitted(self):
        # F8: identical live duplicates on one page agree.
        blob = live_item(1, 33, 0, 5)
        p = page(0x7C, data=padded(blob, blob))
        img = image([p] + [page()] * 13 + [page(0xFE)])
        self.assertEqual(v.oracle_decision(img), ('ADMIT', 'ADMIT_RESUME_DIRECT'))

    def test_oracle_same_page_differ_rejected(self):
        # F8: same ID with differing live values on one page conflicts.
        lo = live_item(1, 33, 0, 5, fill=0xAA)
        hi = live_item(1, 33, 0, 5, fill=0xAB)
        p = page(0x7C, data=padded(lo, hi))
        img = image([p] + [page()] * 13 + [page(0xFE)])
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'TOPO_ACT_CONFLICT'))

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

    def test_oracle_erase_range_covering_dst_rejected(self):
        dst = (bytes((0x7C, 0x01, 0x0F, 0x96))
               + bytes((0xFF, 0xFF, 0xFE, 0x96))
               + bytes((0x10, 0x00, 0x00, 0x96))
               + bytes((0x10, 0x00, 0x00, 0x96))
               + b'\xff' * (PAGE - 16))
        img = image([dst] + [page()] * 13 + [page(0x78)])
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'CMP_ERASE_RANGE_DST'))

    def test_oracle_erase_live_end_rejected(self):
        dst = (bytes((0x78, 0x01, 0x0F, 0x96))
               + bytes((0xFF, 0xFF, 0xFE, 0x96))
               + bytes((0x10, 0x00, 0x00, 0x96))
               + bytes((0x10, 0x00, 0x00, 0x96))
               + b'\xff' * (PAGE - 16))
        live = page(0x7C, data=item_data(20))
        img = image([live] + [page()] * 13 + [dst])
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'CMP_ERASE_LIVE_END'))

    def test_oracle_drained_blank_end_admitted(self):
        # Cut-195 form: the PGCDST range fully drained (eoff 16) and its
        # end page erased. cleanPage erases without reading through the
        # offset, so a blank (or header-only) end page is safe to admit.
        dst = (bytes((0x78, 0x01, 0x0F, 0x96))
               + bytes((0xFF, 0xFF, 0xFE, 0x96))
               + bytes((0x10, 0x00, 0x01, 0x96))
               + bytes((0x10, 0x00, 0x01, 0x96))
               + b'\xff' * (PAGE - 16))
        blank = b'\xff' * PAGE
        img = image([dst, blank] + [page(0x78)] * 13)
        self.assertEqual(v.oracle_decision(img), ('ADMIT', 'ADMIT_RECOVER_ERASE'))
        img = image([dst, page()] + [page(0x78)] * 13)
        self.assertEqual(v.oracle_decision(img), ('ADMIT', 'ADMIT_RECOVER_ERASE'))

    def test_oracle_rdy_cursor_zero_rejected(self):
        # RDY cursors are consumed as data-end offsets: only null and the
        # drained mark are admitted; a torn 16->0 must fail closed.
        rdy = (bytes((0x7E, 0x01, 0x0F, 0x96))
               + bytes((0x00, 0x00, 0xFF, 0x96))
               + b'\xff\xff\xff\x96' * 2
               + b'\xff' * (PAGE - 16))
        img = image([page(0x7C, data=item_data(20)), rdy] + [page()] * 13)
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'CMP_RDY_CURSOR'))

    def test_oracle_rdy_cursor_drained_admitted(self):
        rdy = (bytes((0x7E, 0x01, 0x0F, 0x96))
               + bytes((0x10, 0x00, 0xFF, 0x96))
               + b'\xff\xff\xff\x96' * 2
               + b'\xff' * (PAGE - 16))
        xdst = page(0xFE)
        img = image([xdst, rdy] + [page()] * 13)
        self.assertEqual(v.oracle_decision(img), ('ADMIT', 'ADMIT_RESUME_DIRECT'))

    def test_oracle_dup_pgdst_rejected(self):
        # F7: two PGCDST metadata pages fail closed even when each page is
        # structurally valid on its own.
        fe = (bytes((0x78, 0x01, 0x0F, 0x96))
              + bytes((0xFF, 0xFF, 0xFE, 0x96))
              + b'\xff\xff\xff\x96' * 2
              + b'\xff' * (PAGE - 16))
        img = image([page(0x7C), fe, fe] + [page()] * 12)
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'CMP_DUP_PGCDST'))

    def test_oracle_erase_range_multi_rejected(self):
        # F6: a multi-page range whose non-end page holds data fails closed,
        # since cleanPage erases non-end pages unconditionally.
        dst = (bytes((0x78, 0x01, 0x0F, 0x96))
               + bytes((0xFF, 0xFF, 0xFE, 0x96))
               + bytes((0x10, 0x00, 0x00, 0x96))
               + bytes((0x10, 0x00, 0x01, 0x96))
               + b'\xff' * (PAGE - 16))
        blank = b'\xff' * PAGE
        live = page(0x7C, data=padded(live_item(1, 33, 0, 5)))
        img = image([live, blank, dst] + [page()] * 12)
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'CMP_ERASE_RANGE_MULTI'))

    def test_oracle_erase_range_multi_blank_admitted(self):
        # F6: a multi-page range whose non-end pages are all blank admits
        # (cut-20 lab shape): erasing blank pages destroys nothing.
        dst = (bytes((0x78, 0x01, 0x0F, 0x96))
               + bytes((0xFF, 0xFF, 0xFE, 0x96))
               + bytes((0x10, 0x00, 0x00, 0x96))
               + bytes((0x10, 0x00, 0x01, 0x96))
               + b'\xff' * (PAGE - 16))
        blank = b'\xff' * PAGE
        img = image([page(0x7C), blank, dst] + [page()] * 12)
        self.assertEqual(v.oracle_decision(img), ('ADMIT', 'ADMIT_RECOVER_ERASE'))

    def test_oracle_divergent_act_rejected(self):
        # F8: twins sharing a live ID with differing values conflict, even
        # though each page walks cleanly. (C would additionally admit a
        # divergent pair on a CRC-valid tail ID; the mirror cannot check
        # CRCs, so it conservatively rejects all divergence. The hosted lab
        # mutation cuts prove the C exception admits valid-tail transients.)
        a = page(0x7C, data=padded(live_item(1, 33, 0, 5, fill=0xAA)))
        b = page(0x7C, data=padded(live_item(1, 33, 0, 5, fill=0xAB)))
        img = image([a, b] + [page()] * 12 + [page(0xFE)])
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'TOPO_ACT_CONFLICT'))

    def test_oracle_act_walk_anomaly_rejected(self):
        # F8: an ACT page whose top cannot be parsed to a clean chain end
        # fails closed (agreement unprovable), here a stray byte with no
        # header structure at all.
        p2 = bytearray(page(0x7C))
        p2[20] = 0x00
        img = image([page(0x7C), bytes(p2)] + [page()] * 12 + [page(0xFE)])
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'TOPO_ACT_CONFLICT'))

    def test_oracle_reserved_header_rejected(self):
        # F9: reserved allActive (1/2) and cycle (0x00/0xFF) fail closed.
        vectors = {(0x00, 0x0F): 'BAD_CYCLE', (0xFF, 0x0F): 'BAD_CYCLE',
                   (0x01, 0x0D): 'BAD_ALLACTIVE', (0x01, 0x0E): 'BAD_ALLACTIVE'}
        for (cycle, verbyte), tag in vectors.items():
            with self.subTest(cycle=cycle, verbyte=verbyte):
                bad = (bytes((0x78, cycle, verbyte, 0x96))
                       + b'\xff\xff\xff\x96' * 3
                       + b'\xff' * (PAGE - 16))
                img = image([page(0x7C), bad] + [page()] * 12 + [page(0xFE)])
                self.assertEqual(v.oracle_decision(img), ('REJECT', tag))

    def test_oracle_unknown_topology_latched(self):
        full = image([page(0x78)] * 15)
        self.assertEqual(v.oracle_decision(full), ('REJECT', 'DRIVER_UNKNOWN_LATCH'))

    def test_oracle_erase_below_end_rejected(self):
        # F1/P1: an end offset below the true end, even on an item
        # boundary, is a stale range or torn header: cleanPage would
        # cursor-write it over live items. Only the true end (or the
        # drained mark over a blank end) is consumable.
        dst = (bytes((0x78, 0x01, 0x0F, 0x96))
               + bytes((0xFF, 0xFF, 0xFE, 0x96))
               + bytes((0x10, 0x00, 0x00, 0x96))
               + bytes((0x1C, 0x00, 0x00, 0x96))
               + b'\xff' * (PAGE - 16))
        lo = live_item(1, 33, 0, 5)
        hi = live_item(1, 33, 0, 5)
        end = page(0x7C, data=padded(lo, hi))
        img = image([end] + [page()] * 13 + [dst])
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'CMP_ERASE_BELOW_END'))

    def test_oracle_erase_topology_divergent_rejected(self):
        # F8/P0: the mirror rejects divergent pairs on every topology;
        # only C's resume-gated tail exception may excuse one.
        a = page(0x7C, data=padded(live_item(1, 33, 0, 5, fill=0xAA)))
        b = page(0x7C, data=padded(live_item(1, 33, 0, 5, fill=0xAB)))
        dst = (bytes((0x78, 0x01, 0x0F, 0x96))
               + bytes((0xFF, 0xFF, 0xFE, 0x96))
               + bytes((0x10, 0x00, 0x02, 0x96))
               + bytes((0x10, 0x00, 0x02, 0x96))
               + b'\xff' * (PAGE - 16))
        blank = b'\xff' * PAGE
        img = image([a, b, blank] + [page()] * 11 + [dst])
        self.assertEqual(v.oracle_decision(img), ('REJECT', 'TOPO_ACT_CONFLICT'))


if __name__ == '__main__':
    unittest.main()
