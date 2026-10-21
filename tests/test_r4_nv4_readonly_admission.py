"""Compile an independent C NV4 preflight against synthetic, never real keys."""
from __future__ import annotations

import ctypes
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / 'firmware/slzb-06p7u/r4/qualification'
spec = importlib.util.spec_from_file_location('nv4_synthetic_forensics',
                                             SOURCE_DIR/'nv_five_page_forensics.py')
forensics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forensics)


class Result(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
                ('code', 'reads', 'records', 'active_records', 'fault_offset',
                 'semantic_state')]


READ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
                       ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32)
PAGE_SIZE = 8192


def encoded_record(subid: int, *, sysid: int = 1,
                   active: bool = True, itemid: int = 0x1a,
                   data: bytes = b'not-a-real-key') -> bytes:
    """Real NVOCMP_HDRLE=0 compressed ID/status and CRC, public fake data."""
    header = bytearray(((sysid << 2) | (itemid >> 8), itemid & 0xff, subid >> 2,
                        ((subid & 3) << 6) | (len(data) >> 6),
                        (len(data) & 63) << 2))
    crc = forensics.crc8(data + header)
    header[4] |= crc >> 6
    header += bytes((((crc & 63) << 2) | (2 if active else 0), 0x96))
    return data + header


def stock_like(records: int = 1, duplicate: bool = False,
               *, sysid: int = 1) -> bytes:
    media = bytearray(b'\xff' * (4 * PAGE_SIZE))
    for page, state in enumerate((0x7c, 0x78, 0x78, 0xfe)):
        base = page * PAGE_SIZE
        media[base:base+4] = bytes((state, page + 1, 0x0f, 0x96))
        for marker in (7, 11, 15):
            media[base + marker] = 0x96
    cursor = 16
    for i in range(records):
        part = encoded_record(0 if duplicate else i, sysid=sysid)
        media[cursor:cursor + len(part)] = part
        cursor += len(part)
    if cursor > PAGE_SIZE:
        raise AssertionError('fixture records overrun NV page')
    return bytes(media)


def legacy_osal_record(subid: int, payload: bytes) -> bytes:
    """Exact pinned TI sysid=1, itemid=EX_LEGACY=0, subid=OSAL ID."""
    assert 0 <= subid <= 1023 and 0 < len(payload) <= 4095
    length = len(payload)
    header = bytearray((4, 0, subid >> 2,
                        ((subid & 3) << 6) | (length >> 6),
                        (length & 63) << 2))
    crc = forensics.crc8(payload + header)
    header[4] |= crc >> 6
    header += bytes((((crc & 63) << 2) | 2, 0x96))
    return payload + header


def stock_like_semantic(*, bdb: int | None = 0,
                        logical: int | None = 0, nib: bool = False,
                        bdb_payload: bytes | None = None,
                        startup: int | None = 0,
                        startup_payload: bytes | None = None) -> bytes:
    """Public fake coordinator markers, never a real NIB/key/payload."""
    media = bytearray(stock_like())
    cursor = 16 + len(encoded_record(0))
    parts = []
    if bdb is not None:
        parts.append(legacy_osal_record(0x55, bdb_payload if bdb_payload is not None
                                        else bytes((bdb,))))
    if logical is not None:
        parts.append(legacy_osal_record(0x87, bytes((logical,))))
    if startup is not None:
        parts.append(legacy_osal_record(0x03, startup_payload if startup_payload is not None
                                       else bytes((startup,))))
    if nib:
        parts.append(legacy_osal_record(0x21, b'synthetic-nib-not-a-secret'))
    for part in parts:
        media[cursor:cursor + len(part)] = part
        cursor += len(part)
    return bytes(media)


def ti_normal_resume_with_retained_journals() -> bytes:
    """Synthetic records plus real *state shapes*, never private NV payloads.

    TI NORMAL_RESUME permits tail=XDST page 1, head=page 2 and a separate
    PGACT page 0. FULL pages may retain PGCSRC=F8 and old compaction journals.
    """
    media = bytearray(stock_like_semantic())
    media[PAGE_SIZE] = 0xfe   # XDST moved from page 3 to page 1
    media[3 * PAGE_SIZE] = 0x78
    for page, mode, src, start in ((0, 0xfc, 1, 8170),
                                   (2, 0xf8, 3, 8169),
                                   (3, 0xf8, 0, 8190)):
        base = page * PAGE_SIZE
        media[base + 6] = mode
        media[base + 8:base + 11] = start.to_bytes(2, 'little') + bytes((src,))
        media[base + 12:base + 15] = (16).to_bytes(2, 'little') + bytes((src,))
    return bytes(media)


def dense_ti_normal_resume_media() -> bytes:
    """715 synthetic records / 367 active spread across three item pages."""
    media = bytearray(ti_normal_resume_with_retained_journals())
    active_offset = (16 + len(encoded_record(0)) +
                     len(legacy_osal_record(0x55, b'\x00')) +
                     len(legacy_osal_record(0x87, b'\x00')) +
                     len(legacy_osal_record(0x03, b'\x00')))
    next_subid = 1
    for page, count, cursor in ((0, 71, active_offset),
                                (2, 337, 16),
                                (3, 303, 16)):
        base = page * PAGE_SIZE
        for _ in range(count):
            record = encoded_record(next_subid, active=next_subid <= 363)
            assert cursor + len(record) <= PAGE_SIZE
            media[base + cursor:base + cursor + len(record)] = record
            cursor += len(record)
            next_subid += 1
    assert next_subid == 712
    return bytes(media)


def formed_tc300_rollover_media() -> bytes:
    """779 active IDs, 300 real-width synthetic TC rows, 16 obsolete versions.

    Only the population/TC serialization width and valid settled ring are
    represented, not private board data or Z-Stack security restoration proof.
    FULL0/ACTIVE1/NACT2/XDST3 is a normal TI post-cleanPage shape.
    """
    media = bytearray(stock_like())
    for page, state in enumerate((0x78, 0x7c, 0xff, 0xfe)):
        media[page * PAGE_SIZE] = state
        media[page * PAGE_SIZE + 16:(page + 1) * PAGE_SIZE] = b'\xff' * (PAGE_SIZE - 16)
    media[2] = 0x0c  # FULL page contains obsolete, CRC-valid versions.
    records = [encoded_record(0), legacy_osal_record(0x55, b'\x01'),
               legacy_osal_record(0x87, b'\x00'), legacy_osal_record(0x03, b'\x00'),
               legacy_osal_record(0x21, bytes(range(1, 117)))]

    def tc_payload(index, *, previous=False):
        if index >= 107:
            return bytes(16) + b'\xff\x00\x00\x00'  # allocated empty peer slot
        return ((100000 + index - int(previous)).to_bytes(4, 'little') +
                (200000 + index).to_bytes(4, 'little') +
                (index + 1).to_bytes(8, 'little') + bytes((2, 0, index % 16, 0)))

    records.extend(encoded_record(index, itemid=4, active=False,
                                  data=tc_payload(index, previous=True))
                   for index in range(16))
    records.extend(encoded_record(index, itemid=4, data=tc_payload(index))
                   for index in range(300))
    records.extend(encoded_record(index, data=index.to_bytes(8, 'little'))
                   for index in range(1, 475))
    page, cursor = 0, 16
    for part in records:
        if cursor + len(part) > PAGE_SIZE:
            page, cursor = page + 1, 16
        assert page < 2, 'public population must fit the two live item pages'
        start = page * PAGE_SIZE + cursor
        media[start:start + len(part)] = part
        cursor += len(part)
    assert len(records) == 795
    return bytes(media)


@unittest.skipUnless(shutil.which('gcc'), 'host gcc needed for independent C preflight')
class Nv4AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='nv4-strict-host-')
        cls.binary = Path(cls.temporary.name)/'admit.so'
        r = subprocess.run(['gcc', '-std=c11', '-O2', '-shared', '-fPIC',
                            '-Wall', '-Wextra', '-Werror',
                            str(SOURCE_DIR/'nv4_readonly_admission.c'),
                            '-o', str(cls.binary)], capture_output=True)
        if r.returncode:
            raise RuntimeError(r.stderr.decode('utf-8', 'replace'))
        cls.lib = ctypes.CDLL(str(cls.binary))
        cls.lib.r4_nv4_admit.argtypes = [READ, ctypes.c_void_p]
        cls.lib.r4_nv4_admit.restype = Result

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def probe(self, raw, *, read_error=False):
        def read(_ctx, off, to, count):
            if read_error or off + count > len(raw):
                return -1
            ctypes.memmove(to, raw[off:off + count], count)
            return 0
        callback = READ(read)
        return self.lib.r4_nv4_admit(callback, None)

    def test_settled_four_page_snapshot_admitted_readonly(self):
        before = stock_like()
        result = self.probe(before)
        self.assertEqual(result.code, 8)
        self.assertEqual(result.semantic_state, 0)  # Structure is not a network.
        self.assertEqual((result.records, result.active_records), (1, 1))
        self.assertLess(result.reads, 30000)
        self.assertEqual(before, stock_like())

    def test_366_item_synthetic_population_is_not_blank(self):
        result = self.probe(stock_like(records=366))
        self.assertEqual(result.code, 8)
        self.assertEqual((result.records, result.active_records), (366, 366))
        self.assertLess(result.reads, 30000)

    def test_779_active_identities_do_not_trigger_false_capacity_hold(self):
        # Reproduces the record *count* of the private 20260311 snapshot
        # with public fake payloads and unique IDs. No private NV is stored.
        media = bytearray(stock_like(records=1))
        next_id = 1
        for page, count in ((0, 260), (1, 260), (2, 258)):
            offset = 16 + (len(encoded_record(0)) if page == 0 else 0)
            base = page * PAGE_SIZE
            for _ in range(count):
                record = encoded_record(next_id)
                media[base + offset:base + offset + len(record)] = record
                offset += len(record)
                next_id += 1
            self.assertLessEqual(offset, PAGE_SIZE)
        self.assertEqual(next_id, 779)
        report = self.probe(bytes(media))
        self.assertEqual((report.code, report.records, report.active_records),
                         (8, 779, 779))
        self.assertLess(report.reads, 30000)

    def test_this_logical_end_skips_retired_physical_suffix(self):
        before = bytearray(stock_like())
        logical_end = 16 + len(encoded_record(0))
        before[4:6] = logical_end.to_bytes(2, 'little')
        # A retired suffix remains programmed after TI cleanPage commits THIS.
        before[logical_end:logical_end + 11] = b'RETIRED-OLD'
        self.assertEqual(self.probe(bytes(before)).code, 8)
        before[4:6] = b'\xff\xff'  # physical last-non-FF fallback
        self.assertNotEqual(self.probe(bytes(before)).code, 8)

    def test_invalid_crc_valid_item_status_holds_despite_other_live_item(self):
        before = bytearray(stock_like(records=2))
        before[16 + len(b'not-a-real-key') + 5] |= 1
        # NVOCMP item CRC deliberately excludes the one-way validity marks.
        self.assertEqual(self.probe(bytes(before)).code, 10)

    def test_scoped_duplicate_active_compressed_ids_hold(self):
        self.assertEqual(self.probe(stock_like(records=2, duplicate=True)).code, 9)
        self.assertEqual(self.probe(stock_like(records=2)).code, 8)

    def test_reserved_page_all_active_bit_patterns_hold(self):
        for bad in (1, 2):
            with self.subTest(reserved_all_active=bad):
                before = bytearray(stock_like())
                before[2] = (before[2] & 0xfc) | bad
                result = self.probe(bytes(before))
                self.assertEqual(result.code, 3)
                self.assertEqual(result.fault_offset, 0)
        before = bytearray(stock_like())
        before[2] &= 0xfc  # TI SOMEINACTIVE is also legal.
        self.assertEqual(self.probe(bytes(before)).code, 8)

    def test_ti_four_page_compaction_recycles_valid_empty_inactive_headers(self):
        # The real >2-page NVOCMP_cleanPage leaves PGNACT=0xff with an
        # independently valid page header, not a factory-blank 8 KiB page.
        before = bytearray(stock_like_semantic())
        for page in (1, 2):
            before[page * PAGE_SIZE] = 0xff
        candidate = self.probe(bytes(before))
        self.assertEqual((candidate.code, candidate.semantic_state), (8, 1))
        self.assertEqual(candidate.active_records, 4)

        mutants = []
        torn_body = bytearray(before)
        torn_body[PAGE_SIZE + 23] = 0xf7  # non-erased inactive page
        mutants.append(torn_body)
        missing_header = bytearray(before)
        missing_header[PAGE_SIZE:PAGE_SIZE + 16] = b'\xff' * 16
        mutants.append(missing_header)
        invalid_ring = bytearray(before)
        invalid_ring[3 * PAGE_SIZE] = 0xff  # no destination remains
        mutants.append(invalid_ring)
        for i, mutant in enumerate(mutants):
            with self.subTest(change=i):
                self.assertNotEqual(self.probe(bytes(mutant)).code, 8)

    def test_crc_valid_foreign_namespace_cannot_grant_zstack_candidate(self):
        self.assertEqual(self.probe(stock_like(sysid=2)).code, 11)
        self.assertEqual(self.probe(stock_like(sysid=1)).code, 8)
        # Mixed namespaces do not justify a blanket rejection once an
        # independent live Z-Stack record is structurally present.
        before = bytearray(stock_like())
        other = encoded_record(1, sysid=2)
        end = 16 + len(encoded_record(0))
        before[end:end + len(other)] = other
        self.assertEqual(self.probe(bytes(before)).code, 8)

    def test_uncommissioned_blank_or_inactive_only_media_stays_hold(self):
        self.assertEqual(self.probe(b'\xff' * (4 * PAGE_SIZE)).code, 3)
        before = bytearray(stock_like())
        # NVOCMP status bit 1 is excluded from the record CRC.
        before[16 + len(b'not-a-real-key') + 5] &= ~2
        self.assertEqual(self.probe(bytes(before)).code, 4)

    def test_pinned_ti_formatted_inactive_page_after_cleanpage(self):
        # Genuine TI NVOCMP_erase() erases then reformats the page header as
        # PGNACT=0xff, retaining a valid cycle and four 0x96 signatures.
        media = bytearray(stock_like_semantic())
        for page in (1, 2):
            media[page * PAGE_SIZE] = 0xff
        settled = self.probe(bytes(media))
        self.assertEqual((settled.code, settled.semantic_state), (8, 1))
        self.assertEqual((settled.records, settled.active_records), (4, 4))

        # A blank unformatted page, half-erased header or residual item bytes
        # must never be treated as the formatted, empty PGNACT page.
        invalid = bytearray(media)
        invalid[PAGE_SIZE:2 * PAGE_SIZE] = b'\xff' * PAGE_SIZE
        self.assertEqual(self.probe(bytes(invalid)).code, 3)
        invalid = bytearray(media)
        invalid[PAGE_SIZE + 7] = 0xff
        self.assertEqual(self.probe(bytes(invalid)).code, 3)
        invalid = bytearray(media)
        invalid[PAGE_SIZE + 64] = 0x5a
        self.assertEqual(self.probe(bytes(invalid)).code, 4)

    def test_pinned_legacy_osal_markers_yield_only_candidates(self):
        unformed = self.probe(stock_like_semantic())
        self.assertEqual((unformed.code, unformed.semantic_state), (8, 1))
        formed = self.probe(stock_like_semantic(bdb=1, nib=True))
        self.assertEqual((formed.code, formed.semantic_state), (8, 2))
        self.assertEqual((formed.records, formed.active_records), (5, 5))

    def test_marker_byte_comes_from_crc_checked_read_without_reread(self):
        raw = stock_like_semantic()
        bdb_offset = 16 + len(encoded_record(0))
        role_offset = bdb_offset + len(legacy_osal_record(0x55, b'\x00'))
        startup_offset = role_offset + len(legacy_osal_record(0x87, b'\x00'))
        marker_reads = {bdb_offset: 0, role_offset: 0, startup_offset: 0}

        def traced(_ctx, off, to, count):
            if off + count > len(raw):
                return -1
            if count == 1 and off in marker_reads:
                marker_reads[off] += 1
                # A second post-CRC read could observe a different flash
                # value; the classifier must use the authenticated byte.
                if marker_reads[off] > 1:
                    return -1
            ctypes.memmove(to, raw[off:off + count], count)
            return 0

        result = self.lib.r4_nv4_admit(READ(traced), None)
        self.assertEqual((result.code, result.semantic_state), (8, 1))
        self.assertEqual(marker_reads, {bdb_offset: 1, role_offset: 1, startup_offset: 1})

    def test_missing_incoherent_or_malformed_semantic_markers_hold(self):
        variants = (
            dict(bdb=None), dict(logical=None), dict(bdb=2),
            dict(logical=1), dict(bdb=1), dict(nib=True),
            dict(bdb_payload=b'\x00\x00'),
            dict(startup=None), dict(startup_payload=b'\x00\x00'),
        )
        for variant in variants:
            with self.subTest(**variant):
                result = self.probe(stock_like_semantic(**variant))
                self.assertEqual(result.code, 8)  # CRC-valid structure.
                self.assertEqual(result.semantic_state, 0)  # But HOLD.

    def test_pending_destructive_startup_flags_hold_before_stack_initialization(self):
        for formed in (False, True):
            for startup in (0x01, 0x02, 0x03, 0x80, 0x83, 0xff):
                with self.subTest(formed=formed, startup=startup):
                    result = self.probe(stock_like_semantic(bdb=int(formed), nib=formed,
                                                           startup=startup))
                    self.assertEqual((result.code, result.semantic_state), (8, 0))
        # TI AUTO_START is a separate non-destructive option, not a clear bit.
        result = self.probe(stock_like_semantic(bdb=1, nib=True, startup=0x04))
        self.assertEqual((result.code, result.semantic_state), (8, 2))

    def test_mixed_full_inactive_normal_rollover_keeps_crc_and_empty_page_guards(self):
        media = bytearray(formed_tc300_rollover_media())
        result = self.probe(bytes(media))
        self.assertEqual((result.code, result.semantic_state), (8, 2))
        self.assertEqual((result.records, result.active_records), (795, 779))
        self.assertLess(result.reads, 30000)
        for page, offset, value in ((2, 20, 0x7f), (2, 0, 0x7e),
                                    (3, 0, 0xff), (0, 16, media[16] ^ 1)):
            with self.subTest(page=page, offset=offset):
                corrupted = bytearray(media)
                corrupted[page * PAGE_SIZE + offset] = value
                self.assertNotEqual(self.probe(bytes(corrupted)).code, 8)

    def test_f8_on_active_page_can_be_settled_after_ti_all_active_return(self):
        # TI tags PGACT/PGFULL with PGCSRC mode before its all-active early
        # return; only the page STATE (PGXSRC) requests write-backed recovery.
        before = bytearray(stock_like())
        before[6] = 0xf8
        self.assertEqual(self.probe(bytes(before)).code, 8)

    def test_genuine_ti_normal_resume_page_geometry_not_false_hold(self):
        result = self.probe(ti_normal_resume_with_retained_journals())
        self.assertEqual((result.code, result.semantic_state), (8, 1))
        self.assertEqual((result.records, result.active_records), (4, 4))

    def test_dense_four_page_layout_with_f8_retained_journals(self):
        # Mirrors record *counts and state shapes* only, without board data.
        result = self.probe(dense_ti_normal_resume_media())
        self.assertEqual((result.code, result.semantic_state), (8, 1))
        self.assertEqual((result.records, result.active_records), (715, 367))
        self.assertLess(result.reads, 30000)

    def test_f8_partial_journal_or_unexpected_state_still_holds(self):
        valid = bytearray(ti_normal_resume_with_retained_journals())
        corrupted = bytearray(valid)
        corrupted[2 * PAGE_SIZE + 10] = 0xff  # partial source page
        self.assertEqual(self.probe(bytes(corrupted)).code, 4)
        corrupted = bytearray(valid)
        corrupted[PAGE_SIZE + 6] = 0xf8  # XDST may not claim PGCSRC
        self.assertEqual(self.probe(bytes(corrupted)).code, 4)
        corrupted = bytearray(valid)
        corrupted[2 * PAGE_SIZE] = 0x70  # PGXSRC state requires recovery
        self.assertEqual(self.probe(bytes(corrupted)).code, 4)

    def test_f8_dense_layout_bad_crc_remains_blocked(self):
        corrupted = bytearray(dense_ti_normal_resume_media())
        corrupted[2 * PAGE_SIZE + 16] ^= 1
        self.assertEqual(self.probe(bytes(corrupted)).code, 6)

    def test_fc_completed_mode_checks_compaction_header_range(self):
        before = bytearray(stock_like())
        before[6] = 0xfc
        before[8:11] = bytes((16, 0, 1))
        before[12:15] = bytes((16, 0, 2))
        self.assertEqual(self.probe(bytes(before)).code, 8)
        before[8:10] = b'\xff\xff'
        self.assertEqual(self.probe(bytes(before)).code, 4)

    def test_completed_compaction_cannot_claim_its_own_destination_as_source(self):
        # TI's >2-page NVOCMP_compactPage chooses the tail as destination,
        # then records *other* pages as XSRCSTART/XSRCEND. A committed FC
        # journal pointing back to itself is not a settled page-ring state.
        original = bytearray(stock_like())
        original[6] = 0xfc
        original[8:11] = bytes((16, 0, 1))
        original[12:15] = bytes((16, 0, 2))
        self.assertEqual(self.probe(bytes(original)).code, 8)
        for position in (10, 14):
            with self.subTest(source_page_byte=position):
                bad = bytearray(original)
                bad[position] = 0  # destination is page 0
                self.assertEqual(self.probe(bytes(bad)).code, 4)

    def test_completed_compaction_same_source_page_cannot_run_forwards(self):
        # Pinned TI four-page compact() decrements srcOff; a same-page
        # XSRCEND offset larger than XSRCSTART cannot be produced by it.
        media = bytearray(stock_like())
        media[6] = 0xfc
        media[8:11] = bytes((128, 0, 1))
        media[12:15] = bytes((64, 0, 1))
        self.assertEqual(self.probe(bytes(media)).code, 8)
        media[12] = 192  # CRCs remain valid; only journal ordering is wrong.
        self.assertEqual(self.probe(bytes(media)).code, 4)

    def test_completed_compaction_sources_cannot_cross_destination_page(self):
        # TI's four-page compact() advances source pages via INCPAGE, and
        # its destination tail is never part of the copied source range.
        media = bytearray(stock_like())
        media[6] = 0xfc  # completed compaction journal on destination 0
        media[8:11] = bytes((128, 0, 1))
        media[12:15] = bytes((64, 0, 3))
        self.assertEqual(self.probe(bytes(media)).code, 8)
        media[8 + 2] = 3  # source 3 -> 0 -> 1 crosses destination 0
        media[12 + 2] = 1
        self.assertEqual(self.probe(bytes(media)).code, 4)

    def test_crc_failure_holds(self):
        corrupted = bytearray(stock_like())
        corrupted[16] ^= 1
        self.assertEqual(self.probe(bytes(corrupted)).code, 6)

    def test_unsettled_compaction_holds(self):
        for position, changed in ((0, 0x70), (PAGE_SIZE, 0x7c),
                                  (3*PAGE_SIZE, 0xff)):
            corrupted = bytearray(stock_like())
            corrupted[position] = changed
            self.assertNotEqual(self.probe(bytes(corrupted)).code, 8)

    def test_transport_error_fails_closed(self):
        self.assertEqual(self.probe(stock_like(), read_error=True).code, 2)

    def test_protected_geometry_is_exact_four_pages(self):
        self.assertEqual(self.probe(stock_like()[:-1]).code, 2)

    def test_record_ceiling_is_scan_limit_not_bad_item(self):
        media = bytearray(stock_like())
        for page, count in ((0, 1000), (1, 1000), (2, 1)):
            base = page * PAGE_SIZE
            offset = 16
            for _ in range(count):
                payload = b'X'
                trailer = bytearray((4, 0x1a, 0, 0, 4))
                crc = forensics.crc8(payload + trailer)
                trailer[4] |= crc >> 6
                # Obsolete valid versions may repeat an identity. Active
                # duplicates deliberately hit a different admission guard
                # before the 2000-record scan ceiling can be exercised.
                trailer.extend((((crc & 63) << 2), 0x96))
                media[base + offset:base + offset + 8] = payload + trailer
                offset += 8
        result = self.probe(bytes(media))
        self.assertEqual(result.records, 2000)
        self.assertEqual(result.code, 7)  # R4_NV4_SCAN_LIMIT


if __name__ == '__main__':
    unittest.main()
