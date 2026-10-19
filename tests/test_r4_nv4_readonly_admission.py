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


def encoded_record(subid: int, *, sysid: int = 1) -> bytes:
    """Real NVOCMP_HDRLE=0 compressed ID/status and CRC, public fake data."""
    data = b'not-a-real-key'
    header = bytearray((sysid << 2, 0x1a, subid >> 2,
                        ((subid & 3) << 6) | (len(data) >> 6),
                        (len(data) & 63) << 2))
    crc = forensics.crc8(data + header)
    header[4] |= crc >> 6
    header += bytes((((crc & 63) << 2) | 2, 0x96))
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
                        bdb_payload: bytes | None = None) -> bytes:
    """Public fake coordinator markers, never a real NIB/key/payload."""
    media = bytearray(stock_like())
    cursor = 16 + len(encoded_record(0))
    parts = []
    if bdb is not None:
        parts.append(legacy_osal_record(0x55, bdb_payload if bdb_payload is not None
                                        else bytes((bdb,))))
    if logical is not None:
        parts.append(legacy_osal_record(0x87, bytes((logical,))))
    if nib:
        parts.append(legacy_osal_record(0x21, b'synthetic-nib-not-a-secret'))
    for part in parts:
        media[cursor:cursor + len(part)] = part
        cursor += len(part)
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
        self.assertEqual(candidate.active_records, 3)

        mutants = []
        half_recycled = bytearray(before)
        half_recycled[PAGE_SIZE] = 0x78  # mixed old/new ring states
        mutants.append(half_recycled)
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
        self.assertEqual((settled.records, settled.active_records), (3, 3))

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
        self.assertEqual((formed.records, formed.active_records), (4, 4))

    def test_marker_byte_comes_from_crc_checked_read_without_reread(self):
        raw = stock_like_semantic()
        bdb_offset = 16 + len(encoded_record(0))
        role_offset = bdb_offset + len(legacy_osal_record(0x55, b'\x00'))
        marker_reads = {bdb_offset: 0, role_offset: 0}

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
        self.assertEqual(marker_reads, {bdb_offset: 1, role_offset: 1})

    def test_missing_incoherent_or_malformed_semantic_markers_hold(self):
        variants = (
            dict(bdb=None), dict(logical=None), dict(bdb=2),
            dict(logical=1), dict(bdb=1), dict(nib=True),
            dict(bdb_payload=b'\x00\x00'),
        )
        for variant in variants:
            with self.subTest(**variant):
                result = self.probe(stock_like_semantic(**variant))
                self.assertEqual(result.code, 8)  # CRC-valid structure.
                self.assertEqual(result.semantic_state, 0)  # But HOLD.

    def test_f8_compaction_is_not_silent_settled_admission(self):
        before = bytearray(stock_like())
        before[6] = 0xf8
        self.assertEqual(self.probe(bytes(before)).code, 4)

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


if __name__ == '__main__':
    unittest.main()
