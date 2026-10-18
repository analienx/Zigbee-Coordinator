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
                ('code', 'reads', 'records', 'active_records', 'fault_offset')]


READ = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
                       ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32)
PAGE_SIZE = 8192


def stock_like() -> bytes:
    media = bytearray(b'\xff' * (4 * PAGE_SIZE))
    for page, state in enumerate((0x7c, 0x78, 0x78, 0xfe)):
        base = page * PAGE_SIZE
        media[base:base+4] = bytes((state, page + 1, 0x0f, 0x96))
        for marker in (7, 11, 15):
            media[base + marker] = 0x96
    data = b'not-a-real-key'
    header = bytearray((4, 0x1a, 0, len(data) >> 6, (len(data) & 63) << 2))
    crc = forensics.crc8(data + header)
    header[4] |= crc >> 6
    header += bytes((((crc & 63) << 2) | 2, 0x96))
    media[16:16 + len(data) + len(header)] = data + header
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
        self.assertEqual((result.records, result.active_records), (1, 1))
        self.assertLess(result.reads, 30000)
        self.assertEqual(before, stock_like())

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
