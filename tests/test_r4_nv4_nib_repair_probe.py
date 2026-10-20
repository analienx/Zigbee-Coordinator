"""Real C read-only firmware NIB rescue gate, public synthetic NVOCMP v3."""
from __future__ import annotations

import ctypes
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.test_r4_nv4_readonly_admission import (
    PAGE_SIZE, READ, encoded_record, forensics, stock_like,
)

QUAL = Path(__file__).resolve().parents[1] / 'firmware/slzb-06p7u/r4/qualification'


class Candidate(ctypes.Structure):
    _fields_ = [
        ('nib_payload_offset', ctypes.c_uint32),
        ('startup_value', ctypes.c_uint8),
        ('eligible', ctypes.c_uint8),
    ]


def item(subid: int, data: bytes, *, active=True):
    length = len(data)
    assert 0 < length <= 4095
    h = bytearray((4, 0, subid >> 2,
                   ((subid & 3) << 6) | (length >> 6),
                   (length & 63) << 2))
    crc = forensics.crc8(data + h)
    h[4] |= crc >> 6
    h.extend(((((crc & 63) << 2) | (2 if active else 0)), 0x96))
    return data + h


def formed_deleted_nib(*, startup=3, bad_epid=False, missing=None,
                       nib_active=False, extra_nib=False,
                       bdb=1, role=0) -> bytes:
    base = bytearray(stock_like())
    pan = bytes((0x5b, 0x1c, 0x39, 0x72, 0x2e, 0xa0, 0xd1, 0x48))
    nib = bytearray(b'Q' * 116)
    nib[57:65] = bytes((0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88)) if bad_epid else pan
    entries = [
        (0x55, bytes((bdb,)), True),
        (0x87, bytes((role,)), True),
        (0x03, bytes((startup,)), True),
        (0x2d, pan, True),
        (0x3a, b'A' * 17, True),
        (0x3b, b'B' * 17, True),
        (0x71, b'T' * 8, True),
        (0x101, b'S' * 16, True),
        (0x21, bytes(nib), nib_active),
    ]
    if extra_nib:
        entries.append((0x21, bytes(nib), False))
    cursor = 16 + len(encoded_record(0))
    for sub, payload, active in entries:
        if sub == missing:
            continue
        record = item(sub, payload, active=active)
        base[cursor:cursor + len(record)] = record
        cursor += len(record)
    assert cursor < PAGE_SIZE
    return bytes(base)


@unittest.skipUnless(shutil.which('gcc'), 'gcc required for real C read-only gate')
class P7UNibRepairProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='p7u-nib-probe-')
        target = Path(cls.tmp.name)/'probe.so'
        src = [QUAL/'nv4_readonly_admission.c', QUAL/'nv4_nib_repair_probe.c']
        r = subprocess.run(
            ['gcc', '-std=c11', '-O2', '-shared', '-fPIC', '-Wall', '-Wextra',
             '-Werror', *(str(x) for x in src), '-o', str(target)],
            capture_output=True, text=True, check=False)
        if r.returncode:
            raise RuntimeError(r.stderr)
        cls.lib = ctypes.CDLL(str(target))
        cls.lib.r4_nv4_probe_nib.argtypes = [
            READ, ctypes.c_void_p, ctypes.POINTER(Candidate),
            ctypes.POINTER(ctypes.c_uint8),
        ]
        cls.lib.r4_nv4_probe_nib.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def qualify(self, raw):
        original = bytes(raw)
        def read(_ctx, off, dst, count):
            if off + count > len(raw):
                return -1
            ctypes.memmove(dst, raw[off:off + count], count)
            return 0
        callback = READ(read)
        out = Candidate()
        nib = (ctypes.c_uint8 * 116)()
        accepted = self.lib.r4_nv4_probe_nib(callback, None,
                                             ctypes.byref(out), nib)
        self.assertEqual(original, bytes(raw), 'probe wrote to NV media')
        return accepted, out, bytes(nib)

    def test_exact_deleted_original_nib_qualifies_without_mutation(self):
        for option in (0, 3):
            with self.subTest(option=option):
                raw = formed_deleted_nib(startup=option)
                ok, info, nib = self.qualify(raw)
                self.assertEqual(ok, 1)
                self.assertEqual(info.eligible, 1)
                self.assertEqual(info.startup_value, option)
                self.assertEqual(len(nib), 116)
                self.assertEqual(nib[57:65],
                                 bytes((0x5b, 0x1c, 0x39, 0x72,
                                        0x2e, 0xa0, 0xd1, 0x48)))

    def test_unsafe_or_ambiguous_media_never_eligible(self):
        variants = [
            formed_deleted_nib(startup=1),
            formed_deleted_nib(startup=2),
            formed_deleted_nib(bdb=0),
            formed_deleted_nib(role=1),
            formed_deleted_nib(bad_epid=True),
            formed_deleted_nib(extra_nib=True),
            formed_deleted_nib(nib_active=True),
            *(formed_deleted_nib(missing=id_) for id_ in
              (0x03, 0x2d, 0x3a, 0x3b, 0x71, 0x101, 0x21, 0x55, 0x87)),
        ]
        for i, variant in enumerate(variants):
            with self.subTest(variant=i):
                ok, info, nib = self.qualify(variant)
                self.assertEqual(ok, 0)
                self.assertEqual(info.eligible, 0)
                self.assertEqual(nib, bytes(116))

    def test_crc_failure_and_torn_page_never_eligible(self):
        good = formed_deleted_nib()
        corruption = bytearray(good)
        corruption[16] ^= 0x01
        ok, _, nib = self.qualify(bytes(corruption))
        self.assertEqual(ok, 0)
        self.assertEqual(nib, bytes(116))
        torn = bytearray(good)
        torn[3 * PAGE_SIZE] = 0x70
        self.assertEqual(self.qualify(bytes(torn))[0], 0)
