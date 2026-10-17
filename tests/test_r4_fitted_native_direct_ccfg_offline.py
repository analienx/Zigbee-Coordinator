"""Synthetic-only checks of fitted P7U native ROM direct CCFG plan."""
from __future__ import annotations
import binascii
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

R=Path(__file__).resolve().parents[1]/"firmware/slzb-06p7u/r4"
sys.path.insert(0,str(R/"release"))
sys.path.insert(0,str(R/"b0/tools"))
spec=importlib.util.spec_from_file_location("direct_ccfg",R/"release/r4_fitted_native_direct_ccfg_offline.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
from r4_make_direct_app_only import serialize_app


def synthetic():
    f=bytearray(b"\xff"*m.FULL)
    struct.pack_into("<I",f,m.CCFG+1*4,0xffc00010)
    struct.pack_into("<I",f,m.CCFG+3*4,0xf1b9c1ff)
    struct.pack_into("<I",f,m.BL_CONFIG,0xC5FE0FC5)
    struct.pack_into("<I",f,m.BOOT_WORD,m.STOCK_VECTOR)
    raw={i:0x70 for i in range(0x3C)}
    for i,v in enumerate(struct.pack("<II",0x20023C00,0x25C69)):
        raw[i]=v
    for sector in range(0,m.APP_END,m.SECTOR):
        raw[sector+0x100]=sector//m.SECTOR
    native=dict(raw)
    for address in range(m.CCFG,m.FULL):
        native[address]=f[address]
    for offset,value in ((1,0xff800010),(3,0xffb9c1ff),(17,0)):
        for i,b in enumerate(struct.pack("<I",value)):
            native[m.CCFG+4*offset+i]=b
    return bytes(f),native,serialize_app(raw)

def calculate(factory,native,app,**other):
    return m.plan(factory,factory,native,app,app,
                  factory_pin=m.sha(factory),app_pin=m.sha(app),
                  stock_top_crc=m.crc(factory[m.TOP:]),**other)

class NativeFittedTests(unittest.TestCase):
    def setUp(self):
        self.f,self.n,self.app=synthetic()

    def test_exact_one_word_keep_all_power_and_security_bytes(self):
        wanted,original,report=calculate(self.f,self.n,self.app)
        self.assertEqual(original,self.f[m.TOP:])
        self.assertEqual(len(wanted),m.SECTOR)
        assertbyte=m.BOOT_WORD-m.TOP
        self.assertEqual(wanted[assertbyte:assertbyte+4],b"\x00"*4)
        self.assertEqual(report["fitted_ccfg_compiled_corrections"]["MODE_CONF"]["factory"],
                         "0xf1b9c1ff")
        self.assertEqual(report["fitted_ccfg_compiled_corrections"]["MODE_CONF_1"]["factory"],
                         "0xffc00010")
        self.assertFalse(report["flash_authorized"])
        self.assertTrue(report["rollback_requires_full_top_sector_erase"])
        self.assertFalse(report["rollback_flash_top_sector_physical_restoration_proven"])
        self.assertFalse(report["physical_no_erase_word_program_proven"])
        self.assertEqual(m.crc(wanted),report["candidate_top_sector_crc32"])
        for i in range(m.SECTOR):
            if not assertbyte<=i<assertbyte+4:
                self.assertEqual(wanted[i],original[i])
        self.assertEqual(bytes(a&b for a,b in zip(wanted,original)),wanted)

    def test_second_factory_read_disagreement_denied(self):
        bad=bytearray(self.f);bad[0x100]^=1
        with self.assertRaisesRegex(ValueError,"TWO_ORIGINAL_FACTORY"):
            m.plan(self.f,bytes(bad),self.n,self.app,self.app,
                   factory_pin=m.sha(self.f),app_pin=m.sha(self.app),
                   stock_top_crc=m.crc(self.f[m.TOP:]))

    def test_compiled_ccfg_unexpected_drift_rejected(self):
        other=dict(self.n)
        other[m.CCFG+12*4]^=1
        with self.assertRaisesRegex(ValueError,"UNEXPECTED_COMPILED_CCFG"):
            calculate(self.f,other,self.app)

    def test_bad_backdoor_and_write_protect_denied(self):
        for mutation,name in ((m.BL_CONFIG,"FITTED_ROM_BSL"),(m.PROTECT_64_95,"WRITE_PROTECTED")):
            b=bytearray(self.f)
            if mutation==m.BL_CONFIG:
                b[mutation]=0xFF
            else:
                word=struct.unpack_from("<I",b,mutation)[0]
                struct.pack_into("<I",b,mutation,word&~(1<<(87-64)))
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,name):
                calculate(bytes(b),self.n,self.app)

    def test_direct_boot_old_vector_and_compiled_diff_checks(self):
        b=bytearray(self.f);struct.pack_into("<I",b,m.BOOT_WORD,0)
        with self.assertRaisesRegex(ValueError,"OLD_FITTED_BOOT_ADDRESS"):
            calculate(bytes(b),self.n,self.app)
        nn=dict(self.n)
        for a in range(m.CCFG+4,m.CCFG+8):
            nn[a]=self.f[a]
        with self.assertRaisesRegex(ValueError,"EXPECTED_FITTED_VS_NATIVE_CCFG"):
            calculate(self.f,nn,self.app)

    def test_reject_app_mismatch_and_bad_sector_geometry(self):
        with self.assertRaisesRegex(ValueError,"TWO_IDENTICAL_NATIVE_APP"):
            m.plan(self.f,self.f,self.n,self.app,self.app+b"\x00",
                   factory_pin=m.sha(self.f),app_pin=m.sha(self.app),
                   stock_top_crc=m.crc(self.f[m.TOP:]))
        other=dict(self.n);other[0xA0000]=0
        with self.assertRaisesRegex(ValueError,"RESERVED_NV_OR_BOOT"):
            calculate(self.f,other,self.app)
        other=dict(self.n);other[0x100]^=1
        with self.assertRaisesRegex(ValueError,"NOT_SAME_COMPILED_IMAGE"):
            calculate(self.f,other,self.app)

    def test_native_ccfg_cannot_replace_factory_ccfg(self):
        wanted,original,report=calculate(self.f,self.n,self.app)
        native_ccfg=bytes(self.n[a] for a in range(m.CCFG,m.FULL))
        self.assertNotEqual(original[m.CCFG-m.TOP:],native_ccfg)
        self.assertFalse(report["safe_p7u_compiled_ccfg_replacement"])
        self.assertTrue(report["erase_top_sector_currently_forbidden"])


if __name__=="__main__":
    unittest.main()
