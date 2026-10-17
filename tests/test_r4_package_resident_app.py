"""Hostile synthetic tests for fitted P7U header / sparse app-only container."""
import importlib.util
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
HERE=ROOT/"firmware/slzb-06p7u/r4/release"
spec=importlib.util.spec_from_file_location("p7u_package",HERE/"r4_package_resident_app.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def synthetic():
    p={x:(x*7)%251 for x in range(0x80,0x2000)}
    p.update({i:b for i,b in enumerate(struct.pack("<II",0x20023c00,0x101),start=0x80)})
    p.update({x:0xff for x in range(0xAFFA8,0xB0000)})
    return p

class ResidentHeaderTests(unittest.TestCase):
    def test_app_only_header_matches_fitted_boot_stage(self):
        p=synthetic()
        out,report=module.compose(p)
        self.assertEqual(bytes(out[i] for i in range(4)),struct.pack("<I",0x96f3b83d))
        self.assertEqual(struct.unpack("<I",bytes(out[i] for i in range(8,12)))[0],0x80)
        self.assertEqual(struct.unpack("<I",bytes(out[i] for i in range(12,16)))[0],0x1f80)
        self.assertEqual(struct.unpack("<I",bytes(out[i] for i in range(20,24)))[0],1)
        self.assertEqual(len(out),0x2000)
        self.assertTrue(all(0<=addr<0xa0000 for addr in out))
        self.assertFalse(report["flash_authorized"])
        self.assertFalse(report["bootloader_handoff_hardware_proven"])
        self.assertEqual(out[0x80],p[0x80])
    def test_emit_hex_reparse_exactly(self):
        from b0_image_audit import _parse_intel_hex
        output,_=module.compose(synthetic())
        with tempfile.TemporaryDirectory() as td:
            f=pathlib.Path(td)/"app.hex"
            f.write_bytes(module.intel_hex(output))
            reread,err=_parse_intel_hex(f)
            self.assertIsNone(err)
            self.assertEqual(reread,output)
    def test_absent_or_protected_address_deny(self):
        for name,mutate in (
            ("app-below-0x80",lambda p:p.update({0:10})),
            ("original-nv",lambda p:p.update({0xaa000:10})),
            ("protected-boot",lambda p:p.update({0xac000:10})),
            ("protected-upper",lambda p:p.update({0xae111:10})),
            ("missing-ccfg",lambda p:p.pop(0xaffa8)),
            ("missing-vector",lambda p:p.pop(0x81)),
            ("invalid-sp",lambda p:p.update({0x80:0xff,0x81:0xff,0x82:0xff,0x83:0xff})),
            ("invalid-pc",lambda p:p.update({0x84:0,0x85:0,0x86:0,0x87:0})),
        ):
            with self.subTest(name=name):
                p=synthetic();mutate(p)
                with self.assertRaisesRegex(ValueError,"R4_P7U_PACKAGE_"):
                    module.compose(p)
    def test_nonstandard_or_oversize_header_deny(self):
        for v in (0,0x20,0xa0000,0x9ff81):
            with self.subTest(v=v):
                with self.assertRaisesRegex(ValueError,"IMAGE_LENGTH"):
                    module.make_header(v)

if __name__=="__main__":unittest.main()
