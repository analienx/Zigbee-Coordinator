"""Hostile preflight synthetic corpus; NEVER an actual chip test."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/release"))
from r4_flash_preflight import image_check, private_readbacks, FLASH, CCFG

def record(addr, typ, body=b""):
    raw=bytes((len(body),(addr>>8)&255,addr&255,typ))+body
    return ":"+(raw+bytes((-sum(raw)&255,))).hex().upper()
def hexify(payload):
    out=[];hi=-1
    for addr,value in sorted(payload.items()):
        if addr>>16!=hi:
            hi=addr>>16
            out.append(record(0,4,hi.to_bytes(2,"big")))
        out.append(record(addr&65535,0,bytes((value,))))
    return "\n".join(out+[record(0,1),""])
def example():
    return {**{i:(i*7+19)%256 for i in range(60)},
            **{CCFG+i:i for i in range(88)}}
def fixture(root, contents):
    p=Path(root)/"native.hex"
    p.write_text(hexify(contents))
    (Path(root)/"manifest.json").write_text(json.dumps({
       "schema":"r4-b0-artifact-manifest-v1",
       "files":{"hex":{"file":p.name,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}}}))
    return p

class Tests(unittest.TestCase):
    def test_app_only_and_ccfg_still_no_flash(self):
        with tempfile.TemporaryDirectory() as d:
            raw=example();raw[0xA3FFF]=23;fixture(d,raw)
            result,ccfg=image_check(d)
            self.assertEqual(len(ccfg),88)
            self.assertFalse(result["flash_authorized"])
            self.assertIn("0xa2000",result["application_sectors"])
    def test_protected_union_even_ff_byte_rejected(self):
        for addr in (0xA4000,0xA5FFF,0xAA000,0xADFFF):
            with tempfile.TemporaryDirectory() as d,self.subTest(addr=addr):
                raw=example();raw[addr]=255;fixture(d,raw)
                with self.assertRaisesRegex(ValueError,"protected"):image_check(d)
    def test_other_top_sector_data_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            raw=example();raw[0xAE000]=1;fixture(d,raw)
            with self.assertRaisesRegex(ValueError,"outside exact CCFG"):image_check(d)
    def test_ccfg_hole_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            raw=example();raw.pop(CCFG);fixture(d,raw)
            with self.assertRaisesRegex(ValueError,"CCFG comparison"):image_check(d)
    def test_missing_vector_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            raw=example();raw.pop(0);fixture(d,raw)
            with self.assertRaisesRegex(ValueError,"vectors"):image_check(d)
    def test_hex_hash_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=fixture(d,example());p.write_text("broken")
            with self.assertRaisesRegex(ValueError,"hash bound"):image_check(d)
    def test_symlinked_hex_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=fixture(d,example());t=p.with_name("actual.hex");p.rename(t);p.symlink_to(t)
            with self.assertRaisesRegex(ValueError,"symlinked"):image_check(d)
    def test_duplicated_private_bytes_alone_not_hardware_approval(self):
        with tempfile.TemporaryDirectory() as d:
            raw=bytearray(b"\xff"*FLASH)
            raw[CCFG:]=bytes(range(88))
            a,b=Path(d)/"a.bin",Path(d)/"b.bin"
            a.write_bytes(raw);b.write_bytes(raw)
            receipt=private_readbacks(a,b,bytes(range(88)))
            self.assertTrue(receipt["input_files_identical"])
            self.assertFalse(receipt["actual_hardware_origin_attested"])
    def test_private_mutated_nv_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            raw=bytearray(b"\xff"*FLASH);raw[CCFG:]=bytes(range(88))
            a,b=Path(d)/"a.bin",Path(d)/"b.bin"
            a.write_bytes(raw);raw[0xAA001]=0;b.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,"not byte-identical"):
                private_readbacks(a,b,bytes(range(88)))
    def test_private_ccfg_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            raw=bytearray(b"\xff"*FLASH);raw[CCFG:]=bytes(range(88))
            a,b=Path(d)/"a.bin",Path(d)/"b.bin"
            a.write_bytes(raw);b.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,"CCFG differs"):
                private_readbacks(a,b,b"\x00"*88)
    def test_incomplete_backup_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a,b=Path(d)/"a.bin",Path(d)/"b.bin"
            a.write_bytes(b"x"*23);b.write_bytes(b"x"*23)
            with self.assertRaisesRegex(ValueError,"704KiB"):
                private_readbacks(a,b,bytes(range(88)))

if __name__=="__main__":unittest.main()
