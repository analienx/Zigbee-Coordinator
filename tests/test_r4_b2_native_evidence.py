"""Hostile parser controls; fabricated fixtures are NOT TI ELF validation."""
import json
import tempfile
import unittest
from pathlib import Path
from tools.b2_collect_native_evidence import (
    EvidenceError, checked_member, load_manifest,
    parse_elf, initializer_value, one_symbol,
)

class NativeEvidenceTests(unittest.TestCase):
    def test_reject_bad_elf(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"fake.out"
            path.write_bytes(b"pretend ELF")
            with self.assertRaisesRegex(EvidenceError,"invalid native ELF"):
                parse_elf(path)

    def test_truncated_section_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"fake.out"
            blob=bytearray(52)
            blob[:4]=b"\\x7fELF"
            blob[4]=1
            blob[5]=1
            blob[18:20]=(40).to_bytes(2,"little")
            blob[32:36]=(4096).to_bytes(4,"little")
            blob[46:48]=(40).to_bytes(2,"little")
            blob[48:50]=(4).to_bytes(2,"little")
            blob[50:52]=(1).to_bytes(2,"little")
            path.write_bytes(blob)
            with self.assertRaisesRegex(EvidenceError,"malformed ELF section"):
                parse_elf(path)

    def test_reject_path_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with self.assertRaisesRegex(EvidenceError,"traversal"):
                checked_member(root,"../outside.out")
            (root/"file").write_bytes(b"contents")
            (root/"link").symlink_to(root/"file")
            with self.assertRaisesRegex(EvidenceError,"symlinked"):
                checked_member(root,"link")

    def test_missing_manifest_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"manifest.json").write_text(json.dumps({
                "schema":"r4-b0-artifact-manifest-v1",
                "files":{"elf":{"file":"file.out"}}}))
            with self.assertRaisesRegex(EvidenceError,"missing manifest hash"):
                load_manifest(root)

    def test_mismatched_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ("test.out","test.xml","test.hex","test.bin"):
                (root/name).write_bytes(b"contents")
            (root/"manifest.json").write_text(json.dumps({
                "schema":"r4-b0-artifact-manifest-v1",
                "files":{k:{"file":"test."+ext,"sha256":"0"*64}
                    for k,ext in (("elf","out"),("xml","xml"),("hex","hex"),("bin","bin"))}}))
            with self.assertRaisesRegex(EvidenceError,"artifact hash mismatch"):
                load_manifest(root)

    def test_missing_or_ambiguous_symbol_remains_unknown(self):
        self.assertIsNone(one_symbol({},"rtgSrcTable"))
        s={"name":"rtgSrcTable","size_bytes":192}
        self.assertIsNone(one_symbol({"rtgSrcTable":[s,s]},"rtgSrcTable"))

    def test_read_only_initialized_scalar(self):
        raw=bytes([0x00,0x0c,0x00])
        record={"size_bytes":1,"section_type":1,
                "address":0x1001,"section_address":0x1000,
                "section_size":3,"section_offset":0}
        self.assertEqual(initializer_value(raw,record),12)
        record["section_type"]=8
        self.assertIsNone(initializer_value(raw,record))

if __name__=="__main__":
    unittest.main()
