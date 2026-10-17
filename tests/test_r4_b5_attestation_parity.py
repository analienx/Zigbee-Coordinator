"""Synthetic hostile receipt mutation tests. Actual native proof runs in TI CI."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"firmware"/"slzb-06p7u"/"r4"/"b5"))
from b5_attestation_parity import compare

def example():
    material={"schema":"r4-b5-composite-material-v1",
              "b5_source_sha":"a"*40,"b1_source_sha":"b"*40,
              "ti_sdk_sha":"c"*40,
              "source_sha256":{"source/ti/s%d.c"%i:"e"*64 for i in range(12)},
              "native_sha256":{"elf":"a"*64,"hex":"b"*64,"bin":"c"*64}}
    digest=hashlib.sha256(json.dumps(material,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
    return {"schema":"r4-b5-native-offline-provenance-v1",
            "classification":"HOSTED_NATIVE_LINKED_SOURCE_BOUND",
            "composite_sha256":digest,"material":material,
            "flash_authorized":False,"physical_verified":False,
            "runtime_radio_attestation":False,
            "b1_public_status_digest_is_not_composite":True,
            "raw_linker_xml_excluded_from_composite_id":True,
            "raw_linker_xml_sha256":"d"*64}
class Parity(unittest.TestCase):
    def fixture(self,root,left,right):
        for i,report in enumerate((left,right)):
            sub=root/("replica-"+str(i))/"b0out"
            sub.mkdir(parents=True,exist_ok=True)
            (sub/"b5-native-offline-provenance.json").write_text(json.dumps(report))
    def test_identical_material_but_different_volatile_xml_passes(self):
        with tempfile.TemporaryDirectory() as d:
            a=example();b=example();b["raw_linker_xml_sha256"]="f"*64
            self.fixture(Path(d),a,b)
            out=compare(d)
            self.assertTrue(out["source_material_identical"])
            self.assertEqual(out["raw_xml_sha256_preserved"],["d"*64,"f"*64])
            self.assertFalse(out["flash_authorized"])
    def test_mismatched_final_source_fails(self):
        with tempfile.TemporaryDirectory() as d:
            a=example();b=example()
            b["material"]["source_sha256"]["source/ti/s1.c"]="0"*64
            b["composite_sha256"]=hashlib.sha256(json.dumps(b["material"],sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
            self.fixture(Path(d),a,b)
            with self.assertRaisesRegex(ValueError,"NOT reproducible"):
                compare(d)
    def test_falsified_digest_fails(self):
        with tempfile.TemporaryDirectory() as d:
            a=example();b=example();b["composite_sha256"]="0"*64
            self.fixture(Path(d),a,b)
            with self.assertRaisesRegex(ValueError,"material/hash mismatch"):
                compare(d)
    def test_fabricated_hardware_readiness_fails(self):
        with tempfile.TemporaryDirectory() as d:
            a=example();b=example();b["physical_verified"]=True
            self.fixture(Path(d),a,b)
            with self.assertRaisesRegex(ValueError,"forbidden readiness"):
                compare(d)
    def test_raw_xml_must_not_be_part_of_composite_hash(self):
        with tempfile.TemporaryDirectory() as d:
            a=example();b=example()
            b["material"]["native_sha256"]["xml"]="f"*64
            self.fixture(Path(d),a,b)
            with self.assertRaisesRegex(ValueError,"raw XML entered"):
                compare(d)
if __name__=="__main__":unittest.main()
