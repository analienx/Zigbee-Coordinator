import copy
import unittest
from tools.b2_compare_native import EXPECTED, SDK_SHA, compute, CompareError

SOURCE_SHA="e"*40

def fixture(profile, binhash):
    p1=profile=="P1"
    tables={}
    for name,before,after,sz in EXPECTED:
        n=after if p1 else before
        tables[name]={"linked_count":n,"linked_bytes":n*sz,"entry_sizeof_derived":sz,
                      "status":"HOSTED_NATIVE_LINKED"}
    source={"status":"HOSTED_NATIVE_LINKED_TABLES","sdk_source_sha":SDK_SHA,
            "b2_repository_sha":SOURCE_SHA,
            "memory_regions":{"SRAM":{"size":0x24000}},
            "sram_linker_address_partition":{
                "below_heap_linker_reserved_span_bytes":24624+(3488 if p1 else 0),
                "heap_linker_address_span_bytes":121808-(3488 if p1 else 0),
                "above_heap_linker_reserved_span_bytes":1024},"tables":tables}
    receipt={"result":"NATIVE_STATIC_PROFILE_CONFIRMED","profile":profile,
             "delta_static_table_bytes_vs_p0":3488 if p1 else 0}
    manifest={"files":{"bin":{"sha256":binhash}}}
    return source,receipt,manifest

class TwoNativeBuildComparatorTests(unittest.TestCase):
    def valid(self):
        return [fixture("P0","a"*64),fixture("P1","b"*64),fixture("P1","b"*64)]
    def test_static_delta_and_reproducibility(self):
        results=compute(*self.valid())
        self.assertEqual(results["table_delta_bytes"],3488)
        self.assertEqual(results["unattributed_below_heap_delta_bytes"],0)
        self.assertTrue(results["binary_reproducible"])
        self.assertFalse(results["B2_SOURCE_READY"])
        self.assertIsNone(results["runtime_heap_high_water_bytes"])
    def test_unreproducible_images_rejected(self):
        a=self.valid()
        a[2][2]["files"]["bin"]["sha256"]="c"*64
        with self.assertRaisesRegex(CompareError,"not reproducible"):
            compute(*a)
    def test_noop_profile_rejected(self):
        a=self.valid()
        a[1][0]["tables"]["source_routes"]=copy.deepcopy(a[0][0]["tables"]["source_routes"])
        with self.assertRaisesRegex(CompareError,"linked table delta not proven"):
            compute(*a)
    def test_source_shas_mismatch(self):
        a=self.valid()
        a[2][0]["b2_repository_sha"]="f"*40
        with self.assertRaisesRegex(CompareError,"nonmatching"):
            compute(*a)
    def test_fake_runtime_sram(self):
        a=self.valid()
        a[1][0]["memory_regions"]["SRAM"]["size"]=8192
        with self.assertRaisesRegex(CompareError,"SRAM geometry"):
            compute(*a)
    def test_bad_partition(self):
        a=self.valid()
        a[1][0]["sram_linker_address_partition"]["heap_linker_address_span_bytes"]=1000
        with self.assertRaisesRegex(CompareError,"invalid linked SRAM"):
            compute(*a)
    def test_missing_table_proof(self):
        a=self.valid()
        a[1][0]["tables"]["neighbors"]["status"]="UNKNOWN_LINKED_CAPACITY"
        with self.assertRaisesRegex(CompareError,"missing ELF linked"):
            compute(*a)

if __name__=="__main__":
    unittest.main()
