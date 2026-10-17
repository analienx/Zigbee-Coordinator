import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from tools.b2_compare_native import EXPECTED, SDK_SHA, compute, CompareError, read

SOURCE_SHA="e"*40
RUN_ID="39001340291"

def checked(items,expected=SOURCE_SHA,run=RUN_ID):
    return compute(*items,expected,run)

def fixture(profile, binhash):
    p1=profile=="P1"
    tables={}
    for name,before,after,sz in EXPECTED:
        n=after if p1 else before
        tables[name]={"linked_count":n,"linked_bytes":n*sz,"entry_sizeof_derived":sz,
                      "status":"HOSTED_NATIVE_LINKED"}
    source={"status":"HOSTED_NATIVE_LINKED_TABLES","sdk_source_sha":SDK_SHA,
            "b2_repository_sha":SOURCE_SHA,"github_run_id":RUN_ID,
            "memory_regions":{"SRAM":{"size":0x24000}},
            "sram_linker_address_partition":{
                "below_heap_linker_reserved_span_bytes":24624+(3488 if p1 else 0),
                "heap_linker_address_span_bytes":121808-(3488 if p1 else 0),
                "above_heap_linker_reserved_span_bytes":1024},"tables":tables}
    receipt={"result":"NATIVE_STATIC_PROFILE_CONFIRMED","profile":profile,
             "delta_static_table_bytes_vs_p0":3488 if p1 else 0}
    manifest={"files":{"bin":{"sha256":binhash},
                       "elf":{"sha256":("c" if p1 else "d")*64}}}
    return source,receipt,manifest

class TwoNativeBuildComparatorTests(unittest.TestCase):
    def valid(self):
        return [fixture("P0","a"*64),fixture("P1","b"*64),fixture("P1","b"*64)]
    def test_static_delta_and_reproducibility(self):
        results=checked(self.valid())
        self.assertEqual(results["table_delta_bytes"],3488)
        self.assertEqual(results["unattributed_below_heap_delta_bytes"],0)
        self.assertTrue(results["binary_reproducible"])
        self.assertFalse(results["B2_SOURCE_READY"])
        self.assertIsNone(results["runtime_heap_high_water_bytes"])
    def test_unreproducible_images_rejected(self):
        a=self.valid()
        a[2][2]["files"]["bin"]["sha256"]="c"*64
        with self.assertRaisesRegex(CompareError,"not reproducible"):
            checked(a)
    def test_unreproducible_elves_rejected(self):
        a=self.valid()
        a[2][2]["files"]["elf"]["sha256"]="f"*64
        with self.assertRaisesRegex(CompareError,"ELF not reproducible"):
            checked(a)
    def test_noop_profile_rejected(self):
        a=self.valid()
        a[1][0]["tables"]["source_routes"]=copy.deepcopy(a[0][0]["tables"]["source_routes"])
        with self.assertRaisesRegex(CompareError,"linked table delta not proven"):
            checked(a)
    def test_source_shas_mismatch(self):
        a=self.valid()
        a[2][0]["b2_repository_sha"]="f"*40
        with self.assertRaisesRegex(CompareError,"source SHA differs"):
            checked(a)
    def test_stale_source_sha_common_to_all_rejected(self):
        a=self.valid()
        for p in a:p[0]["b2_repository_sha"]="f"*40
        with self.assertRaisesRegex(CompareError,"source SHA differs"):
            checked(a)
    def test_wrong_workflow_run_rejected(self):
        a=self.valid()
        a[1][0]["github_run_id"]="38964092055"
        with self.assertRaisesRegex(CompareError,"wrong workflow run"):
            checked(a)
    def test_unknown_sram_delta_rejected(self):
        a=self.valid()
        partition=a[1][0]["sram_linker_address_partition"]
        partition["below_heap_linker_reserved_span_bytes"]+=8
        partition["heap_linker_address_span_bytes"]-=8
        a[2][0]["sram_linker_address_partition"].update(partition)
        with self.assertRaisesRegex(CompareError,"unexplained"):
            checked(a)
    def test_replicas_with_different_sram_partitions_rejected(self):
        a=self.valid()
        partition=a[2][0]["sram_linker_address_partition"]
        partition["below_heap_linker_reserved_span_bytes"]+=4
        partition["heap_linker_address_span_bytes"]-=4
        with self.assertRaisesRegex(CompareError,"different linked SRAM partitions"):
            checked(a)
    def test_swapped_native_symbol_receipt_rejected_against_manifest(self):
        # Synthetic metadata only; does not substitute for preceding B0
        # cryptographic ELF/XML/HEX/BIN image audit in the real workflow.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"download"
            out=root/"b0out"
            (out/"b2-linked-baseline").mkdir(parents=True)
            files={}
            for kind,ext in (("bin","bin"),("elf","out"),("xml","xml"),("hex","hex")):
                blob=("SYNTHETIC_"+kind).encode()
                name="candidate."+ext
                (out/name).write_bytes(blob)
                files[kind]={"file":name,"sha256":hashlib.sha256(blob).hexdigest()}
            (out/"manifest.json").write_text(json.dumps({
                "schema":"r4-b0-artifact-manifest-v1","files":files}))
            native={
                "status":"HOSTED_NATIVE_LINKED_TABLES","sdk_source_sha":SDK_SHA,
                "artifact_sha256":{key:meta["sha256"] for key,meta in files.items()},
            }
            native["artifact_sha256"]["elf"]="f"*64
            receipt={
                "result":"NATIVE_STATIC_PROFILE_CONFIRMED","profile":"P1",
                "physical_verified":False,"source_ready":False,
            }
            (out/"b2-linked-baseline"/"B2_BASELINE_ELF_SYMBOLS.json").write_text(json.dumps(native))
            (out/"b2-linked-baseline"/"B2_PROFILE_P1_RECEIPT.json").write_text(json.dumps(receipt))
            with self.assertRaisesRegex(CompareError,"ELF extractor/manifest digest mismatch"):
                read(root,"P1")
    def test_mutated_raw_elf_rejected_despite_consistent_manifest_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"download"
            out=root/"b0out"
            (out/"b2-linked-baseline").mkdir(parents=True)
            records={}
            for kind,ext in (("elf","out"),("xml","xml"),("hex","hex"),("bin","bin")):
                raw=("ORIGINAL_"+kind).encode()
                path=out/("znp."+ext)
                path.write_bytes(raw)
                records[kind]={"file":path.name,"sha256":hashlib.sha256(raw).hexdigest()}
            (out/"manifest.json").write_text(json.dumps({
                "schema":"r4-b0-artifact-manifest-v1","files":records}))
            (out/"b2-linked-baseline"/"B2_BASELINE_ELF_SYMBOLS.json").write_text(json.dumps({
                "status":"HOSTED_NATIVE_LINKED_TABLES","sdk_source_sha":SDK_SHA,
                "artifact_sha256":{k:v["sha256"] for k,v in records.items()}}))
            (out/"b2-linked-baseline"/"B2_PROFILE_P1_RECEIPT.json").write_text(json.dumps({
                "result":"NATIVE_STATIC_PROFILE_CONFIRMED","profile":"P1",
                "physical_verified":False,"source_ready":False}))
            (out/"znp.out").write_bytes(b"TAMPERED ELF")
            with self.assertRaisesRegex(CompareError,"raw native elf hash mismatch"):
                read(root,"P1")
    def test_invalid_commit_or_workflow_run_rejected(self):
        with self.assertRaisesRegex(CompareError,"invalid expected"):
            checked(self.valid(),expected="HEAD")
        with self.assertRaisesRegex(CompareError,"invalid expected GitHub"):
            checked(self.valid(),run="not-a-run")
    def test_fake_runtime_sram(self):
        a=self.valid()
        a[1][0]["memory_regions"]["SRAM"]["size"]=8192
        with self.assertRaisesRegex(CompareError,"SRAM geometry"):
            checked(a)
    def test_bad_partition(self):
        a=self.valid()
        a[1][0]["sram_linker_address_partition"]["heap_linker_address_span_bytes"]=1000
        with self.assertRaisesRegex(CompareError,"invalid linked SRAM"):
            checked(a)
    def test_missing_table_proof(self):
        a=self.valid()
        a[1][0]["tables"]["neighbors"]["status"]="UNKNOWN_LINKED_CAPACITY"
        with self.assertRaisesRegex(CompareError,"missing ELF linked"):
            checked(a)

if __name__=="__main__":
    unittest.main()
