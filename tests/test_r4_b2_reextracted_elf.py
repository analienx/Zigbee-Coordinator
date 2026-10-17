import copy
import unittest
from tools.b2_verify_reextracted_elf import FIELDS, verify, RecomputeError

def row():
    obj={name:{"simulated":1} for name in FIELDS}
    obj["status"]="HOSTED_NATIVE_LINKED_TABLES"
    obj["b2_repository_sha"]="a"*40
    obj["github_run_id"]="39003893494"
    obj["artifact_sha256"]={"elf":"f"*64,"bin":"d"*64}
    obj["tables"]={"neighbors":{"linked_count":64},"source_routes":{"linked_count":192}}
    return obj

class ReextractTests(unittest.TestCase):
    def test_exact_equality_only_static_source_gate(self):
        r=verify(row(),row())
        self.assertEqual(r["status"],"B2_NATIVE_CLAIMS_INDEPENDENTLY_REDERIVED")
        self.assertFalse(r["B2_SOURCE_READY"])
    def test_changed_cache_size_same_elf_digest_rejected(self):
        x=row();y=copy.deepcopy(x)
        x["tables"]["source_routes"]["linked_count"]=255
        with self.assertRaisesRegex(RecomputeError,"tables"):verify(x,y)
    def test_stale_dynamic_heap_partition_rejected(self):
        x=row();y=copy.deepcopy(x)
        x["sram_linker_address_partition"]={"heap_linker_address_span_bytes":123456}
        with self.assertRaisesRegex(RecomputeError,"sram_linker_address_partition"):verify(x,y)
    def test_mto_default_source_disagreement_rejected(self):
        x=row();y=copy.deepcopy(x)
        x["concentrator_config_symbols"]={"zgConcentratorEnable":{"direct_elf_initializer_value":1}}
        with self.assertRaisesRegex(RecomputeError,"concentrator_config_symbols"):verify(x,y)
    def test_source_sha_replay_rejected(self):
        x=row();y=copy.deepcopy(x)
        x["b2_repository_sha"]="b"*40
        with self.assertRaisesRegex(RecomputeError,"b2_repository_sha"):verify(x,y)
    def test_raw_elf_digest_replay_rejected(self):
        x=row();y=copy.deepcopy(x)
        x["artifact_sha256"]["elf"]="0"*64
        with self.assertRaisesRegex(RecomputeError,"artifact_sha256"):verify(x,y)
    def test_partial_linked_evidence_rejected(self):
        x=row();x["status"]="HOSTED_NATIVE_LINKED_PARTIAL"
        with self.assertRaisesRegex(RecomputeError,"completeness"):verify(x,x)

if __name__=="__main__":unittest.main()
