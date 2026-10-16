import copy
import unittest
from tools.b2_capacity_gate import EvidenceError, validate, BASE_COMMIT

def fixture():
    def table(count,size,name):
        return {"linked_count":count,"entry_sizeof":size,"linked_bytes":count*size,
                "elf_symbol":name,"section":".bss","map_reference":"native.map:42",
                "source_reference":"pinned.c:21"}
    return {
        "base_commit":BASE_COMMIT,
        "source_sha":"synthetic-source","build_source_sha":"synthetic-source",
        "sdk_sha":"synthetic-sdk","elf_sha256":"synthetic-elf",
        "map_sha256":"synthetic-map","compiler":"synthetic-compiler",
        "measurement_kind":"HOSTED_NATIVE_LINKED",
        "sram_bytes":80000,"static_allocated_bytes":30000,
        "c_irq_stack_bytes":4096,"task_stack_bytes":{"nwk":2048,"app":2048},
        "heap_arena_bytes":20000,"peak_dynamic_route_bytes":8000,
        "fragmentation_reserve_bytes":4000,
        "static_excludes_heap_and_task_stacks":True,
        "tables":{
            "source_routes":table(192,16,"srcCache"),
            "neighbors":table(64,24,"neighbors"),
            "nwk_routes":table(128,16,"routes"),
            "children":table(96,12,"children"),
        },
    }

class CapacityGateTests(unittest.TestCase):
    def test_synthetic_fixture_only_tests_arithmetic_not_real_native_provenance(self):
        self.assertEqual(validate(fixture())["sram_headroom_bytes"],21808)
    def test_impossible_p3_fails_for_budget(self):
        e=fixture();e["sram_bytes"]=40000
        with self.assertRaisesRegex(EvidenceError,"SRAM_BUDGET_EXCEEDED"):validate(e)
    def test_macro_only_evidence_rejected(self):
        e=fixture();e["measurement_kind"]="SOURCE_DEFINE"
        with self.assertRaisesRegex(EvidenceError,"linked evidence required"):validate(e)
    def test_wrong_sha_rejected(self):
        e=fixture();e["build_source_sha"]="other"
        with self.assertRaisesRegex(EvidenceError,"source SHA"):validate(e)
    def test_wrong_table_arithmetic_rejected(self):
        e=fixture();e["tables"]["neighbors"]["linked_bytes"]+=1
        with self.assertRaisesRegex(EvidenceError,"does not match"):validate(e)
    def test_missing_map_symbol_rejected(self):
        e=fixture();e["tables"]["children"]["elf_symbol"]=""
        with self.assertRaisesRegex(EvidenceError,"missing linked"):validate(e)
    def test_heap_overcommit_rejected(self):
        e=fixture();e["peak_dynamic_route_bytes"]=18000
        with self.assertRaisesRegex(EvidenceError,"exceeds heap"):validate(e)
    def test_non_disjoint_memory_rejected(self):
        e=fixture();e["static_excludes_heap_and_task_stacks"]=False
        with self.assertRaisesRegex(EvidenceError,"disjoint"):validate(e)
    def test_bool_is_not_integer(self):
        e=fixture();e["tables"]["children"]["linked_count"]=True
        with self.assertRaisesRegex(EvidenceError,"positive integer"):validate(e)

if __name__=="__main__":unittest.main()
