"""Adversarial capacity-only release seal; synthetic fixtures are NOT native evidence."""
import copy
import unittest
from tools.b2_seal_native_capacity import SealError, seal

SHA="a"*40
RUN="39005192030"
TI="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
TABS=["children","neighbors","nwk_routes","relay_path","route_requests","source_routes"]

def input_set():
    alloc={"below_heap_linker_reserved_span_bytes":28112,
           "heap_linker_address_span_bytes":118320,
           "above_heap_linker_reserved_span_bytes":1024}
    c={
        "status":"B2_NATIVE_CAPACITY_EVIDENCE_COMPLETE_NOT_B2_SOURCE_READY",
        "source_sha":SHA,"sdk_sha":TI,"B2_SOURCE_READY":False,
        "physical_verified":False,"table_delta_bytes":3488,
        "unattributed_below_heap_delta_bytes":0,"binary_reproducible":True,
        "elf_reproducible":True,"closed_ti_routing_body_tests":"BLOCKED_SOURCE_UNAVAILABLE",
        "elf_sha256":{"P0":"1"*64,"P1":"2"*64},
        "binary_sha256":{"P0":"3"*64,"P1":"4"*64},
        "linked_sram_partitions":{"P0":{"below_heap_linker_reserved_span_bytes":24624,
          "heap_linker_address_span_bytes":121808,"above_heap_linker_reserved_span_bytes":1024},
          "P1a":copy.deepcopy(alloc),"P1b":copy.deepcopy(alloc)}
    }
    e=[{"status":"B2_NATIVE_CLAIMS_INDEPENDENTLY_REDERIVED",
        "source_sha":SHA,"run_id":RUN,"elf_sha256":h,
        "runtime_heap_high_water_measured":False,"B2_SOURCE_READY":False,
        "linked_tables_verified":TABS} for h in ("1"*64,"2"*64,"2"*64)]
    p3={"status":"HOSTED_NATIVE_LINKER_OVERBUDGET_REJECTED",
        "reason":"TI_CLANG_CCS_ERROR_10099_SRAM_EXHAUSTION",
        "linker_exit_status":1,"sram_bytes":147456,
        "test_only_bss_bytes":147456,"usable_firmware_produced":False,
        "physical_verified":False,"TI_SDK_PIN":TI}
    return [c,e,p3]

class NativeCapacitySeal(unittest.TestCase):
    def test_valid_capacity_only_not_source_ready(self):
        c,e,p3=input_set()
        got=seal(c,e,p3,SHA,RUN)
        self.assertEqual(got["status"],"B2_CAPACITY_ONLY_NATIVELY_VERIFIED")
        self.assertFalse(got["B2_SOURCE_READY"])
        self.assertFalse(got["flash_or_release_authorized"])
        self.assertFalse(got["github_PR_merge_authorized"])
        self.assertFalse(got["B1_B2_INTEGRATED_READY"])
    def test_full_ready_fake_rejected(self):
        c,e,p3=input_set()
        c["B2_SOURCE_READY"]=True
        with self.assertRaises(SealError):seal(c,e,p3,SHA,RUN)
    def test_false_ti_closed_source_claim_rejected(self):
        c,e,p3=input_set()
        c["closed_ti_routing_body_tests"]="PASS"
        with self.assertRaisesRegex(SealError,"closed-source"):seal(c,e,p3,SHA,RUN)
    def test_p1_digest_swap_rejected(self):
        c,e,p3=input_set()
        e[1]["elf_sha256"]="0"*64
        with self.assertRaisesRegex(SealError,"digest mismatch"):seal(c,e,p3,SHA,RUN)
    def test_stale_source_sha_rejected(self):
        c,e,p3=input_set()
        c["source_sha"]="f"*40
        with self.assertRaisesRegex(SealError,"exact-HEAD"):seal(c,e,p3,SHA,RUN)
    def test_wrong_run_rejected(self):
        c,e,p3=input_set()
        e[0]["run_id"]="12345678"
        with self.assertRaisesRegex(SealError,"re-extraction"):seal(c,e,p3,SHA,RUN)
    def test_missing_one_native_table_rejected(self):
        c,e,p3=input_set()
        e[2]["linked_tables_verified"].remove("neighbors")
        with self.assertRaisesRegex(SealError,"six genuine"):seal(c,e,p3,SHA,RUN)
    def test_p3_ordinary_compiler_failure_not_valid(self):
        c,e,p3=input_set()
        p3["reason"]="COMPILER_ERROR"
        with self.assertRaisesRegex(SealError,"genuine TI CCS"):seal(c,e,p3,SHA,RUN)
    def test_p3_successful_image_must_reject(self):
        c,e,p3=input_set()
        p3["usable_firmware_produced"]=True
        with self.assertRaisesRegex(SealError,"usable firmware"):seal(c,e,p3,SHA,RUN)
    def test_p3_wrong_sdk_pin_rejected(self):
        c,e,p3=input_set()
        p3["TI_SDK_PIN"]="f"*40
        with self.assertRaisesRegex(SealError,"different TI SDK"):seal(c,e,p3,SHA,RUN)
    def test_mysterious_static_delta_rejected(self):
        c,e,p3=input_set()
        c["unattributed_below_heap_delta_bytes"]=123
        with self.assertRaisesRegex(SealError,"accounting"):seal(c,e,p3,SHA,RUN)
    def test_wrong_number_of_elf_proofs_rejected(self):
        c,e,p3=input_set()
        with self.assertRaisesRegex(SealError,"three independently"):seal(c,e[:2],p3,SHA,RUN)
    def test_invalid_source_identifier_rejected(self):
        c,e,p3=input_set()
        with self.assertRaisesRegex(SealError,"invalid expected source"):seal(c,e,p3,"HEAD",RUN)
if __name__=="__main__":unittest.main()
