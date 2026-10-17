import unittest
from tools.b2_verify_profile import check, ProfileError, BASE, TARGET, EXPECTED_P1_DEFINES

def evidence(profile):
    tables={}
    for name,(n,size) in BASE.items():
        count=TARGET.get(name,n) if profile=="P1" else n
        tables[name]={
            "status":"HOSTED_NATIVE_LINKED",
            "linked_count":count,"linked_bytes":count*size,
            "entry_sizeof_derived":size}
    native={"status":"HOSTED_NATIVE_LINKED_TABLES",
            "tables":tables,
            "memory_regions":{"SRAM":{"size":147456}},
            "linked_heap_address_span":{"span_bytes":120000},
            "linked_c_irq_stack_size":{"size_bytes":1024}}
    overlay={"profile":profile,"compiler_defines":EXPECTED_P1_DEFINES if profile=="P1" else {},
             "native_linked_proof":"REQUIRED_POST_BUILD",
             "tc_nv_security_mto_untouched":True}
    return native,overlay

class ProfileTests(unittest.TestCase):
    def test_synthetic_p0_oracle(self):
        native,over=evidence("P0")
        self.assertEqual(check(native,over,"P0")["delta_static_table_bytes_vs_p0"],0)
    def test_synthetic_p1_expected_3488_bytes(self):
        native,over=evidence("P1")
        r=check(native,over,"P1")
        self.assertEqual(r["delta_static_table_bytes_vs_p0"],3488)
        self.assertFalse(r["source_ready"])
    def test_noop_define_does_not_pass(self):
        native,over=evidence("P1")
        native["tables"]["source_routes"]["linked_count"]=12
        native["tables"]["source_routes"]["linked_bytes"]=96
        with self.assertRaisesRegex(ProfileError,"linked counts/bytes wrong"):
            check(native,over,"P1")
    def test_reject_wrong_profile_receipt(self):
        native,over=evidence("P1")
        over["compiler_defines"]={}
        with self.assertRaisesRegex(ProfileError,"wrong compiler override"):
            check(native,over,"P1")
    def test_reject_unverified_symbol(self):
        native,over=evidence("P1")
        native["tables"]["neighbors"]["status"]="UNKNOWN_LINKED_CAPACITY"
        with self.assertRaisesRegex(ProfileError,"linked counts/bytes wrong"):
            check(native,over,"P1")
    def test_reject_security_mto_mutation(self):
        native,over=evidence("P1")
        over["tc_nv_security_mto_untouched"]=False
        with self.assertRaisesRegex(ProfileError,"security or MTO"):
            check(native,over,"P1")
    def test_reject_undocumented_stack_change(self):
        native,over=evidence("P1")
        native["linked_c_irq_stack_size"]["size_bytes"]=4096
        with self.assertRaisesRegex(ProfileError,"stack changed"):
            check(native,over,"P1")
    def test_reject_fake_heap(self):
        native,over=evidence("P1")
        native["linked_heap_address_span"]=None
        with self.assertRaisesRegex(ProfileError,"heap address span"):
            check(native,over,"P1")

if __name__=="__main__":
    unittest.main()
