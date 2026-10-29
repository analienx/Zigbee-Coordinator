"""Synthetic current-stock security policy tests; never actual flash admission."""
import copy
import unittest
from unittest.mock import patch
import p7u_usb_current_owner_gate as current
import p7u_usb_security_model as strict
from test_p7u_usb_security_model import owner, live_from


class CurrentOwnerTests(unittest.TestCase):
    def setUp(self):
        self.old = owner()
        self.old["devices"][-1]["link_key"] = None
        self.new = copy.deepcopy(self.old)
        self.new["devices"].pop()
        self.live = live_from(self.new)
        self.live["trust_center_raw"] = bytes(8)

    def assess(self, native=True, semantics=True, floor=1000, known=frozenset()):
        with patch.object(current, "_silicon_owner_fields", return_value=self.live):
            return current.reconcile_current(historical=self.old, fresh=self.new,
                     records={}, abi={}, native_preflight_pass=native,
                     candidate_semantics_pass=semantics,
                     baseline_counter_floor=floor,runtime_inventory_peers=known)

    def test_current_stock_106_with_one_historical_keyless_router(self):
        got = self.assess()
        self.assertEqual(got["status"], "PASS_CURRENT_OWNER_OFFLINE_ONLY")
        self.assertEqual((got["historical_devices"],got["current_devices"],got["silicon_devices"]),(107,106,106))
        self.assertFalse(got["flash_authorized"])
        self.assertFalse(got["nv_write_authorized"])
        self.assertFalse(got["replay_old_nv_authorized"])
        self.assertNotIn("network_key", str(got))

    def test_historical_keyed_or_child_missing_never_relaxed(self):
        self.old["devices"][-1]["link_key"] = {"key":"12"*16,"tx_counter":1,"rx_counter":2}
        self.assertIn("HISTORICAL_MISSING_KEYED_OR_CHILD_PEER",self.assess()["reason_codes"])
        self.old["devices"][-1]["link_key"] = None
        self.old["devices"][-1]["is_child"] = True
        self.assertIn("HISTORICAL_MISSING_KEYED_OR_CHILD_PEER",self.assess()["reason_codes"])

    def test_two_missing_keyless_nonchildren_exceed_bounded_exception(self):
        self.old["devices"][-2]["link_key"] = None
        self.old["devices"][-2]["is_child"] = False
        self.new = copy.deepcopy(self.old)
        del self.new["devices"][-2:]
        self.live = live_from(self.new)
        self.live["trust_center_raw"] = bytes(8)
        result = self.assess()
        self.assertEqual(result["historical_only"], 2)
        self.assertEqual(result["status"], "HOLD")
        self.assertIn("HISTORICAL_MISSING_PEER_LIMIT_EXCEEDED", result["reason_codes"])
        self.assertFalse(result["flash_authorized"])

    def test_zero_tc_only_or_exact_current_coordinator(self):
        self.assertEqual(self.assess()["reason_codes"],[])
        self.live["trust_center_raw"] = self.live["coordinator"][::-1]
        self.assertEqual(self.assess()["reason_codes"],[])
        self.live["trust_center_raw"] = b"F"*8
        self.assertIn("CURRENT_SILICON_TC_FOREIGN",self.assess()["reason_codes"])

    def test_missing_silicon_current_peer_fails(self):
        self.live["addresses"] = frozenset(list(self.live["addresses"])[:-1])
        self.assertIn("CURRENT_SILICON_PEER_INVENTORY_MISMATCH",self.assess()["reason_codes"])

    def test_latest_key_reassignment_requires_native_aps_match(self):
        self.new["devices"][0]["link_key"]["key"] = "90"*16
        self.assertIn("CURRENT_APS_KEY_MISMATCH",self.assess()["reason_codes"])
        self.live["aps"][next(iter(self.live["aps"]))] = (b"\x90"*16,6,7)
        self.assertEqual(self.assess()["reason_codes"],[])

    def test_latest_aps_counter_and_missing_owner_count_fail(self):
        peer = next(iter(self.live["aps"]))
        self.live["aps"][peer] = (self.live["aps"][peer][0],4,7)
        self.assertIn("CURRENT_APS_COUNTER_FLOOR_UNPROVEN",self.assess()["reason_codes"])
        self.live["aps"][peer] = (self.live["aps"][peer][0],6,7)
        self.new["devices"][0]["link_key"].pop("rx_counter")
        self.assertIn("CURRENT_APS_COUNTER_FLOOR_UNPROVEN",self.assess()["reason_codes"])

    def test_changed_nwk_key_pan_seed_or_epoch_fails(self):
        for change in ("network_key","pan_id","seed"):
            self.new=copy.deepcopy(self.old)
            self.new["devices"].pop()
            if change=="network_key": self.new["network_key"]["key"]="99"*16
            elif change=="pan_id": self.new["pan_id"]="cc19"
            else:self.new["stack_specific"]["zstack"]["tclk_seed"]="dd"*16
            self.assertIn("NETWORK_HISTORY_IDENTITY_DIFFERENCE",self.assess()["reason_codes"])

    def test_native_or_compiled_proof_mandatory(self):
        self.assertIn("CURRENT_NATIVE_PREFLIGHT_NOT_PASS",self.assess(native=False)["reason_codes"])
        self.assertIn("CURRENT_CANDIDATE_SOURCE_NOT_VERIFIED",self.assess(semantics=False)["reason_codes"])

    def test_counter_floor_and_regression(self):
        self.assertIn("CURRENT_SILICON_NWK_COUNTER_FLOOR_NOT_PROVEN",self.assess(floor=None)["reason_codes"])
        self.assertIn("CURRENT_SILICON_NWK_COUNTER_FLOOR_NOT_PROVEN",self.assess(floor=999)["reason_codes"])
        self.new["network_key"]["frame_counter"]=999
        self.assertIn("CURRENT_OWNER_NWK_COUNTER_REGRESSION",self.assess()["reason_codes"])

    def test_unexpected_new_peer_and_duplicate_owner_hold(self):
        self.new["devices"].append({"ieee_address":"fffffffffffffffe","link_key":None,"is_child":False})
        self.assertIn("CURRENT_UNEXPECTED_PEER",self.assess()["reason_codes"])
        self.new["devices"][0]["ieee_address"]=self.new["devices"][1]["ieee_address"]
        self.assertIn("OWNER_DUPLICATE_OR_INVALID_IEEE",self.assess()["reason_codes"])

    def test_one_keyless_historical_router_can_reappear_only_with_inventory_binding(self):
        peer=bytes.fromhex(self.old["devices"][-1]["ieee_address"])
        self.live["addresses"]=self.live["addresses"]|{peer}
        self.assertEqual(self.assess()["status"],"HOLD")
        result=self.assess(known=frozenset({peer[::-1]}))
        self.assertEqual(result["status"],"PASS_CURRENT_OWNER_OFFLINE_ONLY")
        self.assertEqual(result["runtime_inventory_bound_reappearances"],1)
        self.assertFalse(result["nv_write_authorized"])
        for field,value in (("link_key",{"key":"12"*16,"tx_counter":1,"rx_counter":2}),("is_child",True)):
            previous=self.old["devices"][-1][field];self.old["devices"][-1][field]=value
            self.assertEqual(self.assess(known=frozenset({peer[::-1]}))["status"],"HOLD")
            self.old["devices"][-1][field]=previous
        self.assertEqual(self.assess(known=frozenset({b"foreign!"}))["status"],"HOLD")
        self.live["aps"][peer]=(b"k"*16,1,1)
        self.assertEqual(self.assess(known=frozenset({peer[::-1]}))["status"],"HOLD")

    def test_bound_reappearance_never_hides_missing_current_peer_or_counter_regression(self):
        peer=bytes.fromhex(self.old["devices"][-1]["ieee_address"])
        self.live["addresses"]=self.live["addresses"]|{peer}
        known=frozenset({peer[::-1]})
        self.assertEqual(self.assess(known=known,floor=999)["status"],"HOLD")
        another=next(x for x in self.live["addresses"] if x!=peer)
        self.live["addresses"]=self.live["addresses"]-{another}
        self.assertEqual(self.assess(known=known)["status"],"HOLD")

    def test_historical_strict_audit_is_independent(self):
        with patch.object(strict,"_silicon_owner_fields", return_value=self.live):
            result=strict.reconcile(historical=self.old,fresh=self.new,records={},abi={},
                                    native_preflight_pass=True,candidate_restoration_pass=True,
                                    baseline_counter_floor=1000)
        self.assertEqual(result["status"],"HOLD")
        self.assertIn("SILICON_HISTORICAL_INVENTORY_MISSING",result["reason_codes"])


if __name__=="__main__":
    unittest.main()
