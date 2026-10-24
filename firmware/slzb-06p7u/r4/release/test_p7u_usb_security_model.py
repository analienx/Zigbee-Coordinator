"""Synthetic, non-secret negative tests for owner-to-silicon security gate."""
import copy
import unittest
from unittest.mock import patch

import p7u_usb_security_model as model


def owner(n=107):
    return {
        "coordinator_ieee": "aabbccddeeff1122",
        "pan_id": "1a62", "extended_pan_id": "0123456789abcdef",
        "channel": 11, "channel_mask": [11],
        "nwk_update_id": 2, "security_level": 5,
        "network_key": {"key": "42" * 16, "sequence_number": 1,
                        "frame_counter": 1000},
        "stack_specific": {"zstack": {"tclk_seed": "33" * 16}},
        "devices": [{"ieee_address": f"{i+1:016x}", "is_child": False,
                     "link_key": {"key": f"{i+1:032x}",
                                  "tx_counter": 5, "rx_counter": 6}}
                    for i in range(n)],
    }


def live_from(o):
    own = model.parse_backup(o)
    aps_ids = list(own.peers)[:2]
    return {
        "coordinator": own.coordinator, "trust_center_raw": own.coordinator[::-1],
        "pan": own.pan, "extended_pan": own.extended_pan,
        "channel": own.channel, "update": own.update, "level": own.level,
        "network_key": own.network_key, "sequence": own.sequence,
        "seed": own.seed, "addresses": frozenset(own.peers),
        "aps": {k: (own.peers[k][0], 6, 7) for k in aps_ids},
    }


class SecurityModelTests(unittest.TestCase):
    def setUp(self):
        self.old = owner()
        self.fresh = copy.deepcopy(self.old)
        self.live = live_from(self.old)

    def assess(self, *, native=True, candidate=True, floor=1000):
        with patch.object(model, "_silicon_owner_fields", return_value=self.live):
            return model.reconcile(historical=self.old, fresh=self.fresh,
                                   records={}, abi={}, native_preflight_pass=native,
                                   candidate_restoration_pass=candidate,
                                   baseline_counter_floor=floor)

    def test_explicit_independent_proofs_allow_offline_only_pass(self):
        r = self.assess()
        self.assertEqual(r["status"], "PASS_OWNER_SECURITY_OFFLINE_ONLY")
        self.assertFalse(r["flash_authorized"])
        self.assertFalse(r["nv_write_authorized"])
        self.assertEqual(r["silicon_matching_historical"], 107)
        self.assertNotIn("network_key", r)

    def test_historical_107_not_waived_by_fresh_106(self):
        self.fresh["devices"] = self.fresh["devices"][:106]
        self.live["addresses"] = frozenset(model.parse_backup(self.fresh).peers)
        r = self.assess()
        self.assertEqual(r["status"], "HOLD")
        self.assertEqual(r["missing_historical"], 1)
        self.assertIn("FRESH_BACKUP_HISTORICAL_INVENTORY_MISSING", r["reason_codes"])
        self.assertIn("SILICON_HISTORICAL_INVENTORY_MISSING", r["reason_codes"])

    def test_key_reassigned_to_different_peer_even_same_unordered_key_set(self):
        self.fresh["devices"][0]["link_key"]["key"], self.fresh["devices"][1]["link_key"]["key"] = (
            self.fresh["devices"][1]["link_key"]["key"],
            self.fresh["devices"][0]["link_key"]["key"])
        r = self.assess()
        self.assertIn("OWNER_PEER_KEY_REASSIGNED", r["reason_codes"])
        self.assertIn("APS_PEER_KEY_ASSOCIATION_CHANGED", r["reason_codes"])

    def test_counter_regression(self):
        self.fresh["devices"][0]["link_key"]["tx_counter"] = 1
        r = self.assess()
        self.assertIn("OWNER_PEER_COUNTER_REGRESSION", r["reason_codes"])

    def test_missing_field_never_defaults_to_zero(self):
        del self.fresh["network_key"]["frame_counter"]
        r = self.assess()
        self.assertIn("OWNER_NWK_COUNTER_MISSING", r["reason_codes"])

    def test_mismatched_network_pan_channel_seed_and_key(self):
        for key, value in [("pan_id", "ffff"), ("channel", 12),
                           ("extended_pan_id", "ffffffffffffffff")]:
            with self.subTest(key=key):
                f = copy.deepcopy(self.fresh)
                f[key] = value
                if key == "channel": f["channel_mask"] = [12]
                self.fresh = f
                self.assertIn("OWNER_HISTORICAL_NETWORK_OR_KEY_CHANGED",
                              self.assess()["reason_codes"])
                self.fresh = copy.deepcopy(self.old)
        self.fresh["stack_specific"]["zstack"]["tclk_seed"] = "ff"*16
        self.assertIn("OWNER_HISTORICAL_NETWORK_OR_KEY_CHANGED",
                      self.assess()["reason_codes"])
        self.fresh = copy.deepcopy(self.old)
        self.fresh["network_key"]["key"] = "10"*16
        self.assertIn("OWNER_HISTORICAL_NETWORK_OR_KEY_CHANGED",
                      self.assess()["reason_codes"])

    def test_zero_persisted_tc_and_candidate_gate_both_hold(self):
        self.live["trust_center_raw"] = bytes(8)
        self.assertIn("SILICON_TC_NOT_COORDINATOR", self.assess()["reason_codes"])
        self.live["trust_center_raw"] = self.live["coordinator"][::-1]
        self.assertIn("CANDIDATE_RESTORATION_NOT_PASS",
                      self.assess(candidate=False)["reason_codes"])
        self.assertIn("NATIVE_SECURITY_PREFLIGHT_NOT_PASS",
                      self.assess(native=False)["reason_codes"])

    def test_missing_or_lower_numeric_counter_floor_holds(self):
        self.assertIn("SILICON_NETWORK_COUNTER_FLOOR_NOT_PROVEN",
                      self.assess(floor=None)["reason_codes"])
        self.assertIn("SILICON_NETWORK_COUNTER_FLOOR_NOT_PROVEN",
                      self.assess(floor=999)["reason_codes"])
        self.fresh["network_key"]["frame_counter"] = 999
        self.assertIn("OWNER_NETWORK_COUNTER_REGRESSION", self.assess()["reason_codes"])

    def test_wrong_silicon_aps_key_or_peer_holds(self):
        peer = next(iter(self.live["aps"]))
        self.live["aps"][peer] = (b"bad"*5+b"!", 10, 10)
        self.assertIn("APS_PEER_KEY_ASSOCIATION_CHANGED", self.assess()["reason_codes"])

    def test_missing_aps_counters_holds_not_silently_zero(self):
        self.old["devices"][0]["link_key"].pop("rx_counter")
        self.fresh["devices"][0]["link_key"].pop("rx_counter")
        self.assertIn("APS_PEER_COUNTER_FLOOR_NOT_PROVEN",
                      self.assess()["reason_codes"])

    def test_invalid_duplicate_ieee_and_unrecognized_structure(self):
        self.fresh["devices"][0]["ieee_address"] = self.fresh["devices"][1]["ieee_address"]
        self.assertIn("OWNER_DUPLICATE_OR_INVALID_IEEE", self.assess()["reason_codes"])
        self.fresh = copy.deepcopy(self.old)
        self.fresh["stack_specific"].pop("zstack")
        self.assertIn("OWNER_SECURITY_FIELDS_MISSING", self.assess()["reason_codes"])


if __name__ == "__main__":
    unittest.main()
