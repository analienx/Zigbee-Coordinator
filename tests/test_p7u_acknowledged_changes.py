"""Owner acknowledgements in both P7U retained-security gates (synthetic, no hardware)."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for sub in ("firmware/slzb-06p7u/r4/qualification", "firmware/slzb-06p7u/r4/release", "host/flash"):
    sys.path.insert(0, str(ROOT / sub))
import stock20260311_security_preflight as sec  # noqa: E402
import p7u_usb_current_owner_gate as gate  # noqa: E402
import p7u_usb_security_model as model  # noqa: E402
import p7u_paired_binding as pb  # noqa: E402

ABI = {"structs": {"AddrMgrEntry_t": {"size": 12, "fields": {"user": [0, 1], "nwkAddr": [2, 2], "extAddr": [4, 8]}}}}
KNOWN = bytes.fromhex("70dc3313da38c1a4")      # native order of 0xa4c138da1333dc70
GHOST = bytes.fromhex("a6a50afeff52fd08")      # native order of 0x08fd52fffe0aa5a6
OTHER = bytes.fromhex("0102030405060708")


def row(user, short, ext):
    return bytes((user, 0)) + short.to_bytes(2, "little") + ext


EMPTY = row(0, 0xFFFE, bytes(8))


def state(addresses, empty):
    return {"identity": b"id", "active": b"a", "seed": b"s", "alternate": b"t", "addresses": addresses,
            "empty_addresses": set(empty), "aps": {}, "aps_opaque_tail": b"", "selected_floor": 5,
            "legacy_floor": 5, "peers": {}, "materials": {}}


class AddressGate(unittest.TestCase):
    def run_gate(self, before, after, empty_before, empty_after, acks=frozenset(), inventory=frozenset()):
        states = {"old": state(before, empty_before), "now": state(after, empty_after)}
        with patch.object(sec, "validate_abi", lambda abi: None), \
             patch.object(sec, "inspect_state", lambda records, abi: states[records]):
            return sec.evaluate_records("now", "old", ABI, runtime_upgrade=True,
                                        runtime_inventory_peers=inventory, acknowledged_changes=acks)

    def test_assoc_gain_refused_without_acknowledgement(self):
        r = self.run_gate({85: row(2, 0x1111, KNOWN)}, {85: row(3, 0x2222, KNOWN)}, [], [])
        self.assertEqual(r["reason_codes"], ["ADDRESS_MANAGER_RETAINED_ROWS_CHANGED_NO_MIGRATION_AUTHORIZED"])

    def test_acknowledged_assoc_gain_admitted_for_that_device_only(self):
        r = self.run_gate({85: row(2, 0x1111, KNOWN)}, {85: row(3, 0x2222, KNOWN)}, [], [],
                          acks=frozenset({(KNOWN, "ASSOC_GAIN")}))
        self.assertTrue(r["semantic_checks_passed"], r)
        self.assertEqual(r["acknowledged_association_gains"], 1)
        r = self.run_gate({85: row(2, 0x1111, KNOWN)}, {85: row(3, 0x1111, KNOWN)}, [], [],
                          acks=frozenset({(OTHER, "ASSOC_GAIN")}))
        self.assertFalse(r["semantic_checks_passed"])

    def test_acknowledged_gain_never_clears_security_or_other_bits(self):
        for after_user in (1, 7, 0x83):
            r = self.run_gate({85: row(2, 0x1111, KNOWN)}, {85: row(after_user, 0x1111, KNOWN)}, [], [],
                              acks=frozenset({(KNOWN, "ASSOC_GAIN")}))
            self.assertFalse(r["semantic_checks_passed"], after_user)

    def test_vacant_fill_needs_inventory_or_new_peer_acknowledgement(self):
        before, after = {107: EMPTY}, {107: row(2, 0x3333, GHOST)}
        self.assertFalse(self.run_gate(before, after, [107], [])["semantic_checks_passed"])
        r = self.run_gate(before, after, [107], [], acks=frozenset({(GHOST, "NEW_PEER")}))
        self.assertTrue(r["semantic_checks_passed"], r)
        self.assertEqual(r["acknowledged_address_fills"], 1)
        # A NEW_PEER acknowledgement is not an ASSOC_GAIN acknowledgement.
        r = self.run_gate(before, after, [107], [], acks=frozenset({(GHOST, "ASSOC_GAIN")}))
        self.assertFalse(r["semantic_checks_passed"])

    def test_acknowledgement_cannot_replace_an_occupied_row(self):
        r = self.run_gate({40: row(2, 0x1111, KNOWN)}, {40: row(2, 0x1111, GHOST)}, [], [],
                          acks=frozenset({(GHOST, "NEW_PEER"), (KNOWN, "ASSOC_GAIN")}))
        self.assertFalse(r["semantic_checks_passed"])

    def tc_gate(self, before, after, acks):
        old, now = state({1: row(2, 1, KNOWN)}, []), state({1: row(2, 1, KNOWN)}, [])
        old["peers"], now["peers"] = {KNOWN: before}, {KNOWN: after}
        states = {"old": old, "now": now}
        with patch.object(sec, "validate_abi", lambda abi: None), \
             patch.object(sec, "inspect_state", lambda records, abi: states[records]):
            return sec.evaluate_records("now", "old", ABI, runtime_upgrade=True, acknowledged_changes=acks)

    @staticmethod
    def tc(shift, attrs=2, index=7, ktype=0, ic=0, tx=10):
        meta = (KNOWN, bytes((attrs,)), bytes((ktype,)), bytes((shift,)), bytes((ic,)))
        return {"index": index, "key_metadata": meta, "key": None, "tx": tx, "rx": tx}

    def test_key_reroll_only_with_acknowledgement_and_only_seed_shift(self):
        self.assertEqual(self.tc_gate(self.tc(3), self.tc(9), frozenset())["reason_codes"],
                         ["TC_RETAINED_KEY_OR_REFERENCE_CHANGED"])
        r = self.tc_gate(self.tc(3), self.tc(9, tx=12), frozenset({(KNOWN, "KEY_REROLL")}))
        self.assertTrue(r["semantic_checks_passed"], r)
        self.assertEqual(r["acknowledged_key_rerolls"], 1)
        for after in (self.tc(9, attrs=1), self.tc(9, index=8), self.tc(9, ktype=1), self.tc(9, ic=1),
                      self.tc(9, tx=5)):
            r = self.tc_gate(self.tc(3), after, frozenset({(KNOWN, "KEY_REROLL")}))
            self.assertFalse(r["semantic_checks_passed"], after)
        r = self.tc_gate(self.tc(3, attrs=1), self.tc(9, attrs=1), frozenset({(KNOWN, "KEY_REROLL")}))
        self.assertFalse(r["semantic_checks_passed"])   # only VERIFIED keys
        r = self.tc_gate(self.tc(3), self.tc(9), frozenset({(OTHER, "KEY_REROLL")}))
        self.assertFalse(r["semantic_checks_passed"])

    def test_malformed_acknowledgements_fail_closed(self):
        for acks in (frozenset({(KNOWN, "ANYTHING")}), frozenset({(bytes(8), "NEW_PEER")}), {(KNOWN, "NEW_PEER")}):
            r = self.run_gate({1: row(2, 1, KNOWN)}, {1: row(2, 1, KNOWN)}, [], [], acks=acks)
            self.assertEqual(r["reason_codes"], ["ACKNOWLEDGED_CHANGES_INVALID"])


def backup(peers):
    return model.Backup(coordinator=b"c" * 8, pan=1, extended_pan=b"e" * 8, channel=11, update=0, level=0,
                        network_key=b"k" * 16, sequence=0, frame_counter=10, seed=b"s" * 16, peers=peers)


class OwnerGate(unittest.TestCase):
    def reconcile(self, extra_peer, acks):
        unkeyed = (None, None, None, False)
        old_peers = {bytes([i]) * 8: unkeyed for i in range(1, 108)}
        now_peers = {**old_peers, extra_peer: unkeyed}
        backups = {"old": backup(old_peers), "now": backup(now_peers)}
        live = {"addresses": set(now_peers), "aps": {}, "trust_center_raw": bytes(8), "coordinator": b"c" * 8,
                **{k: getattr(backups["now"], k) for k in ("pan", "extended_pan", "channel", "update", "level",
                                                          "network_key", "sequence", "seed")}}
        with patch.object(gate, "parse_backup", lambda raw: backups[raw]), \
             patch.object(gate, "_silicon_owner_fields", lambda records, abi: live):
            return gate.reconcile_current(historical="old", fresh="now", records={}, abi={},
                                          native_preflight_pass=True, candidate_semantics_pass=True,
                                          baseline_counter_floor=10, acknowledged_new_peers=acks)

    def test_new_peer_refused_unless_acknowledged(self):
        ghost = GHOST[::-1]
        self.assertIn("CURRENT_UNEXPECTED_PEER", self.reconcile(ghost, frozenset())["reason_codes"])
        r = self.reconcile(ghost, frozenset({ghost}))
        self.assertNotIn("CURRENT_UNEXPECTED_PEER", r["reason_codes"])
        self.assertEqual(r["acknowledged_new_peers"], 1)
        self.assertIn("CURRENT_UNEXPECTED_PEER", self.reconcile(ghost, frozenset({OTHER}))["reason_codes"])


class BindingAcks(unittest.TestCase):
    def test_parses_and_orders(self):
        native, new = pb.acknowledged({"acknowledged_changes": [
            {"ieee": "0x08fd52fffe0aa5a6", "change": "NEW_PEER"},
            {"ieee": "0xa4c138da1333dc70", "change": "ASSOC_GAIN"}]})
        self.assertEqual(native, frozenset({(GHOST, "NEW_PEER"), (KNOWN, "ASSOC_GAIN")}))
        self.assertEqual(new, frozenset({GHOST[::-1]}))
        self.assertEqual(pb.acknowledged({}), (frozenset(), frozenset()))

    def test_rejects_malformed(self):
        for acks in ([{"ieee": "0x08FD52FFFE0AA5A6", "change": "NEW_PEER"}],
                     [{"ieee": "0x0000000000000000", "change": "NEW_PEER"}],
                     [{"ieee": "0x08fd52fffe0aa5a6", "change": "REPLACE"}],
                     [{"ieee": "0x08fd52fffe0aa5a6", "change": "NEW_PEER", "x": 1}],
                     [{"ieee": "0x08fd52fffe0aa5a6", "change": "NEW_PEER"}] * 2, "x"):
            with self.subTest(acks=acks), self.assertRaisesRegex(ValueError, "ACKNOWLEDGED_CHANGES"):
                pb.acknowledged({"acknowledged_changes": acks})


if __name__ == "__main__":
    unittest.main()
