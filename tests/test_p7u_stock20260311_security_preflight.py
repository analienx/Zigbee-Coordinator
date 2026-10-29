"""Synthetic semantic/containment cases; these never certify a private network.

The intentionally artificial ABI fixture tests that offsets come from a bound
layout instead of host guesses. Genuine ARM ABI and TI reader compilation are
separate required hosted gates. No private capture is used by this module.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/qualification"
sys.path.insert(0, str(HERE))
import stock20260311_security_preflight as security


def synthetic_abi() -> dict:
    layouts = {
        "nwkIB_t": (40, {"nwkDevAddress": (0, 2), "nwkLogicalChannel": (2, 1),
                        "nwkCoordAddress": (4, 2), "nwkPanId": (6, 2), "nwkState": (8, 1),
                        "extendedPANID": (9, 8), "nwkKeyLoaded": (17, 1),
                        "nwkCoordExtAddress": (18, 8), "SecurityLevel": (26, 1),
                        "channelList": (28, 4), "nwkManagerAddr": (32, 2),
                        "nwkUpdateId": (34, 1), "nwkProtocolVersion": (35, 1)}),
        "nwkKeyDesc": (17, {"keySeqNum": (0, 1), "key": (1, 16)}),
        "nwkActiveKeyItems": (24, {"active": (0, 17), "frameCounter": (20, 4)}),
        "nwkSecMaterialDesc_t": (12, {"FrameCounter": (0, 4), "extendedPanID": (4, 8)}),
        "APSME_TCLinkKeyNVEntry_t": (20, {"txFrmCntr": (0, 4), "rxFrmCntr": (4, 4),
                                       "extAddr": (8, 8), "keyAttributes": (16, 1),
                                       "keyType": (17, 1), "SeedShift": (18, 1), "IcIndex": (19, 1)}),
        "APSME_ApsLinkKeyNVEntry_t": (24, {"key": (0, 16), "txFrmCntr": (16, 4), "rxFrmCntr": (20, 4)}),
        "nvDeviceListHdr_t": (2, {"numRecs": (0, 2)}),
        "ZDSecMgrEntry_t": (6, {"ami": (0, 2), "keyNvId": (2, 2), "authenticateOption": (4, 1)}),
        "AddrMgrEntry_t": (12, {"user": (0, 1), "nwkAddr": (2, 2), "extAddr": (4, 8)}),
    }
    return {"schema": "p7u-security-native-abi-v1", "sdk_sha": security.abi_tool.SDK_SHA,
            "status": "ACTUAL_ARM_ELF_SERIALIZED_LAYOUTS_EXTRACTED", "byte_order": "little",
            "flash_authorized": False,
            "structs": {name: {"size": size, "fields": fields} for name, (size, fields) in layouts.items()},
            "constants": {"NWK_ROUTER": 8, "ZDSECMGR_TC_DEVICE_MAX": 300,
                          "ZDSECMGR_ENTRY_MAX": 3, "MAX_NWK_SEC_MATERIAL_TABLE_ENTRIES": 5,
                          "MAX_APS_FRAMECOUNTER_CHANGES": 1000, "MAX_TCLK_FRAMECOUNTER_CHANGES": 10,
                          "NWK_MAX_ADDRESSES": 406, "ADDRMGR_USER_SECURITY": 2}}


def record(abi: dict, typename: str, **values) -> bytes:
    result = bytearray(abi["structs"][typename]["size"])
    for name, value in values.items():
        offset, width = abi["structs"][typename]["fields"][name]
        raw = value.to_bytes(width, "little") if isinstance(value, int) else value
        assert len(raw) == width
        result[offset:offset + width] = raw
    return bytes(result)


def formed(abi: dict) -> dict:
    ext, pan = bytes(range(1, 9)), bytes(range(11, 19))
    active = record(abi, "nwkKeyDesc", keySeqNum=7, key=bytes(range(21, 37)))
    records = {(1, 0, 1): ext, (1, 0, 3): b"\x00", (1, 0, 0x55): b"\x01",
               (1, 0, 0x87): b"\x00", (1, 0, 0x71): ext,
               (1, 0, 0x101): bytes(range(41, 57)), (1, 0, 0x3a): active,
               (1, 0, 0x3b): bytes(17),
               (1, 0, 0x82): record(abi, "nwkActiveKeyItems", active=active, frameCounter=400),
               (1, 0, 0x21): record(abi, "nwkIB_t", nwkDevAddress=0, nwkLogicalChannel=15,
                                      nwkCoordAddress=0, nwkPanId=123, nwkState=8,
                                      extendedPANID=pan, nwkKeyLoaded=1, SecurityLevel=5,
                                      channelList=1 << 15, nwkProtocolVersion=2),
               (1, 7, 0): record(abi, "nwkSecMaterialDesc_t", FrameCounter=500, extendedPanID=pan),
               (1, 0, 0x4c): record(abi, "nvDeviceListHdr_t", numRecs=0)}
    for index in range(357):
        records[1, 1, index] = record(abi, "AddrMgrEntry_t", nwkAddr=0xfffe)
    for index in (9, 10):
        records[1, 1, index] = record(abi, "AddrMgrEntry_t", user=2, nwkAddr=index,
                                    extAddr=bytes([index]) * 8)
    for index in range(300):
        records[1, 4, index] = record(abi, "APSME_TCLinkKeyNVEntry_t", keyAttributes=0xff)
    records[1, 4, 299] = record(abi, "APSME_TCLinkKeyNVEntry_t", txFrmCntr=150, rxFrmCntr=130,
                               extAddr=bytes(range(61, 69)), keyAttributes=2, keyType=0, SeedShift=9)
    return records


class RetainedSecurityTests(unittest.TestCase):
    def setUp(self):
        self.abi = synthetic_abi()
        self.before = formed(self.abi)
        self.now = copy.deepcopy(self.before)

    def outcome(self):
        return security.evaluate_records(self.now, self.before, self.abi)

    def hold(self, code):
        result = self.outcome()
        self.assertFalse(result["semantic_checks_passed"])
        self.assertEqual(result["reason_codes"], [code])

    def test_coherent_state_is_preserved_without_counter_margin(self):
        before = copy.deepcopy(self.now)
        result = self.outcome()
        self.assertTrue(result["semantic_checks_passed"])
        self.assertEqual(result["tc_live_peers"], 1)
        self.assertEqual(self.now, before)
        self.assertNotIn("status", result)  # pure fixture never becomes private proof

    def test_zero_persisted_tc_on_formed_coordinator_is_stock_compatible(self):
        self.before[1, 0, 0x71] = self.now[1, 0, 0x71] = bytes(8)
        before = copy.deepcopy(self.now)
        result = self.outcome()
        self.assertTrue(result["semantic_checks_passed"], result["reason_codes"])
        self.assertEqual(self.now, before)
        self.assertNotIn("flash_authorized", result)

    def test_nonzero_foreign_persisted_tc_remains_blocked(self):
        self.now[1, 0, 0x71] = b"F" * 8
        self.hold("COORDINATOR_TRUST_CENTER_IDENTITY_MISMATCH")
        self.now = copy.deepcopy(self.before)
        self.now[1, 0, 1] = bytes(8)
        self.hold("COORDINATOR_TRUST_CENTER_IDENTITY_MISMATCH")

    def test_legacy_counter_may_lag_selected_material_but_must_not_exceed_it(self):
        self.assertTrue(self.outcome()["semantic_checks_passed"])
        active = self.now[1, 0, 0x3a]
        self.now[1, 0, 0x82] = record(self.abi, "nwkActiveKeyItems", active=active, frameCounter=501)
        self.hold("NETWORK_PERSISTED_FLOOR_INCONSISTENT")

    def test_marker_destructive_options_and_native_nib_rejected(self):
        for identity, value, reason in [
            ((1, 0, 0x55), b"\x00", "FORMED_COORDINATOR_MARKERS_INVALID"),
            ((1, 0, 3), b"\x80", "DESTRUCTIVE_STARTUP_OPTIONS_SET"),
            ((1, 0, 0x21), bytes(40), "FORMED_NATIVE_NIB_INVALID"),
        ]:
            with self.subTest(reason=reason):
                self.now = copy.deepcopy(self.before)
                self.now[identity] = value
                self.hold(reason)

    def test_key_epoch_change_and_seed_change_never_invent_new_network(self):
        self.now[1, 0, 0x101] = bytes(range(71, 87))
        self.hold("RETAINED_NETWORK_IDENTITY_OR_KEY_CHANGED")
        self.now = copy.deepcopy(self.before)
        self.now[1, 0, 0x3a] = bytes(17)
        self.hold("ACTIVE_NETWORK_KEY_MISMATCH")

    def test_missing_last_tc_slot_is_not_an_empty_slot(self):
        del self.now[1, 4, 299]
        self.hold("MANDATORY_SECURITY_RECORD_MISSING_OR_WRONG_LENGTH")

    def test_duplicate_last_tc_peer_and_counter_regression(self):
        self.now[1, 4, 0] = self.now[1, 4, 299]
        self.hold("TC_PEER_DUPLICATE_OR_INVALID")
        self.now = copy.deepcopy(self.before)
        self.now[1, 4, 299] = record(self.abi, "APSME_TCLinkKeyNVEntry_t", txFrmCntr=149,
            rxFrmCntr=130, extAddr=bytes(range(61, 69)), keyAttributes=2, SeedShift=9)
        self.hold("TC_PERSISTED_COUNTER_REGRESSION")

    def test_fallback_counter_can_be_selected_but_never_below_legacy_floor(self):
        del self.now[1, 7, 0]
        del self.before[1, 7, 0]
        fallback = record(self.abi, "nwkSecMaterialDesc_t", FrameCounter=500, extendedPanID=b"\xff" * 8)
        self.now[1, 7, 4] = self.before[1, 7, 4] = fallback
        self.assertTrue(self.outcome()["semantic_checks_passed"])
        self.now[1, 7, 4] = record(self.abi, "nwkSecMaterialDesc_t", FrameCounter=399, extendedPanID=b"\xff" * 8)
        self.hold("NETWORK_PERSISTED_FLOOR_INCONSISTENT")

    def test_duplicate_security_material_cannot_choose_a_winner(self):
        self.now[1, 7, 1] = self.now[1, 7, 0]
        self.hold("DUPLICATE_NETWORK_SECURITY_MATERIAL")

    def test_unsupported_tc_attributes_and_missing_provisional_key_hold(self):
        for attr, reason in [(0xfe, "TC_KEY_RESTORATION_SEMANTICS_UNSUPPORTED"),
                             (0, "MANDATORY_SECURITY_RECORD_MISSING_OR_WRONG_LENGTH")]:
            with self.subTest(attr=attr):
                self.now[1, 4, 299] = record(self.abi, "APSME_TCLinkKeyNVEntry_t", txFrmCntr=150,
                    rxFrmCntr=130, extAddr=bytes(range(61, 69)), keyAttributes=attr, SeedShift=9)
                self.hold(reason)

    def test_pinned_ti_fffe_empty_aps_slot_does_not_alias_live_key(self):
        # TI 8.33 nwk.h INVALID_NODE_ADDR=0xFFFE, not broadcast 0xFFFF.
        # An unused slot legitimately carries a stale keyNvId=0.
        table = record(self.abi, "nvDeviceListHdr_t", numRecs=2)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=9, keyNvId=0)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=10, keyNvId=1)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=0xfffe, keyNvId=0)
        self.now[1, 0, 0x4c] = self.before[1, 0, 0x4c] = table
        for index in range(2):
            entry = record(self.abi, "APSME_ApsLinkKeyNVEntry_t",
                key=bytes(range(71 + 16 * index, 87 + 16 * index)),
                txFrmCntr=110, rxFrmCntr=90)
            self.now[1, 6, index] = self.before[1, 6, index] = entry
        result = self.outcome()
        self.assertTrue(result["semantic_checks_passed"], result["reason_codes"])
        self.assertEqual(result["aps_live_entries"], 2)

    def test_broadcast_ffff_is_not_an_aps_empty_slot(self):
        table = record(self.abi, "nvDeviceListHdr_t", numRecs=1)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=0xffff, keyNvId=0)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=0xfffe) * 2
        self.now[1, 0, 0x4c] = table
        self.hold("APS_REFERENCE_DUPLICATE_OR_OUT_OF_RANGE")

    def test_aps_out_of_range_key_reference_holds(self):
        table = record(self.abi, "nvDeviceListHdr_t", numRecs=1)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=9, keyNvId=3)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=0xfffe) * 2
        self.now[1, 0, 0x4c] = table
        self.hold("APS_REFERENCE_DUPLICATE_OR_OUT_OF_RANGE")

    def test_abi_overlap_and_capacity_change_hold(self):
        self.abi["structs"]["nwkIB_t"]["fields"]["nwkState"] = (0, 1)
        self.hold("NATIVE_ABI_LAYOUT_INVALID")
        self.abi = synthetic_abi()
        self.abi["constants"]["ZDSECMGR_TC_DEVICE_MAX"] = 192
        self.hold("NATIVE_ABI_LAYOUT_INVALID")

    def test_private_pipe_duplicate_and_unsealed_output_rejected(self):
        prefix = security.MAGIC + struct.pack("<II", 2, 2)
        entry = struct.pack("<BHHH", 1, 0, 0x55, 1) + b"\x01"
        sealed = security.DONE + struct.pack("<III", 0, 0, 0)
        with self.assertRaisesRegex(ValueError, "DUPLICATE"):
            security.parse_private_pipe(prefix + entry + entry + sealed)
        with self.assertRaisesRegex(ValueError, "UNSEALED"):
            security.parse_private_pipe(security.MAGIC + struct.pack("<II", 1, 1) + entry + sealed[:-1])

    def test_physical_record_budget_accepts_history_above_old_2000_limit(self):
        entry = struct.pack("<BHHH", 1, 0, 0x55, 1) + b"\x01"
        seal = security.DONE + struct.pack("<III", 0, 0, 0)
        _, receipt = security.parse_private_pipe(security.MAGIC + struct.pack("<II", 2001, 1) + entry + seal)
        self.assertEqual(receipt["all_records"], 2001)
        self.assertEqual(security.MAX_RECORDS, 3066)
        entries = b"".join(struct.pack("<BHHH", 1, 2 + i // 1024, i % 1024, 1) + b"x"
                           for i in range(security.MAX_RECORDS))
        raw = security.MAGIC + struct.pack("<II", security.MAX_RECORDS, security.MAX_RECORDS) + entries + seal
        self.assertEqual(len(raw), security.MAX_OUTPUT)
        self.assertEqual(len(security.parse_private_pipe(raw)[0]), security.MAX_RECORDS)
        with self.assertRaisesRegex(ValueError, "BUDGET"):
            security.parse_private_pipe(security.MAGIC + struct.pack("<II", security.MAX_RECORDS + 1, 1) + entry + seal)

    def test_alternate_key_descriptor_is_retained_without_using_nib_spares(self):
        self.now[1, 0, 0x3b] = record(self.abi, "nwkKeyDesc", keySeqNum=8, key=b"q" * 16)
        self.hold("RETAINED_NETWORK_IDENTITY_OR_KEY_CHANGED")

    def test_address_manager_growth_preserves_stock_tail_and_only_adds_empty_rows(self):
        # The real TI capacity-extension default is 12 bytes of all-FF,
        # including user=0xFF. This used to falsely reject a healthy tail.
        size = self.abi["structs"]["AddrMgrEntry_t"]["size"]
        for index in range(357, 406):
            self.now[1, 1, index] = b"\xff" * size
        self.assertTrue(self.outcome()["semantic_checks_passed"])
        # Existing native zero-user empty rows remain accepted as well.
        for index in range(357, 406):
            self.now[1, 1, index] = record(self.abi, "AddrMgrEntry_t", nwkAddr=0xfffe)
        self.assertTrue(self.outcome()["semantic_checks_passed"])
        self.now[1, 1, 405] = record(self.abi, "AddrMgrEntry_t", user=2, extAddr=b"p" * 8)
        self.hold("ADDRESS_MANAGER_NEW_TAIL_NOT_EMPTY")
        self.now = copy.deepcopy(self.before)
        self.now[1, 1, 356] = record(self.abi, "AddrMgrEntry_t", user=4, extAddr=b"b" * 8)
        self.hold("ADDRESS_MANAGER_RETAINED_ROWS_CHANGED_NO_MIGRATION_AUTHORIZED")

    def test_runtime_upgrade_allows_only_short_address_bytes(self):
        self.now[1, 1, 9] = record(self.abi, 'AddrMgrEntry_t', user=2, nwkAddr=1234, extAddr=bytes([9])*8)
        self.hold('ADDRESS_MANAGER_RETAINED_ROWS_CHANGED_NO_MIGRATION_AUTHORIZED')
        before = copy.deepcopy(self.now)
        result = security.evaluate_records(self.now, self.before, self.abi, runtime_upgrade=True)
        self.assertTrue(result['semantic_checks_passed'], result)
        self.assertEqual(result['runtime_short_address_changes'], 1)
        self.assertEqual(self.now, before)
        for index in (0, 1, 4):  # ownership, native padding, IEEE identity
            with self.subTest(byte=index):
                raw = bytearray(before[1, 1, 9]); raw[index] ^= 1
                self.now[1, 1, 9] = bytes(raw)
                result = security.evaluate_records(self.now, self.before, self.abi, runtime_upgrade=True)
                self.assertFalse(result['semantic_checks_passed'])

    def test_runtime_upgrade_still_rejects_counter_regression_and_new_peer(self):
        self.now[1, 1, 9] = record(self.abi, 'AddrMgrEntry_t', user=2, nwkAddr=1234, extAddr=bytes([9])*8)
        self.now[1, 7, 0] = record(self.abi, 'nwkSecMaterialDesc_t', FrameCounter=499, extendedPanID=bytes(range(11,19)))
        r = security.evaluate_records(self.now, self.before, self.abi, runtime_upgrade=True)
        self.assertEqual(r['reason_codes'], ['NWK_PERSISTED_COUNTER_REGRESSION'])
        self.now = copy.deepcopy(self.before)
        self.now[1, 4, 298] = record(self.abi, 'APSME_TCLinkKeyNVEntry_t', txFrmCntr=150,
            rxFrmCntr=130, extAddr=b'new-peer', keyAttributes=2)
        r = security.evaluate_records(self.now, self.before, self.abi, runtime_upgrade=True)
        self.assertEqual(r['reason_codes'], ['TC_RETAINED_SET_CHANGED'])

    def test_runtime_association_release_retains_security_identity_and_bytes(self):
        self.before[1, 1, 9] = record(self.abi, 'AddrMgrEntry_t', user=3, nwkAddr=9, extAddr=bytes([9])*8)
        self.now[1, 1, 9] = record(self.abi, 'AddrMgrEntry_t', user=2, nwkAddr=1234, extAddr=bytes([9])*8)
        original=copy.deepcopy(self.now)
        self.hold('ADDRESS_MANAGER_RETAINED_ROWS_CHANGED_NO_MIGRATION_AUTHORIZED')
        result=security.evaluate_records(self.now,self.before,self.abi,runtime_upgrade=True)
        self.assertTrue(result['semantic_checks_passed'],result)
        self.assertEqual(result['runtime_association_releases'],1)
        self.assertEqual(self.now,original)
        for index in (1,4):
            altered=copy.deepcopy(original);raw=bytearray(altered[1,1,9]);raw[index]^=1;altered[1,1,9]=bytes(raw)
            self.assertFalse(security.evaluate_records(altered,self.before,self.abi,runtime_upgrade=True)['semantic_checks_passed'])
        for user in (0,1,4,6,7):
            altered=copy.deepcopy(original)
            altered[1,1,9]=record(self.abi,'AddrMgrEntry_t',user=user,nwkAddr=1234,extAddr=bytes([9])*8)
            self.assertFalse(security.evaluate_records(altered,self.before,self.abi,runtime_upgrade=True)['semantic_checks_passed'])
        self.now[1,7,0]=record(self.abi,'nwkSecMaterialDesc_t',FrameCounter=499,extendedPanID=bytes(range(11,19)))
        self.assertEqual(security.evaluate_records(self.now,self.before,self.abi,runtime_upgrade=True)['reason_codes'],
                         ['NWK_PERSISTED_COUNTER_REGRESSION'])

    def test_runtime_vacant_fill_requires_independent_inventory_and_preserves_inputs(self):
        peer=b'known-db'
        self.now[1,1,12]=record(self.abi,'AddrMgrEntry_t',user=2,nwkAddr=1234,extAddr=peer)
        original=copy.deepcopy(self.now)
        denied=security.evaluate_records(self.now,self.before,self.abi,runtime_upgrade=True)
        self.assertFalse(denied['semantic_checks_passed'])
        allowed=security.evaluate_records(self.now,self.before,self.abi,runtime_upgrade=True,
                                          runtime_inventory_peers=frozenset({peer}))
        self.assertTrue(allowed['semantic_checks_passed'],allowed)
        self.assertEqual(allowed['runtime_inventory_bound_address_fills'],1)
        self.assertEqual(self.now,original)
        self.hold('ADDRESS_MANAGER_RETAINED_ROWS_CHANGED_NO_MIGRATION_AUTHORIZED')
        for user in (0,1,3,4,6,255):
            changed=copy.deepcopy(original)
            changed[1,1,12]=record(self.abi,'AddrMgrEntry_t',user=user,nwkAddr=1234,extAddr=peer)
            self.assertFalse(security.evaluate_records(changed,self.before,self.abi,runtime_upgrade=True,
                runtime_inventory_peers=frozenset({peer}))['semantic_checks_passed'])
        changed=copy.deepcopy(original);row=bytearray(changed[1,1,12]);row[1]=1;changed[1,1,12]=bytes(row)
        self.assertFalse(security.evaluate_records(changed,self.before,self.abi,runtime_upgrade=True,
            runtime_inventory_peers=frozenset({peer}))['semantic_checks_passed'])
        changed=copy.deepcopy(original)
        changed[1,7,0]=record(self.abi,'nwkSecMaterialDesc_t',FrameCounter=499,extendedPanID=bytes(range(11,19)))
        self.assertEqual(security.evaluate_records(changed,self.before,self.abi,runtime_upgrade=True,
            runtime_inventory_peers=frozenset({peer}))['reason_codes'],['NWK_PERSISTED_COUNTER_REGRESSION'])
        # An existing occupied row, duplicate identity, or new capacity tail is never admitted.
        for index in (9,357):
            changed=copy.deepcopy(self.before)
            changed[1,1,index]=record(self.abi,'AddrMgrEntry_t',user=2,nwkAddr=1234,extAddr=peer)
            self.assertFalse(security.evaluate_records(changed,self.before,self.abi,runtime_upgrade=True,
                runtime_inventory_peers=frozenset({peer}))['semantic_checks_passed'])
        changed=copy.deepcopy(original);changed[1,1,13]=changed[1,1,12]
        self.assertFalse(security.evaluate_records(changed,self.before,self.abi,runtime_upgrade=True,
            runtime_inventory_peers=frozenset({peer}))['semantic_checks_passed'])

    def test_aps_reference_requires_existing_address_and_security_user(self):
        table = record(self.abi, "nvDeviceListHdr_t", numRecs=1)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=9, keyNvId=0)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=0xfffe) * 2
        self.now[1, 0, 0x4c] = self.before[1, 0, 0x4c] = table
        self.now[1, 6, 0] = self.before[1, 6, 0] = record(self.abi, "APSME_ApsLinkKeyNVEntry_t",
            key=b"k" * 16, txFrmCntr=110, rxFrmCntr=90)
        self.now[1, 1, 9] = record(self.abi, "AddrMgrEntry_t", user=1, extAddr=b"p" * 8)
        self.hold("APS_ADDRESS_MANAGER_SECURITY_REFERENCE_INVALID")
        self.now = copy.deepcopy(self.before)
        table = record(self.abi, "nvDeviceListHdr_t", numRecs=1)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=400, keyNvId=0)
        table += record(self.abi, "ZDSecMgrEntry_t", ami=0xfffe) * 2
        self.now[1, 0, 0x4c] = table
        self.hold("APS_ADDRESS_MANAGER_REFERENCE_MISSING")

    def test_aggregate_counts_cannot_replace_private_records_or_emit_pass(self):
        capture = bytes(security.FLASH_BYTES)
        bindings = {"capture_sha256": security.abi_tool.sha(capture),
                    "baseline_capture_sha256": security.abi_tool.sha(capture),
                    "profile_sha256": "a" * 64, "native_manifest_sha256": "b" * 64,
                    "reader_sha256": security.abi_tool.sha(b"synthetic executable")}
        self.abi.update(profile_sha256="a" * 64, native_manifest_sha256="b" * 64)
        bindings["abi_sha256"] = security.abi_tool.sha(security.abi_tool.canonical(self.abi))
        with mock.patch.object(Path, "read_bytes", return_value=b"synthetic executable"), \
             mock.patch.object(security, "read_private", side_effect=ValueError("reader failed")):
            result = security.preflight(capture=capture, baseline=capture, abi=self.abi,
                                        reader=Path("synthetic-reader"), bindings=bindings)
        self.assertEqual(result["status"], "HOLD")
        self.assertIsNone(result["write_attempts"])
        self.assertFalse(result["flash_authorized"])
        self.assertFalse(result["live_network_counter_floors_verified"])
        self.assertNotIn("extAddr", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
