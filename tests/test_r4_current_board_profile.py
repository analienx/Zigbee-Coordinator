"""Synthetic-only adversarial checks for CURRENT P7U capture profiles."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

MODULE = (Path(__file__).resolve().parents[1] /
          "firmware/slzb-06p7u/r4/release/r4_current_board_profile.py")
spec = importlib.util.spec_from_file_location("current_board_profile", MODULE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def identity():
    return {"model": "SLZB-06P7U", "hardware_revision": "1.73",
            "soc": "CC2652P7", "flash_bytes": m.FLASH_BYTES,
            "board_binding_id": "synthetic-private-board-identity"}


def capture(*, vector=0, boost=False, dcdc=True):
    data = bytearray(b"\xff" * m.FLASH_BYTES)
    mode1 = 0xFFC00010 if boost else 0xFF800010
    mode = 0xF1B9C1FF if boost else 0xF3B9C1FF
    if not dcdc:
        mode |= (1 << 26) | (1 << 27)
    struct.pack_into("<III", data, m.CCFG + 4, mode1, 0x0058FFFD, mode)
    struct.pack_into("<I", data, m.IMAGE_VALID, vector)
    struct.pack_into("<I", data, m.BL_CONFIG, 0xC5FE0FC5)
    for address in (0, m.RESIDENT_BOOT):
        struct.pack_into("<II", data, address, 0x20023C00, address + 0x101)
    data[m.APP_LIMIT + 20:m.APP_LIMIT + 28] = b"nvCanary"
    data[m.CCFG + 32:m.CCFG + 48] = b"privateIEEEvalue"
    return bytes(data)


def profile(data, **kwargs):
    board = kwargs.pop("board_identity", identity())
    pins = {"expected_pass1_sha256": m.sha256(data),
            "expected_pass2_sha256": m.sha256(data),
            "board_identity": board,
            "expected_board_identity_sha256": m.board_identity_digest(board)}
    pins.update(kwargs)
    return m.analyze_capture_pair(data, data, **pins)


class CurrentBoardProfileTests(unittest.TestCase):
    def test_actual_current_direct_profile_uses_no_historical_pins(self):
        data = capture(boost=False, dcdc=False)
        result = profile(data)
        self.assertEqual(result["boot_gate"], m.DIRECT_GATE)
        self.assertEqual(result["capture_sha256"], m.sha256(data))
        self.assertTrue(result["source_profile"]["source_generation_supported"])
        self.assertFalse(result["source_profile"]["force_vddr_hh"])
        self.assertFalse(result["source_profile"]["dcdc_active_enabled"])
        self.assertEqual(result["geometry"]["protected_ranges"],
                         [[m.APP_LIMIT, m.FLASH_BYTES]])
        self.assertEqual(result["protection"]["writable_application_sector_indices"],
                         list(range(80)))
        self.assertFalse(result["flash_authorized"])
        self.assertFalse(result["boot_proven"])
        self.assertFalse(result["nv_compatibility_proven"])
        self.assertEqual(result["nv_observations"][0]["schema_compatibility"], "UNKNOWN")
        self.assertEqual(result["nv_observations"][0]["non_erased_bytes"], 8)
        self.assertEqual(m.validate_profile(result, expected_profile_sha256=
                         result["profile_sha256"], capture=data), result)

    def test_current_boost_ac000_requires_recovery_not_direct_flash(self):
        result = profile(capture(vector=m.RESIDENT_BOOT, boost=True))
        self.assertEqual(result["boot_gate"], m.RECOVERY_GATE)
        self.assertTrue(result["source_profile"]["force_vddr_hh"])
        self.assertTrue(result["source_profile"]["dcdc_recharge_enabled"])
        self.assertFalse(result["boot"]["ccfg_recovery_qualified"])

    def test_full_capture_and_external_pins_are_mandatory(self):
        data = capture()
        for bad in (data[:-1], data + b"\x00", bytearray(data)):
            with self.subTest(length=len(bad)), self.assertRaisesRegex(
                    ValueError, "CAPTURE_NOT_COMPLETE_704K"):
                profile(bad)
        with self.assertRaisesRegex(ValueError, "EXTERNAL_CAPTURE_HASH"):
            profile(data, expected_pass1_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "SHA256_FORMAT"):
            profile(data, expected_pass2_sha256="auto")

    def test_individually_pinned_different_passes_still_rejected(self):
        one = capture()
        two = bytearray(one)
        two[0x2000] ^= 1
        two = bytes(two)
        board = identity()
        with self.assertRaisesRegex(ValueError, "PASSES_DISAGREE"):
            m.analyze_capture_pair(one, two, expected_pass1_sha256=m.sha256(one),
                expected_pass2_sha256=m.sha256(two), board_identity=board,
                expected_board_identity_sha256=m.board_identity_digest(board))

    def test_board_binding_pinned_and_other_hardware_rejected(self):
        with self.assertRaisesRegex(ValueError, "EXTERNAL_BOARD_IDENTITY_HASH"):
            profile(capture(), expected_board_identity_sha256="0" * 64)
        for key, bad in (("model", "SLZB-06P7"), ("soc", "CC2674P10"),
                         ("hardware_revision", "1.72"), ("flash_bytes", True)):
            board = identity()
            board[key] = bad
            with self.subTest(key=key), self.assertRaisesRegex(
                    ValueError, "NOT_SUPPORTED_P7U"):
                m.board_identity_digest(board)
        board = identity()
        board["ieee"] = "forbidden-unstructured-field"
        with self.assertRaisesRegex(ValueError, "BOARD_IDENTITY_FIELDS"):
            m.board_identity_digest(board)

    def test_unknown_vector_or_no_safe_backdoor_blocks(self):
        for address, value in ((m.IMAGE_VALID, 0x8000), (m.BL_CONFIG, 0xC5FFFFFF),
                               (m.BL_CONFIG, 0x00FE0FC5), (0, 0x20024004),
                               (4, 0x100)):
            data = bytearray(capture())
            struct.pack_into("<I", data, address, value)
            with self.subTest(address=address, value=value):
                result = profile(bytes(data))
                self.assertEqual(result["boot_gate"], m.BLOCKED_GATE)
                self.assertTrue(result["boot_gate_reasons"])

    def test_ambiguous_power_fields_are_observed_but_never_invent_profile(self):
        for address, mask in ((m.CCFG + 4, 1 << 20),
                               (m.CCFG + 12, 1 << 26),
                               (m.CCFG + 8, 1 << 16)):
            data = bytearray(capture())
            struct.pack_into("<I", data, address,
                             struct.unpack_from("<I", data, address)[0] ^ mask)
            with self.subTest(address=address):
                result = profile(bytes(data))
                self.assertFalse(result["source_profile"]["source_generation_supported"])
                self.assertTrue(result["source_profile"]["unsupported_reasons"])

    def test_protection_decodes_real_sector_87_not_legacy_sector_31(self):
        data = bytearray(capture())
        struct.pack_into("<I", data, m.PROTECTION, 0xFFFFFFFE)
        struct.pack_into("<I", data, m.PROTECTION + 8, 0xFF7FFFFF)
        result = profile(bytes(data))
        self.assertNotIn(0, result["protection"]["writable_application_sector_indices"])
        self.assertFalse(result["protection"]["top_sector_writable"])
        self.assertTrue(result["protection"]["resident_boot_sector_writable"])

    def test_sanitized_output_excludes_private_input_values(self):
        result = profile(capture())
        encoded = json.dumps(result)
        for secret in ("privateIEEEvalue", "nvCanary", identity()["board_binding_id"],
                       "BL_CONFIG", "CCFG_TAP_DAP", "PROTECT_64_95"):
            self.assertNotIn(secret, encoded)

    def test_mutation_and_recomputed_self_digest_cannot_replace_external_pin(self):
        data = capture()
        good = profile(data)
        edited = copy.deepcopy(good)
        edited["boot_gate"] = m.RECOVERY_GATE
        edited["profile_sha256"] = m.profile_digest(edited)
        with self.assertRaisesRegex(ValueError, "EXTERNAL_PROFILE_HASH"):
            m.validate_profile(edited, expected_profile_sha256=good["profile_sha256"])
        with self.assertRaisesRegex(ValueError, "BOOT_GATE_INCONSISTENT"):
            m.validate_profile(edited, expected_profile_sha256=edited["profile_sha256"],
                               capture=data)
        edited = copy.deepcopy(good)
        edited["protection"]["top_sector_writable"] = False
        edited["profile_sha256"] = m.profile_digest(edited)
        with self.assertRaisesRegex(ValueError, "OBSERVATION_MISMATCH"):
            m.validate_profile(edited, expected_profile_sha256=edited["profile_sha256"],
                               capture=data)
        with self.assertRaisesRegex(ValueError, "PROFILE_CAPTURE_HASH"):
            m.validate_profile(good, expected_profile_sha256=good["profile_sha256"],
                               capture=capture(boost=True))

    def test_rehashed_receipt_still_cannot_contradict_its_source_or_claim_proof(self):
        good = profile(capture())
        for section, key, bad, reason in (
                ("source_profile", "force_vddr_hh", True, "SOURCE_INCONSISTENT"),
                ("geometry", "protected_ranges", [], "PROFILE_GEOMETRY"),
                ("boot", "ccfg_recovery_qualified", True, "BOOT_INCONSISTENT"),
                (None, "nv_compatibility_proven", True, "PROOF_ASSERTION")):
            edited = copy.deepcopy(good)
            target = edited if section is None else edited[section]
            target[key] = bad
            edited["profile_sha256"] = m.profile_digest(edited)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, reason):
                m.validate_profile(edited, expected_profile_sha256=edited["profile_sha256"])

    def test_cli_exclusive_sanitized_receipt_and_capture_alias_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            one, two, board, out = [root / name for name in
                                    ("one.bin", "two.bin", "identity.json", "profile.json")]
            data = capture()
            one.write_bytes(data)
            two.write_bytes(data)
            board.write_text(json.dumps(identity()), "utf-8")
            command = [sys.executable, str(MODULE), "--capture-pass1", str(one),
                       "--capture-pass2", str(two), "--board-identity-json", str(board),
                       "--output", str(out), "--expected-pass1-sha256", m.sha256(data),
                       "--expected-pass2-sha256", m.sha256(data),
                       "--expected-board-identity-sha256", m.board_identity_digest(identity())]
            success = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(json.loads(out.read_text("utf-8")), profile(data))
            again = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            self.assertIn("OUTPUT_ALREADY_EXISTS", again.stderr)
            command[command.index(str(two))] = str(one)
            alias = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(alias.returncode, 0)
            self.assertIn("CAPTURE_INPUT_PATHS_ALIAS", alias.stderr)


if __name__ == "__main__":
    unittest.main()
