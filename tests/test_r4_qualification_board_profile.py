"""Qualification validator controls; synthetic receipts NEVER prove native builds."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

from tests.test_r4_b0_verify_generated_board import HDR, SRC, DEV
from tests.test_r4_current_app_package import current_fixture, profiles

QUALIFICATION = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/qualification"
sys.path.insert(0, str(QUALIFICATION))
import board_profile as board
import compare_replicas as replicas


def seed_generated(directory, power, *, unsafe_gpio=None, external_init=False):
    entries = ["0"] * 31
    entries[12], entries[13] = "GPIO_CFG_INPUT", "GPIO_CFG_OUTPUT"
    if unsafe_gpio is not None:
        entries[unsafe_gpio] = "GPIO_CFG_OUTPUT | GPIO_CFG_OUT_LOW"
    drivers = SRC.replace("GPIO_PinConfig gpioPinConfigs[31] = {};",
                          "GPIO_PinConfig gpioPinConfigs[31] = {" + ",".join(entries) + "};")
    if external_init:
        drivers += "\nvoid Board_shutDownExtFlash(void) { /* rejected even if empty */ }\n"
    device = (DEV if not power["dcdc_enabled"] else DEV.replace("0x1", "0x0"))
    device += "#define CCFG_FORCE_VDDR_HH 0x" + str(int(power["force_vddr"])) + "\n"
    (directory / "ti_drivers_config.h").write_text(HDR)
    (directory / "ti_drivers_config.c").write_text(drivers)
    (directory / "ti_devices_config.c").write_text(device)


class QualificationBoardProfileTests(unittest.TestCase):
    def test_both_historical_profiles_check_actual_generated_macros(self):
        for reference in board.REFERENCES:
            power = board.settings(reference=reference)
            with self.subTest(reference=reference), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                seed_generated(root, power)
                report = board.inspect_generated(root, power, transport_only=True)
                self.assertFalse(report["native_verified"])
                self.assertFalse(report["flash_authorized"])
                self.assertFalse(report["current_board_qualified"])
                self.assertEqual(report["dcdc"]["active_disabled"], not power["dcdc_enabled"])
                other = board.settings(reference=next(name for name in board.REFERENCES if name != reference))
                with self.assertRaisesRegex(ValueError, "POWER_PROFILE_MISMATCH|NOT_DISABLED|FORCE_VDDR"):
                    board.inspect_generated(root, other, transport_only=True)

    def test_unwanted_gpio_and_external_flash_initialization_rejected(self):
        power = board.settings(reference="historical-fitted-20260311")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for dio in (0, 6, 7, 15, 30):
                seed_generated(root, power, unsafe_gpio=dio)
                with self.subTest(dio=dio), self.assertRaisesRegex(ValueError, "UNVERIFIED_GPIO"):
                    board.inspect_generated(root, power, transport_only=True)
            seed_generated(root, power, external_init=True)
            with self.assertRaisesRegex(ValueError, "EXTERNAL_FLASH_INITIALIZATION"):
                board.inspect_generated(root, power, transport_only=True)

    def test_current_profile_requires_external_pin_and_consistent_power_words(self):
        _, profile, _, _ = current_fixture()
        power = board.settings(current_profile=profile, expected_profile_sha256=profile["profile_sha256"])
        self.assertTrue(power["force_vddr"])
        self.assertTrue(power["dcdc_enabled"])
        self.assertFalse(power["current_board_verified"])
        with self.assertRaisesRegex(ValueError, "EXTERNAL_PROFILE_HASH_MISMATCH"):
            board.settings(current_profile=profile, expected_profile_sha256="0" * 64)
        forged = copy.deepcopy(profile)
        forged["source_profile"]["force_vddr_hh"] = False
        forged["profile_sha256"] = profiles.profile_digest(forged)
        with self.assertRaisesRegex(ValueError, "SOURCE_INCONSISTENT"):
            board.settings(current_profile=forged, expected_profile_sha256=forged["profile_sha256"])

    def test_native_power_and_vector_words_are_independently_checked(self):
        power = board.settings(reference="historical-fitted-20260311")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            seed_generated(root, power)
            raw = bytearray(b"\xff" * 0xB0000)
            for address, value in ((0xAFFB4, power["mode_conf"]),
                                   (0xAFFAC, power["mode_conf_1"]), (0xAFFEC, 0)):
                raw[address:address + 4] = value.to_bytes(4, "little")
            binary = root / "image.bin"
            binary.write_bytes(raw)
            report = board.inspect_generated(root, power, transport_only=True, binary=binary)
            # This unit tests board words only; it is not a native ELF audit.
            self.assertTrue(report["native_verified"])
            self.assertFalse(report["rf_qualified"])
            for address in (0xAFFB4, 0xAFFAC, 0xAFFEC):
                mutated = bytearray(raw)
                mutated[address] ^= 1
                binary.write_bytes(mutated)
                with self.subTest(address=address), self.assertRaisesRegex(ValueError, "NATIVE_CCFG_MISMATCH"):
                    board.inspect_generated(root, power, transport_only=True, binary=binary)


class QualificationReplicaComparatorTests(unittest.TestCase):
    """Comparator fixtures are arbitrary bytes, never native image proof."""
    source = "a" * 40
    reference = "historical-fitted-20260311"

    def seed(self, root, ordinal):
        root.mkdir()
        fingerprints, files = {}, {}
        for extension, kind in ((".hex", "hex"), (".bin", "bin")):
            raw = ("synthetic comparison bytes" + extension).encode()
            name = "synthetic" + extension
            (root / name).write_bytes(raw)
            fingerprint = replicas.hashlib.sha256(raw).hexdigest()
            fingerprints[extension] = fingerprint
            files[kind] = {"file": name, "sha256": fingerprint}
        build = {"schema": "r4-p7u-qualification-build-v1", "source_sha": self.source,
                 "profile": "transport-only", "reference_power": self.reference,
                 "replica": str(ordinal), "run_id": "synthetic-hosted-run",
                 "firmware": fingerprints, "flash_authorized": False}
        native = {"schema": "r4-p7u-transport-profile-native-v1", "profile": "transport-only",
                  "source_sha": self.source, "native_compilation_verified": True,
                  "image_binding": {"files": files}, "flash_authorized": False}
        board_receipt = {"schema": "r4-p7u-qualification-board-v1", "native_verified": True,
                         "transport_only": True,
                         "power": board.settings(reference=self.reference),
                         "native_binary_sha256": fingerprints[".bin"], "flash_authorized": False}
        for name, value in (("qualification-build.json", build), ("transport-profile-native.json", native),
                            ("board-native.json", board_receipt)):
            (root / name).write_text(json.dumps(value))

    def test_actual_replica_bytes_and_ordinals_are_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            first, second = Path(temp) / "first", Path(temp) / "second"
            self.seed(first, 1)
            self.seed(second, 2)
            report = replicas.compare(first, second, source_sha=self.source, reference=self.reference)
            self.assertFalse(report["physical_uart_verified"])
            self.assertFalse(report["flash_authorized"])
            (second / "synthetic.bin").write_bytes(b"tampered content")
            with self.assertRaisesRegex(ValueError, "CONTENT_MISMATCH"):
                replicas.compare(first, second, source_sha=self.source, reference=self.reference)

    def test_wrong_source_or_replica_independence_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            first, second = Path(temp) / "first", Path(temp) / "second"
            self.seed(first, 1)
            self.seed(second, 1)
            with self.assertRaisesRegex(ValueError, "INDEPENDENT_REPLICAS_DIVERGE"):
                replicas.compare(first, second, source_sha=self.source, reference=self.reference)
            with self.assertRaisesRegex(ValueError, "RECEIPT_MISMATCH"):
                replicas.compare(first, second, source_sha="b" * 40, reference=self.reference)

    def test_stale_power_board_binary_and_native_profile_receipts_rejected(self):
        for mutation in ("power", "board_binary", "native_schema", "native_profile", "transport"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                first, second = Path(temp) / "first", Path(temp) / "second"
                self.seed(first, 1)
                self.seed(second, 2)
                if mutation.startswith("native"):
                    path = second / "transport-profile-native.json"
                    receipt = json.loads(path.read_text())
                    receipt["schema" if mutation == "native_schema" else "profile"] = "unqualified"
                else:
                    path = second / "board-native.json"
                    receipt = json.loads(path.read_text())
                    if mutation == "power": receipt["power"] = board.settings(reference="historical-20240710")
                    if mutation == "board_binary": receipt["native_binary_sha256"] = "0" * 64
                    if mutation == "transport": receipt["transport_only"] = False
                path.write_text(json.dumps(receipt))
                with self.assertRaisesRegex(ValueError, "RECEIPT_MISMATCH|BOARD_NATIVE_CONTENT_MISMATCH"):
                    replicas.compare(first, second, source_sha=self.source, reference=self.reference)


if __name__ == "__main__":
    unittest.main()
