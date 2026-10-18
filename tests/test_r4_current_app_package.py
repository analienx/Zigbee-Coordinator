"""Synthetic current-board geometry; no native-build or hardware qualification."""
import copy
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest

RELEASE = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/release"
sys.path.insert(0, str(RELEASE))
import r4_current_app_package as m
import r4_current_board_profile as profiles


def current_fixture(*, image_valid=0, protected_index=None):
    capture = bytearray(b"\xff" * m.FLASH)
    capture[:m.SECTOR] = b"\x11" * m.SECTOR
    capture[0x4000:0x6000] = b"\x22" * m.SECTOR
    struct.pack_into("<II", capture, image_valid, 0x20023C00, 0x101)
    struct.pack_into("<I", capture, profiles.CCFG + 4, 0xFFC00010)
    struct.pack_into("<I", capture, profiles.CCFG + 8, 0x0058FFFF)
    struct.pack_into("<I", capture, profiles.CCFG + 12, 0xF1B9C1FF)
    struct.pack_into("<I", capture, profiles.IMAGE_VALID, image_valid)
    struct.pack_into("<I", capture, profiles.BL_CONFIG, 0xC5FE0FC5)
    if protected_index is not None:
        at = profiles.PROTECTION + protected_index // 32 * 4
        word = struct.unpack_from("<I", capture, at)[0]
        struct.pack_into("<I", capture, at, word & ~(1 << (protected_index % 32)))
    snapshot = bytes(capture)
    identity = {"model": "SLZB-06P7U", "hardware_revision": "1.73", "soc": "CC2652P7",
                "flash_bytes": m.FLASH, "board_binding_id": "synthetic-fixture-0001"}
    profile = profiles.analyze_capture_pair(snapshot, snapshot,
        expected_pass1_sha256=m.sha(snapshot), expected_pass2_sha256=m.sha(snapshot),
        board_identity=identity, expected_board_identity_sha256=profiles.board_identity_digest(identity))
    native = {i: 0 for i in range(0x3C)}
    native.update(enumerate(struct.pack("<II", 0x20023C00, 0x101)))
    native[0x100] = 0x70
    native[0x101] = 0x47
    native[0x4004] = 0xA5
    native.update({a: snapshot[a] for a in range(m.CCFG, m.FLASH)})
    evidence = {"manifest_sha256": "1" * 64, "elf_sha256": "2" * 64,
                "hex_sha256": "3" * 64, "xml_sha256": "4" * 64, "bin_sha256": "5" * 64}
    return snapshot, profile, native, evidence


def synthetic_package(**kwargs):
    snapshot, profile, native, evidence = current_fixture(**kwargs)
    return m._bind_payload(native, profile, snapshot, evidence,
                           expected_profile_sha256=profile["profile_sha256"])


class CurrentAppPackageTests(unittest.TestCase):
    def test_dynamic_sparse_sector_set_and_current_restore(self):
        package = synthetic_package()
        self.assertEqual(set(package.sectors), {0, 0x4000})
        self.assertEqual(package.manifest["program_order"], [0x4000, 0])
        self.assertEqual(package.sectors[0x4000][4], 0xA5)
        self.assertEqual(package.sectors[0x4000][:4], b"\xff" * 4)
        self.assertFalse(package.manifest["flash_authorized"])
        self.assertFalse(package.manifest["network_compatibility_verified"])
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "private"
            m.export_private(package, out, expected_profile_sha256=package.profile["profile_sha256"],
                             expected_package_sha256=package.manifest["package_sha256"])
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
            self.assertEqual((out / "restore-current-app-04000.bin").read_bytes(), package.snapshot[0x4000:0x6000])
            self.assertFalse(any("ccfg" in path.name or "nv" in path.name for path in out.iterdir()))
            parsed, error = m._parse_intel_hex(out / "CURRENT-APP-ONLY-NOT-FLASH-AUTHORIZED.hex")
            self.assertIsNone(error)
            self.assertEqual(set(a // m.SECTOR * m.SECTOR for a in parsed), {0, 0x4000})
            with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                m.export_private(package, out, expected_profile_sha256=package.profile["profile_sha256"],
                                 expected_package_sha256=package.manifest["package_sha256"])

    def test_native_23_sector_requirement_is_absent(self):
        snapshot, profile, native, evidence = current_fixture()
        for address in (0x10000, 0x30000, 0x9FFF0):
            native[address] = 0x55
        package = m._bind_payload(native, profile, snapshot, evidence,
                                  expected_profile_sha256=profile["profile_sha256"])
        self.assertEqual(set(package.sectors), {0, 0x4000, 0x10000, 0x30000, 0x9E000})

    def test_boot_gate_protected_sector_and_current_capture_denied(self):
        with self.assertRaisesRegex(ValueError, "NOT_ALREADY_DIRECT_ROM"):
            synthetic_package(image_valid=0xAC000)
        with self.assertRaisesRegex(ValueError, "NOT_CURRENTLY_WRITABLE"):
            synthetic_package(protected_index=2)
        snapshot, profile, native, evidence = current_fixture()
        for address in (0xA0000, 0xA4000, 0xAC000, 0xAE000):
            modified = dict(native)
            modified[address] = 0
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, "NV_BOOT_OR_TOP"):
                m._bind_payload(modified, profile, snapshot, evidence,
                                expected_profile_sha256=profile["profile_sha256"])
        changed = bytearray(snapshot)
        changed[0x2000] ^= 1
        with self.assertRaisesRegex(ValueError, "CAPTURE_HASH_MISMATCH"):
            m._bind_payload(native, profile, bytes(changed), evidence,
                            expected_profile_sha256=profile["profile_sha256"])

    def test_recomputed_profile_forgery_rejected_against_capture(self):
        snapshot, profile, native, evidence = current_fixture()
        forged = copy.deepcopy(profile)
        forged["geometry"]["application_limit_exclusive"] = 0xAE000
        forged["geometry"]["protected_ranges"] = [[0xAE000, m.FLASH]]
        forged["profile_sha256"] = profiles.profile_digest(forged)
        with self.assertRaisesRegex(ValueError, "PROFILE_GEOMETRY|OBSERVATION_MISMATCH"):
            m._bind_payload(native, forged, snapshot, evidence,
                            expected_profile_sha256=forged["profile_sha256"])

    def test_native_ccfg_vectors_and_payload_tamper(self):
        snapshot, profile, native, evidence = current_fixture()
        changed = dict(native)
        changed[profiles.CCFG + 4] ^= 1
        with self.assertRaisesRegex(ValueError, "CCFG_NOT_EXACT"):
            m._bind_payload(changed, profile, snapshot, evidence,
                            expected_profile_sha256=profile["profile_sha256"])
        changed = dict(native)
        changed.pop(0x100)
        with self.assertRaisesRegex(ValueError, "RESET_NOT_IN_LINKED_APP"):
            m._bind_payload(changed, profile, snapshot, evidence,
                            expected_profile_sha256=profile["profile_sha256"])
        package = synthetic_package()
        package.sectors[0] = b"\x00" * m.SECTOR
        with self.assertRaisesRegex(ValueError, "PACKAGE_HASH_OR_CONTENT_CHANGED"):
            m.validate_package(package, expected_profile_sha256=profile["profile_sha256"],
                               expected_package_sha256=package.manifest["package_sha256"])

    def test_external_native_manifest_pin_required_before_audit(self):
        snapshot, profile, native, evidence = current_fixture()
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory)
            (artifacts / "manifest.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "NATIVE_MANIFEST_HASH_MISMATCH"):
                m.from_artifacts(artifacts, profile, snapshot,
                    expected_profile_sha256=profile["profile_sha256"], expected_manifest_sha256="0" * 64)
            with self.assertRaisesRegex(ValueError, "NATIVE_AUDIT_FAILED"):
                m.from_artifacts(artifacts, profile, snapshot,
                    expected_profile_sha256=profile["profile_sha256"],
                    expected_manifest_sha256=m.sha(b"{}"))

    def test_private_app_export_rejects_git_worktrees_and_symlink_escape(self):
        package = synthetic_package()
        kwargs = {"expected_profile_sha256": package.profile["profile_sha256"],
                  "expected_package_sha256": package.manifest["package_sha256"]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_tree = root / "nested"
            git_tree.mkdir()
            (git_tree / ".git").write_text("gitdir: /private/external\n")
            with self.assertRaisesRegex(ValueError, "INSIDE_GIT_WORKTREE"):
                m.export_private(package, git_tree / "capture", **kwargs)
            self.assertFalse((git_tree / "capture").exists())
            symlink = root / "export-link"
            symlink.symlink_to(root / "nonexistent-export", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "PRIVATE_OUTPUT_SYMLINK"):
                m.export_private(package, symlink, **kwargs)
            self.assertFalse((root / "nonexistent-export").exists())
            placeholder = root / ".git"
            placeholder.mkdir()
            safe = root / "private-export"
            m.export_private(package, safe, **kwargs)
            self.assertTrue((safe / "manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
