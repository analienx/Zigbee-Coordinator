"""Independent audited-native-image regression; no radio operations.

Set R12_AUDIT_BUNDLE to a REAL downloaded native candidate bundle for
full negative/tamper tests. Host-only CI may skip if no signed build exists.
"""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from r12_artifact_audit import AuditFailure, audit

FIXTURE = os.environ.get("R12_AUDIT_BUNDLE")


@unittest.skipUnless(FIXTURE and Path(FIXTURE).is_dir(),
                     "exact native candidate artifact not mounted")
class NativeArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "candidate"
        shutil.copytree(FIXTURE, self.root)
        # The independent report is not a build artifact.
        (self.root / "INDEPENDENT_RELEASE_AUDIT.json").unlink(missing_ok=True)

    def test_real_r12_is_authentic_but_unapproved(self):
        report = audit(self.root)
        self.assertEqual(report["status"],
                         "COMPILED_BINARY_AUTHENTICATED_HARDWARE_BLOCKED")
        self.assertFalse(report["approved_to_flash"])
        self.assertGreaterEqual(len(report["critical_unresolved"]), 2)
        self.assertEqual(report["acknowledged_rearm_protocol"],
                         "NOT_REQUIRED_FOR_ONE_SHOT")
        self.assertTrue(report["ccfg_and_nvs_geometry_verified"])

    def test_binary_byte_corruption_denied(self):
        image = self.root / "T832-R12-A1-DIAG-vendor-20240716.slzb.bin"
        raw = bytearray(image.read_bytes())
        raw[1234] ^= 0x01
        image.write_bytes(raw)
        with self.assertRaisesRegex(AuditFailure, "bundle hash/size"):
            audit(self.root)

    def test_wrong_revision_denied(self):
        manifest = self.root / "T832-BUILD-MANIFEST.json"
        value = json.loads(manifest.read_text())
        value["sys_version_revision"] = 8320052
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(AuditFailure, "revision"):
            audit(self.root)

    def test_hardware_claim_not_accepted_without_proof(self):
        manifest = self.root / "T832-BUILD-MANIFEST.json"
        value = json.loads(manifest.read_text())
        value["R12"]["flash_authorized"] = True
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(AuditFailure, "qualification"):
            audit(self.root)

    def test_manifest_internal_sha_mutation_denied(self):
        manifest = self.root / "T832-BUILD-MANIFEST.json"
        value = json.loads(manifest.read_text())
        key = "T832-R12-A1-DIAG-vendor-20240716.out"
        value["artifacts"][key]["sha256"] = "0"*64
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(AuditFailure, "bundle hash/size"):
            audit(self.root)


if __name__ == "__main__":
    unittest.main()
