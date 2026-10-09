"""Host-only, synthetic negative controls. No radio, SWD or device I/O."""
from __future__ import annotations
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import r12_swd_offline as x


def bytes20(*, generation=1, sequence=12, entry=0x0f, exit_=0x07,
            status=0xffff, site=4, phase=0, dev=0xff, nwk=0xff,
            valid=0, reserved=0):
    return struct.pack("<IIHHHBBBBBB", generation, sequence, entry, exit_,
                       status, site, phase, dev, nwk, valid, reserved)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw_bin = b"R11-test-firmware-only"
        self.raw_elf = b"R11-test-elf"
        self.raw_map = (
            "20001220    00000014     mt_debug.o (.data.t832R11Startup)\n"
            "20001220  t832R11Startup\n"
            "20001220  t832R11Startup\n"
        ).encode("utf8")
        self.fake_sha = hashlib.sha256(self.raw_bin).hexdigest()
        artifacts = {}
        for ext, value in ((".slzb.bin", self.raw_bin), (".out", self.raw_elf),
                           (".map", self.raw_map)):
            name = x.STEM + ext
            (self.root / name).write_bytes(value)
            artifacts[name] = {"bytes": len(value),
                               "sha256": hashlib.sha256(value).hexdigest()}
        self.manifest = {
            "variant": x.STEM, "repository_commit": x.COMMIT,
            "sys_version_revision": x.REVISION,
            "flash_authorized": False, "artifacts": artifacts,
        }
        (self.root / "T832-BUILD-MANIFEST.json").write_text(json.dumps(self.manifest))
        p = patch.object(x, "FIRMWARE_SHA", self.fake_sha)
        p.start()
        self.addCleanup(p.stop)

    def test_exact_map_and_image_manifest(self):
        value = x.verify_artifacts(self.root)
        self.assertEqual(value["startup_pod"]["address"], "0x20001220")
        self.assertEqual(value["startup_pod"]["length"], 20)
        self.assertFalse(value["hardware_access_proven"])

    def test_firmware_digest_mismatch_blocks(self):
        (self.root / (x.STEM + ".slzb.bin")).write_bytes(b"tampered-firmware")
        with self.assertRaisesRegex(x.EvidenceError, "artifact hash/size"):
            x.verify_artifacts(self.root)

    def test_manifest_bound_symbol_relocation_reported_not_guessed(self):
        wrong = self.raw_map.replace(b"20001220", b"20001320")
        (self.root / (x.STEM + ".map")).write_bytes(wrong)
        entry = self.manifest["artifacts"][x.STEM + ".map"]
        entry["sha256"] = hashlib.sha256(wrong).hexdigest()
        entry["bytes"] = len(wrong)
        (self.root / "T832-BUILD-MANIFEST.json").write_text(json.dumps(self.manifest))
        # No hardcoded guessed address: exact map evidence is reported.
        self.assertEqual(x.verify_artifacts(self.root)["startup_pod"]["address"], "0x20001320")

    def test_map_symbol_section_disagree_blocks(self):
        broken = self.raw_map.replace(b"20001220  t832R11Startup", b"20001230  t832R11Startup")
        with self.assertRaisesRegex(x.EvidenceError, "linker section and symbol|address/size|ambiguous"):
            x.linker_symbol(broken.decode())


class DecodeTests(unittest.TestCase):
    def setUp(self):
        self.provenance = {
            "schema": x.SCHEMA,
            "image": {"sha256": x.FIRMWARE_SHA},
            "startup_pod": {"address": "0x20001220", "length": 20},
        }

    def test_matching_stable_entry_decodes_with_observation_warning(self):
        raw = bytes20()
        d = x.review_pair(raw, raw, self.provenance)
        self.assertEqual(d["pod"]["last_site"], "RestoreNetworkState/NLME")
        self.assertEqual(d["pod"]["last_phase"], "entry")
        self.assertIn("RestoreNetworkState/NLME", d["pod"]["unmatched_entries"])
        self.assertIn("observation_only", d["pod"]["interpretation"])
        self.assertEqual(d["state"], "COHERENT_20B_READS_ORIGIN_UNPROVEN")

    def test_mismatch_blocks(self):
        with self.assertRaisesRegex(x.EvidenceError, "disagree"):
            x.review_pair(bytes20(), bytes20(sequence=14), self.provenance)

    def test_odd_sequence_torn_blocks(self):
        with self.assertRaisesRegex(x.EvidenceError, "odd sequence"):
            x.decode_pod(bytes20(sequence=11))

    def test_illegal_exit_mask_blocks(self):
        with self.assertRaisesRegex(x.EvidenceError, "impossible"):
            x.decode_pod(bytes20(entry=0x07, exit_=0x0f))

    def test_phase_exit_requires_exit_bit(self):
        with self.assertRaisesRegex(x.EvidenceError, "exit phase"):
            x.decode_pod(bytes20(phase=1))

    def test_unknown_status_not_confused_with_zero(self):
        got = x.decode_pod(bytes20(status=0, valid=0))
        self.assertIsNone(got["last_status"])

    def test_nlme_restored_flag_requires_validity(self):
        with self.assertRaisesRegex(x.EvidenceError, "NLME"):
            x.decode_pod(bytes20(valid=16))

    def test_extra_bytes_block(self):
        with self.assertRaisesRegex(x.EvidenceError, "exactly 20"):
            x.decode_pod(bytes20() + b"x")

    def test_foreign_manifest_blocks(self):
        self.provenance["image"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(x.EvidenceError, "foreign/unverified"):
            x.review_pair(bytes20(), bytes20(), self.provenance)

    def test_confirm_only_site7(self):
        confirmed = x.decode_pod(bytes20(entry=0x40, exit_=0x40, site=7,
                                         phase=2, valid=1, status=0))
        self.assertEqual(confirmed["last_status"], 0)
        self.assertEqual(confirmed["last_site"], "formation-confirm")
        with self.assertRaisesRegex(x.EvidenceError, "confirm only"):
            x.decode_pod(bytes20(site=4, phase=2))


if __name__ == "__main__":
    unittest.main()
