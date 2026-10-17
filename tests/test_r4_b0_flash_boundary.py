"""Pure offline regression tests for R4-B0 never-flash raw-BIN boundary."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/b0/tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("flash_boundary", TOOLS / "b0_flash_boundary.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def intel_hex(count, addr, kind, data=b""):
    assert len(data) == count
    record = bytes([count, addr >> 8, addr & 255, kind]) + data
    record += bytes([(-sum(record)) & 255])
    return ":" + record.hex().upper() + "\n"


def build_hex(with_nv=False):
    records = [
        intel_hex(2, 0, 4, b"\x00\x00"),
        intel_hex(8, 0, 0, bytes(range(8))),
        intel_hex(2, 0, 4, b"\x00\x0a"),
        intel_hex(8, 0xffa8, 0, bytes([0xff] * 8)),
    ]
    if with_nv:
        records.append(intel_hex(8, 0xa000, 0, b"\x00" * 8))
    records.append(intel_hex(0, 0, 1))
    return "".join(records).encode("ascii")


def setup(tmp, with_nv=False):
    path = Path(tmp)
    binary = bytearray(gate.IMAGE_LEN)
    binary[:8] = bytes(range(8))
    binary[gate.CCFG_BEGIN:gate.CCFG_BEGIN+8] = bytes([0xff]*8)
    hexfile = build_hex(with_nv)
    (path / "znp.hex").write_bytes(hexfile)
    (path / "znp.bin").write_bytes(binary)
    files = {}
    for logical in ("bin", "hex"):
        name = "znp." + logical
        files[logical] = {
            "file": name,
            "sha256": hashlib.sha256((path / name).read_bytes()).hexdigest(),
        }
    (path / "manifest.json").write_text(json.dumps({
        "schema": "r4-b0-artifact-manifest-v1", "files": files
    }))
    return path


class FlashBoundaryTests(unittest.TestCase):
    def test_green_only_source_build_and_full_nv_span_is_nonflashable(self):
        with tempfile.TemporaryDirectory() as td:
            root = setup(td)
            receipt = gate.inspect(root)
            self.assertIs(receipt["flash_authorized"], False)
            self.assertIs(receipt["production_release_authorized"], False)
            self.assertIs(receipt["network_migration_authorized"], False)
            self.assertFalse(receipt["bin"]["safe_to_flash_whole"])
            self.assertFalse(receipt["hex"]["safe_to_flash_without_separate_hardware_approval"])
            self.assertEqual(receipt["protected_nv"]["bytes"], 0x4000)
            self.assertEqual(receipt["protected_nv"]["raw_bin_nv_pad_byte"], 0)

    def test_hex_data_in_nv_protected_pages_must_fail(self):
        with tempfile.TemporaryDirectory() as td:
            root = setup(td, with_nv=True)
            with self.assertRaisesRegex(ValueError, "HEX_WRITES_PROTECTED_NV"):
                gate.inspect(root)

    def test_historical_nv5_candidate_hex_range_is_protected(self):
        # Source-history NV5 candidate starts at 0xA4000, while donor
        # NV2 starts at 0xAA000. Neither is proof of actual stock NV.
        with tempfile.TemporaryDirectory() as td:
            root = setup(td)
            old_hex = (root / "znp.hex").read_bytes().decode("ascii")
            extra = intel_hex(8, 0x4000, 0, bytes(8))
            new_hex = old_hex.replace(intel_hex(0, 0, 1),
                                      extra + intel_hex(0, 0, 1))
            (root / "znp.hex").write_text(new_hex, encoding="ascii")
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["files"]["hex"]["sha256"] = hashlib.sha256(
                new_hex.encode("ascii")).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "HISTORICAL_NV5_CANDIDATE"):
                gate.inspect(root)

    def test_old_nv5_candidate_raw_bin_padding_must_be_uniform(self):
        with tempfile.TemporaryDirectory() as td:
            root = setup(td)
            state = gate.inspect(root)
            nv = state["protected_nv"]
            self.assertEqual(nv["conservative_protected_begin"], "0xA4000")
            self.assertEqual(nv["conservative_protected_bytes"], 0xA000)
            self.assertFalse(nv["historical_nv5_layout_verified_on_current_stock"])
            blob = bytearray((root / "znp.bin").read_bytes())
            blob[0xA4000 + 0x100] = 0xA5  # outside donor NV2, inside candidate NV5
            (root / "znp.bin").write_bytes(blob)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["files"]["bin"]["sha256"] = hashlib.sha256(blob).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "NV_PADDING_NOT_UNIFORM"):
                gate.inspect(root)

    def test_bin_nv_padding_uniformity_and_digest_both_required(self):
        with tempfile.TemporaryDirectory() as td:
            root = setup(td)
            blob = bytearray((root / "znp.bin").read_bytes())
            blob[gate.NV_BEGIN + 7] = 0x72
            (root / "znp.bin").write_bytes(blob)
            with self.assertRaisesRegex(ValueError, "SHA256_MISMATCH"):
                gate.inspect(root)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["files"]["bin"]["sha256"] = hashlib.sha256(blob).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "NV_PADDING_NOT_UNIFORM"):
                gate.inspect(root)

    def test_programmed_flash_byte_change_rejected_even_if_hash_is_updated(self):
        with tempfile.TemporaryDirectory() as td:
            root = setup(td)
            binary = bytearray((root / "znp.bin").read_bytes())
            binary[5] ^= 0x01  # outside protected NV; HEX still original
            (root / "znp.bin").write_bytes(binary)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["files"]["bin"]["sha256"] = hashlib.sha256(binary).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "HEX_BIN_PROGRAMMED_BYTES_DIFFER"):
                gate.inspect(root)

    def test_extra_hex_data_beyond_flash_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = setup(td)
            data = build_hex().decode()
            data = data.replace(intel_hex(0, 0, 1),
                intel_hex(2, 0, 4, bytes((0, 11))) +
                intel_hex(4, 0, 0, bytes((0x12, 0x34, 0x56, 0x78))) +
                intel_hex(0, 0, 1))
            blob = data.encode()
            (root / "znp.hex").write_bytes(blob)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["files"]["hex"]["sha256"] = hashlib.sha256(blob).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "HEX_BIN_PROGRAMMED_BYTES_DIFFER"):
                gate.inspect(root)

    def test_truncated_binary_fails_even_with_refreshed_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root = setup(td)
            b = (root / "znp.bin").read_bytes()[:gate.NV_BEGIN]
            (root / "znp.bin").write_bytes(b)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["files"]["bin"]["sha256"] = hashlib.sha256(b).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "NOT_704K_FLAT_IMAGE"):
                gate.inspect(root)

    def test_failed_retry_never_leaves_stale_accepted_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            root = setup(td)
            receipt = root / "DO_NOT_FLASH_NV_BOUNDARY.json"
            receipt.write_text('{"flash_authorized":true,"status":"STALE"}')
            (root / "manifest.json").write_text('{"schema":"bad","files":null}')
            with patch.object(sys, "argv", ["b0_flash_boundary.py",
                                           "--artifacts", str(root),
                                           "--receipt", str(receipt)]):
                self.assertEqual(gate.main(), 1)
            state = json.loads(receipt.read_text())
            self.assertFalse(state["flash_authorized"])
            self.assertFalse(state["network_migration_authorized"])
            self.assertEqual(state["status"], "FAILED_CLOSED")
            self.assertNotIn("STALE", receipt.read_text())

    def test_malformed_manifest_cannot_preserve_stale_flash_authorization(self):
        with tempfile.TemporaryDirectory() as td:
            root = setup(td)
            receipt = root / "DO_NOT_FLASH_NV_BOUNDARY.json"
            for invalid in ("[]", "null", '"not a manifest"',
                            '{"schema":"r4-b0-artifact-manifest-v1","files":[]}',
                            " " * 131073):
                with self.subTest(manifest=invalid[:40]):
                    receipt.write_text('{"flash_authorized":true}')
                    (root / "manifest.json").write_text(invalid)
                    with patch.object(sys, "argv", ["b0_flash_boundary.py",
                         "--artifacts", str(root), "--receipt", str(receipt)]):
                        self.assertEqual(gate.main(), 1)
                    result = json.loads(receipt.read_text())
                    self.assertIs(result["flash_authorized"], False)
                    self.assertEqual(result["status"], "FAILED_CLOSED")

    def test_receipt_does_not_pretend_to_prove_native_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            state = gate.inspect(setup(td))
            self.assertFalse(state["source_abi_verified_by_this_receipt"])
            self.assertIn("NOT_SOURCE_OR_HARDWARE", state["qualification"])

    def test_manifest_path_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = setup(td)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["files"]["bin"]["file"] = "../znp.bin"
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "UNSAFE_bin_PATH"):
                gate.inspect(root)


if __name__ == "__main__":
    unittest.main()
