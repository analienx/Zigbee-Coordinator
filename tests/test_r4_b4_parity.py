"""B4 strict native parity oracle mutants (synthetic bytes, NEVER native proof)."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "firmware" / "slzb-06p7u" / "r4" / "b4"))
from b4_artifact_parity import compare

def blob_sha(data):
    return hashlib.sha256(data).hexdigest()

def write_pair(root):
    for index in (1, 2):
        d = root / ("native-" + str(index))
        d.mkdir()
        outputs = {
            "elf": b"\x7fELF" + bytes(3000),
            "xml": (
                '<link_info>\n'
                '<banner>TI ARM Clang Linker Unix v3.2.2.LTS</banner>\n'
                f'<link_time>0x{index:08x}</link_time>\n'
                '<link_errors>0x0</link_errors>\n'
                '<output_file>/tmp/b0ws/board.out</output_file>\n'
                '</link_info>\n'
            ).encode(),
            "hex": b":00000001FF\n",
            "bin": bytes(300),
        }
        files = {}
        for k, data in outputs.items():
            name = "znp." + k
            (d / name).write_bytes(data)
            files[k] = {"file": name, "sha256": blob_sha(data)}
        (d / "manifest.json").write_text(json.dumps({
            "schema":"r4-b0-artifact-manifest-v1", "files": files,
        }))
        (d / "b4-native-linked.json").write_text(json.dumps({
            "schema":"b4-native-link-proof-v1",
            "evidence":"HOSTED_NATIVE_LINKED", "f0_native_handler_linked":True,
            "hardware_verified":False, "host_installed":False,
            "elf_sha256": files["elf"]["sha256"],
        }))
        (d / "b4-native-overlay.json").write_text(json.dumps({
            "stage":"PATCHED_DISPOSABLE_SDK_NOT_LINKED",
            "valid_counter_indices":[0,1,2,3,4], "radio_boot_identity":"UNKNOWN",
        }))

def change_with_new_digest(path, kind, raw):
    (path / ("znp." + kind)).write_bytes(raw)
    manifest = path / "manifest.json"
    m = json.loads(manifest.read_text())
    m["files"][kind]["sha256"] = blob_sha(raw)
    manifest.write_text(json.dumps(m))
    if kind == "elf":
        proof = path / "b4-native-linked.json"
        q = json.loads(proof.read_text())
        q["elf_sha256"] = blob_sha(raw)
        proof.write_text(json.dumps(q))

class ParityAttacks(unittest.TestCase):
    def test_two_real_image_hashes_and_timestamp_only_xml_allowance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pair(root)
            out = compare(root)
            self.assertTrue(out["images_byte_identical"])
            self.assertEqual(len(set(out["raw_linker_xml_sha256"])), 2)
            self.assertEqual(out["linker_xml_normalization"],
                             "ONLY_HEX_LINK_TIME_AS_CONFIRMED_BY_NATIVE_DIFF")

    def test_mutant_xml_output_file_drift_must_fail_even_with_updated_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); write_pair(root)
            d = root / "native-2"
            raw = (d / "znp.xml").read_bytes().replace(b"/tmp/b0ws/board.out",
                                                      b"/tmp/b0ws/DIFFERENT.out")
            change_with_new_digest(d, "xml", raw)
            with self.assertRaisesRegex(ValueError, "beyond allowlisted"):
                compare(root)

    def test_mutant_link_errors_is_not_masked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); write_pair(root)
            d = root / "native-2"
            raw = (d / "znp.xml").read_bytes().replace(b"<link_errors>0x0</link_errors>",
                                                      b"<link_errors>0x1</link_errors>")
            change_with_new_digest(d, "xml", raw)
            with self.assertRaisesRegex(ValueError, "linker errors"):
                compare(root)

    def test_mutant_bin_image_drift_fails_even_if_digest_updated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); write_pair(root)
            change_with_new_digest(root / "native-2", "bin", bytes(299) + b"X")
            with self.assertRaisesRegex(ValueError, "bin bytes"):
                compare(root)

    def test_mutant_elf_drift_fails_even_if_linked_receipt_and_manifest_updated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); write_pair(root)
            change_with_new_digest(root / "native-2", "elf", b"\x7fELF" + bytes(2999) + b"X")
            with self.assertRaisesRegex(ValueError, "elf bytes"):
                compare(root)

    def test_mutant_manifest_wrong_digest_fails_before_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); write_pair(root)
            (root/"native-2"/"znp.hex").write_bytes(b"BAD")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                compare(root)

    def test_mutant_traversal_or_third_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); write_pair(root)
            p = root / "native-1" / "manifest.json"
            m = json.loads(p.read_text())
            m["files"]["hex"]["file"] = "../secret"
            p.write_text(json.dumps(m))
            with self.assertRaisesRegex(ValueError, "basename"):
                compare(root)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); write_pair(root)
            (root/"third").mkdir()
            with self.assertRaisesRegex(ValueError, "exactly two"):
                compare(root)

if __name__ == "__main__":
    unittest.main()
