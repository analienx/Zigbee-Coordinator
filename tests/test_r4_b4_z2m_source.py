"""Exact Zigbee2MQTT 2.14.0/herdsman 10.9.1 source gate mutants.

No serial device, MQTT, actual installed Z2M, network or radio is accessed.
"""
from pathlib import Path
import json
import sys
import tempfile
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "r4-b4"))
from b4_verify_z2m_source import validate, Z2M_SHA

EXT = """abstract class Extension {
 protected zigbee: Zigbee;
 protected eventBus: EventBus;
 constructor() {}
}
"""

class Zigbee2MQTTSourceContracts(TestCase):
    def fixture(self, root, *, version="2.14.0", herdsman="10.9.1", source=EXT):
        (root / "lib" / "extension").mkdir(parents=True)
        (root / "lib" / "extension" / "extension.ts").write_text(source)
        (root / "package.json").write_text(json.dumps({
            "version": version, "dependencies": {"zigbee-herdsman": herdsman},
        }))

    def test_exact_release_and_private_request_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            with patch("b4_verify_z2m_source.subprocess.check_output",
                       return_value=Z2M_SHA + "\n"):
                r = validate(root)
            self.assertEqual(r["herdsman_package_dependency"], "10.9.1")
            self.assertEqual(r["required_strategy"], "PATCH_INTERNAL_EXISTING_OWNER_ONLY")
            self.assertEqual(r["installed_z2m_version"], "UNKNOWN")
            self.assertFalse(r["host_installed"])

    def test_pinned_version_mismatch_rejected(self):
        for version, herdsman in (("2.14.1", "10.9.1"), ("2.14.0", "10.8.0")):
            with tempfile.TemporaryDirectory() as d:
                root = Path(d)
                self.fixture(root, version=version, herdsman=herdsman)
                with patch("b4_verify_z2m_source.subprocess.check_output",
                           return_value=Z2M_SHA + "\n"), self.assertRaises(ValueError):
                    validate(root)

    def test_wrong_commit_sha_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.fixture(root)
            with patch("b4_verify_z2m_source.subprocess.check_output",
                       return_value="0"*40), self.assertRaisesRegex(ValueError,"wrong upstream"):
                validate(root)

    def test_mutated_extension_public_raw_mt_api_fails_instead_of_claiming_private_as_public(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root, source=EXT + "public requestRaw() {}")
            with patch("b4_verify_z2m_source.subprocess.check_output",
                       return_value=Z2M_SHA + "\n"), self.assertRaisesRegex(ValueError,"manual audit"):
                validate(root)

    def test_removed_public_extension_shape_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root, source="abstract class Extension {}")
            with patch("b4_verify_z2m_source.subprocess.check_output",
                       return_value=Z2M_SHA + "\n"), self.assertRaisesRegex(ValueError,"source drift"):
                validate(root)
