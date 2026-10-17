"""B4 Z2M OTA source overlay fail-closed proof, disposable fixtures only."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host" / "r4-b4"))
from b4_z2m_ota_overlay import (PIN, OTA, CONTROLLER, PACKAGE, apply)

OTA_SOURCE = """export default class OTAUpdate extends Extension {
    #inProgress = new Set<string>();
    override async start(): Promise<void> {
        for (const device of this.zigbee.devicesIterator(utils.deviceNotCoordinator)) {
            if (this.state.get(device).update?.state === "updating") {
                this.state.get(device).update.state = "idle";
            }
        }
    }

    // mostly intended for testing
    clearState(): void {
        this.#inProgress.clear();
    }
}
"""
CONTROLLER_SOURCE = """export class Controller {
    async start(): Promise<void> {
        this.#startAbortController = new AbortController();
    }
}
"""
PACKAGE_SOURCE = json.dumps({"version": "2.14.0",
                             "dependencies": {"zigbee-herdsman": "10.9.1"}})

class PinnedZ2MOtaAdmission(unittest.TestCase):
    def setup(self, root):
        files = {OTA: OTA_SOURCE, CONTROLLER: CONTROLLER_SOURCE,
                 PACKAGE: PACKAGE_SOURCE}
        for name, body in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        def fake_git(_root, *args):
            if args == ("rev-parse", "HEAD"):
                return (PIN + "\n").encode()
            if args[0] == "show":
                return files[args[1].split(":", 1)[1]].encode()
            raise ValueError("unexpected command")
        return files, fake_git

    def test_only_true_runtime_ota_set_and_same_herdsman_owner(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            original, git = self.setup(root)
            with patch("b4_z2m_ota_overlay.git", side_effect=git):
                proof = apply(root)
                self.assertFalse(proof["enabled_by_default"])
                self.assertFalse(proof["host_installed"])
                self.assertTrue(proof["no_secondary_serial_owner"])
                self.assertEqual(proof["ota_state"], "NATIVE_PRIVATE_INPROGRESS_SET")
                self.assertEqual(len(proof["files"]), 2)
                ota = (root / OTA).read_text()
                ctrl = (root / CONTROLLER).read_text()
                self.assertIn("this.#inProgress.size === 0", ota)
                self.assertIn("this.#b4Started = false;", ota)
                self.assertIn("this.#b4Started = true;", ota)
                self.assertIn("ota.b4CanAcceptReadOnlyDiagnostics()", ctrl)
                self.assertIn("herdsman.b4ReadOnlyDiagnosticsFromExistingOwner", ctrl)
                self.assertIn("stillAllowed", ctrl)
                self.assertNotIn("new Znp(", ctrl)
                self.assertNotIn("new SerialPort(", ctrl)
                self.assertEqual((root / PACKAGE).read_text(), original[PACKAGE])
                with self.assertRaisesRegex(ValueError, "dirty Z2M"):
                    apply(root)

    def test_dirty_source_or_wrong_pin_rejected_before_write(self):
        for target, mutate in (
            (OTA, lambda v: v.replace("#inProgress", "#unknown")),
            (CONTROLLER, lambda v: v.replace("async start()", "async boot()")),
            (PACKAGE, lambda v: v.replace('"10.9.1"', '"99.0.0"')),
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory(dir="/tmp") as tmp:
                root = Path(tmp)
                originals, git = self.setup(root)
                file = root / target
                file.write_text(mutate(file.read_text()))
                before = {key: (root / key).read_bytes() for key in originals}
                with patch("b4_z2m_ota_overlay.git", side_effect=git), self.assertRaises(ValueError):
                    apply(root)
                self.assertEqual(before, {key: (root / key).read_bytes() for key in originals})

    def test_wrong_source_git_sha_never_patched(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            originals, _ = self.setup(root)
            with patch("b4_z2m_ota_overlay.git", return_value=b"wrongsha\n"), self.assertRaisesRegex(ValueError, "wrong pinned"):
                apply(root)
            self.assertEqual(originals[CONTROLLER], (root / CONTROLLER).read_text())

if __name__ == "__main__":
    unittest.main()
