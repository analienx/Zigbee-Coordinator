"""CCS SysConfig tool selection is verified without a TI installation."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "firmware/slzb-06p7u/r4/b0/tools/b0_bind_sysconfig.py"
spec = importlib.util.spec_from_file_location("binder", P)
binder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binder)


def executable(path, version):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\necho '" + version + "'\n", encoding="utf-8")
    path.chmod(0o755)


@unittest.skipIf(os.name == "nt", "hosted Linux shell fixture")
class BindingTests(unittest.TestCase):
    def setup_tools(self, root, version="1.21.1+3772"):
        eclipse = root / "ccs" / "eclipse" / "eclipse"
        bundled = root / "ccs" / "utils" / "sysconfig_1.21.0" / "sysconfig_cli.sh"
        standalone = root / "standalone" / "sysconfig_cli.sh"
        executable(eclipse, "CCS12.8")
        executable(bundled, "1.21.0+3721")
        executable(standalone, version)
        return eclipse, bundled, standalone

    def test_dispatch_is_pinned_and_preserves_vendor_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            eclipse, bundled, standalone = self.setup_tools(Path(tmp))
            original = bundled.read_bytes()
            result = binder.bind(eclipse, standalone)
            self.assertEqual(result["status"], "PINNED_1_21_1_VERIFIED")
            self.assertIn("1.21.1+3772", binder._version(bundled))
            self.assertEqual((bundled.parent / "sysconfig_cli.sh.vendor-original").read_bytes(), original)
            with self.assertRaisesRegex(RuntimeError, "already modified"):
                binder.bind(eclipse, standalone)

    def test_wrong_standalone_version_refuses_all_modifications(self):
        with tempfile.TemporaryDirectory() as tmp:
            eclipse, bundled, standalone = self.setup_tools(Path(tmp), "1.21.0+3721")
            before = bundled.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                binder.bind(eclipse, standalone)
            self.assertEqual(bundled.read_bytes(), before)
            self.assertFalse((bundled.parent / "sysconfig_cli.sh.vendor-original").exists())

    def test_unrecognized_bundled_cli_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            eclipse, bundled, standalone = self.setup_tools(Path(tmp))
            executable(bundled, "9.9.9")
            with self.assertRaisesRegex(RuntimeError, "unexpected CCS bundled"):
                binder.bind(eclipse, standalone)


if __name__ == "__main__":
    unittest.main()
