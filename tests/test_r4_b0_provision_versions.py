"""Host-only fail-closed exact-version probes from independent P2 review."""
import importlib.util
from pathlib import Path
import unittest

SRC = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/b0/tools/b0_provision.py"
spec = importlib.util.spec_from_file_location("b0_provision_exact", SRC)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ExactVersionTests(unittest.TestCase):
    def test_real_ti_clang_stdout_exactly_accepted(self):
        self.assertTrue(gate._matches_version(
            "ti_arm_clang", "/tmp/tiarmclang",
            "TI Arm Clang Compiler 3.2.2.LTS\nTarget: arm-ti-none-eabi\n"
            "Thread model: posix\n"
            "InstalledDir: /tmp/b0ti/installed/clang/ti-cgt-armllvm_3.2.2.LTS/bin\n"))

    def test_false_positive_clang_version_strings_rejected(self):
        self.assertFalse(gate._matches_version(
            "ti_arm_clang", "/tmp/tiarmclang",
            "TI Arm Clang Compiler 13.2.2.LTS\n"))
        self.assertFalse(gate._matches_version(
            "ti_arm_clang", "/tmp/tiarmclang",
            "TI Arm Clang Compiler 4.0.0.LTS\nInstalledDir: /ti/3.2.2.LTS/bin\n"))
        self.assertFalse(gate._matches_version(
            "ti_arm_clang", "/tmp/tiarmclang",
            "TI Arm Clang Compiler 3.2.2.LTS\nTI Arm Clang Compiler 4.0.0.LTS\n"))

    def test_exact_sysconfig_release_not_substring(self):
        self.assertTrue(gate._matches_version("sysconfig", "/tmp/syscfg", "1.21.1+3772\n"))
        self.assertFalse(gate._matches_version("sysconfig", "/tmp/syscfg", "1.21.1+37720\n"))
        self.assertFalse(gate._matches_version("sysconfig", "/tmp/syscfg", "1.21.1+3772\n1.21.1+37720\n"))


if __name__ == "__main__":
    unittest.main()
