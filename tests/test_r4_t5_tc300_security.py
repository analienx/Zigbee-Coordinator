"""Pinned post-fusion TI APS/TCLK TC300 source fault tests; no private NV or RF.

The optional R4_T5_SECURITY_SOURCE path is supplied by the exact-head hosted
B1+B3 fusion workflow, so the C routines are extracted from genuinely patched
TI 8.33 source, not a rewritten Python reference model. Without it, only the
offline source/generator contract runs; source-native proof is explicitly SKIP.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "firmware/slzb-06p7u/r4/b1/tools"
HARNESS = TOOLS / "make_security_harness.py"
PROFILE = ROOT / "firmware/slzb-06p7u/r4/profiles/p7u-r4-full-nv4.json"
sys.path.insert(0, str(TOOLS))

spec = importlib.util.spec_from_file_location("t5_tc300_harness", HARNESS)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class T5Tc300PinnedSecurityTests(unittest.TestCase):
    def test_actual_full_profile_is_tc300_aps3(self):
        import json

        profile = json.loads(PROFILE.read_text())
        self.assertEqual(profile["capacities"]["trust_center_devices"], 300)
        self.assertEqual(profile["capacities"]["aps_table_entries"], 3)
        self.assertIn("formed_sparse_255", generator.TC300_SCENARIOS)
        self.assertIn("formed_sparse_256", generator.TC300_SCENARIOS)
        self.assertIn("formed_sparse_299", generator.TC300_SCENARIOS)
        self.assertEqual(len(generator.TC300_MUTANTS), 3)

    def test_actual_pinned_patched_ti_functions_and_adversarial_mutants(self):
        source_path = os.environ.get("R4_T5_SECURITY_SOURCE")
        if not source_path:
            self.skipTest("R4_T5_SECURITY_SOURCE not set: native post-fusion extraction unverified")
        source = Path(source_path)
        self.assertTrue(source.is_file() and not source.is_symlink())
        self.assertIn("b1_sec_validate_restored", source.read_text())
        self.assertIn("ZDSecMgrSaveTCLinkKey", source.read_text())

        env = dict(os.environ,
                   ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                   UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")

        def run(args, *, timeout=15):
            return subprocess.run([str(x) for x in args], capture_output=True,
                                  text=True, env=env, timeout=timeout)

        with tempfile.TemporaryDirectory(prefix="r4-t5-tc300-") as temporary:
            root = Path(temporary)

            def compile_harness(label, mutant=None):
                body = root / (label + ".c")
                args = ["python3", HARNESS, "--source", source,
                        "--output", body, "--tc300"]
                if mutant:
                    args.extend(["--tc300-mutant", mutant])
                rendered = run(args)
                self.assertEqual(rendered.returncode, 0, rendered.stderr)
                binary = root / label
                built = run(["gcc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra",
                             "-Werror", "-Wno-unused-parameter",
                             *(["-Wno-error=type-limits"] if mutant == "truncated_slot_index" else []),
                             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                             "-fno-pie", "-no-pie", body, "-o", binary])
                self.assertEqual(built.returncode, 0, built.stderr)
                return binary

            binary = compile_harness("pinned-tc300")
            for scenario in generator.TC300_SCENARIOS:
                with self.subTest(scenario=scenario):
                    result = run([binary, scenario])
                    self.assertEqual(result.returncode, 0,
                                     f"{scenario}: {result.stdout}{result.stderr}")
                    self.assertIn("T5_TC300_REAL_FUNCTIONS_PASS", result.stdout)

            for mutant, (scenario, _, _) in generator.TC300_MUTANTS.items():
                with self.subTest(mutant=mutant):
                    corrupted = compile_harness("mutant-" + mutant, mutant)
                    result = run([corrupted, scenario], timeout=5)
                    self.assertNotEqual(result.returncode, 0,
                                        f"Mutant was wrongly accepted: {mutant}")
                    self.assertIn("Assertion", result.stderr,
                                  f"Mutant failed for unrelated reason: {mutant}: {result.stderr}")
            print("R4_T5_PINNED_TC300_19_SCENARIOS_3_MUTANTS_PASS; RF=NOT_MEASURED")


if __name__ == "__main__":
    unittest.main()
