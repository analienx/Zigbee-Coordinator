"""Static CI dependency contracts: avoid stale native evidence on PR inputs.

These tests run in the path-filtered jobs themselves, as well as the regular
Python test suite. No GitHub API, external SDK, or device is required.
"""
from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
import re
import unittest


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def paths(workflow: str) -> list[str]:
    source = (WORKFLOWS / workflow).read_text()
    return re.findall(r"^      - '([^']+)'$", source, flags=re.MULTILINE)


def jobs(workflow: str) -> dict[str, str]:
    source = (WORKFLOWS / workflow).read_text()
    matches = list(re.finditer(r"^  ([a-z0-9-]+):\n", source, re.MULTILINE))
    return {match.group(1): source[match.end():
                                  matches[i + 1].start() if i + 1 < len(matches)
                                  else len(source)]
            for i, match in enumerate(matches)}


class NativeWorkflowDependencyTests(unittest.TestCase):
    def test_any_build_input_change_retriggers_affected_native_job(self):
        dependencies = {
            "test-r4-npi-native.yml": (
                "firmware/slzb-06p7u/r4/qualification/transport_profile.py",
                "firmware/slzb-06p7u/r4/qualification/board_profile.py",
                "firmware/slzb-06p7u/r4/qualification/make_transport_harness.py",
                "firmware/slzb-06p7u/r4/b0/tools/b0_sdk_build_scope.py",
                "tests/test_r4_workflow_gate_deps.py",
            ),
            "test-r4-stock-nv4-native.yml": (
                "firmware/slzb-06p7u/r4/qualification/nv4_source_overlay.py",
                "firmware/slzb-06p7u/r4/qualification/nv4_b1_bridge.py",
                "firmware/slzb-06p7u/r4/qualification/board_profile.py",
                "firmware/slzb-06p7u/r4/b0/tools/b0_sdk_build_scope.py",
                "firmware/slzb-06p7u/r4/b1/tools/apply_b1.py",
                "tests/test_r4_workflow_gate_deps.py",
            ),
        }
        for workflow, inputs in dependencies.items():
            patterns = paths(workflow)
            self.assertTrue(patterns, workflow)
            for input_path in inputs:
                with self.subTest(workflow=workflow, input=input_path):
                    self.assertTrue(any(fnmatchcase(input_path, p) for p in patterns),
                                    f"{input_path} does not trigger {workflow}")

    def test_full_native_requires_all_source_and_donor_gates(self):
        for workflow in (
            "test-r4-b0-native.yml",
            "test-r4-b1-direct-native.yml",
            "test-r4-b1b3-fusion-native.yml",
            "test-r4-b0b4-composite-native.yml",
            "test-r4-final-composite-native.yml",
        ):
            native = jobs(workflow)["r4-b0-native-build"]
            match = re.search(r"^    needs: \[([^]]+)\]$", native, re.MULTILINE)
            self.assertIsNotNone(match, workflow)
            needs = set(match.group(1).replace(" ", "").split(","))
            with self.subTest(workflow=workflow):
                self.assertIn("r4-b0-overlay", needs)
                self.assertIn("r4-b0-upstream-inventory", needs)
                if workflow != "test-r4-b0-native.yml":
                    self.assertIn("r4-b1-admission-source", needs)
                self.assertIn("r4-b0-overlay", jobs(workflow))

    def test_nv4_source_provenance_is_exact_head_and_action_pinned(self):
        source = (WORKFLOWS / "test-r4-stock-nv4-source.yml").read_text()
        self.assertIn("actions/checkout@11d5960a326750d5838078e36cf38b85af677262", source)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", source)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SOURCE_SHA"', source)
        self.assertIn("tests/test_r4_workflow_gate_deps.py", paths(
            "test-r4-stock-nv4-source.yml"))


if __name__ == "__main__":
    unittest.main()
