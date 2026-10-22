"""Qualification safety gates; real-source hosted tests use an optional local TI cache.

CI's native builder always fetches/validates the exact TI source and runs the
same harness. These unit tests never download code or open a radio transport.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "firmware/slzb-06p7u/r4/qualification"
sys.path.insert(0, str(QUALIFICATION))
import transport_profile as profile
import native_profile_audit as native
import make_transport_harness as harness


def symbol_set(source_sha="a" * 40):
    values = {name: {"address": index * 16, "size": 4, "bytes": b"\0" * 4,
                     "function": True} for index, name in enumerate(native.REQUIRED_FUNCTIONS)}
    marker = profile.identity(source_sha)
    values["r4q_build_identity"] = {"address": 0x1000, "size": len(marker),
                                    "bytes": marker, "function": False}
    return values


def symbol_fixture(entries):
    """Parser-only ELF fixture; has no load headers/native-image proof."""
    names = bytearray(b"\0")
    symbols = bytearray(16)
    for name, address, section_index in entries:
        offset = len(names); names.extend(name.encode() + b"\0")
        symbols.extend(struct.pack("<IIIBBH", offset, address, 4, 2 if section_index == 1 else 17,
                                   0, section_index))
    head = bytearray(52)
    head[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HH", head, 16, 2, 40)
    struct.pack_into("<I", head, 32, 52)
    struct.pack_into("<HH", head, 46, 40, 5)
    content_start = 52 + 5 * 40
    text = b"\0" * 32
    sections = [tuple([0] * 10),
                (0, 1, 6, 0x100, content_start, len(text), 0, 0, 2, 0),
                (0, 3, 0, 0, content_start + len(text), len(names), 0, 0, 1, 0),
                (0, 2, 0, 0, content_start + len(text) + len(names), len(symbols), 2, 0, 4, 16),
                (0, 1, 0, 0x90000000, content_start, 4, 0, 0, 4, 0)]
    return bytes(head) + b"".join(struct.pack("<10I", *section) for section in sections) + \
        text + names + symbols


class SourceGates(unittest.TestCase):
    def test_source_sha_must_be_full_lowercase_commit(self):
        for bad in ("", "a" * 39, "a" * 41, "A" * 40, "g" * 40, "a" * 39 + "/"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                profile.identity(bad)
        self.assertEqual(profile.identity("a" * 40),
                         (profile.PROFILE_ID + ":" + "a" * 40 + "\0").encode())

    def test_no_unpinned_source_is_accepted(self):
        for bad in ({}, {path: "// plausible but unpinned" for path in profile.PINS}):
            with self.assertRaisesRegex(ValueError, "PINNED_DONOR_MISMATCH"):
                profile.transform(bad, "a" * 40)

    def test_duplicate_or_missing_function_fails_before_transform(self):
        for text in ("", "void f()\n{}\nvoid f()\n{}"):
            with self.assertRaises(RuntimeError):
                profile.replace_function(text, "void f()", "void f()\n{ return; }")

    def test_output_receipt_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "existing.json"
            path.write_text("sentinel")
            with self.assertRaisesRegex(ValueError, "RECEIPT_EXISTS"):
                profile.apply(Path(temp) / "absent-sdk", "a" * 40, path)
            self.assertEqual(path.read_text(), "sentinel")

    def test_isolated_npi_wake_is_real_and_native_link_required(self):
        code = (QUALIFICATION / 'r4_transport_only_support.c').read_text()
        mapping = (QUALIFICATION / 'transport_profile.py').read_text()
        self.assertIn('"b1_evidence_note_npi_wake": "r4q_note_npi_wake"', mapping)
        self.assertIn('npi.count("r4q_note_npi_wake();") != 1', mapping)
        self.assertIn('void r4q_note_npi_wake(void)', code)
        self.assertIn('++r4q_npi_wakes', code)
        self.assertIn('Task_getPri(Task_self())', code)
        self.assertIn('#ifndef R4_TRANSPORT_HOST', code)
        self.assertIn('r4q_note_npi_wake', native.REQUIRED_FUNCTIONS)
        self.assertNotIn('b1_management.c', code)

    def test_next_trial_boot_beacon_is_diagnostic_only(self):
        body = profile.NPI_TASK_BODY
        self.assertEqual(body.count("NPITask_inititializeTask();"), 1)
        self.assertEqual(body.count("NPITask_process();"), 1)
        self.assertEqual(body.count("Task_sleep("), 1)
        self.assertEqual(body.count("MT_BuildAndSendZToolResponse("), 1)
        self.assertIn("0x41u, 0xF7u, 1u, &phase", body)
        self.assertIn("if (!r4q_npi_initialized()) return;", body)
        for forbidden in ("UART2_open(", "stackTask_init(", "NVOCMP_", "RF_"):
            self.assertNotIn(forbidden, body)


class NativeGates(unittest.TestCase):
    def test_symbols_alone_are_only_an_internal_check(self):
        result = native.check_transport_symbols(symbol_set(), "a" * 40)
        self.assertEqual(set(result), native.REQUIRED_FUNCTIONS)
        self.assertNotIn("native_compilation_verified", result)

    def test_all_mutation_and_stack_graphs_are_denied(self):
        for name in sorted(native.FORBIDDEN_EXACT | {
            "NVOCMP_writeItem", "osal_nv_init", "stackTaskFxn", "ZMacStartReq",
            "MAC_MlmeSetReq", "MT_SysReset", "MT_SysOsalNVWrite", "MT_SysSetExtAddr",
        }):
            values = symbol_set()
            values[name] = {"address": 0x2000, "size": 4, "function": True, "bytes": b"x" * 4}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "MUTATION_GRAPH_PRESENT"):
                native.check_transport_symbols(values, "a" * 40)

    def test_uart_pin_configuration_dependency_may_link_gpio_write(self):
        # Exact TI GPIO_setConfigAndMux uses GPIO_write for output configurations;
        # UART2Support_pinMux needs that generic helper for the validated UART pins.
        values = symbol_set()
        values["GPIO_write"] = {"address": 0x2000, "size": 4, "function": True, "bytes": b"x" * 4}
        self.assertEqual(set(native.check_transport_symbols(values, "a" * 40)), native.REQUIRED_FUNCTIONS)

    def test_each_required_function_and_bound_marker_is_required(self):
        for name in native.REQUIRED_FUNCTIONS:
            values = symbol_set(); del values[name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "REQUIRED_FUNCTIONS_MISSING"):
                native.check_transport_symbols(values, "a" * 40)
        for marker in (b"plausible identity", profile.identity("b" * 40), profile.identity("a" * 40)[:-1]):
            values = symbol_set(); values["r4q_build_identity"]["bytes"] = marker
            with self.assertRaisesRegex(ValueError, "IDENTITY_MISMATCH"):
                native.check_transport_symbols(values, "a" * 40)

    def test_missing_artifacts_cannot_claim_compilation(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "NATIVE_IMAGE_BLOCKED"):
                native.audit_image_binding(Path(temp))

    def test_fake_or_wrong_machine_elf_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fake.out"
            for raw in (b"ELF-like marker", b"\x7fELF\x01\x01\x01" + b"\0" * 64):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    native.elf_symbols(path)

    def test_real_ti_local_name_duplicates_and_nonallocated_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "parser-only.out"
            path.write_bytes(symbol_fixture([("OUTLINED_FUNCTION_0", 0x101, 1),
                                             ("OUTLINED_FUNCTION_0", 0x109, 1),
                                             ("TimestampP_nativeFormat64_copy", 0x90000000, 4)]))
            result = native.elf_symbols(path)
            self.assertEqual(set(result), {"OUTLINED_FUNCTION_0", "OUTLINED_FUNCTION_0@108"})
            path.write_bytes(symbol_fixture([("main", 0x101, 1), ("main", 0x109, 1)]))
            with self.assertRaisesRegex(ValueError, "AMBIGUOUS_SYMBOL main"):
                native.elf_symbols(path)

    def test_executable_symbol_may_not_escape_its_section(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "parser-only.out"
            path.write_bytes(symbol_fixture([("main", 0x11F, 1)]))
            with self.assertRaisesRegex(ValueError, "SYMBOL_OUTSIDE_SECTION"):
                native.elf_symbols(path)


class RealPinnedDonor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.donor = Path(os.environ.get("R4_TI833_SOURCE_DIR", ""))
        if not (cls.donor / profile.MAIN).is_file():
            cls.donor = Path(tempfile.gettempdir()) / "r4-transport-ti833-3615ad5d"
        if not (cls.donor / profile.MAIN).is_file():
            raise unittest.SkipTest("Exact TI source unavailable locally; native CI runs mandatory real-source harness")
        cls.originals = profile.read_donor(cls.donor)

    def test_real_source_never_enters_nv_or_stack_and_keeps_one_owner(self):
        changed = profile.transform(self.originals, "a" * 40)
        boot = profile.extract_function(changed[profile.MAIN],
                                        "__attribute__((noinline)) int r4q_transport_start(void)")
        self.assertNotRegex(boot, r"\b(?:NVOCMP_\w+|initNV|stackTask_init|macTaskInit|RF_\w+)\s*\(")
        self.assertEqual(boot.count("NPITask_createTask();"), 1)
        self.assertNotIn("MTTask_getServiceTaskId", profile.extract_function(
            changed[profile.NPI], "Void NPITask_Fxn(UArg a0, UArg a1)"))
        npi_task = profile.extract_function(changed[profile.NPI], "void NPITask_task(void)")
        self.assertEqual(npi_task.count("MT_BuildAndSendZToolResponse("), 1)
        self.assertIn("Clock_tickPeriod", npi_task)
        dispatch = profile.extract_function(changed[profile.SYS], "uint8_t MT_SysCommandProcessing(uint8_t *pBuf)")
        self.assertNotIn("MT_SYS_OSAL", dispatch)
        self.assertEqual(dispatch.count("case MT_SYS_"), 2)
        self.assertNotIn("b1_management", "".join(changed.values()))
        self.assertIn("r4q_note_npi_wake();", changed[profile.NPI])
        self.assertNotIn("b1_evidence_note_npi_wake", changed[profile.NPI])
        self.assertNotIn("b1_startup_", changed[profile.UART])
        self.assertNotIn("params.eventCallback = b1_startup_uart_event", changed[profile.UART])

    def test_every_real_preimage_is_individually_pinned(self):
        for relative in profile.PINS:
            changed = dict(self.originals); changed[relative] += "\n// unexpected drift\n"
            with self.subTest(path=relative), self.assertRaisesRegex(ValueError, "PINNED_DONOR_MISMATCH"):
                profile.transform(changed, "a" * 40)

    def test_failed_real_preflight_leaves_all_inputs_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            sdk = Path(temp)
            for relative, text in self.originals.items():
                path = sdk / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
            with (sdk / profile.UART).open("a") as stream:
                stream.write("\n// source drift\n")
            before = {relative: (sdk / relative).read_bytes() for relative in profile.PINS}
            receipt = sdk / "receipt.json"
            with self.assertRaisesRegex(ValueError, "PINNED_DONOR_MISMATCH"):
                profile.apply(sdk, "a" * 40, receipt)
            self.assertFalse(receipt.exists())
            self.assertEqual(before, {relative: (sdk / relative).read_bytes() for relative in profile.PINS})

    def test_real_extracted_bodies_under_host_boundaries(self):
        compiler = shutil.which("cc") or shutil.which("gcc")
        fallback = Path(r"C:\Workspace\runtime\proxmark3\ProxSpace\msys2\mingw64\bin\gcc.exe")
        if not compiler and fallback.is_file():
            compiler = str(fallback)
        if not compiler:
            self.skipTest("Host C compiler absent; mandatory native CI performs hosted qualification")
        with tempfile.TemporaryDirectory() as temp:
            sdk = Path(temp)
            for relative, text in self.originals.items():
                path = sdk / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
            receipt = sdk / "receipt.json"
            report = profile.apply(sdk, "a" * 40, receipt)
            self.assertFalse(report["native_compilation_verified"])
            self.assertFalse(report["flash_authorized"])
            output = sdk / "host.c"; output.write_text(harness.make(sdk, receipt))
            executable = sdk / ("host.exe" if os.name == "nt" else "host")
            env = dict(os.environ, PATH=str(Path(compiler).parent) + os.pathsep + os.environ.get("PATH", ""))
            result = subprocess.run([compiler, "-std=c11", "-O1", "-DR4_TRANSPORT_HOST",
                                     "-Wno-incompatible-pointer-types", "-I", str(QUALIFICATION),
                                     str(output), "-o", str(executable)], capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for scenario in harness.SCENARIOS:
                with self.subTest(scenario=scenario):
                    result = subprocess.run([str(executable), scenario], capture_output=True, text=True, env=env)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("HOSTED_SYNTHETIC_PASS", result.stdout)
            # Source drift after extraction must invalidate future receipts/harnesses.
            with (sdk / profile.MT).open("a") as stream:
                stream.write("\n// changed after source admission\n")
            with self.assertRaisesRegex(ValueError, "SOURCE_DRIFT"):
                harness.make(sdk, receipt)


if __name__ == "__main__":
    unittest.main()
