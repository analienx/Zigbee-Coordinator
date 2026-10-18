"""Targeted offline checks; hosted tests do not claim UART electrical delivery."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

QUALIFICATION = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/qualification"
sys.path.insert(0, str(QUALIFICATION))
import uart_smoke_profile as smoke
import uart_smoke_native_audit as native


class UARTSmokeSource(unittest.TestCase):
    def test_unique_marker_has_correct_mt_checksum(self):
        self.assertEqual(smoke.MARKER, bytes.fromhex("fe0141f7a81f"))
        self.assertEqual(smoke.PRE_MARKER, bytes.fromhex("fe0141f7a91e"))
        self.assertEqual(smoke.TASK_MARKER, bytes.fromhex("fe0141f7aa1d"))
        self.assertEqual(smoke.CONSTRUCT_MARKER, bytes.fromhex("fe0141f7ab1c"))
        self.assertEqual(len(smoke.MARKER), 6)
        self.assertEqual(smoke.MARKER[0], 0xFE)
        self.assertEqual(smoke.MARKER[1], len(smoke.MARKER) - 5)
        self.assertEqual(smoke.MARKER[-1],
                         smoke.MARKER[1] ^ smoke.MARKER[2] ^ smoke.MARKER[3] ^ smoke.MARKER[4])

    def test_bounded_sys_responses_are_well_formed_and_diagnostic(self):
        for frame, cmd in ((smoke.SYS_PING_RESPONSE, 1),
                           (smoke.SYS_VERSION_RESPONSE, 2)):
            with self.subTest(cmd=cmd):
                self.assertEqual(frame[0], 0xFE)
                self.assertEqual(frame[1], len(frame) - 5)
                self.assertEqual(frame[2:4], bytes((0x61, cmd)))
                self.assertEqual(frame[-1], __import__("functools").reduce(
                    lambda a, b: a ^ b, frame[1:-1], 0))
        self.assertEqual(smoke.SYS_PING_RESPONSE[4:6], b"\x01\x00")
        self.assertEqual(smoke.SYS_VERSION_RESPONSE[4:9], b"\x02\x00\x00\x00\x00")
        self.assertEqual(smoke.SYS_VERSION_RESPONSE[9:13], b"DIA1")

    def test_actual_c_uart_parser_rejects_invalid_frames_and_answers_two_sys_commands(self):
        """Exercise the real C byte-feed routine with a deterministic fake UART."""
        first = smoke.ENTRY.index("static const uint8_t r4q_uart_sys_ping_response[]")
        last = smoke.ENTRY.index("__attribute__((noinline)) static void r4q_uart_smoke_emit(")
        actual_parser = smoke.ENTRY[first:last]
        source = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
typedef void *UART2_Handle;
#define UART2_STATUS_SUCCESS 0
volatile uint32_t r4q_uart_smoke_stage;
static uint8_t sent[2][16];
static size_t sizes[2];
static int calls;
static int_fast16_t UART2_write(UART2_Handle handle, const void *data,
                                 size_t length, size_t *written)
{
    (void)handle;
    assert(calls < 2 && length <= 16u);
    memcpy(sent[calls], data, length);
    sizes[calls++] = length;
    *written = length;
    return UART2_STATUS_SUCCESS;
}
''' + actual_parser + r'''
static void feed(r4q_uart_frame_parser *parser, const uint8_t *frame, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        r4q_uart_smoke_accept_byte(NULL, parser, frame[i]);
}
int main(void)
{
    r4q_uart_frame_parser parser = {0};
    const uint8_t ping[] = {0xFE,0x00,0x21,0x01,0x20};
    const uint8_t version[] = {0xFE,0x00,0x21,0x02,0x23};
    const uint8_t bad[] = {0xFE,0x00,0x21,0x01,0xFF};
    const uint8_t nonzero[] = {0xFE,0x01,0x21,0x01,0xAB,0x8A};
    const uint8_t unknown[] = {0xFE,0x00,0x21,0x03,0x22};
    feed(&parser, bad, sizeof(bad));
    feed(&parser, nonzero, sizeof(nonzero));
    feed(&parser, unknown, sizeof(unknown));
    assert(calls == 0);
    feed(&parser, ping, 2); /* fragmented UART stream */
    feed(&parser, ping + 2, sizeof(ping) - 2);
    assert(calls == 1 && sizes[0] == sizeof(r4q_uart_sys_ping_response));
    assert(!memcmp(sent[0], r4q_uart_sys_ping_response, sizes[0]));
    feed(&parser, version, sizeof(version));
    assert(calls == 2 && sizes[1] == sizeof(r4q_uart_sys_version_response));
    assert(!memcmp(sent[1], r4q_uart_sys_version_response, sizes[1]));
    assert(r4q_uart_smoke_stage == 8u);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            src, exe = path / "npi_parser.c", path / "npi_parser"
            src.write_text(source)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=undefined", "-fno-sanitize-recover=all",
                            src, "-o", exe], check=True, capture_output=True)
            execution = subprocess.run([exe], capture_output=True)
            self.assertEqual(execution.returncode, 0, execution.stderr.decode(errors="replace"))

    def test_image_is_direct_uart_without_npi_nv_rf_stack(self):
        code = smoke.ENTRY
        for forbidden in ("NPITask", "NPITL", "NVOCMP_", "initNV(",
                          "stackTask", "RF_open", "NVS_open", "MT_Build"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, code)
        self.assertIn("UART2_open(CONFIG_DISPLAY_UART", code)
        self.assertIn("UART2_write(uart, r4q_uart_smoke_frame", code)
        self.assertIn("UART2_readTimeout(uart, &input, 1u, &received,", code)
        self.assertIn("parser->cmd0 == 0x21u", code)
        self.assertIn("value == parser->fcs && parser->length == 0u", code)
        self.assertIn("Board_initGeneral();", code)
        self.assertIn("r4q_uart_smoke_emit(r4q_uart_smoke_pre_frame, 16u);", code)
        self.assertIn("r4q_uart_smoke_emit(r4q_uart_smoke_task_frame, 16u);", code)
        self.assertIn("r4q_uart_smoke_emit(r4q_uart_smoke_construct_frame, 12u);", code)
        self.assertIn("Power_releaseDependency(PowerCC26XX_PERIPH_UART0)", code)
        self.assertIn("BIOS_start();", code)
        self.assertEqual(code.count("UART2_open("), 1)
        self.assertEqual(code.count("UART2_write("), 2)
        self.assertEqual(code.count("UART2_readTimeout("), 1)

    def test_sha_and_exact_donor_preflight(self):
        for bad in ("", "F" * 40, "g" * 40, "a" * 39):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                smoke.identity(bad)
        candidate = '#include "nvocmp.h"\nint main()\n{ return 1; }\n'
        with self.assertRaisesRegex(ValueError, "PINNED_DONOR_MISMATCH"):
            smoke.transform(candidate, "a" * 40)
        with patch.object(smoke.transport_profile.patch_management, "blob",
                          return_value=smoke.DONOR_BLOB):
            changed = smoke.transform(candidate, "a" * 40)
        self.assertIn('r4q_uart_smoke_identity', changed)
        self.assertIn('r4q_uart_smoke_start(void)', changed)
        self.assertNotIn("int main()\n{ return 1; }", changed)

    def test_preexisting_receipt_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp) / "old.json"
            receipt.write_text("keep")
            with self.assertRaisesRegex(ValueError, "RECEIPT_EXISTS"):
                smoke.apply(Path(temp), "a" * 40, receipt)
            self.assertEqual(receipt.read_text(), "keep")


class UARTSmokeNative(unittest.TestCase):
    def symbol_set(self):
        values = {name: {"address": index * 16, "size": 4, "bytes": b"\0" * 4,
                         "function": True} for index, name in enumerate(sorted(native.REQUIRED))}
        values["r4q_uart_smoke_identity"] = {"address": 0x1234,
                                              "size": len(smoke.identity("a" * 40)),
                                              "bytes": smoke.identity("a" * 40), "function": False}
        for name, marker in (("r4q_uart_smoke_frame", smoke.MARKER),
                             ("r4q_uart_smoke_pre_frame", smoke.PRE_MARKER),
                             ("r4q_uart_smoke_task_frame", smoke.TASK_MARKER),
                             ("r4q_uart_smoke_construct_frame", smoke.CONSTRUCT_MARKER),
                             ("r4q_uart_sys_ping_response", smoke.SYS_PING_RESPONSE),
                             ("r4q_uart_sys_version_response", smoke.SYS_VERSION_RESPONSE)):
            values[name] = {"address": 0x1240, "size": len(marker),
                            "bytes": marker, "function": False}
        return values

    def test_only_minimal_linked_function_graph(self):
        self.assertEqual(set(native.linked_symbols(self.symbol_set(), "a" * 40)), native.REQUIRED)
        for name in ("NVOCMP_loadApiPtrs", "NPITask_Fxn", "MT_SysVersion",
                     "stackTask_init", "RF_open", "NVS_open"):
            values = self.symbol_set()
            values[name] = {"address": 0x100, "size": 4,
                            "bytes": b"1234", "function": True}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "GRAPH_PRESENT"):
                native.linked_symbols(values, "a" * 40)

    def test_missing_or_altered_marker_is_rejected(self):
        for name in native.REQUIRED:
            values = self.symbol_set()
            del values[name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "REQUIRED_FUNCTIONS"):
                native.linked_symbols(values, "a" * 40)
        values = self.symbol_set()
        values["r4q_uart_smoke_frame"]["bytes"] = b"bad"
        with self.assertRaisesRegex(ValueError, "LINKED_MARKER"):
            native.linked_symbols(values, "a" * 40)


if __name__ == "__main__":
    unittest.main()
