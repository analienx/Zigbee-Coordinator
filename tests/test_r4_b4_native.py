"""B4 source-overlay mutation tests; all inputs synthetic/ephemeral.

A positive mocked linker signal in this file is never a native proof.
Only separate CI's actual tiarmnm/ELF/CCFG audit may qualify native code.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware" / "slzb-06p7u" / "r4" / "b4"))
from b4_native_patch import (
    TI_SHA, MT_SYS, NPI_TASK, NPI_CLIENT, NPI_UART, B4_FUNCTION,
    apply as patch_native, build_patches,
)
from b4_native_link_audit import verify as verify_link

SYS = """#include "mt.h"
uint8_t MT_SysCommandProcessing(uint8_t *pBuf)
{
  switch (pBuf[MT_RPC_POS_CMD1]) {
    case MT_SYS_VERSION:
      MT_SysVersion();
      break;
    default:
      break;
  }
  return 0;
}
"""
TASK = """void NPITask_sendToHost(uint8_t *pMsg)
{
key = OsalPort_enterCS();
#if defined(NPI_SREQRSP)
Queue_enqueue(npiSyncTxQueue, &recPtr->_elem);
#endif
Queue_enqueue(npiTxQueue, &recPtr->_elem);
OsalPort_leaveCS(key);
}
static void NPITask_processStackMsg(uint8_t *pMsg)
{
key = OsalPort_enterCS();
#if defined(NPI_SREQRSP)
Queue_enqueue(npiSyncTxQueue, &recPtr->_elem);
#endif
Queue_enqueue(npiTxQueue, &recPtr->_elem);
OsalPort_leaveCS(key);
}
static void NPITask_ProcessTXQ(void)
{
key = OsalPort_enterCS();
recPtr = Queue_dequeue(npiTxQueue);
if (recPtr != NULL) {}
OsalPort_leaveCS(key);
}
static void NPITask_ProcessSyncTXQ(void)
{
key = OsalPort_enterCS();
recPtr = Queue_dequeue(npiSyncTxQueue);
if (recPtr != NULL) {}
OsalPort_leaveCS(key);
}
"""
CLIENT = "void MT_BuildAndSendZToolResponse() { OsalPort_msgAllocate(1); }"
UART = """void NPITLUART_initializeTransport(uint8_t *tRxBuf, uint8_t *tTxBuf, npiCB_t npiCBack)
{
UART2_Params params;
params.writeCallback = NPITLUART_writeCallBack;
uartHandle = UART2_open(CONFIG_DISPLAY_UART, &params);
}
"""
UART2H = "UART2_EVENT_TX_FINISHED\nUART2_EventCallback eventCallback;\nuint32_t eventMask;\n"
MTC = "#if !defined(NPI)\nvoid MT_BuildAndSendZToolResponse() {}\n#endif\n"

class NativeOverlayProofs(unittest.TestCase):
    def fixture(self, root):
        items = {MT_SYS: SYS, NPI_TASK: TASK, NPI_CLIENT: CLIENT, NPI_UART: UART}
        for name, source in items.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(source)
        def git(_root, *arguments):
            if arguments == ("rev-parse", "HEAD"):
                return (TI_SHA + "\n").encode()
            if arguments[0] == "show":
                name = arguments[1].split(":", 1)[1]
                if name == "source/ti/zstack/mt/mt.c":
                    return MTC.encode()
                if name == "source/ti/drivers/UART2.h":
                    return UART2H.encode()
                return items[name].encode()
            raise RuntimeError("unexpected git command")
        return items, git

    def test_disposable_pinned_source_generates_b4_only(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            root = Path(d)
            files, git = self.fixture(root)
            with patch("b4_native_patch._git", side_effect=git):
                out = patch_native(root)
                self.assertEqual(out["stage"], "PATCHED_DISPOSABLE_SDK_NOT_LINKED")
                self.assertEqual(out["valid_counter_indices"], [0, 1, 2, 3, 4, 5])
                self.assertEqual(out["radio_boot_identity"], "UNKNOWN")
                self.assertEqual(len(out["written"]), 3)
                self.assertIn("case 0xF0", (root / MT_SYS).read_text())
                self.assertEqual((root / NPI_TASK).read_text().count("++B4_NpiSrspEnqueued;"), 2)
                self.assertEqual((root / NPI_TASK).read_text().count("++B4_NpiSrspDepth;"), 2)
                self.assertEqual((root / NPI_TASK).read_text().count("++B4_NpiAsyncDepth;"), 2)
                self.assertEqual((root / NPI_TASK).read_text().count("--B4_NpiSrspDepth;"), 1)
                self.assertEqual((root / NPI_TASK).read_text().count("--B4_NpiAsyncDepth;"), 1)
                self.assertIn("params.eventMask = UART2_EVENT_TX_FINISHED;", (root / NPI_UART).read_text())
                self.assertIn("params.eventCallback = B4_NpiUartTxFinishedCallback;", (root / NPI_UART).read_text())
                self.assertEqual((root / NPI_UART).read_text().count("++B4_NpiUartTxFinishedEvents;"), 1)
                self.assertEqual((root / NPI_CLIENT).read_text(), CLIENT)
                # A repeat patch cannot silently duplicate the new handler.
                with self.assertRaisesRegex(ValueError, "modified before"):
                    patch_native(root)

    def test_source_mutants_fail_before_any_write(self):
        mutations = [
            (MT_SYS, SYS.replace("case MT_SYS_VERSION", "case MT_SYS_PING")),
            (MT_SYS, SYS.replace("    case MT_SYS_VERSION:", "    case 0xF0:\n    case MT_SYS_VERSION:")),
            (NPI_TASK, TASK.replace("Queue_enqueue", "Queue_push")),
            (NPI_CLIENT, CLIENT.replace("OsalPort_msgAllocate", "malloc")),
            (NPI_UART, UART.replace("params.writeCallback = NPITLUART_writeCallBack;", "params.writeCallback = another;")),
        ]
        for name, mutation in mutations:
            with self.subTest(path=name), tempfile.TemporaryDirectory(dir="/tmp") as d:
                root = Path(d)
                files, git = self.fixture(root)
                target = root / name
                target.write_text(mutation)
                before = {p: (root / p).read_bytes() for p in files}
                with patch("b4_native_patch._git", side_effect=git), self.assertRaises(ValueError):
                    patch_native(root)
                self.assertEqual(before, {p: (root / p).read_bytes() for p in files})

    def test_wrong_sdk_sha_is_never_patched(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            root = Path(d)
            self.fixture(root)
            with patch("b4_native_patch._git", return_value=b"wrong-sha\n"), self.assertRaisesRegex(ValueError, "pinned TI"):
                build_patches(root)

    def test_native_counter_is_preexisting_critical_section_only(self):
        start = B4_FUNCTION.index("key = OsalPort_enterCS()")
        end = B4_FUNCTION.index("OsalPort_leaveCS(key)", start)
        region = B4_FUNCTION[start:end]
        self.assertIn("B4_NpiSrspEnqueued", region)
        self.assertNotIn("MT_BuildAndSendZToolResponse", region)
        for secret in ("ZCD_NV", "OsalPort_msgSend", "ZMac", "AF_DataRequest", "RF_TX"):
            self.assertNotIn(secret, B4_FUNCTION)

class BinaryAuditOracleMutants(unittest.TestCase):
    def configure(self, d):
        root = Path(d)
        elf = root / "znp.out"
        # Synthetic ELF magic is not legitimate object code. Here we exercise
        # only negative SHA/symbol enforcement with MOCKED tiarmnm output.
        elf.write_bytes(b"\x7fELF" + bytes(2000))
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({
            "schema": "r4-b0-artifact-manifest-v1",
            "files": {"elf": {"file": elf.name, "sha256": hashlib.sha256(elf.read_bytes()).hexdigest()}},
        }))
        patchreceipt = root / "overlay.json"
        patchreceipt.write_text(json.dumps({
            "stage": "PATCHED_DISPOSABLE_SDK_NOT_LINKED", "payload_bytes": 132,
            "valid_counter_indices": [0, 1, 2, 3, 4], "radio_boot_identity": "UNKNOWN",
            "written": {"mt.c": {}, "npi.c": {}, "uart.c": {}},
        }))
        nm = root / "tiarmnm"
        nm.touch()
        return elf, nm, manifest, patchreceipt

    def test_reject_elf_not_bound_to_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            elf, nm, manifest, receipt = self.configure(d)
            elf.write_bytes(elf.read_bytes() + b"t")
            with self.assertRaisesRegex(ValueError, "SHA"):
                verify_link(elf, nm, manifest, receipt)

    def test_reject_linker_output_missing_real_b4_symbols(self):
        with tempfile.TemporaryDirectory() as d:
            elf, nm, manifest, receipt = self.configure(d)
            from subprocess import CompletedProcess
            with patch("b4_native_link_audit.subprocess.run",
                       return_value=CompletedProcess([], 0, stdout="0010 T MT_SysCommandProcessing\n")):
                with self.assertRaisesRegex(ValueError, "not in actual ELF"):
                    verify_link(elf, nm, manifest, receipt)

    def test_reject_counter_as_text_symbol(self):
        with tempfile.TemporaryDirectory() as d:
            elf, nm, manifest, receipt = self.configure(d)
            from subprocess import CompletedProcess
            listing = ("0010 T MT_SysCommandProcessing\n"
                       "0020 T B4_SysReadOnlyDiagnostics\n"
                       "0030 B B4_NpiSrspDepth\n"
                       "0040 B B4_NpiSrspHighWater\n"
                       "0050 B B4_NpiAsyncDepth\n"
                       "0060 B B4_NpiAsyncHighWater\n"
                       "0070 T B4_NpiSrspEnqueued\n"
                       "0080 B B4_NpiUartTxFinishedEvents\n")
            with patch("b4_native_link_audit.subprocess.run",
                       return_value=CompletedProcess([], 0, stdout=listing)):
                with self.assertRaisesRegex(ValueError, "not native RAM"):
                    verify_link(elf, nm, manifest, receipt)

    def test_reject_fake_link_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            elf, nm, manifest, receipt = self.configure(d)
            obj = json.loads(receipt.read_text())
            obj["radio_boot_identity"] = "PROVEN"
            receipt.write_text(json.dumps(obj))
            with self.assertRaisesRegex(ValueError, "not proven"):
                verify_link(elf, nm, manifest, receipt)

if __name__ == "__main__":
    unittest.main()
