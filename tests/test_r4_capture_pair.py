import binascii
import importlib.util
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/qualification/capture_pair.py"
SPEC = importlib.util.spec_from_file_location("capture_pair", PATH)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)
PIN = "a" * 64


class ReadAdapter:
    def __init__(self, *, wrong_identity=False, short=False, bad_crc=False):
        self.raw = bytes(range(256)) * (capture.FLASH_BYTES // 256)
        self.calls = []
        self.wrong_identity, self.short, self.bad_crc = wrong_identity, short, bad_crc

    async def identity_sha256(self):
        self.calls.append("identity")
        return "b" * 64 if self.wrong_identity else PIN

    async def flash_size(self):
        return len(self.raw)

    async def read_flash(self, address, length):
        self.calls.append((address, length))
        data = self.raw[address:address + length]
        return data[:-1] if self.short else data

    async def crc32(self, address, length):
        value = binascii.crc32(self.raw[address:address + length]) & 0xFFFFFFFF
        return value ^ 1 if self.bad_crc else value


class CapturePairTests(unittest.IsolatedAsyncioTestCase):
    async def test_two_complete_bounded_passes_and_no_automatic_stock_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "new-private"
            adapter = ReadAdapter()
            report = await capture.capture_pair(adapter, output, expected_identity_sha256=PIN)
            self.assertEqual((output / "current-pass1.bin").read_bytes(), adapter.raw)
            self.assertEqual((output / "current-pass2.bin").read_bytes(), adapter.raw)
            self.assertEqual(report["pass1_sha256"], report["pass2_sha256"])
            self.assertFalse(report["return_to_stock_verified"])
            reads = [item for item in adapter.calls if isinstance(item, tuple)]
            self.assertTrue(all(length <= 240 and address % 4 == length % 4 == 0
                                for address, length in reads))

    async def test_identity_mismatch_prevents_capture_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "new-private"
            with self.assertRaisesRegex(ValueError, "IDENTITY_MISMATCH"):
                await capture.capture_pair(ReadAdapter(wrong_identity=True), output, expected_identity_sha256=PIN)
            self.assertFalse(output.exists())

    async def test_short_read_or_crc_failure_never_emits_success_receipt(self):
        for adapter in (ReadAdapter(short=True), ReadAdapter(bad_crc=True)):
            with tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / "new-private"
                with self.assertRaises(ValueError):
                    await capture.capture_pair(adapter, output, expected_identity_sha256=PIN)
                self.assertFalse((output / "capture-receipt.json").exists())

    async def test_private_output_and_finite_timeout_guards(self):
        for output, timeout in ((capture.REPO / "private", 600), (Path("unused"), float("nan"))):
            with self.assertRaises(ValueError):
                await capture.capture_pair(ReadAdapter(), output, expected_identity_sha256=PIN,
                                           total_timeout_seconds=timeout)
