"""Hostile fake-ROM tests. No network, physical flash, reset, or key fixtures."""
import asyncio
import unittest

from tests.test_r4_current_app_package import m, synthetic_package
import r4_app_sector_transaction as tx


class FakeROM:
    def __init__(self, package):
        self.memory = bytearray(package.snapshot)
        # Capture operator hashes the live management identity; the private
        # profile's board-identity digest is deliberately a DIFFERENT domain.
        self.identity = "c" * 64
        self.erases, self.downloads, self.packets = [], [], []
        self.position = None
        self.packet_failure = False
        self.status_failure = False
        self.crc_disagreement = False
        self.corrupt_protected_on_packet = False
        self.corrupt_final_app = False
        self.corrupt_vector_on_packet = False
        self.corrupt_unrelated_on_packet = False
        self.events = []

    async def identity_sha256(self):
        return self.identity

    async def read(self, address, length):
        assert length == tx.SECTOR and address % tx.SECTOR == 0
        self.events.append(("read", address))
        return bytes(self.memory[address:address + length])

    async def crc32(self, address, length):
        value = tx.crc(bytes(self.memory[address:address + length]))
        return value ^ int(self.crc_disagreement)

    async def erase_sector(self, address):
        assert address in (0, 0x4000), "unexpected non-application erase"
        self.erases.append(address)
        self.events.append(("erase", address))
        self.memory[address:address + tx.SECTOR] = b"\xff" * tx.SECTOR
        return True

    async def begin_download(self, address, length):
        assert address in (0, 0x4000) and length == tx.SECTOR
        self.downloads.append((address, length))
        self.position = address
        return True

    async def send_data(self, payload):
        self.packets.append(bytes(payload))
        if self.packet_failure:
            return False
        self.memory[self.position:self.position + len(payload)] = payload
        self.position += len(payload)
        if self.corrupt_protected_on_packet:
            self.memory[0xA0000] = 0
        if self.corrupt_final_app and self.position == 0x6000:
            self.memory[0x4004] ^= 1
        if self.corrupt_vector_on_packet:
            self.memory[4] = 0xFF
        if self.corrupt_unrelated_on_packet:
            self.memory[0x2000] = 0
        return True

    async def status(self):
        return not self.status_failure


class AppSectorTransactionTests(unittest.TestCase):
    def setUp(self):
        self.package = synthetic_package()
        self.capture_receipt = {
            "schema": "r4-p7u-capture-pair-v1", "status": "DUPLICATE_READBACK_MATCH",
            "board_identity_sha256": "c" * 64, "flash_bytes": tx.FLASH,
            "pass1_sha256": self.package.profile["capture_sha256"],
            "pass2_sha256": self.package.profile["capture_sha256"],
            "capture_origin": "SUPPLIED_ROM_ADAPTER_REQUIRES_OPERATOR_PROVENANCE",
            "nv_compatibility_verified": False, "reset_issued": False,
            "flash_performed": False, "return_to_stock_verified": False,
        }
        self.pins = {"expected_profile_sha256": self.package.profile["profile_sha256"],
                     "expected_package_sha256": self.package.manifest["package_sha256"],
                     "capture_receipt": self.capture_receipt,
                     "expected_capture_receipt_sha256": tx.sha(tx.canonical(self.capture_receipt)),
                     "expected_live_identity_sha256": "c" * 64}

    async def execute(self, rom, admission=None):
        admission = admission or await tx.admit(rom, self.package, **self.pins)
        return await tx.execute(rom, self.package, admission, **self.pins,
                                expected_admission_sha256=admission["admission_sha256"])

    def test_read_only_admission_dynamic_allowlist_vector_last(self):
        async def scenario():
            rom = FakeROM(self.package)
            admission = await tx.admit(rom, self.package, **self.pins)
            self.assertEqual(rom.erases, [])
            result = await self.execute(rom, admission)
            self.assertEqual(rom.erases, [0x4000, 0])
            self.assertEqual(rom.downloads, [(0x4000, tx.SECTOR), (0, tx.SECTOR)])
            self.assertEqual(bytes(rom.memory[0xA0000:]), self.package.snapshot[0xA0000:])
            self.assertEqual(bytes(rom.memory[:tx.SECTOR]), self.package.sectors[0])
            self.assertTrue(all(0 < len(p) <= 252 and len(p) % 4 == 0 for p in rom.packets))
            self.assertFalse(result["reset_issued"])
            self.assertFalse(result["network_rollback_qualified"])
        asyncio.run(scenario())

    def test_changed_live_board_capture_or_protected_bytes_never_erases(self):
        async def scenario():
            for mutation in ("identity", "app", "protected", "crc", "receipt"):
                rom = FakeROM(self.package)
                admission = await tx.admit(rom, self.package, **self.pins)
                if mutation == "identity": rom.identity = "0" * 64
                if mutation == "app": rom.memory[0x2000] ^= 1
                if mutation == "protected": rom.memory[0xAE000] ^= 1
                if mutation == "crc": rom.crc_disagreement = True
                if mutation == "receipt": admission["flash_authorized"] = True
                with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "R4_APP_TRANSACTION_BLOCKED"):
                    await self.execute(rom, admission)
                self.assertEqual(rom.erases, [])
        asyncio.run(scenario())

    def test_live_management_identity_and_original_capture_receipt_are_both_mandatory(self):
        async def scenario():
            rom = FakeROM(self.package)
            self.assertNotEqual(self.package.profile["board_identity_sha256"], rom.identity)
            admission = await tx.admit(rom, self.package, **self.pins)
            self.assertEqual(admission["live_management_identity_sha256"], rom.identity)
            self.assertEqual(admission["board_identity_sha256"],
                             self.package.profile["board_identity_sha256"])
            for modification in ("receipt_sha", "live_pin", "capture", "origin", "flags", "extra_claim"):
                changed = dict(self.pins)
                if modification == "receipt_sha":
                    changed["expected_capture_receipt_sha256"] = "0" * 64
                elif modification == "live_pin":
                    changed["expected_live_identity_sha256"] = self.package.profile["board_identity_sha256"]
                else:
                    receipt = dict(self.capture_receipt)
                    if modification == "capture": receipt["pass2_sha256"] = "0" * 64
                    if modification == "origin": receipt["capture_origin"] = "UNVERIFIED"
                    if modification == "flags": receipt["flash_performed"] = True
                    if modification == "extra_claim": receipt["stock_boot_qualified"] = True
                    changed["capture_receipt"] = receipt
                    changed["expected_capture_receipt_sha256"] = tx.sha(tx.canonical(receipt))
                with self.subTest(modification=modification), self.assertRaisesRegex(
                        ValueError, "R4_APP_TRANSACTION_BLOCKED"):
                    await tx.admit(rom, self.package, **changed)
            self.assertEqual(rom.erases, [])
        asyncio.run(scenario())

    def test_failed_packet_stops_immediately_and_explicit_current_app_rollback(self):
        async def scenario():
            rom = FakeROM(self.package)
            rom.packet_failure = True
            with self.assertRaisesRegex(ValueError, "PACKET_FAILED"):
                await self.execute(rom)
            self.assertEqual(rom.erases, [0x4000])
            self.assertEqual(len(rom.packets), 1)
            self.assertEqual(bytes(rom.memory[:tx.SECTOR]), self.package.snapshot[:tx.SECTOR])
            live = {address: tx.sha(await rom.read(address, tx.SECTOR)) for address in self.package.sectors}
            rom.packet_failure = False
            result = await tx.rollback_current_app(rom, self.package, **self.pins,
                                                    expected_live_sector_sha256=live)
            self.assertEqual(bytes(rom.memory), self.package.snapshot)
            self.assertEqual(rom.erases, [0x4000, 0x4000])
            self.assertIn("STILL_IN_BSL", result["status"])
        asyncio.run(scenario())

    def test_status_failure_has_no_download_retry_or_reset(self):
        async def scenario():
            rom = FakeROM(self.package)
            rom.status_failure = True
            with self.assertRaisesRegex(ValueError, "ERASE_REJECTED.*STATUS"):
                await self.execute(rom)
            self.assertEqual(rom.erases, [0x4000])
            self.assertEqual(rom.downloads, [])
            self.assertEqual(rom.packets, [])
        asyncio.run(scenario())

    def test_final_byte_readback_failure_never_programs_vector_sector(self):
        async def scenario():
            rom = FakeROM(self.package)
            rom.corrupt_final_app = True
            with self.assertRaisesRegex(ValueError, "FINAL_SECTOR_READBACK_FAILED"):
                await self.execute(rom)
            self.assertEqual(rom.erases, [0x4000])
            self.assertEqual(bytes(rom.memory[:tx.SECTOR]), self.package.snapshot[:tx.SECTOR])
        asyncio.run(scenario())

    def test_protected_mutation_mid_write_blocks_next_sector_and_rollback(self):
        async def scenario():
            rom = FakeROM(self.package)
            rom.corrupt_protected_on_packet = True
            with self.assertRaisesRegex(ValueError, "LIVE_STATE_CHANGED_BEFORE_ERASE"):
                await self.execute(rom)
            self.assertEqual(rom.erases, [0x4000])
            live = {address: tx.sha(await rom.read(address, tx.SECTOR)) for address in self.package.sectors}
            with self.assertRaisesRegex(ValueError, "ROLLBACK_LIVE_OR_PROTECTED_STATE_CHANGED"):
                await tx.rollback_current_app(rom, self.package, **self.pins,
                                               expected_live_sector_sha256=live)
            self.assertEqual(rom.erases, [0x4000])
        asyncio.run(scenario())

    def test_rollback_rejects_missing_or_stale_application_pins(self):
        async def scenario():
            rom = FakeROM(self.package)
            for pins in ({}, {address: "0" * 64 for address in self.package.sectors}):
                with self.assertRaisesRegex(ValueError, "ROLLBACK_"):
                    await tx.rollback_current_app(rom, self.package, **self.pins,
                                                   expected_live_sector_sha256=pins)
            self.assertEqual(rom.erases, [])
        asyncio.run(scenario())

    def test_per_erase_reads_only_target_and_all_protected_sectors(self):
        async def scenario():
            rom = FakeROM(self.package)
            admission = await tx.admit(rom, self.package, **self.pins)
            rom.events.clear()
            await self.execute(rom, admission)
            full = tx.FLASH // tx.SECTOR
            protected = set(range(0xA0000, tx.FLASH, tx.SECTOR))
            first_erase = rom.events.index(("erase", 0x4000))
            second_erase = rom.events.index(("erase", 0))
            initial_reads = [address for kind, address in rom.events[:first_erase] if kind == "read"]
            middle_reads = [address for kind, address in rom.events[first_erase + 1:second_erase] if kind == "read"]
            self.assertEqual(initial_reads[:full], list(range(0, tx.FLASH, tx.SECTOR)))
            self.assertEqual(set(initial_reads[full:]), protected | {0x4000})
            # One readback of the first programmed sector, then second-target guard.
            self.assertEqual(middle_reads[0], 0x4000)
            self.assertEqual(set(middle_reads[1:]), protected | {0})
            final_reads = [address for kind, address in rom.events[second_erase + 1:] if kind == "read"]
            self.assertEqual(final_reads[-full:], list(range(0, tx.FLASH, tx.SECTOR)))
            reads = sum(kind == "read" for kind, _ in rom.events)
            self.assertEqual(reads, 2 * full + len(self.package.sectors) * (len(protected) + 2))
        asyncio.run(scenario())

    def test_vector_drift_stops_before_vector_erase_unrelated_drift_fails_final_check(self):
        async def scenario():
            for mutation in ("vector", "unrelated"):
                rom = FakeROM(self.package)
                rom.corrupt_vector_on_packet = mutation == "vector"
                rom.corrupt_unrelated_on_packet = mutation == "unrelated"
                error = "LIVE_STATE_CHANGED_BEFORE_ERASE" if mutation == "vector" else "FINAL_FULL_STATE_CHANGED"
                with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, error):
                    await self.execute(rom)
                self.assertEqual(rom.erases, [0x4000] if mutation == "vector" else [0x4000, 0])
        asyncio.run(scenario())

    def test_hanging_read_operation_times_out_without_writes_or_retry(self):
        class HangingReadROM(FakeROM):
            attempts = 0
            cancelled = False

            async def read(self, address, length):
                self.attempts += 1
                try:
                    await asyncio.Future()
                finally:
                    self.cancelled = True

        async def scenario():
            rom = HangingReadROM(self.package)
            with self.assertRaisesRegex(ValueError, "ADAPTER_OPERATION_TIMEOUT_read"):
                await asyncio.wait_for(tx.admit(rom, self.package, **self.pins,
                    operation_timeout=0.01, session_timeout=1.0), timeout=1.0)
            self.assertEqual(rom.attempts, 1)
            self.assertTrue(rom.cancelled)
            self.assertEqual(rom.erases, [])
        asyncio.run(scenario())

    def test_single_session_deadline_is_shared_across_individually_successful_calls(self):
        class SlowROM(FakeROM):
            attempts = 0

            async def read(self, address, length):
                self.attempts += 1
                await asyncio.sleep(0.01)
                return await super().read(address, length)

        async def scenario():
            rom = SlowROM(self.package)
            with self.assertRaisesRegex(ValueError, "SESSION_DEADLINE_EXCEEDED"):
                await asyncio.wait_for(tx.admit(rom, self.package, **self.pins,
                    operation_timeout=1.0, session_timeout=0.03), timeout=1.0)
            self.assertGreater(rom.attempts, 0)
            self.assertLess(rom.attempts, tx.FLASH // tx.SECTOR)
            self.assertEqual(rom.erases, [])
        asyncio.run(scenario())

    def test_hanging_packet_stops_after_one_attempt_without_automatic_rollback(self):
        class HangingPacketROM(FakeROM):
            cancelled = False

            async def send_data(self, payload):
                self.packets.append(payload)
                try:
                    await asyncio.Future()
                finally:
                    self.cancelled = True

        async def scenario():
            rom = HangingPacketROM(self.package)
            admission = await tx.admit(rom, self.package, **self.pins)
            with self.assertRaisesRegex(ValueError, "ADAPTER_OPERATION_TIMEOUT_send_data"):
                await asyncio.wait_for(tx.execute(rom, self.package, admission, **self.pins,
                    expected_admission_sha256=admission["admission_sha256"],
                    operation_timeout=0.01, session_timeout=1.0), timeout=1.0)
            self.assertEqual(rom.erases, [0x4000])
            self.assertEqual(len(rom.packets), 1)
            self.assertTrue(rom.cancelled)
        asyncio.run(scenario())

    def test_invalid_deadline_limits_rejected_before_adapter_calls(self):
        async def scenario():
            for limits in ({"operation_timeout": 0}, {"operation_timeout": True},
                           {"session_timeout": -1}, {"session_timeout": float("inf")},
                           {"session_timeout": float("nan")}):
                rom = FakeROM(self.package)
                with self.subTest(limits=limits), self.assertRaisesRegex(ValueError, "INVALID_TIMEOUT_LIMIT"):
                    await tx.admit(rom, self.package, **self.pins, **limits)
                self.assertEqual(rom.events, [])
                self.assertEqual(rom.erases, [])
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
