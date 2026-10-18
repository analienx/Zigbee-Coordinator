"""Hostile fake-ROM tests. No network, physical flash, reset, or key fixtures."""
import asyncio
import unittest

from tests.test_r4_current_app_package import m, synthetic_package
import r4_app_sector_transaction as tx


class FakeROM:
    def __init__(self, package):
        self.memory = bytearray(package.snapshot)
        self.identity = package.profile["board_identity_sha256"]
        self.erases, self.downloads, self.packets = [], [], []
        self.position = None
        self.packet_failure = False
        self.status_failure = False
        self.crc_disagreement = False
        self.corrupt_protected_on_packet = False
        self.corrupt_final_app = False

    async def identity_sha256(self):
        return self.identity

    async def read(self, address, length):
        assert length == tx.SECTOR and address % tx.SECTOR == 0
        return bytes(self.memory[address:address + length])

    async def crc32(self, address, length):
        value = tx.crc(bytes(self.memory[address:address + length]))
        return value ^ int(self.crc_disagreement)

    async def erase_sector(self, address):
        assert address in (0, 0x4000), "unexpected non-application erase"
        self.erases.append(address)
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
        return True

    async def status(self):
        return not self.status_failure


class AppSectorTransactionTests(unittest.TestCase):
    def setUp(self):
        self.package = synthetic_package()
        self.pins = {"expected_profile_sha256": self.package.profile["profile_sha256"],
                     "expected_package_sha256": self.package.manifest["package_sha256"]}

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


if __name__ == "__main__":
    unittest.main()
