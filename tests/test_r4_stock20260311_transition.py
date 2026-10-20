"""Synthetic transition checks; no adapter, actual hardware or private NV."""
import asyncio
import binascii
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4"
sys.path.insert(0, str(ROOT / "release"))
spec = importlib.util.spec_from_file_location("current_transition", ROOT / "release/r4_stock20260311_transition.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# Public derived vendor CCFG reference, with the factory IMAGE_VALID=AC000.
CCFG = bytes.fromhex(
    "000080011000c0fffdff5800ffc1b9f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc50ffec5ffffffff00ffffff00c5c5ff000000ff00c00a00ffffffffffffffffffffffffffffffff")
LIVE = "b" * 64


def ihex_record(kind, address, payload):
    body = bytes([len(payload)]) + address.to_bytes(2, "big") + bytes([kind]) + payload
    return ":" + (body + bytes([-sum(body) & 255])).hex().upper()


def inputs():
    capture = bytearray(b"".join(bytes([i])*m.SECTOR for i in range(m.FLASH//m.SECTOR)))
    struct.pack_into("<I", capture, 0, 0x96F3B83D)
    struct.pack_into("<II", capture, m.BOOT, 0x20022000, 0xAE809)
    capture[0xAFFA8:] = CCFG
    capture = bytes(capture)
    vector = struct.pack("<II", 0x20022000, 0x101) + b"\x00"*0x34
    app = ("\n".join([ihex_record(0, 0, vector), ihex_record(0, 0x100, b"\x00\xbf"),
                       ihex_record(0, 0x2000, b"\x00\xbf"), ihex_record(1, 0, b"")])+"\n").encode("ascii")
    stage = struct.pack("<54I", 0x20022000, m.BOOT+0xD9, *([m.BOOT+0xE1]*52))
    stage += b"\x00"*32 + b"\xff"*(m.SECTOR-len(stage)-32)
    candidate = {"schema": "p7u-stock20260311-candidate-v1", "source_sha": "1"*40,
                 "profile_sha256": "2"*64, "native_manifest_sha256": "3"*64,
                 "app_hex_sha256": m.sha(app), "handoff_sha256": m.sha(stage), "flash_authorized": False}
    security = {"schema": "p7u-stock20260311-security-preflight-v1",
                "status": "PASS_RETAINED_SECURITY_OFFLINE_ONLY", "capture_sha256": m.sha(capture),
                "profile_sha256": candidate["profile_sha256"],
                "native_manifest_sha256": candidate["native_manifest_sha256"],
                "write_attempts": 0, "erase_attempts": 0, "compaction_attempts": 0,
                "flash_authorized": False}
    return {"candidate": candidate, "expected_candidate_sha256": m.sha(m.canonical(candidate)),
            "app_hex": app, "handoff": stage, "pass1": capture, "pass2": capture,
            "expected_capture_sha256": m.sha(capture), "board_identity_sha256": "a"*64,
            "security_receipt": security, "expected_security_receipt_sha256": m.sha(m.canonical(security))}


def capture_args(plan):
    receipt = {"schema": "r4-p7u-capture-pair-v1", "status": "DUPLICATE_READBACK_MATCH",
               "board_identity_sha256": LIVE, "flash_bytes": m.FLASH,
               "pass1_sha256": plan.manifest["capture_sha256"], "pass2_sha256": plan.manifest["capture_sha256"],
               "capture_origin": "SUPPLIED_ROM_ADAPTER_REQUIRES_OPERATOR_PROVENANCE",
               "nv_compatibility_verified": False, "reset_issued": False,
               "flash_performed": False, "return_to_stock_verified": False}
    return {"expected_plan_sha256": plan.manifest["plan_sha256"], "capture_receipt": receipt,
            "expected_capture_receipt_sha256": m.sha(m.canonical(receipt)),
            "expected_live_identity_sha256": LIVE}


class FakeROM:
    def __init__(self, capture):
        self.image = bytearray(capture)
        self.identity = LIVE
        self.trace = []
        self.fail_packet = False
        self.cursor = self.end = None

    async def identity_sha256(self):
        return self.identity

    async def read(self, address, length):
        return bytes(self.image[address:address+length])

    async def crc32(self, address, length):
        return binascii.crc32(self.image[address:address+length]) & 0xFFFFFFFF

    async def erase_sector(self, address):
        self.trace.append(("erase", address))
        self.image[address:address+m.SECTOR] = b"\xff"*m.SECTOR
        return True

    async def begin_download(self, address, length):
        self.trace.append(("download", address, length))
        self.cursor, self.end = address, address+length
        return True

    async def send_data(self, payload):
        self.trace.append(("packet", self.cursor, len(payload)))
        if self.fail_packet:
            return False
        if not payload or len(payload) > 252 or len(payload) % 4 or self.cursor+len(payload) > self.end:
            raise AssertionError("invalid ROM packet")
        self.image[self.cursor:self.cursor+len(payload)] = payload
        self.cursor += len(payload)
        return True

    async def status(self):
        return True


class CurrentTransitionTests(unittest.TestCase):
    def test_complete_order_protects_nv_top_and_commits_boot_vectors_last(self):
        async def scenario():
            data = inputs()
            plan = m.prepare(**data)
            rom = FakeROM(plan.snapshot)
            args = capture_args(plan)
            admission = await m.admit(rom, plan, **args)
            self.assertEqual(rom.trace, [])
            async def journal(event):
                rom.trace.append(("journal", event["event"], event["address"]))
                return True
            result = await m.execute(rom, plan, admission, **args,
                expected_admission_sha256=admission["admission_sha256"], journal=journal)
            self.assertEqual([item[1] for item in rom.trace if item[0] == "erase"], [0x2000, 0, m.BOOT])
            self.assertEqual([item[1:] for item in rom.trace if item[0] == "download"],
                             [(0x2000, m.SECTOR), (0, m.SECTOR), (m.BOOT+8, m.SECTOR-8), (m.BOOT, 8)])
            self.assertEqual([item for item in rom.trace if item[0] == "packet"][-1], ("packet", m.BOOT, 8))
            commit = rom.trace.index(("journal", "BEFORE_BOOT_VECTOR_COMMIT", m.BOOT))
            self.assertLess(commit, rom.trace.index(("download", m.BOOT, 8)))
            self.assertEqual(rom.image[0xA0000:m.BOOT], plan.snapshot[0xA0000:m.BOOT])
            self.assertEqual(rom.image[m.TOP:], plan.snapshot[m.TOP:])
            for address, payload in plan.sectors.items():
                self.assertEqual(rom.image[address:address+m.SECTOR], payload)
            self.assertEqual(result["status"], "APP_AND_AC000_VERIFIED_STILL_IN_BSL")
            self.assertFalse(result["reset_issued"])
            self.assertFalse(result["automatic_rollback"])
        asyncio.run(scenario())

    def test_security_hold_and_external_pin_or_capture_mismatch_never_prepare(self):
        for mutation in ("security_hold", "candidate_pin", "capture", "security_pin"):
            data = inputs()
            if mutation == "security_hold":
                data["security_receipt"]["status"] = "HOLD_SECURITY"
                data["expected_security_receipt_sha256"] = m.sha(m.canonical(data["security_receipt"]))
            elif mutation == "candidate_pin":
                data["expected_candidate_sha256"] = "f"*64
            elif mutation == "capture":
                data["pass2"] = b"\x00" + data["pass2"][1:]
            else:
                data["expected_security_receipt_sha256"] = "f"*64
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "TRANSITION_BLOCKED"):
                m.prepare(**data)

    def test_stale_admission_does_not_erase(self):
        async def scenario():
            plan = m.prepare(**inputs())
            rom, args = FakeROM(plan.snapshot), capture_args(plan)
            admission = await m.admit(rom, plan, **args)
            rom.image[0x2000] ^= 1
            async def journal(event):
                self.fail("journal must not run with stale baseline")
            with self.assertRaisesRegex(ValueError, "BASELINE_CHANGED|STALE_ADMISSION"):
                await m.execute(rom, plan, admission, **args,
                    expected_admission_sha256=admission["admission_sha256"], journal=journal)
            self.assertEqual(rom.trace, [])
        asyncio.run(scenario())

    def test_packet_failure_stops_once_without_retry_rollback_or_nv_replay(self):
        async def scenario():
            plan = m.prepare(**inputs())
            rom, args = FakeROM(plan.snapshot), capture_args(plan)
            admission = await m.admit(rom, plan, **args)
            rom.fail_packet = True
            async def journal(event):
                return True
            with self.assertRaisesRegex(ValueError, "UNCERTAIN_SEND_DATA"):
                await m.execute(rom, plan, admission, **args,
                    expected_admission_sha256=admission["admission_sha256"], journal=journal)
            self.assertEqual([item[1] for item in rom.trace if item[0] == "erase"], [0x2000])
            self.assertEqual(len([item for item in rom.trace if item[0] == "packet"]), 1)
            self.assertEqual(rom.image[0xA0000:], plan.snapshot[0xA0000:])
        asyncio.run(scenario())

    def test_journal_rejection_or_reserved_mutation_blocks_first_erase(self):
        async def scenario():
            for mutation in ("rejected", "nv_changed", "identity_changed"):
                plan = m.prepare(**inputs())
                rom, args = FakeROM(plan.snapshot), capture_args(plan)
                admission = await m.admit(rom, plan, **args)
                async def journal(event):
                    if mutation == "nv_changed":
                        rom.image[0xA4000] ^= 1
                    if mutation == "identity_changed":
                        rom.identity = "c"*64
                    return mutation != "rejected"
                with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "TRANSITION_BLOCKED"):
                    await m.execute(rom, plan, admission, **args,
                        expected_admission_sha256=admission["admission_sha256"], journal=journal)
                self.assertEqual([item for item in rom.trace if item[0] == "erase"], [])
        asyncio.run(scenario())

    def test_journal_mutation_before_vector_commit_leaves_vectors_erased(self):
        async def scenario():
            plan = m.prepare(**inputs())
            rom, args = FakeROM(plan.snapshot), capture_args(plan)
            admission = await m.admit(rom, plan, **args)
            async def journal(event):
                if event["event"] == "BEFORE_BOOT_VECTOR_COMMIT":
                    rom.image[m.TOP] ^= 1
                return True
            with self.assertRaisesRegex(ValueError, "STATE_CHANGED_BEFORE_BOOT_VECTOR"):
                await m.execute(rom, plan, admission, **args,
                    expected_admission_sha256=admission["admission_sha256"], journal=journal)
            self.assertNotIn(("download", m.BOOT, 8), rom.trace)
            self.assertEqual(rom.image[m.BOOT:m.BOOT+8], b"\xff"*8)
            self.assertEqual([item[1] for item in rom.trace if item[0] == "erase"], [0x2000, 0, m.BOOT])
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
