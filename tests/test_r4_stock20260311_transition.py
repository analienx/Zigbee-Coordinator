"""Synthetic transition checks; no adapter, actual hardware or private NV."""
import asyncio
import binascii
import importlib.util
import json
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


def upgrade_inputs(*, shrink=False):
    old = inputs()
    installed = m.prepare(**old)
    capture = bytearray(installed.snapshot)
    for address, payload in installed.sectors.items():
        capture[address:address + m.SECTOR] = payload
    capture[0xA4004] ^= 1  # legitimate post-boot NV is never a rollback payload
    capture = bytes(capture)
    new = inputs()
    vector = struct.pack("<II", 0x20022000, 0x181) + b"\x00" * 0x34
    lines = [ihex_record(0, 0, vector), ihex_record(0, 0x180, b"\x00\xbf")]
    if not shrink:
        lines.append(ihex_record(0, 0x2000, b"\x01\xbf"))
    new["app_hex"] = ("\n".join(lines + [ihex_record(1, 0, b"")]) + "\n").encode()
    new["handoff"] = old["handoff"][:-1] + b"\x00"
    candidate = dict(new["candidate"], source_sha="4" * 40,
        app_hex_sha256=m.sha(new["app_hex"]), handoff_sha256=m.sha(new["handoff"]))
    receipt = {"schema": "r4-p7u-stock20260311-compiled-handoff-v1",
        "status": "COMPILED_M4F_SINGLE_SECTOR_TRANSFER_AUDITED",
        "sector_sha256": candidate["handoff_sha256"], "profile_sha256": candidate["profile_sha256"],
        "source_native_manifest_sha256": candidate["native_manifest_sha256"],
        "app_initial_sp": "0x20022000", "app_reset_thumb": "0x181"}
    receipt = json.dumps(receipt).encode()
    candidate["files"] = {"handoff-receipt.json": m.sha(receipt)}
    security = dict(new["security_receipt"], capture_sha256=m.sha(capture),
                    baseline_capture_sha256=installed.manifest["capture_sha256"])
    new.update(candidate=candidate, expected_candidate_sha256=m.sha(m.canonical(candidate)),
        pass1=capture, pass2=capture, expected_capture_sha256=m.sha(capture),
        security_receipt=security, expected_security_receipt_sha256=m.sha(m.canonical(security)))
    result = {"status": "APP_AND_AC000_VERIFIED_STILL_IN_BSL",
              "written_sectors": [a for a in installed.manifest["program_order"]
                                  if installed.sectors[a] != installed.snapshot[a:a + m.SECTOR]],
              "nv_touched": False, "ccfg_touched": False, "reset_issued": False,
              "automatic_rollback": False}
    return dict(new, installed_plan=installed,
        expected_installed_plan_sha256=installed.manifest["plan_sha256"],
        installed_candidate=old["candidate"], expected_installed_candidate_sha256=old["expected_candidate_sha256"],
        installed_app_hex=old["app_hex"], installed_handoff=old["handoff"],
        installed_result=result, expected_installed_result_sha256=m.sha(m.canonical(result)),
        handoff_receipt=receipt)


class FakeROM:
    def __init__(self, capture):
        self.image = bytearray(capture)
        self.identity = LIVE
        self.trace = []
        self.fail_packet = False
        self.cursor = self.end = None
        self.reader, self.writer = object(), object()
        self.read_calls = 0
        self.crc_calls = 0

    async def identity_sha256(self):
        return self.identity

    async def read(self, address, length):
        self.read_calls += 1
        return bytes(self.image[address:address+length])

    async def crc32(self, address, length):
        self.crc_calls += 1
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
    def test_packet_status_elision_only_for_exact_verified_rom_implementation(self):
        sys.path.insert(0, str(ROOT / "release" / "rom_writer"))
        from p7u_stock20260311_rom_adapter import Stock20260311ROM
        self.assertTrue(m._verified_wire_status_embedded(Stock20260311ROM()))
        self.assertFalse(m._verified_wire_status_embedded(FakeROM(inputs()["pass1"])))

    def test_unqualified_fast_adapter_keeps_independent_packet_status_gate(self):
        async def scenario():
            plan = m.prepare(**inputs())
            rom, args = FakeROM(plan.snapshot), capture_args(plan)
            admission = await m.admit(rom, plan, **args, seal_same_session=True)
            original_status = rom.status
            async def fail_after_one_packet():
                if any(x[0] == "packet" for x in rom.trace):
                    return False
                return await original_status()
            rom.status = fail_after_one_packet
            async def journal(event): return True
            with self.assertRaisesRegex(ValueError, "UNCERTAIN_SEND_DATA"):
                await m.execute(rom, plan, admission, **args,
                    expected_admission_sha256=admission["admission_sha256"],
                    journal=journal, same_session_fast=True)
            self.assertEqual(len([x for x in rom.trace if x[0] == "packet"]), 1)
        asyncio.run(scenario())

    def test_fast_session_preserves_complete_parity_and_avoids_duplicate_full_reads(self):
        async def scenario():
            plan = m.prepare(**inputs())
            rom, args = FakeROM(plan.snapshot), capture_args(plan)
            admission = await m.admit(rom, plan, **args, seal_same_session=True)
            after_admission = rom.read_calls
            self.assertEqual(after_admission, m.FLASH // m.SECTOR)
            async def journal(event): return True
            result = await m.execute(rom, plan, admission, **args,
                expected_admission_sha256=admission["admission_sha256"],
                journal=journal, same_session_fast=True)
            self.assertEqual(result["status"], "APP_AND_AC000_VERIFIED_STILL_IN_BSL")
            self.assertEqual(result["written_sectors"], [m.SECTOR, 0, m.BOOT])
            # Final all-88 SHA parity and sector readbacks remain. Neither
            # a repeated full admission nor any boot-stage full scan remains.
            self.assertLess(rom.read_calls - after_admission, 105)
            self.assertGreater(rom.crc_calls, 100)
            self.assertEqual(rom.image[m.TOP:], plan.snapshot[m.TOP:])
            with self.assertRaisesRegex(ValueError, "SAME_TRANSPORT_SHA_ADMISSION_REQUIRED"):
                await m.execute(rom, plan, admission, **args,
                    expected_admission_sha256=admission["admission_sha256"],
                    journal=journal, same_session_fast=True)
        asyncio.run(scenario())

    def test_fast_session_rejects_reopen_and_expiry_without_any_erase(self):
        async def scenario():
            for mutation in ("reopen", "expired", "unsealed"):
                plan = m.prepare(**inputs())
                rom, args = FakeROM(plan.snapshot), capture_args(plan)
                admission = await m.admit(rom, plan, **args, seal_same_session=(mutation != "unsealed"))
                if mutation == "reopen":
                    rom.writer = object()  # a new network/serial connection
                elif mutation == "expired":
                    m._SAME_SESSION_ADMISSIONS[rom]["admitted_monotonic"] -= 120
                async def journal(event): self.fail("no journal for stale fast admission")
                with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError,
                        "SAME_TRANSPORT_SHA_ADMISSION_REQUIRED"):
                    await m.execute(rom, plan, admission, **args,
                        expected_admission_sha256=admission["admission_sha256"],
                        journal=journal, same_session_fast=True)
                self.assertEqual([x for x in rom.trace if x[0] == "erase"], [])
        asyncio.run(scenario())

    def test_fast_session_detects_current_app_and_nv_drift_before_first_erase(self):
        async def scenario():
            for changed in (m.SECTOR + 32, 0xA4000, m.TOP):
                plan = m.prepare(**inputs())
                rom, args = FakeROM(plan.snapshot), capture_args(plan)
                admission = await m.admit(rom, plan, **args, seal_same_session=True)
                rom.image[changed] ^= 1
                async def journal(event): self.fail("no journal on changed baseline")
                with self.subTest(changed=hex(changed)), self.assertRaisesRegex(ValueError,
                        "STATE_CHANGED_AFTER_SHA_ADMISSION"):
                    await m.execute(rom, plan, admission, **args,
                        expected_admission_sha256=admission["admission_sha256"],
                        journal=journal, same_session_fast=True)
                self.assertEqual([x for x in rom.trace if x[0] == "erase"], [])
        asyncio.run(scenario())

    def test_fast_session_rejects_boot_vector_interruption(self):
        async def scenario():
            plan = m.prepare(**inputs())
            rom, args = FakeROM(plan.snapshot), capture_args(plan)
            admission = await m.admit(rom, plan, **args, seal_same_session=True)
            async def journal(event):
                if event["event"] == "BEFORE_BOOT_VECTOR_COMMIT":
                    rom.image[m.TOP] ^= 1
                return True
            with self.assertRaisesRegex(ValueError, "STATE_CHANGED_BEFORE_BOOT_VECTOR"):
                await m.execute(rom, plan, admission, **args,
                    expected_admission_sha256=admission["admission_sha256"],
                    journal=journal, same_session_fast=True)
            self.assertEqual(rom.image[m.BOOT:m.BOOT+8], bytes([255])*8)
            self.assertNotIn(("download", m.BOOT, 8), rom.trace)
        asyncio.run(scenario())

    def test_known_r4_upgrade_uses_fresh_nv_and_retires_only_old_owned_app(self):
        data = upgrade_inputs(shrink=True)
        plan = m.prepare_upgrade(**data)
        self.assertEqual(plan.manifest["plan_kind"], "UPGRADE_KNOWN_R4_APP_AND_COMPILED_HANDOFF")
        self.assertEqual(plan.manifest["retired_owned_app_sectors"], [0x2000])
        self.assertEqual(plan.sectors[0x2000], b"\xff" * m.SECTOR)
        self.assertEqual(plan.snapshot[0xA4000:m.BOOT], data["pass1"][0xA4000:m.BOOT])
        self.assertEqual(set(plan.sectors), {0, 0x2000, m.BOOT})
        self.assertEqual(plan.manifest["program_order"], [0x2000, 0, m.BOOT])
        common = {k: data[k] for k in inputs()}
        with self.assertRaisesRegex(ValueError, "CURRENT_FACTORY_BOOT_OR_CCFG"):
            m.prepare(**common)

    def test_upgrade_rejects_partial_pair_and_unexplained_non_nv_drift(self):
        for address in (0, 0x2000, 0x8000, m.BOOT, m.TOP):
            data = upgrade_inputs()
            damaged = bytearray(data["pass1"])
            damaged[address] ^= 1
            damaged = bytes(damaged)
            data.update(pass1=damaged, pass2=damaged, expected_capture_sha256=m.sha(damaged))
            data["security_receipt"]["capture_sha256"] = m.sha(damaged)
            data["expected_security_receipt_sha256"] = m.sha(m.canonical(data["security_receipt"]))
            with self.subTest(address=hex(address)), self.assertRaisesRegex(ValueError, "TRANSITION_BLOCKED"):
                m.prepare_upgrade(**data)

    def test_upgrade_requires_bound_success_and_matching_compiled_handoff(self):
        for failure in ("receipt", "handoff_pair", "baseline"):
            data = upgrade_inputs()
            if failure == "receipt":
                data["installed_result"]["nv_touched"] = True
                data["expected_installed_result_sha256"] = m.sha(m.canonical(data["installed_result"]))
            elif failure == "handoff_pair":
                receipt = json.loads(data["handoff_receipt"])
                receipt["app_reset_thumb"] = "0x101"
                data["handoff_receipt"] = json.dumps(receipt).encode()
                data["candidate"]["files"]["handoff-receipt.json"] = m.sha(data["handoff_receipt"])
                data["expected_candidate_sha256"] = m.sha(m.canonical(data["candidate"]))
            else:
                data["security_receipt"]["baseline_capture_sha256"] = "f" * 64
                data["expected_security_receipt_sha256"] = m.sha(m.canonical(data["security_receipt"]))
            with self.subTest(failure=failure), self.assertRaisesRegex(ValueError, "TRANSITION_BLOCKED"):
                m.prepare_upgrade(**data)

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

    def test_explicit_recovery_restores_only_original_app_boot_and_keeps_current_nv(self):
        async def scenario():
            data = inputs()
            forward = m.prepare(**data)
            current = bytearray(forward.snapshot)
            current[:m.SECTOR] = forward.sectors[0]
            current[0x2000:0x4000] = b"\xff"*m.SECTOR
            current[0x2000:0x2080] = forward.sectors[0x2000][:0x80]
            current[m.BOOT:m.TOP] = b"\xff"*m.SECTOR
            current[m.BOOT+8:m.BOOT+128] = forward.sectors[m.BOOT][8:128]
            # Synthetic newly admitted NV state: its bytes may not be replayed
            # from the original forward snapshot even during APP rollback.
            current[0xA4004] ^= 1
            current = bytes(current)
            def recovery_args(capture):
                security = dict(data["security_receipt"])
                security.update(capture_sha256=m.sha(capture),
                                baseline_capture_sha256=forward.manifest["capture_sha256"])
                return {"expected_forward_plan_sha256": forward.manifest["plan_sha256"],
                        "pass1": capture, "pass2": capture, "expected_capture_sha256": m.sha(capture),
                        "security_receipt": security,
                        "expected_security_receipt_sha256": m.sha(m.canonical(security))}
            recovery = m.prepare_recovery(forward, **recovery_args(current))
            self.assertEqual(recovery.manifest["plan_kind"], "RECOVER_ORIGINAL_APP_AND_BOOT_ONLY")
            self.assertEqual(set(recovery.sectors), set(forward.sectors))
            rom, args = FakeROM(current), capture_args(recovery)
            admission = await m.admit(rom, recovery, **args)
            async def journal(event):
                return True
            result = await m.execute(rom, recovery, admission, **args,
                expected_admission_sha256=admission["admission_sha256"], journal=journal)
            for address in forward.sectors:
                self.assertEqual(rom.image[address:address+m.SECTOR],
                                 forward.snapshot[address:address+m.SECTOR])
            self.assertEqual(rom.image[0xA4000:m.BOOT], current[0xA4000:m.BOOT])
            self.assertNotEqual(rom.image[0xA4000:m.BOOT], forward.snapshot[0xA4000:m.BOOT])
            self.assertFalse(result["automatic_rollback"])
            self.assertFalse(result["reset_issued"])
            for address in (0xA2000, m.TOP+0x100):
                drift = bytearray(current)
                drift[address] ^= 1
                with self.subTest(address=hex(address)), self.assertRaisesRegex(ValueError, "UNEXPLAINED_NON_TARGET_DRIFT"):
                    m.prepare_recovery(forward, **recovery_args(bytes(drift)))
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
