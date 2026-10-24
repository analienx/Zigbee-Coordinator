"""New source-only sparse ROM admission and write transaction invariants."""
import asyncio, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]/"firmware/slzb-06p7u/r4"
sys.path.insert(0,str(ROOT/"release"))
sys.path.insert(0,str(ROOT/"release/rom_writer"))
import r4_stock20260311_transition as m
from p7u_usb_sparse_capture import capture_sparse
from test_r4_stock20260311_transition import inputs,upgrade_inputs,FakeROM,LIVE

async def scenario():
    data=inputs()
    plan=m.prepare(**data)
    rom=FakeROM(plan.snapshot)
    async def flash_read(addr,length):
        return bytes(rom.image[addr:addr+length])
    rom.read_flash=flash_read
    result=await capture_sparse(rom,prior_full_verified=plan.snapshot,
                                expected_identity_sha256=LIVE)
    sparse=m.canonical(vars(result.receipt))
    import json
    proof=json.loads(sparse)
    bound=m.bind_sparse_plan(plan,
           expected_plan_sha256=plan.manifest["plan_sha256"],
           previous_verified_image=plan.snapshot,
           sparse_receipt=proof,
           expected_sparse_receipt_sha256=m.sha(m.canonical(proof)))
    args=dict(expected_plan_sha256=bound.manifest["plan_sha256"],
              sparse_receipt=proof,
              expected_sparse_receipt_sha256=m.sha(m.canonical(proof)),
              security_receipt=data["security_receipt"],
              expected_security_receipt_sha256=data["expected_security_receipt_sha256"],
              expected_live_identity_sha256=LIVE)
    return rom,bound,args

class SparseTransitionTests(unittest.IsolatedAsyncioTestCase):
    async def test_rom_crc_sparse_admission_executes_readback_without_full_sha(self):
        rom,plan,args=await scenario()
        admission=await m.admit_sparse(rom,plan,**args)
        self.assertEqual(admission["mode"],m.SPARSE_MODE)
        self.assertEqual(rom.read_calls,0)
        async def journal(event):return True
        receipt=await m.execute(rom,plan,admission,
             expected_plan_sha256=args["expected_plan_sha256"],
             expected_admission_sha256=admission["admission_sha256"],
             capture_receipt=args["sparse_receipt"],
             expected_capture_receipt_sha256=args["expected_sparse_receipt_sha256"],
             expected_live_identity_sha256=LIVE,
             journal=journal,same_session_sparse=True)
        self.assertEqual(receipt["status"],"APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL")
        self.assertEqual(receipt["verification_scope"],"WRITTEN_SHA_PLUS_ALL88_ROM_CRC")
        self.assertEqual(receipt["written_sectors"],[m.SECTOR,0,m.BOOT])
        self.assertLess(rom.read_calls,12,"no full 88-sector SHA or full duplicate capture")
        self.assertEqual(rom.image[0xA0000:m.BOOT],plan.snapshot[0xA0000:m.BOOT])
        self.assertEqual(rom.image[m.TOP:],plan.snapshot[m.TOP:])

    async def test_follow_on_custom_release_accepts_bound_sparse_previous_receipt(self):
        data=upgrade_inputs()
        old_source=data["installed_plan"]
        old=m.Transition(old_source.manifest,old_source.snapshot,old_source.sectors)
        receipt=dict(
            status="SPARSE_ROM_CRC_WITH_FRESH_NV_READ_ONLY_NOT_FLASH_ADMISSION",
            source_baseline_sha256=m.sha(old.snapshot),
            live_reconstructed_sha256=m.sha(old.snapshot),
            expected_identity_sha256=LIVE,
            nv_bytes_read=0xC000,baseline_nv_changed_sectors=0,
            rom_crc32_sector_checks=88)
        marked=m.bind_sparse_plan(old,
             expected_plan_sha256=old.manifest["plan_sha256"],
             previous_verified_image=old.snapshot,sparse_receipt=receipt,
             expected_sparse_receipt_sha256=m.sha(m.canonical(receipt)))
        data["installed_plan"]=marked
        data["expected_installed_plan_sha256"]=marked.manifest["plan_sha256"]
        data["installed_result"]["status"]="APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL"
        data["installed_result"]["verification_scope"]="WRITTEN_SHA_PLUS_ALL88_ROM_CRC"
        data["expected_installed_result_sha256"]=m.sha(m.canonical(data["installed_result"]))
        followup=m.prepare_upgrade(**data)
        self.assertEqual(followup.manifest["plan_kind"],"UPGRADE_KNOWN_R4_APP_AND_COMPILED_HANDOFF")
        data["installed_result"]["verification_scope"]="CRC_ONLY_WITHOUT_BYTE_READBACK"
        data["expected_installed_result_sha256"]=m.sha(m.canonical(data["installed_result"]))
        with self.assertRaisesRegex(ValueError,"INSTALLED_SUCCESS_RECEIPT"):
            m.prepare_upgrade(**data)

    async def test_wrong_native_security_holds_before_erase(self):
        rom,plan,args=await scenario()
        args["security_receipt"]["status"]="HOLD_SECURITY"
        with self.assertRaisesRegex(ValueError,"SPARSE_NATIVE_SECURITY_NOT_VERIFIED"):
            await m.admit_sparse(rom,plan,**args)
        self.assertFalse(rom.trace)

    async def test_unexpected_current_nv_drift_holds_before_erase(self):
        rom,plan,args=await scenario()
        rom.image[0xA4000]^=1
        with self.assertRaisesRegex(ValueError,"SPARSE_BASELINE_DRIFT"):
            await m.admit_sparse(rom,plan,**args)
        self.assertFalse(rom.trace)

    async def test_mismatched_synthetic_proof_holds(self):
        rom,plan,args=await scenario()
        args["sparse_receipt"]["nv_bytes_read"]=0
        with self.assertRaisesRegex(ValueError,"SPARSE_LIVE_CAPTURE_EVIDENCE_INVALID"):
            await m.admit_sparse(rom,plan,**args)
        self.assertFalse(rom.trace)

    async def test_tampered_sparse_receipt_is_rejected_before_erase(self):
        rom,plan,args=await scenario()
        admission=await m.admit_sparse(rom,plan,**args)
        altered=dict(args["sparse_receipt"],baseline_nv_changed_sectors=123)
        async def journal(event):self.fail("no irreversible action allowed")
        with self.assertRaisesRegex(ValueError,"SPARSE_RECEIPT_CHANGED_BEFORE_EXECUTION"):
            await m.execute(rom,plan,admission,
               expected_plan_sha256=args["expected_plan_sha256"],
               expected_admission_sha256=admission["admission_sha256"],
               capture_receipt=altered,
               expected_capture_receipt_sha256=args["expected_sparse_receipt_sha256"],
               expected_live_identity_sha256=LIVE,
               journal=journal,same_session_sparse=True)
        self.assertFalse(rom.trace)

    async def test_wrong_mode_mixing_never_erases(self):
        rom,plan,args=await scenario()
        admission=await m.admit_sparse(rom,plan,**args)
        async def journal(event):self.fail("should not journal")
        common=dict(expected_plan_sha256=args["expected_plan_sha256"],
          expected_admission_sha256=admission["admission_sha256"],
          capture_receipt=args["sparse_receipt"],
          expected_capture_receipt_sha256=args["expected_sparse_receipt_sha256"],
          expected_live_identity_sha256=LIVE,journal=journal)
        with self.assertRaisesRegex(ValueError,"SAME_TRANSPORT_SHA_ADMISSION_REQUIRED"):
            await m.execute(rom,plan,admission,**common,same_session_fast=True)
        self.assertFalse(rom.trace)

    async def test_sparse_seal_lifetime_and_reopen_guard(self):
        for fault in ("expired","reopen"):
            rom,plan,args=await scenario()
            admission=await m.admit_sparse(rom,plan,**args)
            if fault=="expired":
                m._SAME_SESSION_ADMISSIONS[rom]["admitted_monotonic"]-=120
            else:
                rom.writer=object()
            async def journal(event):self.fail("should not journal")
            with self.subTest(fault=fault),self.assertRaisesRegex(
                    ValueError,"SAME_TRANSPORT_SPARSE_ADMISSION_REQUIRED"):
                await m.execute(rom,plan,admission,
                  expected_plan_sha256=args["expected_plan_sha256"],
                  expected_admission_sha256=admission["admission_sha256"],
                  capture_receipt=args["sparse_receipt"],
                  expected_capture_receipt_sha256=args["expected_sparse_receipt_sha256"],
                  expected_live_identity_sha256=LIVE,
                  journal=journal,same_session_sparse=True)
            self.assertFalse(rom.trace)

    async def test_sparse_guard_catches_final_ccfg_drift_before_erase(self):
        rom,plan,args=await scenario()
        admission=await m.admit_sparse(rom,plan,**args)
        rom.image[m.TOP]^=1
        async def journal(event):self.fail("should not journal")
        with self.assertRaisesRegex(ValueError,"STATE_CHANGED_AFTER_SPARSE_ADMISSION"):
            await m.execute(rom,plan,admission,
              expected_plan_sha256=args["expected_plan_sha256"],
              expected_admission_sha256=admission["admission_sha256"],
              capture_receipt=args["sparse_receipt"],
              expected_capture_receipt_sha256=args["expected_sparse_receipt_sha256"],
              expected_live_identity_sha256=LIVE,journal=journal,same_session_sparse=True)
        self.assertFalse(rom.trace)

if __name__=="__main__":
    unittest.main()
