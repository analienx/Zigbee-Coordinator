"""V47 source composition, one-shot edits and B1 safety gates (offline)."""
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from r4_startup_ingress_priority import TASK, ZDO, apply

NPI="""/* B4_F2_V6_OWNED_STAGE */
/* B4_V46_PENDING_SRSP_TASK_PRIORITY */
#define B4_V46_SRSP_PRIORITY 6
__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)
{
    unsigned int schedulerKey = Task_disable();
    uint32_t key = OsalPort_enterCS();
    uint8_t urgent = B4_V44_SrspQueue != NULL &&
                     !b1_management_transport_unavailable() &&
                     !Queue_empty(B4_V44_SrspQueue);
    OsalPort_leaveCS(key);
    /* Unsupported RTOS configurations preserve the original safe priority.
     * Native qualification must independently bind numPriorities >= 8. */
    int priority = urgent && Task_numPriorities > B4_V46_SRSP_PRIORITY ?
                   B4_V46_SRSP_PRIORITY : NPITASK_PRIORITY;
    Task_Handle task = Task_handle(&npiTaskStruct);
    if (Task_getPri(task) != priority)
        (void)Task_setPri(task, priority);
    Task_restore(schedulerKey);
}
"""

ZDO_BODY="""#define B1_RETAINED_STARTUP_EVENT 0x00010000u
void b1_mt_zdo_retained_startup_event(void)
{
  if (!b1_startup_begin()) return;
  (void)OsalPortTimers_stopTimer(ZDAppTaskID, B1_RETAINED_STARTUP_EXPIRE_EVENT);
  if (b1_mt_zdo_retained_valid() != ZSuccess) return;
  if (!b1_startup_checkpoint(B1_PHASE_BDB)) return;
  b1_evidence_milestone(B1_M_RETAINED_DISPATCH, 0u);
  b1_evidence_milestone(B1_M_BDB_ENTRY, 0u);
  bdb_StartCommissioning(0); /* Initialize original network only, once per boot. */
  b1_evidence_milestone(B1_M_BDB_RETURN, 0u);
}
"""

class TestV47(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix="p7u-v47-source-")
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.npi=self.root/TASK
        self.zdo=self.root/ZDO
        for f in (self.npi,self.zdo):
            f.parent.mkdir(parents=True,exist_ok=True)
        self.npi.write_text(NPI)
        self.zdo.write_text(ZDO_BODY)

    def test_exact_b1_event_not_ti_formation(self):
        result=apply(self.root)
        self.assertEqual(result["schema"],"p7u-v47-bounded-b1-npi-ingress-v1")
        self.assertFalse(result["root_cause_proven"])
        self.assertFalse(result["flash_authorized"])
        npi=self.npi.read_text()
        zdo=self.zdo.read_text()
        self.assertEqual(npi.count("B4_V47_ArmStartupNpi(void)"),1)
        self.assertEqual(zdo.count("B4_V47_ArmStartupNpi();"),1)
        self.assertLess(zdo.index("if (!b1_startup_begin()) return;"),
                        zdo.index("B4_V47_ArmStartupNpi();"))
        self.assertLess(zdo.index("B4_V47_ArmStartupNpi();"),
                        zdo.index("bdb_StartCommissioning(0)"))
        self.assertNotIn("BDB_COMMISSIONING_MODE_NWK_FORMATION",zdo)
        self.assertIn("Clock_getTicks() - B4_V47_StartTick",npi)
        self.assertIn("b1_management_transport_unavailable()",npi)

    def test_double_application_denied_without_mutation(self):
        apply(self.root)
        a,b=self.npi.read_bytes(),self.zdo.read_bytes()
        with self.assertRaisesRegex(ValueError,"V47_ALREADY_APPLIED"):
            apply(self.root)
        self.assertEqual(self.npi.read_bytes(),a)
        self.assertEqual(self.zdo.read_bytes(),b)

    def test_missing_guarded_b1_event_denied(self):
        self.zdo.write_text(ZDO_BODY.replace(
            "b1_mt_zdo_retained_startup_event","TI_wrong_entry"))
        with self.assertRaises(ValueError):
            apply(self.root)
        self.assertEqual(self.npi.read_text(),NPI)

    def test_no_b1_security_or_original_bdb_change(self):
        original=self.zdo.read_text()
        apply(self.root)
        modified=self.zdo.read_text()
        self.assertIn("if (!b1_startup_begin()) return;",modified)
        self.assertIn("if (!b1_startup_checkpoint(B1_PHASE_BDB)) return;",modified)
        self.assertEqual(modified.count("bdb_StartCommissioning(0)"),1)
        self.assertEqual(modified.count("b1_startup_checkpoint(B1_PHASE_BDB)"),1)
        self.assertEqual(modified.count("OsalPortTimers_stopTimer("),1)

    def test_v46_missing_rejected(self):
        self.npi.write_text(NPI.replace(
            "B4_V46_PENDING_SRSP_TASK_PRIORITY","unqualified"))
        with self.assertRaisesRegex(ValueError,"V47_COMPOSITE_PREIMAGE_DRIFT"):
            apply(self.root)

if __name__=="__main__":
    unittest.main()
