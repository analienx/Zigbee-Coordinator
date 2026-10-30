"""V48 exact B1 retained-event fairness, no synthetic events or NV changes."""
import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from r4_retained_zdapp_fairness import apply, BEFORE, AFTER, STACK, MARKER

class V48(unittest.TestCase):
    def setUp(self):
        # Synthetic unit tests have no TI git worktree; the *native* pipeline
        # independently verifies the immutable TI SHA and real patch anchor.
        check=patch("r4_retained_zdapp_fairness.pinned_source",
                    return_value=b"static void stackTaskFxn(UArg a0, UArg a1)")
        check.start()
        self.addCleanup(check.stop)
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.stack=self.root/STACK
        self.stack.parent.mkdir(parents=True,exist_ok=True)
        self.stack.write_text(
            'static void stackTaskFxn(UArg a0, UArg a1)\n{\n'
            +BEFORE+'\n'
            '        b1_evidence_dispatch(idx, events);\n'
            '        if (events != 0u) Semaphore_post(stackSemHandle);\n'
            '}\n'
            'void bind(void){ b1_evidence_bind_pending(&zdAppServiceEvents); }\n'
        )
        other=self.root/"source/ti/zstack/npi/npi_task.c"
        other.parent.mkdir(parents=True,exist_ok=True)
        other.write_text("/* B4_F2_V6_OWNED_STAGE */")
        zd=self.root/"source/ti/zstack/stack/zdo/zd_app.c"
        zd.parent.mkdir(parents=True,exist_ok=True)
        zd.write_text("#define B1_RETAINED_STARTUP_EVENT 0x10000")
    def test_selection_changes_only_when_real_init_pending(self):
        r=apply(self.root)
        t=self.stack.read_text()
        self.assertEqual(r['schema'],"p7u-v48-retained-zdapp-fairness-v1")
        self.assertFalse(r['flash_authorized'])
        self.assertEqual(t.count(MARKER),1)
        self.assertIn("b1_retained_attempt_active()",t)
        self.assertIn("zdAppServiceEvents & (ZDO_NETWORK_INIT | ZDO_NETWORK_START)",t)
        self.assertIn("pTasksEvents[idx] == &zdAppServiceEvents",t)
        self.assertIn("if (*(pTasksEvents[idx]))",t)
        self.assertIn("Semaphore_post(stackSemHandle)",t)
        self.assertNotIn("OsalPort_setEvent(",t)
        self.assertNotIn("bdb_StartCommissioning(",t)
    def test_reapply_denied(self):
        apply(self.root)
        recorded=self.stack.read_bytes()
        with self.assertRaisesRegex(ValueError,"V48_ALREADY_APPLIED"):
            apply(self.root)
        self.assertEqual(recorded,self.stack.read_bytes())
    def test_unknown_scheduler_denied_without_write(self):
        old=self.stack.read_text().replace(BEFORE,"uint8_t idx=0;")
        self.stack.write_text(old)
        with self.assertRaises(ValueError):
            apply(self.root)
        self.assertEqual(self.stack.read_text(),old)
    def test_missing_b1_evidence_denied(self):
        self.stack.write_text(self.stack.read_text().replace(
            "b1_evidence_bind_pending(&zdAppServiceEvents)","unknown_binding()"))
        with self.assertRaisesRegex(ValueError,"V48_REQUIRES_EXACT_B1"):
            apply(self.root)

if __name__=="__main__":unittest.main()
