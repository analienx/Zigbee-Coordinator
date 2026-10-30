"""V49 READY-to-poststart NPI scheduling regression on exact V47 helper seam."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from r4_ready_npi_priority import apply,TASK,MARKER

SOURCE = """/* B4_F2_V6_OWNED_STAGE B4_V46_PENDING_SRSP_TASK_PRIORITY */
#define B4_V47_STARTUP_US 90000000u
/* B4_V47_BOUNDED_B1_STARTUP_NPI */
static volatile uint8_t B4_V47_Armed;
static uint32_t B4_V47_StartTick, B4_V47_WindowTicks;
static uint8_t B4_V47_ActiveLocked(void)
{
    if (!B4_V47_Armed) return 0u;
    if ((uint32_t)(Clock_getTicks() - B4_V47_StartTick) <
        B4_V47_WindowTicks) return 1u;
    B4_V47_Armed = 0u;
    return 0u;
}
__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void);
__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)
{
    unsigned int schedulerKey = Task_disable();
    uint32_t key = OsalPort_enterCS();
    uint8_t urgent = 0u;
    uint8_t startup = B4_V47_ActiveLocked();
    OsalPort_leaveCS(key);
    if (startup && (b1_startup_state() != B1_STARTUP_RUNNING ||
        b1_management_transport_unavailable()))
        startup = 0u;
    int priority = (urgent || startup) && Task_numPriorities > 6 ?
                   6 : NPITASK_PRIORITY;
    Task_restore(schedulerKey);
}
"""

class V49ReadyNpi(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix="v49-ready-npi-")
        self.addCleanup(t.cleanup)
        self.p=Path(t.name)/TASK
        self.p.parent.mkdir(parents=True,exist_ok=True)
        self.p.write_text(SOURCE)

    def test_exact_sticky_ready_and_ordinary_90s_timeout(self):
        out=apply(self.p.parents[4])
        actual=self.p.read_text()
        self.assertEqual(out["schema"],"p7u-v49-retained-ready-npi-owner-v1")
        self.assertFalse(out["flash_authorized"])
        self.assertEqual(actual.count(MARKER),1)
        self.assertIn("b1_startup_state() == B1_STARTUP_READY",actual)
        self.assertIn("b1_management_transport_unavailable()",actual)
        self.assertIn("B4_V47_ActiveLocked(retained_ready)",actual)
        if shutil.which("cc") is None: raise unittest.SkipTest("native C compiler needed")
        begin=actual.index("static uint8_t B4_V47_ActiveLocked(uint8_t retained_ready)")
        end=actual.index("__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void);",begin)
        helper=actual[begin:end]
        c="""#include <stdint.h>
static uint32_t fake_tick;
static uint32_t Clock_getTicks(void) { return fake_tick; }
""" + actual[actual.index("static volatile uint8_t B4_V47_Armed;"):begin] + helper + """
int main(void)
{
    B4_V47_Armed=0u; fake_tick=500u;
    B4_V47_StartTick=0u; B4_V47_WindowTicks=100u;
    if (B4_V47_ActiveLocked(1u)!=0u) return 11;
    B4_V47_Armed=1u;
    if (B4_V47_ActiveLocked(1u)!=1u || !B4_V47_Armed) return 12;
    if (B4_V47_ActiveLocked(0u)!=0u || B4_V47_Armed) return 13;
    B4_V47_Armed=1u; fake_tick=10u;
    if (B4_V47_ActiveLocked(0u)!=1u || !B4_V47_Armed) return 14;
    return 0;
}
"""
        root=self.p.parents[4]
        (root/"control.c").write_text(c)
        compile=subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                                str(root/"control.c"),"-o",str(root/"control")],
                               capture_output=True,text=True)
        self.assertEqual(compile.returncode,0,compile.stderr)
        run=subprocess.run([str(root/"control")],capture_output=True,text=True)
        self.assertEqual(run.returncode,0,run.stderr)

    def test_reapply_fails_closed_without_write(self):
        apply(self.p.parents[4])
        saved=self.p.read_bytes()
        with self.assertRaisesRegex(ValueError,"V49_ALREADY_APPLIED"):
            apply(self.p.parents[4])
        self.assertEqual(saved,self.p.read_bytes())

    def test_wrong_preimage_fails_closed(self):
        self.p.write_text(SOURCE.replace("B4_V47_BOUNDED_B1_STARTUP_NPI","MISSING"))
        with self.assertRaisesRegex(ValueError,"V49_REQUIRES_V48_V47_NPI"):
            apply(self.p.parents[4])
        self.assertNotIn(MARKER,self.p.read_text())
