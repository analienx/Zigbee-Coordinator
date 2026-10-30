"""V48: real TI 8.33 selector regression, compiled with a perpetually ready NWK service.

The exact donor code preimages are source-bound in patch_security.patch_startup.
This is not native-build or hardware acceptance evidence.
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                       "firmware/slzb-06p7u/r4/b1/tools"))
from patch_security import patch_startup

DONOR = """#include "zstackconfig.h"
static void stackTaskFxn(UArg a0, UArg a1)
{
    while(1)
    {
      /* Block here until TIRTOS task gets an event */
      Semaphore_pend(stackSemHandle, BIOS_WAIT_FOREVER);

      uint8_t idx = 0;

     // copy the priority-based round-robin scheduler from OSAL
      do {
        if (*(pTasksEvents[idx]))  // Task is highest priority that is ready.
        {
          break;
        }
      } while (++idx < zstackTasksCnt);

      if (idx < zstackTasksCnt)
      {
        uint32_t events, key;
        key = OsalPort_enterCS();
        events = *(pTasksEvents[idx]);
        *(pTasksEvents[idx]) = 0;
        OsalPort_leaveCS(key);
        events = (zstackTasksArr[idx])( 0U, events );
        key = OsalPort_enterCS();
        *(pTasksEvents[idx]) |= events;  // Add back unprocessed events to the current task.
        OsalPort_leaveCS(key);
      }
    }
}
void register_services(void)
{
    MT_TaskInit( tmpServiceId );
    pTasksEvents[idx] = &zdAppServiceEvents;
    idx++;
}
"""

def extract_selector(src):
    begin = src.index("      uint8_t idx = ")
    end = src.index("      if (idx < zstackTasksCnt)", begin)
    selection = src[begin:end]
    cursor = ""
    if "b1_next_service" in selection:
        assert src.count("b1_next_service = (uint8_t)(idx + 1u);") == 1
        cursor = ("        b1_next_service = (uint8_t)(idx + 1u);\\n"
                  "        if (b1_next_service >= zstackTasksCnt) b1_next_service = 0u;")
    return selection, cursor

def run_c_selector(src):
    if not shutil.which("cc"):
        raise unittest.SkipTest("C compiler required for hosted scheduler behavior")
    selection, cursor = extract_selector(src)
    c = """#include <stdint.h>
int main(void)
{
    uint32_t word[7] = {0};
    uint32_t *pTasksEvents[7];
    const uint8_t zstackTasksCnt = 7u;
    uint8_t b1_next_service = 0u;
    unsigned init_processed = 0u;
    for (unsigned i=0; i<7; ++i) pTasksEvents[i] = &word[i];
    word[2] = 0xa070u;  /* continuously ready NWK */
    word[6] = 1u;       /* pending ZDApp ZDO_NETWORK_INIT */
    for (unsigned turn=0; turn<32; ++turn)
    {
""" + selection + """
      if (idx < zstackTasksCnt)
      {
""" + cursor + """
        if (idx == 6u) { ++init_processed; word[6] = 0u; }
        if (idx == 2u) word[2] = 0xa070u;
      }
    }
    return init_processed == 1u ? 0 : 12;
}
"""
    with tempfile.TemporaryDirectory(prefix="p7u-v48-fairness-") as tmp:
        p = Path(tmp)
        (p / "scheduler.c").write_text(c)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(p / "scheduler.c"), "-o", str(p / "scheduler")],
                       check=True, capture_output=True, text=True)
        return subprocess.run([str(p / "scheduler")], capture_output=True,
                              text=True).returncode

class V48FairStackTest(unittest.TestCase):
    def test_donor_starves_but_original_handlers_fair_selection_succeeds(self):
        self.assertEqual(run_c_selector(DONOR), 12)
        patched = patch_startup(DONOR)
        self.assertEqual(run_c_selector(patched), 0)
        self.assertIn("b1_evidence_dispatch(idx, events);", patched)
        self.assertIn("if (events != 0u) Semaphore_post(stackSemHandle);", patched)
        self.assertIn("if (!b1_sec_validate_restored()) return;", patched)

    def test_source_edit_is_fail_closed_and_not_idempotent(self):
        patched = patch_startup(DONOR)
        self.assertEqual(patched.count("b1_next_service = 0u;"), 2)
        self.assertIn("pTasksEvents[idx]", patched)
        with self.assertRaises(ValueError):
            patch_startup(patched)

if __name__ == "__main__":
    unittest.main()
