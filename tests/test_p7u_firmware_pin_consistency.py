"""One exact paired firmware SHA everywhere; no unflashed predecessor left behind."""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/release"))
import p7u_r4_startup_observer as observer

# Committed but never flashed; a stale pin to any of them is a partial re-pin.
SUPERSEDED = ("540d75a23d11587fb45fd892c5e9ae01ec0aab15",
              "e31a07579e06cfde261b3531ae1061d47fd975f5",
              "2b3d737bbd447215e1c10ddbc288be649c55e1b5")
PINNED_FILES = ("host/flash/p7u_paired_binding.py", "host/flash/p7u_paired_hold.py",
                "host/flash/p7u_pr154_ha.py", "tools/package_p7u_pr154_ha.py",
                "firmware/slzb-06p7u/r4/release/p7u_r4_startup_observer.py")


class FirmwarePinConsistency(unittest.TestCase):
    def test_single_current_source_for_every_evidence_generation(self):
        # The newest generation is one exact source; it must also be in
        # every older evidence set it still answers.
        self.assertEqual(len(observer.V53_SOURCES), 1)
        self.assertEqual(observer.V50_SOURCES, observer.V51_SOURCES)
        self.assertEqual(observer.V51_SOURCES, observer.V52_SOURCES)
        self.assertLessEqual(observer.V53_SOURCES, observer.V52_SOURCES)
        (current,) = observer.V53_SOURCES
        self.assertRegex(current, "^[0-9a-f]{40}$")
        self.assertEqual(observer.expected_ready_npi_priority(current), 6)
        for name in PINNED_FILES:
            text = (ROOT / name).read_text()
            self.assertIn(current, text, name)
            for stale in SUPERSEDED:
                self.assertNotIn(stale, text, name + " still pins " + stale[:8])

    def test_no_other_repository_file_pins_a_superseded_source(self):
        hits = []
        for path in list((ROOT / "host").rglob("*.py")) + list((ROOT / "tools").rglob("*.py")) + \
                list((ROOT / "firmware/slzb-06p7u/r4/release").rglob("*.py")):
            text = path.read_text(errors="ignore")
            hits += [str(path.relative_to(ROOT)) for stale in SUPERSEDED if stale in text]
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
