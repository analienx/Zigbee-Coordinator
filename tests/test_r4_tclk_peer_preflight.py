"""Small compiled check of the actual B1 restored-TCLK identity guard."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1] / 'firmware/slzb-06p7u/r4/b1/tools'
sys.path.insert(0, str(TOOLS))
from make_security_harness import PREAMBLE, peer_storage  # noqa: E402
from patch_security import SUPPORT  # noqa: E402
from patch_zdapp import extract_function  # noqa: E402


SIGNATURES = (
    'static uint8_t b1_sec_validate_nib(uint8_t onNetwork)',
    'static uint16_t b1_tclk_peer_bucket(const uint8_t *addr)',
    'static uint8_t b1_tclk_unique_peer(uint16_t index, const uint8_t *addr)',
    'int b1_sec_validate_restored(void)',
    'int b1_sec_restored_network_validated(void)',
)

MAIN = r'''
int main(int argc, char **argv)
{
  assert(argc == 2);
  setup();
  if (!strcmp(argv[1], "duplicate")) {
    tc[1].extAddr[0] = tc[0].extAddr[0];
    assert(!b1_sec_validate_restored() && held);
  } else if (!strcmp(argv[1], "duplicate_last")) {
    tc[gZDSECMGR_TC_DEVICE_MAX - 1u].extAddr[0] = tc[0].extAddr[0];
    assert(!b1_sec_validate_restored() && held);
  } else if (!strcmp(argv[1], "broadcast")) {
    memset(tc[0].extAddr, 0xff, Z_EXTADDR_LEN);
    assert(!b1_sec_validate_restored() && held);
  } else if (!strcmp(argv[1], "collision")) {
    uint16_t bucket = b1_tclk_peer_bucket(tc[0].extAddr);
    uint8_t found = FALSE;
    for (unsigned a = 1u; a < 256u && !found; ++a)
      for (unsigned b = 0u; b < 256u && !found; ++b) {
        memset(tc[1].extAddr, 0, Z_EXTADDR_LEN);
        tc[1].extAddr[0] = (uint8_t)a;
        tc[1].extAddr[1] = (uint8_t)b;
        if (b1_tclk_peer_bucket(tc[1].extAddr) == bucket) found = TRUE;
      }
    assert(found && !OsalPort_memcmp(tc[0].extAddr, tc[1].extAddr, Z_EXTADDR_LEN));
    assert(b1_sec_validate_restored() && !held);
  } else if (!strcmp(argv[1], "clean")) {
    assert(b1_sec_validate_restored() && !held);
    assert(b1_sec_validate_restored() && !held); /* scratch reset on recheck */
  } else abort();
  assert(writes == 0 && creates == 0 && erases == 0);
  puts("TCLK_PRECHECK_PASS");
  return 0;
}
'''


@unittest.skipUnless(shutil.which('gcc'), 'gcc is required for the bounded C check')
class ActualRestoredTclkIdentity(unittest.TestCase):
    def test_real_patch_functions_compile_and_reject_ambiguous_peers(self):
        with tempfile.TemporaryDirectory(prefix='r4-tclk-preflight-') as root:
            for tc_count in (4, 300):
                preamble = PREAMBLE.replace('#define gZDSECMGR_TC_DEVICE_MAX 4u',
                                            f'#define gZDSECMGR_TC_DEVICE_MAX {tc_count}u')
                code = (preamble + peer_storage(SUPPORT) +
                        '\n'.join(extract_function(SUPPORT, s) for s in SIGNATURES) + MAIN)
                source = Path(root) / f'guard-{tc_count}.c'
                executable = Path(root) / f'guard-{tc_count}'
                source.write_text(code, encoding='utf-8')
                compiled = subprocess.run(
                    ['gcc', '-std=c11', '-O1', '-Wall', '-Wextra',
                     '-Wno-unused-function', '-Wno-unused-parameter',
                     '-Wno-unused-variable', str(source), '-o', str(executable)],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                for scenario in ('clean', 'duplicate', 'duplicate_last',
                                 'broadcast', 'collision'):
                    with self.subTest(tc_count=tc_count, scenario=scenario):
                        result = subprocess.run([str(executable), scenario],
                                                capture_output=True, text=True, timeout=5)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn('TCLK_PRECHECK_PASS', result.stdout)

    def test_missing_native_peer_storage_declaration_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'SECURITY_TC_PEER_STORAGE_SOURCE_DRIFT'):
            peer_storage(SUPPORT.replace('B1_TCLK_PEER_BUCKETS 512u',
                                         'B1_TCLK_PEER_BUCKETS 511u'))


if __name__ == '__main__':
    unittest.main()
