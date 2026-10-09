"""Compile the actual SDK-patched R11 recorder under the existing host stubs."""
import argparse
from pathlib import Path
import subprocess
import shutil
import tempfile
p=argparse.ArgumentParser();p.add_argument('--sdk',type=Path,required=True);p.add_argument('--pages',required=True)
p.add_argument('--dump',type=Path,default=None);a=p.parse_args()
root=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory() as folder:
    overlay=Path(folder)
    # Quote-includes search beside the implementation before -I. Copy the
    # exact runtime bytes only, so platform includes resolve to test stubs.
    for name in ('t832_diag_impl.inc','t832_diag.h','t832_diag_r5.inc','t832_fatal.h','r6_nv_export.inc','nv_r6_probe.h','r11_startup.h','r11_ext_export.inc'):
        shutil.copy2(a.sdk/'source/ti/zstack/mt'/name,overlay/name)
    shutil.copy2(a.sdk/'source/ti/common/nv/nv_r6_probe.inc',overlay/'nv_r6_probe.inc')
    subprocess.run(['gcc','-std=c11','-DNVOCMP_NVPAGES='+a.pages,
                    '-I'+str(overlay),'-I'+str(root/'host_harness'),
                    '-I'+str(root/'host_harness/stubs'),str(root/'r6/r11_host_test.c'),
                    '-Wl,--wrap=malloc','-Wl,--wrap=calloc','-Wl,--wrap=realloc','-Wl,--wrap=free',
                    '-o',str(overlay/'r11-observer-test')],check=True)
    command=[str(overlay/'r11-observer-test')]
    if a.dump:command+=['dump',str(a.dump)]
    subprocess.run(command,check=True)
