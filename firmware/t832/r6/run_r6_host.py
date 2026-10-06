"""Compile the actual SDK-patched R6 recorder under the existing host stubs."""
import argparse
from pathlib import Path
import subprocess
p=argparse.ArgumentParser();p.add_argument('--sdk',type=Path,required=True);p.add_argument('--pages',required=True);a=p.parse_args()
root=Path(__file__).resolve().parent.parent
subprocess.run(['gcc','-std=c11','-DNVOCMP_NVPAGES='+a.pages,
                '-I'+str(a.sdk/'source/ti/zstack/mt'),'-I'+str(root/'host_harness'),
                '-I'+str(root/'host_harness/stubs'),str(root/'r6/r6_host_test.c'),
                '-Wl,--wrap=malloc','-Wl,--wrap=calloc','-Wl,--wrap=realloc','-Wl,--wrap=free',
                '-o','/tmp/r6-observer-test'],check=True)
subprocess.run(['/tmp/r6-observer-test'],check=True)
