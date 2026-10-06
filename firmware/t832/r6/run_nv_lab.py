"""Host regression runner. Run only in GitHub-hosted Actions, never on HA."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from nv_contract import budget

HERE=Path(__file__).resolve().parent

def compile_lab(sdk,out,contract,pages=None):
    p=contract['capacities'];exe=out/'nv-population'
    command=['gcc','-std=c11','-O1','-g','-D_GNU_SOURCE','-DNV_LINUX','-DNVOCMP_POSIX_MUTEX',
             '-DDeviceFamily_CC26X4','-DNVOCMP_NVPAGES='+str(pages or contract['nvs_pages']),
             '-DTCLK_COUNT='+str(p['tc_devices']),'-DDEVICE_COUNT='+str(p['device_list']),
             '-DADDRESS_COUNT='+str(p['addresses']),'-DMINIMUM_FREE_BYTES='+str(0 if pages else contract['minimum_free_bytes']),
             '-I'+str(HERE),'-I'+str(sdk/'source'),'-I'+str(sdk/'source/ti/common/nv'),
             str(sdk/'source/ti/common/nv/nvocmp.c'),str(sdk/'source/ti/common/nv/crc.c'),
             str(HERE/'nv_linux.c'),str(HERE/'nv_population.c'),'-pthread','-o',str(exe)]
    subprocess.run(command,check=True)
    return exe

def operation(exe,image,verb,cut=None):
    env=dict(os.environ,NVLAB_IMAGE=str(image))
    env.pop('NVLAB_CUT_OP',None)
    if cut is not None:env['NVLAB_CUT_OP']=str(cut)
    result=subprocess.run([str(exe),verb],env=env,capture_output=True,text=True,timeout=30)
    if cut is not None and result.returncode==77:return {'power_cut':cut}
    if result.returncode:raise RuntimeError(f'{verb}: exit={result.returncode}: {result.stderr}')
    return json.loads(result.stdout)

def run(sdk,out):
    out.mkdir(parents=True,exist_ok=False)
    head=subprocess.check_output(['git','-C',str(sdk),'rev-parse','HEAD'],text=True).strip()
    if head!='6499c3f53fc5fb5806213be695450a7b43fbaf3d':raise ValueError('SDK pin mismatch')
    report={'sdk_commit':head,'real_algorithm_sha256':hashlib.sha256((sdk/'source/ti/common/nv/nvocmp.c').read_bytes()).hexdigest(),'profiles':{},'hardware_validated':False}
    for profile in ('production-demand','capacity-400'):
        contract=budget(profile);folder=out/profile;folder.mkdir();exe=compile_lab(sdk,folder,contract)
        image=folder/'population.bin'
        seed=operation(exe,image,'seed');exercise=operation(exe,image,'exercise');verify=operation(exe,image,'verify')
        # Each subprocess is a real reopen: driver static state is not retained.
        baseline=folder/'fault-base.bin';shutil.copyfile(image,baseline)
        measured=operation(exe,image,'compact')['physical_operations']
        cuts=sorted({1,2,3,4,5,6,7,8,9,10,measured//4,measured//2,3*measured//4,measured-1,measured})
        cuts=[n for n in cuts if n>0 and n<=measured]
        for cut in cuts:
            damaged=folder/f'cut-{cut}.bin';shutil.copyfile(baseline,damaged)
            result=operation(exe,damaged,'compact',cut)
            if result.get('power_cut')!=cut:raise ValueError('fault not reached')
            operation(exe,damaged,'verify')
        report['profiles'][profile]={'budget':contract,'seed':seed,'exercise':exercise,'reopen':verify,'compaction_operations':measured,'power_cut_points_verified':cuts}
    negative=out/'five-page-negative';negative.mkdir()
    exe=compile_lab(sdk,negative,budget('capacity-400'),pages=5)
    report['five_page_400_negative_control']=operation(exe,negative/'full.bin','repro')
    (out/'nv-lab-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--sdk',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();print(json.dumps(run(a.sdk.resolve(),a.out.resolve()),indent=2))
