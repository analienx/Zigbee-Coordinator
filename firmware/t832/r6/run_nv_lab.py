"""Host regression runner. Run only in GitHub-hosted Actions, never on HA."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
from nv_contract import budget

HERE=Path(__file__).resolve().parent

def compile_lab(sdk,out,contract,pages=None,diagnostic=False):
    p=contract['capacities'];exe=out/'nv-population'
    from nv_recovery_fix import apply_fix as apply_recovery_fix,verify_fixed as verify_recovery_fixed,FIX_ID as RECOVERY_FIX_ID
    nv_source=out/'nvocmp.c';shutil.copy2(sdk/'source/ti/common/nv/nvocmp.c',nv_source)
    fix_edits=apply_recovery_fix(nv_source)
    fix_fingerprint=verify_recovery_fixed(nv_source.read_text())
    if len(fix_edits)!=5 or fix_fingerprint['fix_id']!=RECOVERY_FIX_ID:raise ValueError('recovery fix not applied to lab source')
    if diagnostic:
        from r6_observer import patch_nv
        patch_nv(nv_source)
    command=['gcc','-std=c11','-O1','-g','-D_GNU_SOURCE','-DNV_LINUX','-DNVOCMP_POSIX_MUTEX',
             '-DDeviceFamily_CC26X4','-DNVOCMP_NVPAGES='+str(pages or contract['nvs_pages']),
             '-DTCLK_COUNT='+str(p['tc_devices']),'-DDEVICE_COUNT='+str(p['device_list']+1),
             '-DADDRESS_COUNT='+str(p['addresses']),'-DMINIMUM_FREE_BYTES='+str(0 if pages else contract['minimum_free_bytes']),
             '-I'+str(HERE),'-I'+str(sdk/'source'),'-I'+str(sdk/'source/ti/common/nv'),
             str(nv_source),str(sdk/'source/ti/common/nv/crc.c'),
             str(HERE/'nv_linux.c'),str(HERE/'nv_population.c'),'-pthread','-o',str(exe)]
    if diagnostic:command[1:1]=['-DT832_NVLAB_DIAG=1','-I'+str(out)]
    subprocess.run(command,check=True)
    (out/'recovery-fix.json').write_text(json.dumps(fix_fingerprint,indent=2)+'\n')
    return exe

def operation(exe,image,verb,cut=None):
    env=dict(os.environ,NVLAB_IMAGE=str(image))
    env.pop('NVLAB_CUT_OP',None)
    if cut is not None:env['NVLAB_CUT_OP']=str(cut)
    result=subprocess.run([str(exe),verb],env=env,capture_output=True,text=True,timeout=30)
    if cut is not None and result.returncode==77:return {'power_cut':cut}
    if result.returncode:raise RuntimeError(f'{verb}: exit={result.returncode}: {result.stderr} {result.stdout}')
    return json.loads(result.stdout)

def run(sdk,out,profiles=('production-demand','capacity-400')):
    out.mkdir(parents=True,exist_ok=False)
    head=subprocess.check_output(['git','-C',str(sdk),'rev-parse','HEAD'],text=True).strip()
    if head!='6499c3f53fc5fb5806213be695450a7b43fbaf3d':raise ValueError('SDK pin mismatch')
    report={'sdk_commit':head,'real_algorithm_sha256':hashlib.sha256((sdk/'source/ti/common/nv/nvocmp.c').read_bytes()).hexdigest(),'profiles':{},'hardware_validated':False}
    for profile,variant in ((p,v) for p in profiles for v in ('BASE','DIAG')):
        contract=budget(profile);folder=out/(profile+'-'+variant);folder.mkdir();exe=compile_lab(sdk,folder,contract,diagnostic=variant=='DIAG')
        image=folder/'population.bin'
        seed=operation(exe,image,'seed')
        if variant=='DIAG':
            observer_image=folder/'observer-api.bin';shutil.copyfile(image,observer_image)
            observer=operation(exe,observer_image,'observer-api')
        exercise=operation(exe,image,'exercise');verify=operation(exe,image,'verify')
        operation(exe,image,'anchor')
        operation(exe,image,'churn')
        readonly=folder/'readonly-reopen.bin';shutil.copyfile(image,readonly)
        readonly_before=hashlib.sha256(readonly.read_bytes()).hexdigest()
        operation(exe,readonly,'verify')
        readonly_after=hashlib.sha256(readonly.read_bytes()).hexdigest()
        readonly_unchanged=(readonly_before==readonly_after)
        if not readonly_unchanged:raise ValueError('read-only reopen mutated '+profile+'-'+variant)
        # Each subprocess is a real reopen: driver static state is not retained.
        baseline=folder/'fault-base.bin';shutil.copyfile(image,baseline)
        measured=operation(exe,image,'compact')['physical_operations']
        if not 6<measured<=4096:raise ValueError('compaction fixture must transfer actual live data with bounded operations')
        # The vendor-20240716 fixture cuts EVERY physical compaction operation.
        # Other profiles keep the bounded sample (first/last 32 plus 64 spread).
        # Electrical partial writes and every full-store interleaving remain
        # outside this bounded hosted characterization.
        if profile=='vendor-20240716':
            cuts=list(range(1,measured+1))
        else:
            cuts=sorted(set(range(1,min(measured,32)+1))|set(range(max(1,measured-31),measured+1))|{max(1,i*measured//64) for i in range(1,65)})
        unresolved=[];passed=[];write_proofs=[]
        for cut in cuts:
            damaged=folder/f'cut-{cut}.bin';shutil.copyfile(baseline,damaged)
            result=operation(exe,damaged,'compact',cut)
            if result.get('power_cut')!=cut:raise ValueError('fault not reached')
            reopened=folder/f'reopen-{cut}.bin';shutil.copyfile(damaged,reopened)
            try:
                anchor_check=operation(exe,reopened,'verify-anchor')
                proof=folder/f'write-proof-{cut}.bin';shutil.copyfile(damaged,proof)
                try:
                    proof_check=operation(exe,proof,'write-proof')
                except RuntimeError as proof_error:
                    unresolved.append({'cut':cut,'operations':measured,'error':str(proof_error),'classification':'UNRESOLVED_POST_CUT_WRITE_PROOF','recovery_accepted':False});continue
                if proof_check['free_bytes']<contract['minimum_free_bytes']:
                    unresolved.append({'cut':cut,'operations':measured,'error':'write-proof headroom=%u required=%u'%(proof_check['free_bytes'],contract['minimum_free_bytes']),'classification':'UNRESOLVED_POST_CUT_WRITE_PROOF_HEADROOM','recovery_accepted':False});continue
                if proof_check['free_bytes']!=anchor_check['free_bytes']:
                    unresolved.append({'cut':cut,'operations':measured,'error':'nondeterministic free boot1=%u boot2=%u'%(anchor_check['free_bytes'],proof_check['free_bytes']),'classification':'UNRESOLVED_POST_CUT_NONDETERMINISM','recovery_accepted':False});continue
                write_proofs.append(cut);passed.append(cut)
            except RuntimeError as error:
                # Keep the exact interruption immutable. Do not convert data
                # loss, an assertion or another error into a green result.
                headroom_failure=re.fullmatch(r'verify-anchor: exit=62: (?:flash program rejected 0-to-1: page=\d+ offset=\d+ bytes=\d+\n)*headroom=(\d+) required=(\d+)\s*',str(error))
                if profile=='vendor-20240716' and headroom_failure:
                    inspection=folder/f'negative-headroom-{cut}.bin';shutil.copyfile(damaged,inspection)
                    readable=operation(exe,inspection,'verify-known-headroom-failure')
                    if readable['required_bytes']!=contract['minimum_free_bytes'] or readable['free_bytes']>=readable['required_bytes']:
                        raise ValueError('interrupted-compaction headroom failure not reproduced')
                    unresolved.append({'cut':cut,'operations':measured,'error':str(error),'negative_control':readable,
                        'classification':'UNRESOLVED_POST_CUT_FLASH_PROGRAM_AND_HEADROOM' if 'flash program rejected' in str(error) else 'UNRESOLVED_POST_CUT_HEADROOM',
                        'recovery_accepted':False})
                    continue
                if 'init index=0 status=1' not in str(error) or 'flash program rejected 0-to-1: page=' not in str(error):raise
                inspection=folder/f'negative-init-{cut}.bin';shutil.copyfile(damaged,inspection)
                readable=operation(exe,inspection,'verify-known-init-failure')
                unresolved.append({'cut':cut,'operations':measured,'error':str(error),'negative_control':readable,
                                   'classification':'UNRESOLVED_UPSTREAM_RECOVERY','recovery_accepted':False})
        mutation_image=folder/'mutation-measure.bin';shutil.copyfile(baseline,mutation_image)
        mutation_ops=operation(exe,mutation_image,'mutate')['physical_operations']
        if not 0<mutation_ops<=4096:raise ValueError('mutation fault fixture outside bounds')
        for cut in range(1,mutation_ops+1):
            damaged=folder/f'mutation-cut-{cut}.bin';shutil.copyfile(baseline,damaged)
            result=operation(exe,damaged,'mutate',cut)
            if result.get('power_cut')!=cut:raise ValueError('mutation fault not reached')
            operation(exe,damaged,'verify-cut')
        report['profiles'][profile+'-'+variant]={'budget':contract,'seed':seed,'exercise':exercise,'reopen':verify,'compaction_operations':measured,'power_cut_points_tested':cuts,'power_cut_points_verified':passed,'power_cut_points_write_proof':write_proofs,'unresolved_recovery_negative_controls':unresolved,'mutation_operations':mutation_ops,'mutation_cut_points_verified':list(range(1,mutation_ops+1)),'readonly_reopen_unchanged':readonly_unchanged,'readonly_reopen_sha256':[readonly_before,readonly_after]}
        if variant=='DIAG':report['profiles'][profile+'-'+variant]['observer_api_contract']=observer
    negative=out/'five-page-negative';negative.mkdir()
    exe=compile_lab(sdk,negative,budget('capacity-400'),pages=5)
    report['five_page_400_negative_control']=operation(exe,negative/'full.bin','repro')
    # Characterize PR #40's preserved-geometry proposal without pretending
    # guessed table occupancy is a household fixture. All TCLK slots exist;
    # 104 addresses models the published device count; child NV occupancy
    # varies explicitly. Results are evidence, not a hardware release gate.
    report['preserved_five_page_112_characterization']=[]
    for child_records in (4,14,20,36,50,76):
        folder=out/f'five-page-112-children-{child_records}';folder.mkdir()
        contract=budget('production-demand')
        contract['capacities']=dict(contract['capacities'],tc_devices=112,device_list=child_records-1,addresses=104)
        executable=compile_lab(sdk,folder,contract,pages=5)
        image=folder/'population.bin';env=dict(os.environ,NVLAB_IMAGE=str(image));env.pop('NVLAB_CUT_OP',None)
        seed=subprocess.run([str(executable),'seed'],env=env,capture_output=True,text=True,timeout=30)
        row={'tclk_slots':112,'addresses':104,'child_records':child_records,'other_payload_bytes':1600,
             'seed_returncode':seed.returncode,'seed_status':seed.stderr.strip(),
             'synthetic_assumptions_only':True,'hardware_validated':False}
        if seed.returncode==0:
            row['seed']=json.loads(seed.stdout)
            lifecycle=subprocess.run([str(executable),'exercise'],env=env,capture_output=True,text=True,timeout=30)
            row['lifecycle']={'returncode':lifecycle.returncode,'status':lifecycle.stderr.strip()}
            if lifecycle.returncode==0:
                row['lifecycle']['result']=json.loads(lifecycle.stdout);row['reopen']=operation(executable,image,'verify')
            elif lifecycle.returncode not in (21,25):raise RuntimeError('unexpected characterization lifecycle error '+lifecycle.stderr)
        elif seed.returncode!=21:raise RuntimeError('unexpected characterization failure: '+seed.stderr)
        report['preserved_five_page_112_characterization'].append(row)
    # PR40 used 112 TCLK slots AND 76 device slots AND 197 addresses.
    # Test all three configured families, not only the occupied backup rows.
    # A failed real-driver population is a deployment rejection even if a
    # tiny write happens to fit in the remaining fragment.
    if 'vendor-20240716' in profiles:
        folder=out/'pr40-full-capacity-negative';folder.mkdir()
        contract=budget('vendor-20240716')
        contract['capacities']=dict(contract['capacities'],tc_devices=112,device_list=75,addresses=197)
        executable=compile_lab(sdk,folder,contract,pages=5)
        env=dict(os.environ,NVLAB_IMAGE=str(folder/'population.bin'));env.pop('NVLAB_CUT_OP',None)
        result=subprocess.run([str(executable),'seed'],env=env,capture_output=True,text=True,timeout=30)
        if result.returncode!=21 or 'status=1' not in result.stderr:
            raise ValueError('PR40 full-capacity negative control did not reject allocation')
        report['pr40_full_capacity_negative_control']={'tclk_slots':112,'device_records':76,'address_records':197,
            'pages':5,'seed_returncode':result.returncode,'allocation_failure':result.stderr.strip(),
            'deployment_rejected':True,'synthetic_table_sized_records':True,'hardware_validated':False}
    fps=[]
    for fix_json in sorted(out.rglob('recovery-fix.json')):
        fps.append(json.loads(fix_json.read_text()))
    if not fps:raise ValueError('recovery fix evidence missing')
    if any(fp!=fps[0] for fp in fps):raise ValueError('lab algorithm skew across fixtures')
    report['recovery_fix']=fps[0]
    report['all_power_cut_recovery_passed']=all(not p['unresolved_recovery_negative_controls'] and p['power_cut_points_write_proof']==p['power_cut_points_verified'] and p['readonly_reopen_unchanged'] for p in report['profiles'].values())
    report['scope']='Normal NV lifecycle release evidence; power-cut characterization and known negative controls are reported separately, never recovery acceptance.'
    (out/'nv-lab-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--sdk',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--profiles',nargs='+',choices=['production-demand','capacity-400','vendor-20240716'],default=['production-demand','capacity-400'])
    a=p.parse_args();print(json.dumps(run(a.sdk.resolve(),a.out.resolve(),a.profiles),indent=2))
