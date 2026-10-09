"""Hosted artifact gate: generated NVS, effective macros, map and exact BIN."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'deploy'))
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from t832_preflash_audit import ihex,management_container,decode
from audit_contract import memory_rows
from nv_contract import budget,check_macros,check_map,check_generated

def package(a):
    c=budget(a.profile);generated=a.generated.read_text();macros=a.macros.read_text();maptext=a.map.read_text()
    check_generated(generated,c);check_macros(macros,c);check_map(maptext,c)
    rows=memory_rows(maptext)
    if rows.get('SRAM',{}).get('unused',0)<8192:raise ValueError('SRAM margin below 8 KiB')
    if a.series=='R11' and (c['nvs_base'],c['nvs_bytes'])!=(0xF8800,0x7800):raise ValueError('R11 FLASH_NV must be exactly 0x7800 at 0xF8800')
    memory=ihex(a.hex.read_bytes())
    if any(c['nvs_base']<=address<1048576 for address in memory):raise ValueError('image contains NV region bytes')
    offsets={k:int(v,16) for k,v in re.findall(r'^#define CCFG_O_(\w+)\s+(0x[\da-fA-F]+)',a.header.read_text(),re.M)}
    cfg=decode(memory,offsets)
    if not all(cfg[k] for k in ('bootloader_enabled','backdoor_enabled','vector_valid')) or cfg['backdoor_dio']!=15 or cfg['backdoor_level']!=0:
        raise ValueError('P10 recovery/boot-vector CCFG gate failed')
    if a.variant=='DIAG':
        for symbol in ('T832Diag_exportPoll','T832Diag_captureResetCauseEarly','T832R6Nv_capture','T832R6Nv_captureCtx','t832R6Nv','t832R11Startup','T832Diag_uartWriteComplete'):
            if symbol not in maptext:raise ValueError('missing linked diagnostic hook '+symbol)
        if 'NVOCMP_RECOVER_FROM_COMPACT_FAILURE' in macros:raise ValueError('destructive recovery present')
        expected='0x'+os.environ['GITHUB_SHA'][:8]
        if '#define T832_BUILD_ID '+expected not in macros:raise ValueError('DEBUG identity mismatch')
    payload,segments,padding=management_container(memory)
    vendor_proof=None
    if a.series in ('R7','R11'):
        if not a.vendor_audit:raise ValueError('R7 requires the pinned vendor binary audit')
        sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'r7'))
        from vendor_nvs_audit import audit_candidate, SHA as VENDOR_SHA
        reference=json.loads(a.vendor_audit.read_text())
        if reference.get('reference_sha256')!=VENDOR_SHA:raise ValueError('reference binary proof identity mismatch')
        vendor_proof={'reference':reference,'candidate':audit_candidate(payload,maptext,c)}
    a.out.mkdir(parents=True,exist_ok=False)
    if a.series not in ('R6','R7','R11') or ((a.series in ('R7','R11')) != (a.profile=='vendor-20240716')):
        raise ValueError('series/profile mismatch')
    stem=f'T832-{a.series}-{a.variant}-{a.profile}'
    (a.out/(stem+'.slzb.bin')).write_bytes(payload)
    for path,suffix in ((a.hex,'.hex'),(a.elf,'.out'),(a.map,'.map')):shutil.copy2(path,a.out/(stem+suffix))
    provenance=a.out/'provenance';provenance.mkdir()
    if vendor_proof:(provenance/'vendor-layout-proof.json').write_text(json.dumps(vendor_proof,indent=2)+'\n')
    for path in (a.generated,a.macros,a.patch,a.lab,a.header):shutil.copy2(path,provenance/path.name)
    for name in ('source-gates.json','sdk.patch','project-seed.patch','ccs-build.log','ti_zstack_config.h'):
        path=a.patch.parent/name
        if not path.is_file():raise ValueError('missing build provenance '+name)
        shutil.copy2(path,provenance/name)
    if a.series=='R11':
        extra=['toolchain-hashes.txt']
        if a.variant=='DIAG':
            extra+=['r11-payloads.hex','z2m-r11-roundtrip.log','z2m-r11-negative.log',
                    'r11-decoded.jsonl','r11-negative-decoded.jsonl','r11-chain.txt',
                    'herdsman-pin.txt','r11-sizeof-15.json','r11-sizeof-18.json']
        for name in extra:
            path=a.patch.parent/name
            if not path.is_file():raise ValueError('missing R11 gate evidence '+name)
            shutil.copy2(path,provenance/name)
    (provenance/'nv-contract.json').write_text(json.dumps(c,indent=2)+'\n')
    (provenance/'ccfg-gate.json').write_text(json.dumps(cfg,indent=2)+'\n')
    source=Path(__file__).resolve().parent.parent
    for name in ('t832_incident.py','t832_diag_decode.py','diag_schema.json'):
        shutil.copy2(source/name,a.out/name)
    shutil.copy2(source/'r6/decode_raw.py',a.out/'decode_raw.py')
    readme='r6/R11_RUNBOOK.md' if a.series=='R11' else ('r7/README.md' if a.series=='R7' else 'r6/README.md')
    shutil.copy2(source/readme,a.out/'README.md')
    lab=json.loads(a.lab.read_text())
    if a.series in ('R7','R11') and not lab.get('all_power_cut_recovery_passed'):
        raise ValueError('required recovery/write gate failed; candidate packaging refused')
    startup=None
    if a.series in ('R7','R11'):
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        from verify_startup_guard import (REJECT_CASES, ADMIT_CASES, CORPUS_VERSION,
                                          ADMIT_MAX_OPS)
        guard_report=a.lab.parent/'startup-guard-report.json'
        startup=json.loads(guard_report.read_text())
        if startup.get('ok') is not True:
            raise ValueError('nonblank startup preservation gate failed: ok!=true')
        corpus=startup.get('corpus',{})
        if corpus.get('version')!=CORPUS_VERSION:
            raise ValueError('startup corpus version mismatch')
        if list(corpus.get('reject_names',[]))!=list(REJECT_CASES):
            raise ValueError('startup reject corpus binding mismatch')
        if list(corpus.get('admit_names',[]))!=list(ADMIT_CASES):
            raise ValueError('startup admit corpus binding mismatch')
        lanes=startup.get('lanes',[])
        if sorted((l.get('embedded_asserts'),l.get('sanitizer')) for l in lanes)!=[(False,False),(False,True),(True,False),(True,True)]:
            raise ValueError('startup lane shape mismatch')
        for l in lanes:
            rej=l.get('rejections',{})
            if set(rej)!=set(REJECT_CASES):
                raise ValueError('startup lane reject binding mismatch')
            for name,r in rej.items():
                if r.get('physical_operations')!=0:
                    raise ValueError('startup rejection wrote: '+name)
                adv=r.get('adverse',{})
                if adv.get('physical_operations')!=0:
                    raise ValueError('startup adverse path wrote: '+name)
                if r.get('sanity_status')!=(1<<r.get('init_status',-1)):
                    raise ValueError('startup sanity bit wrong: '+name)
                if r.get('init_status')!=r.get('reinit_status'):
                    raise ValueError('startup re-init unstable: '+name)
                if 'unchanged_sha256' not in r or 'mutation' not in r:
                    raise ValueError('startup preservation proof missing: '+name)
            adm=l.get('admits',{})
            if set(adm)!=set(ADMIT_CASES):
                raise ValueError('startup lane admit binding mismatch')
            for name,ad in adm.items():
                if ad.get('init_status')!=0 or ad.get('reinit_status')!=0:
                    raise ValueError('startup admit case failed: '+name)
                if ad.get('physical_operations',ADMIT_MAX_OPS+1)>ADMIT_MAX_OPS:
                    raise ValueError('startup admit case wrote too much: '+name)
                if ad.get('stability_operations')!=0:
                    raise ValueError('startup admit case did not converge: '+name)
            if l.get('sanitizer') and not startup.get('sanitizer_flags'):
                raise ValueError('startup sanitizer presence missing')
        exp_rej=len(lanes)*len(REJECT_CASES)*2
        exp_san=len([l for l in lanes if l.get('sanitizer')])*len(REJECT_CASES)*2
        exp_adm=len(lanes)*len(ADMIT_CASES)*2
        if startup.get('rejection_cases')!=exp_rej or startup.get('reject_runs_expected')!=exp_rej:
            raise ValueError('startup reject count not derived')
        if startup.get('sanitizer_sweeps')!=exp_san or startup.get('sanitizer_runs_expected')!=exp_san:
            raise ValueError('startup sanitizer count not derived')
        if startup.get('admit_runs')!=exp_adm or startup.get('admit_runs_expected')!=exp_adm:
            raise ValueError('startup admit count not derived')
        if startup.get('oracle',{}).get('enumeration',{}).get('total')!=15504:
            raise ValueError('startup topology enumeration incomplete')
        shutil.copy2(guard_report,provenance/guard_report.name)
    manifest={'variant':stem,'repository_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],
              'profile':c,'sdk_commit':'6499c3f53fc5fb5806213be695450a7b43fbaf3d',
              'examples_commit':'87ff5b638b632050228a7504f35cf3b95581c278',
              'board':'SLZB-06P10 / CC2674P10; UART and DIO15 BSL; bench acceptance pending',
              'toolchain':{'ccs':'12.8.0.00012','ti_clang':'3.2.2.LTS','sysconfig':'1.21.1.3772','xdc':'3.62.01.16'},
              'sram_unused_bytes':rows['SRAM']['unused'],'container_segments':segments,'erased_gap_padding_bytes':padding,
              'sys_version_revision':(8320052 if a.variant=='DIAG' else 8320051) if a.series=='R11' else ((8320042 if a.variant=='DIAG' else 8320041) if a.series=='R7' else (8320012 if a.variant=='DIAG' else 8320011)),
              'debug_build_id':int(os.environ['GITHUB_SHA'][:8],16) if a.variant=='DIAG' else None,
              'hardware_validated':False,'flash_authorized':False,
              'startup_preservation_cases':startup['rejection_cases'] if startup else None,
              'startup_sanitizer_sweeps':startup['sanitizer_sweeps'] if startup else None,
              'startup_corpus_version':startup['corpus']['version'] if startup else None,
              'startup_admit_runs':startup['admit_runs'] if startup else None,
              'all_power_cut_recovery_passed':lab['all_power_cut_recovery_passed'],
              'unresolved_recovery_negative_controls':lab['profiles'][a.profile+'-'+a.variant]['unresolved_recovery_negative_controls'],
              'artifacts':{str(p.relative_to(a.out)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in a.out.rglob('*') if p.is_file()}}
    (a.out/'T832-BUILD-MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (a.out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(a.out))+'\n' for p in sorted(a.out.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'))
    print(json.dumps(manifest,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--profile',required=True);p.add_argument('--variant',required=True)
    p.add_argument('--series',choices=['R6','R7','R11'],default='R6')
    p.add_argument('--vendor-audit',type=Path)
    for name in ('generated','macros','map','hex','elf','header','patch','lab','out'):p.add_argument('--'+name,type=Path,required=True)
    package(p.parse_args())
