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
    memory=ihex(a.hex.read_bytes())
    if any(c['nvs_base']<=address<1048576 for address in memory):raise ValueError('image contains NV region bytes')
    offsets={k:int(v,16) for k,v in re.findall(r'^#define CCFG_O_(\w+)\s+(0x[\da-fA-F]+)',a.header.read_text(),re.M)}
    cfg=decode(memory,offsets)
    if not all(cfg[k] for k in ('bootloader_enabled','backdoor_enabled','vector_valid')) or cfg['backdoor_dio']!=15 or cfg['backdoor_level']!=0:
        raise ValueError('P10 recovery/boot-vector CCFG gate failed')
    if a.variant=='DIAG':
        for symbol in ('T832Diag_exportPoll','T832Diag_captureResetCauseEarly','T832R6Nv_capture','t832R6Nv','T832Diag_uartWriteComplete'):
            if symbol not in maptext:raise ValueError('missing linked diagnostic hook '+symbol)
        if 'NVOCMP_RECOVER_FROM_COMPACT_FAILURE' in macros:raise ValueError('destructive recovery present')
        expected='0x'+os.environ['GITHUB_SHA'][:8]
        if '#define T832_BUILD_ID '+expected not in macros:raise ValueError('DEBUG identity mismatch')
    payload,segments,padding=management_container(memory)
    vendor_proof=None
    if a.series=='R7':
        if not a.vendor_audit:raise ValueError('R7 requires the pinned vendor binary audit')
        sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'r7'))
        from vendor_nvs_audit import audit_candidate, SHA as VENDOR_SHA
        reference=json.loads(a.vendor_audit.read_text())
        if reference.get('reference_sha256')!=VENDOR_SHA:raise ValueError('reference binary proof identity mismatch')
        vendor_proof={'reference':reference,'candidate':audit_candidate(payload,maptext,c)}
    a.out.mkdir(parents=True,exist_ok=False)
    if a.series not in ('R6','R7') or ((a.series=='R7') != (a.profile=='vendor-20240716')):
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
    (provenance/'nv-contract.json').write_text(json.dumps(c,indent=2)+'\n')
    (provenance/'ccfg-gate.json').write_text(json.dumps(cfg,indent=2)+'\n')
    source=Path(__file__).resolve().parent.parent
    for name in ('t832_incident.py','t832_diag_decode.py','diag_schema.json'):
        shutil.copy2(source/name,a.out/name)
    shutil.copy2(source/'r6/decode_raw.py',a.out/'decode_raw.py')
    shutil.copy2(source/('r7/README.md' if a.series=='R7' else 'r6/README.md'),a.out/'README.md')
    lab=json.loads(a.lab.read_text())
    if a.series=='R7' and not lab.get('all_power_cut_recovery_passed'):
        raise ValueError('required recovery/write gate failed; candidate packaging refused')
    startup=None
    if a.series=='R7':
        guard_report=a.lab.parent/'startup-guard-report.json'
        startup=json.loads(guard_report.read_text())
        if startup.get('ok') is not True or startup.get('rejection_cases')!=20:
            raise ValueError('nonblank startup preservation gate failed')
        shutil.copy2(guard_report,provenance/guard_report.name)
    manifest={'variant':stem,'repository_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],
              'profile':c,'sdk_commit':'6499c3f53fc5fb5806213be695450a7b43fbaf3d',
              'examples_commit':'87ff5b638b632050228a7504f35cf3b95581c278',
              'board':'SLZB-06P10 / CC2674P10; UART and DIO15 BSL; bench acceptance pending',
              'toolchain':{'ccs':'12.8.0.00012','ti_clang':'3.2.2.LTS','sysconfig':'1.21.1.3772','xdc':'3.62.01.16'},
              'sram_unused_bytes':rows['SRAM']['unused'],'container_segments':segments,'erased_gap_padding_bytes':padding,
              'sys_version_revision':(8320042 if a.variant=='DIAG' else 8320041) if a.series=='R7' else (8320012 if a.variant=='DIAG' else 8320011),
              'debug_build_id':int(os.environ['GITHUB_SHA'][:8],16) if a.variant=='DIAG' else None,
              'hardware_validated':False,'flash_authorized':False,
              'startup_preservation_cases':startup['rejection_cases'] if startup else None,
              'all_power_cut_recovery_passed':lab['all_power_cut_recovery_passed'],
              'unresolved_recovery_negative_controls':lab['profiles'][a.profile+'-'+a.variant]['unresolved_recovery_negative_controls'],
              'artifacts':{str(p.relative_to(a.out)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in a.out.rglob('*') if p.is_file()}}
    (a.out/'T832-BUILD-MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (a.out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(a.out))+'\n' for p in sorted(a.out.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'))
    print(json.dumps(manifest,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--profile',required=True);p.add_argument('--variant',required=True)
    p.add_argument('--series',choices=['R6','R7'],default='R6')
    p.add_argument('--vendor-audit',type=Path)
    for name in ('generated','macros','map','hex','elf','header','patch','lab','out'):p.add_argument('--'+name,type=Path,required=True)
    package(p.parse_args())
