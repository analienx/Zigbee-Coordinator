"""Minimal R6 BASE and observation-only DIAG on pristine pinned TI sources.

Run only in hosted CI. No KCTRL routing, MAC queue or UART completion changes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from apply_diag import Exact, apply_diag
from nv_contract import budget
from nv_recovery_fix import apply_fix as apply_recovery_fix,verify_fixed as verify_recovery_fixed

HERE=Path(__file__).resolve().parent
SDK='6499c3f53fc5fb5806213be695450a7b43fbaf3d'
EXAMPLES='87ff5b638b632050228a7504f35cf3b95581c278'

def base(sdk,examples,profile):
    for root,pin in ((sdk,SDK),(examples,EXAMPLES)):
        if subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()!=pin:
            raise ValueError('input pin mismatch')
    c=budget(profile);p=c['capacities'];ex=Exact()
    opts=sdk/'source/ti/zstack/apps/znp/znp_cnf.opts'
    defines={'FEATURE_NVEXID':1,'MT_SYS_KEY_MANAGEMENT':1,'ZDSECMGR_TC_DEVICE_MAX':p['tc_devices'],
             'NWK_MAX_DEVICE_LIST':p['device_list'],'NWK_MAX_BINDING_ENTRIES':p['binding_entries'],
             'NVOCMP_NVS_INDEX':0,'NVOCMP_NVPAGES':c['nvs_pages']}
    ex.append(opts,'\n'.join(f'-D{k}={v}' for k,v in defines.items()),'r6.restore_capacity_defines')
    seed=examples/'examples/rtos/LP_EM_CC2674P10/zstack/znp/tirtos7'
    project=seed/'ticlang/znp_LP_EM_CC2674P10_tirtos7_ticlang.projectspec'
    ex.replace(project,'-DNVOCMP_NVPAGES=5',f'-DNVOCMP_NVPAGES={c["nvs_pages"]}','r6.compiler_pages')
    ex.replace(project,'--define=NVOCMP_NVPAGES=2',f'--define=NVOCMP_NVPAGES={c["nvs_pages"]}','r6.linker_pages')
    linker=sdk/'source/ti/zstack/boards/cc13x4_cc26x4/cc13x4_cc26x4_tirtos7_ticlang.cmd'
    ex.replace(linker,'#define NVOCMP_NVPAGES          5',f'#define NVOCMP_NVPAGES          {c["nvs_pages"]}','r6.linker_region')
    cfg=seed/'znp.syscfg';raw=cfg.read_bytes();newline=b'\r\n' if b'\r\n' in raw else b'\n'
    old=b'    NVS1.internalFlash.regionBase = 0xFD800;\n    NVS1.internalFlash.regionSize = 0x2800;'.replace(b'\n',newline)
    new=f'    NVS1.internalFlash.regionBase = {hex(c["nvs_base"])};\n    NVS1.internalFlash.regionSize = {hex(c["nvs_bytes"])};'.encode().replace(b'\n',newline)
    if raw.count(old)!=1:raise ValueError('pinned P10 SysConfig region mismatch')
    result=raw.replace(old,new);cfg.write_bytes(result)
    ex.edits.append({'label':'r6.generated_nvs_region','path':str(cfg),'before_sha256':hashlib.sha256(raw).hexdigest(),'after_sha256':hashlib.sha256(result).hexdigest()})
    version=sdk/'source/ti/zstack/mt/mt_version.c'
    defines['NVOCMP_NVPAGES']=c['nvs_pages']
    assertions='\n#include "nwk_globals.h"\n'+''.join(f'_Static_assert({k} == {v}, "R6 effective {k}");\n' for k,v in defines.items())
    assertions+=f'_Static_assert(NWK_MAX_ADDRESSES == {p["addresses"]}, "R6 TI-derived address capacity");\n'
    assertions+='#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE\n#error "R6 destructive recovery forbidden"\n#endif\n'
    ex.replace(version,'#include "mt_version.h"\n','#include "mt_version.h"\n'+assertions,'r6.compile_contract')
    ex.replace(version,'0,  /* Product ID */','1,  /* Product ID: custom coordinator */','r6.product_id')
    ex.replace(version,'1,  /* Software maintenance release number */',
               '1,  /* Software maintenance release number */\n'+''.join(f'                                   ((CODE_REVISION_NUMBER >> {n}) & 0xFF),\n' for n in (0,8,16,24)).rstrip(),
               'r6.revision_format')
    nvocmp=sdk/'source/ti/common/nv/nvocmp.c'
    recovery_edits=apply_recovery_fix(nvocmp)
    recovery_fix=verify_recovery_fixed(nvocmp.read_text())
    if len(recovery_edits)!=13:raise ValueError('recovery and startup preservation fixes not applied to firmware source')
    return {'variant':'T832-R6-BASE','budget':c,'edits':ex.edits+recovery_edits,'nv_recovery_fix':recovery_fix,'recovery_policy':'T832-R8 bounded init recovery (t832-r8-nv-recovery-02); destructive RECOVER_FROM_COMPACT_FAILURE stays off',
            'transport_policy':'pristine TI write callback completion','sdk_commit':SDK,'examples_commit':EXAMPLES}

def apply(sdk,examples,profile,variant,series='R6'):
    if series not in ('R6','R7') or ((series=='R7') != (profile=='vendor-20240716')):
        raise ValueError('series/profile mismatch')
    base_revision,diag_revision=(8320041,8320042) if series=='R7' else (8320011,8320012)
    if variant=='DIAG':
        evidence=apply_diag(sdk,examples,HERE/'profiles.json',base_apply=lambda s,e,m:base(s,e,profile),
                            revision=diag_revision,pristine_transport=True)
        evidence['variant']=f'T832-{series}-DIAG'
        from r6_observer import apply_observer
        evidence['r6_observer']=apply_observer(sdk)
    else:
        evidence=base(sdk,examples,profile)
        version=sdk/'source/ti/zstack/mt/mt_version.c'
        ex=Exact();ex.replace(version,'CODE_REVISION_NUMBER >>',f'{base_revision}u >>','r6.base_revision',count=4)
        evidence['edits']+=ex.edits
        evidence['variant']=f'T832-{series}-BASE'
    return evidence

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--sdk',type=Path,required=True);p.add_argument('--examples',type=Path,required=True)
    p.add_argument('--profile',choices=['production-demand','capacity-400','vendor-20240716'],required=True);p.add_argument('--variant',choices=['BASE','DIAG'],required=True)
    p.add_argument('--series',choices=['R6','R7'],default='R6')
    p.add_argument('--evidence',type=Path,required=True);a=p.parse_args()
    e=apply(a.sdk.resolve(),a.examples.resolve(),a.profile,a.variant,a.series)
    a.evidence.parent.mkdir(parents=True,exist_ok=True);a.evidence.write_text(json.dumps(e,indent=2)+'\n')
