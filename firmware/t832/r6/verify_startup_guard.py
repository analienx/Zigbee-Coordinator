"""Actual pinned driver; run only in GitHub-hosted Actions."""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
from nv_recovery_fix import apply_fix

HERE=Path(__file__).resolve().parent
PAGE=2048
VALID_STATES=frozenset((0xFF,0xFE,0x7E,0x7C,0x78,0x70))
def torn(byte,offset):
    """Valid-NOR torn encoding: clear a strict subset of pristine 1-bits to a
    value the startup classifier must reject. Fails closed if no mask applies."""
    for mask in (0xF0,0x0F):
        v=byte&mask
        if v==byte:continue
        if offset==0 and v in VALID_STATES:continue
        if offset==2 and (v>>2)==0x03:continue
        if offset==3 and v==0x96:continue
        return mask,v
    raise ValueError('no torn encoding for byte 0x%02x at header offset %d'%(byte,offset))
def hand_picked(name,b,last):
    if name=='signature':b[last+3]=0x94
    if name=='version':b[last+2]=4
    if name=='state':b[last]=0
    if name=='erased-header-with-data':b[last:last+16]=b'\xff'*16;b[last+32]=0
    if name=='nact-with-data':b[0]=0xff
    if name=='two-xdst':b[2048]=0xfe
    if name=='two-ready':b[2048]=0x7e;b[4096]=0x7e
    if name=='blank-before-bad':b[2048:4096]=b'\xff'*2048;b[last+3]=0x94
    if name=='blank-before-two-xdst':b[2048:4096]=b'\xff'*2048;b[4096]=0xfe
    if name=='blank-before-only-ready':b[:2048]=b'\xff'*2048;b[2048]=0x7e;b[last]=0xff
    if name in ('full-without-destination','source-without-destination'):
        for page in range(15):b[page*2048]=0x78
        if name=='source-without-destination':b[0]=0x70
    return {'family':'hand-picked'}
def generated(name,b):
    """Enumerated deterministic corpus v1. Every mutation is preserve-and-reject
    by construction: torn headers break signature/version/state, topology pairs
    exceed the single destination/source/ready budget, lone-ready has no
    destination/source/data page, torn-erase leaves data under an erased header."""
    if name.startswith('gen-torn-state-') or name.startswith('gen-torn-version-') or name.startswith('gen-torn-signature-'):
        pg=int(name.rsplit('-',1)[1]);off={'state':0,'version':2,'signature':3}[name.split('-')[2]]
        at=pg*PAGE+off;mask,v=torn(b[at],off);b[at]=v
        return {'family':'gen-torn-header','page':pg,'header_offset':off,'mask':'0x%02x'%mask,'torn_byte':'0x%02x'%v,'nor_valid_bit_clear':True}
    if name.startswith('gen-two-'):
        kind,i,j=name.split('-')[2:5];i,j=int(i),int(j)
        state={'xdst':0xFE,'xsrc':0x70,'ready':0x7E}[kind]
        b[i*PAGE]=state;b[j*PAGE]=state
        return {'family':'gen-ambiguous-topology','kind':kind,'pages':[i,j],'state':'0x%02x'%state}
    if name.startswith('gen-lone-ready-'):
        pg=int(name.rsplit('-',1)[1])
        for p in range(15):b[p*PAGE:(p+1)*PAGE]=b'\xff'*PAGE
        b[pg*PAGE:pg*PAGE+4]=bytes((0x7E,0x01,0x0C,0x96))
        return {'family':'gen-lone-ready','page':pg}
    if name.startswith('gen-torn-erase-'):
        pg=int(name.rsplit('-',1)[1])
        b[pg*PAGE:(pg+1)*PAGE]=b'\xff'*PAGE;b[pg*PAGE+64]=0x00
        return {'family':'gen-torn-erase-remnant','page':pg,'remnant_offset':64}
    raise ValueError('unknown generated case '+name)
CASES=['signature','version','state','erased-header-with-data','nact-with-data','two-xdst','two-ready','blank-before-bad','blank-before-two-xdst','blank-before-only-ready','full-without-destination','source-without-destination']
for _pg in (0,1,7,13,14):
    for _f in ('state','version','signature'):CASES.append('gen-torn-%s-%d'%(_f,_pg))
for _pair in ((0,1),(0,14),(7,13)):
    for _k in ('xdst','xsrc','ready'):CASES.append('gen-two-%s-%d-%d'%(_k,_pair[0],_pair[1]))
for _pg in (3,8,11):CASES.append('gen-lone-ready-%d'%_pg)
for _pg in (2,5,9,12):CASES.append('gen-torn-erase-%d'%_pg)
def verify(sdk,out):
    out.mkdir(parents=True,exist_ok=False)
    source=out/'nvocmp.c';shutil.copy2(sdk/'source/ti/common/nv/nvocmp.c',source);apply_fix(source)
    rows=[]
    for embedded in (False,True):
      for sanitizer in (False,True):
        tag=('embedded' if embedded else 'asserting')+('-sanitizer' if sanitizer else '')
        exe=out/tag
        cmd=['gcc','-std=c11','-O1','-g','-D_GNU_SOURCE','-DNV_LINUX','-DNVOCMP_POSIX_MUTEX','-DENABLE_SANITY_CHECK','-DDeviceFamily_CC26X4','-DNVOCMP_NVPAGES=15',
             '-I'+str(out),'-I'+str(HERE),'-I'+str(sdk/'source'),'-I'+str(sdk/'source/ti/common/nv'),
             str(HERE/'startup_guard_probe.c'),str(sdk/'source/ti/common/nv/crc.c'),str(HERE/'nv_linux.c'),'-pthread','-o',str(exe)]
        if embedded:cmd.insert(1,'-DNVLAB_EMBEDDED_ASSERT=1')
        if sanitizer:cmd[1:1]=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
        subprocess.run(cmd,check=True)
        def invoke(image,verb):
            env=dict(os.environ,NVLAB_IMAGE=str(image));env.pop('NVLAB_CUT_OP',None)
            p=subprocess.run([str(exe),verb],env=env,capture_output=True,text=True,timeout=20)
            if p.returncode:raise RuntimeError(f'{image.name}/{verb}: exit={p.returncode}, stderr={p.stderr}, stdout={p.stdout}')
            return json.loads(p.stdout)
        seed=out/(exe.name+'-seed.bin');blank=invoke(seed,'seed');assert blank['physical_operations']>0
        pristine=seed.read_bytes();before=hashlib.sha256(pristine).hexdigest();healthy=invoke(seed,'healthy')
        assert seed.read_bytes()==pristine and healthy['physical_operations']==0
        cases={}
        for name in CASES:
            b=bytearray(pristine);last=14*2048
            if name.startswith('gen-'):mutation=generated(name,b)
            else:mutation=hand_picked(name,b,last)
            p=out/(exe.name+'-'+name+'.bin');p.write_bytes(b);raw=p.read_bytes();r=invoke(p,'reject')
            assert p.read_bytes()==raw and r['physical_operations']==0
            adv=invoke(p,'adverse')
            assert p.read_bytes()==raw and adv['physical_operations']==0
            cases[name]={**r,'mutation':mutation,'unchanged_sha256':hashlib.sha256(raw).hexdigest(),'adverse':adv}
        rows.append({'embedded_asserts':embedded,'sanitizer':sanitizer,'blank_init':blank,'healthy':healthy,'healthy_sha256':before,'rejections':cases})
    total=len(CASES)*2
    result={'ok':True,'lanes':rows,'rejection_cases':total,'sanitizer_sweeps':total,'corpus':{'version':'enumerated-v1','hand_picked':12,'generated':len(CASES)-12,'case_names':CASES},'sanitizer_flags':['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'],'hardware_validated':False,'private_data_used':False}
    (out/'report.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'ok':True,'rejection_cases':total,'sanitizer_sweeps':total}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--sdk',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();verify(a.sdk.resolve(),a.out.resolve())
