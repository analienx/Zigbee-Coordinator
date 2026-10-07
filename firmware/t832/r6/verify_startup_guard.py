"""Actual pinned driver; run only in GitHub-hosted Actions."""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
from nv_recovery_fix import apply_fix

HERE=Path(__file__).resolve().parent
def verify(sdk,out):
    out.mkdir(parents=True,exist_ok=False)
    source=out/'nvocmp.c';shutil.copy2(sdk/'source/ti/common/nv/nvocmp.c',source);apply_fix(source)
    rows=[]
    for embedded in (False,True):
        exe=out/('embedded' if embedded else 'asserting')
        cmd=['gcc','-std=c11','-O1','-g','-D_GNU_SOURCE','-DNV_LINUX','-DNVOCMP_POSIX_MUTEX','-DDeviceFamily_CC26X4','-DNVOCMP_NVPAGES=15',
             '-I'+str(out),'-I'+str(HERE),'-I'+str(sdk/'source'),'-I'+str(sdk/'source/ti/common/nv'),
             str(HERE/'startup_guard_probe.c'),str(sdk/'source/ti/common/nv/crc.c'),str(HERE/'nv_linux.c'),'-pthread','-o',str(exe)]
        if embedded:cmd.insert(1,'-DNVLAB_EMBEDDED_ASSERT=1')
        subprocess.run(cmd,check=True)
        def invoke(image,verb):
            env=dict(os.environ,NVLAB_IMAGE=str(image));env.pop('NVLAB_CUT_OP',None)
            p=subprocess.run([str(exe),verb],env=env,capture_output=True,text=True,check=True,timeout=20)
            return json.loads(p.stdout)
        seed=out/(exe.name+'-seed.bin');blank=invoke(seed,'seed');assert blank['physical_operations']>0
        pristine=seed.read_bytes();before=hashlib.sha256(pristine).hexdigest();healthy=invoke(seed,'healthy')
        assert seed.read_bytes()==pristine and healthy['physical_operations']==0
        cases={}
        for name in ('signature','version','state','erased-header-with-data','nact-with-data','two-xdst','two-ready','blank-before-bad'):
            b=bytearray(pristine);last=14*2048
            if name=='signature':b[last+3]=0x94
            if name=='version':b[last+2]=4
            if name=='state':b[last]=0
            if name=='erased-header-with-data':b[last:last+16]=b'\xff'*16;b[last+32]=0
            if name=='nact-with-data':b[0]=0xff
            if name=='two-xdst':b[2048]=0xfe
            if name=='two-ready':b[2048]=0x7e;b[4096]=0x7e
            if name=='blank-before-bad':b[2048:4096]=b'\xff'*2048;b[last+3]=0x94
            p=out/(exe.name+'-'+name+'.bin');p.write_bytes(b);raw=p.read_bytes();r=invoke(p,'reject')
            assert p.read_bytes()==raw and r['physical_operations']==0
            cases[name]={**r,'unchanged_sha256':hashlib.sha256(raw).hexdigest()}
        rows.append({'embedded_asserts':embedded,'blank_init':blank,'healthy':healthy,'healthy_sha256':before,'rejections':cases})
    result={'ok':True,'lanes':rows,'rejection_cases':16,'hardware_validated':False,'private_data_used':False}
    (out/'report.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'ok':True,'rejection_cases':16}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--sdk',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();verify(a.sdk.resolve(),a.out.resolve())
