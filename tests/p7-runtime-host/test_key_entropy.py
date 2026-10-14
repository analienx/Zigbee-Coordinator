#!/usr/bin/env python3
"""Actual key generator: valid entropy succeeds; failed entropy holds its caller."""
import argparse,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import runtime_overlay
import security_overlay

HEAD=r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <ti/drivers/cryptoutils/cryptokey/CryptoKey.h>
typedef void *TRNG_Handle;
TRNG_Handle TRNG_handle=(void*)1;
#define SEC_KEY_LEN 16
#define TRNG_STATUS_SUCCESS 0
#define DEV_HOLD 0
#define OsalPort_memcpy memcpy
static volatile sig_atomic_t fault,paused,held;
static int fail;
static uint8_t key[SEC_KEY_LEN];
static void CryptoKeyPlaintext_initBlankKey(CryptoKey *key,uint8_t *bytes,size_t n) {
  memset(key,0,sizeof(*key));key->u.plaintext.keyMaterial=bytes;key->u.plaintext.keyLength=n;
}
static int_fast16_t TRNG_generateEntropy(TRNG_Handle handle,CryptoKey *key) {
  assert(handle==TRNG_handle && key->u.plaintext.keyLength==16);
  if(fail)return -1;memset(key->u.plaintext.keyMaterial,0xA5,16);return 0;
}
static void p7_security_latch_failure(void) {fault=1;}
static void ZDApp_PauseNwk(void) {paused=1;}
static void ZDApp_ChangeState(uint8_t state) {assert(state==DEV_HOLD);held=1;}
static void timeout(int sig) {
  (void)sig;
  if(!fault || !paused || !held)_Exit(2);
  for(unsigned i=0;i<16;i++)if(key[i]!=0x5A)_Exit(3);
  _Exit(0);
}
'''
MAIN=r'''
int main(int argc,char **argv) {
  assert(argc==2);fail=atoi(argv[1]);memset(key,0x5A,sizeof(key));
  if(fail){signal(SIGALRM,timeout);alarm(1);}
  ZDSecMgrGenerateRndKey(key);
  assert(!fail && !fault && !paused && !held);
  for(unsigned i=0;i<16;i++)assert(key[i]==0xA5);
  return 0;
}
'''
def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    source=(a.sdk/"source/ti/zstack/stack/zdo/zd_sec_mgr.c").read_text()
    original=runtime_overlay.function(source,"ZDSecMgrGenerateRndKey")
    patched=security_overlay.patch_entropy(original)
    for version,body in (("pre",original),("post",patched)):
        cfile=a.out/(version+"-entropy.c");binary=cfile.with_suffix("");cfile.write_text(HEAD+body+MAIN)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-unused-function","-Wno-misleading-indentation","-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie","-I",str(a.sdk/"source"),str(cfile),"-o",str(binary)],check=True)
        for failure in (0,1):
            run=subprocess.run([str(binary),str(failure)],capture_output=True,text=True,timeout=4,env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"})
            (a.out/(version+"-"+str(failure)+".log")).write_text(run.stdout+run.stderr)
            assert (run.returncode!=0)==(version=="pre" and failure==1),(version,failure,run.stdout,run.stderr)
    print("PINNED_KEY_ENTROPY_SUCCESS_AND_FAIL_STOP_PRE_POST_PASS")
if __name__=="__main__":main()
