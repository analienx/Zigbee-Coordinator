#include "entropy_stub.h"
#include <assert.h>
#include <stdio.h>
TRNG_Handle TRNG_handle=(TRNG_Handle)(uintptr_t)1;
static int_fast16_t entropy_status=TRNG_STATUS_SUCCESS;
static unsigned entropy_calls, hold_calls, copies;
void b1_security_runtime_hold_latch(void) {++hold_calls;}
void CryptoKeyPlaintext_initBlankKey(CryptoKey *key,uint8_t *buffer,size_t size) {
    assert(size==SEC_KEY_LEN);key->u.plaintext.keyMaterial=buffer;
}
int_fast16_t TRNG_generateEntropy(TRNG_Handle handle,CryptoKey *key) {
    assert(handle!=NULL);
    ++entropy_calls;
    memset(key->u.plaintext.keyMaterial,
           entropy_status==TRNG_STATUS_SUCCESS?0xA5:0x42,
           entropy_status==TRNG_STATUS_SUCCESS?SEC_KEY_LEN:SEC_KEY_LEN/2);
    return entropy_status;
}
void *OsalPort_memcpy(void *dst,const void *src,size_t n) {
    ++copies;return memcpy(dst,src,n);
}
extern uint8_t ZDSecMgrGenerateRndKey(uint8_t *);
static void all(const uint8_t *buf,uint8_t val) {
    for(size_t i=0;i<SEC_KEY_LEN;i++)assert(buf[i]==val);
}
int main(void) {
    uint8_t output[SEC_KEY_LEN];
    memset(output,0x78,sizeof(output));
    assert(ZDSecMgrGenerateRndKey(output)==ZSuccess);
    all(output,0xA5);
    assert(hold_calls==0 && copies==1 && entropy_calls==1);
    entropy_status=-1;copies=entropy_calls=hold_calls=0;
    memset(output,0x78,sizeof(output));
    assert(ZDSecMgrGenerateRndKey(output)!=ZSuccess);
    all(output,0);
    assert(hold_calls==1 && copies==0 && entropy_calls==1);
    TRNG_handle=NULL;copies=entropy_calls=hold_calls=0;
    memset(output,0x78,sizeof(output));
    assert(ZDSecMgrGenerateRndKey(output)!=ZSuccess);
    all(output,0);
    assert(hold_calls==1 && entropy_calls==0 && copies==0);
    hold_calls=0;
    assert(ZDSecMgrGenerateRndKey(NULL)!=ZSuccess);
    assert(hold_calls==1);
    puts("B1_B3_ENTROPY_REAL_TI_HOLD_AND_FOUR_CALLER_TESTS_PASS");
    return 0;
}
