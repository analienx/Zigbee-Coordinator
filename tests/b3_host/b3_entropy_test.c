/* Real extracted TI zd_sec_mgr.c entropy implementation under actual fail path.
 * Mock TRNG deliberately writes half the entropy output then fails:
 * a weak driver must not expose it as a new network key.
 */
#include "b3_entropy_stub.h"
#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
TRNG_Handle TRNG_handle=(TRNG_Handle)(uintptr_t)1;
static int_fast16_t entropy_status=TRNG_STATUS_SUCCESS;
static unsigned entropy_calls, key_copies;
void CryptoKeyPlaintext_initBlankKey(CryptoKey *key, uint8_t *buf, size_t len) {
    assert(len==SEC_KEY_LEN);
    memset(buf,0,len);
    key->u.plaintext.keyMaterial=buf;
}
int_fast16_t TRNG_generateEntropy(TRNG_Handle h, CryptoKey *key) {
    assert(h != NULL);
    entropy_calls++;
    memset(key->u.plaintext.keyMaterial,
           entropy_status == TRNG_STATUS_SUCCESS ? 0xA5 : 0x42,
           entropy_status == TRNG_STATUS_SUCCESS ? SEC_KEY_LEN : SEC_KEY_LEN/2);
    return entropy_status;
}
void *OsalPort_memcpy(void *dst, const void *src, size_t len) {
    key_copies++;
    return memcpy(dst,src,len);
}
extern uint8_t ZDSecMgrGenerateRndKey(uint8_t *);
static void check_all(const uint8_t *b,uint8_t val) {
    for(size_t i=0;i<SEC_KEY_LEN;i++) assert(b[i]==val);
}
int main(void) {
    uint8_t out[SEC_KEY_LEN];
    memset(out,0x78,sizeof(out));
    assert(ZDSecMgrGenerateRndKey(out)==ZSuccess);
    check_all(out,0xA5);
    assert(entropy_calls==1 && key_copies==1);
    entropy_status=-1;
    entropy_calls=key_copies=0;
    memset(out,0x78,sizeof(out));
    assert(ZDSecMgrGenerateRndKey(out)!=ZSuccess);
    check_all(out,0);
    assert(entropy_calls==1 && key_copies==0);
    entropy_calls=key_copies=0;
    TRNG_handle=NULL;
    memset(out,0x78,sizeof(out));
    assert(ZDSecMgrGenerateRndKey(out)!=ZSuccess);
    check_all(out,0);
    assert(entropy_calls==0 && key_copies==0);
    assert(ZDSecMgrGenerateRndKey(NULL)!=ZSuccess);
    puts("B3_ORIGINAL_TI_TRNG_REAL_FUNCTION_REJECTS_PARTIAL_ENTROPY_AND_ALL_CALLERS_GUARDED");
    return 0;
}
