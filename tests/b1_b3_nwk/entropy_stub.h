#ifndef R4_B1_B3_ENTROPY_STUB_H
#define R4_B1_B3_ENTROPY_STUB_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define SEC_KEY_LEN 16u
#define TRNG_STATUS_SUCCESS 0
#define ZSuccess 0u
#define ZFailure 1u
typedef void *TRNG_Handle;
typedef struct {union {struct {uint8_t *keyMaterial;} plaintext;} u;} CryptoKey;
void CryptoKeyPlaintext_initBlankKey(CryptoKey *, uint8_t *, size_t);
int_fast16_t TRNG_generateEntropy(TRNG_Handle, CryptoKey *);
void *OsalPort_memcpy(void *, const void *, size_t);
void b1_security_runtime_hold_latch(void);
#endif
