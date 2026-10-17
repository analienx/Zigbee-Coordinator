#ifndef B3_TRANSPORT_STUB_H
#define B3_TRANSPORT_STUB_H
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#define SUCCESS 0
#define ZSuccess 0
#define ZFailure 1
#define TRUE 1
#define FALSE 0
#define SEC_KEY_LEN 16
#define Z_EXTADDR_LEN 8
#define ZCD_NV_TCLK_SEED 0x101
#define ZCD_NV_NWK_ACTIVE_KEY_INFO 0x102
#define KEY_TYPE_APP_MASTER 2
#define KEY_TYPE_TC_LINK 3
#define KEY_TYPE_NWK 4
typedef uint8_t ZStatus_t;
typedef struct {uint8_t *partExtAddr;uint8_t keyType;uint16_t srcAddr;} ZDO_RequestKeyInd_t;
typedef struct {uint8_t extAddr[8];uint8_t SeedShift;} APSME_TCLinkKeyNVEntry_t;
typedef struct {uint16_t tna;uint8_t *dea;} APSDE_FrameTunnel_t;
typedef struct {
 uint16_t dstAddr;uint8_t *extAddr;uint8_t keyType;uint8_t *key;
 uint8_t keySeqNum;uint8_t nwkSecure;uint8_t apsSecure;uint8_t initiator;
 APSDE_FrameTunnel_t *tunnel;
} APSME_TransportKeyReq_t;
typedef struct {uint16_t nwkAddr;uint8_t *extAddr;uint16_t parentAddr;} ZDSecMgrDevice_t;
typedef struct {uint8_t keySeqNum;uint8_t key[SEC_KEY_LEN];} nwkKeyDesc;
uint8_t osal_nv_read(uint16_t,uint16_t,uint16_t,void *);
void *OsalPort_memcpy(void *,const void *,size_t);
uint8_t APSME_LookupNwkAddr(const uint8_t *,uint16_t *);
uint8_t APSME_LookupExtAddr(uint16_t,uint8_t *);
void APSME_SearchTCLinkKeyEntry(const uint8_t *,uint8_t *,APSME_TCLinkKeyNVEntry_t *);
ZStatus_t APSME_TransportKeyReq(APSME_TransportKeyReq_t *);
uint8_t NLME_ReadNwkKeyInfo(uint8_t,uint16_t,void *,uint16_t);
uint16_t NLME_GetShortAddr(void);
#endif
