/* Actual TI C functions, fake only peripheral/NV and transport interfaces. */
#include "b3_transport_stub.h"
#include <assert.h>
#include <stdio.h>
static uint8_t seed_status=SUCCESS, nwk_status=SUCCESS;
static int tx_calls=0, seed_reads=0, nwk_reads=0;
static uint8_t tx_key[SEC_KEY_LEN];
uint8_t osal_nv_read(uint16_t id,uint16_t off,uint16_t len,void *out) {
 assert(id==ZCD_NV_TCLK_SEED && off==0 && len==SEC_KEY_LEN);
 seed_reads++;
 if(seed_status!=SUCCESS) {
  memset(out,0x42,SEC_KEY_LEN/2); /* torn or partial read */
  return seed_status;
 }
 for(int i=0;i<SEC_KEY_LEN;i++) ((uint8_t *)out)[i]=(uint8_t)(i+1);
 return SUCCESS;
}
void *OsalPort_memcpy(void *dst,const void *src,size_t n) {return memcpy(dst,src,n);}
uint8_t APSME_LookupNwkAddr(const uint8_t *addr,uint16_t *nwk) {(void)addr;*nwk=1;return TRUE;}
uint8_t APSME_LookupExtAddr(uint16_t addr,uint8_t *ext) {(void)addr;memset(ext,0x0A,8);return TRUE;}
void APSME_SearchTCLinkKeyEntry(const uint8_t *addr,uint8_t *found,APSME_TCLinkKeyNVEntry_t *entry) {
 (void)addr;*found=TRUE;memset(entry->extAddr,0xAA,8);entry->SeedShift=1;
}
ZStatus_t APSME_TransportKeyReq(APSME_TransportKeyReq_t *req) {
 assert(req->key!=NULL);
 memcpy(tx_key,req->key,SEC_KEY_LEN);
 tx_calls++;
 return ZSuccess;
}
uint8_t NLME_ReadNwkKeyInfo(uint8_t i,uint16_t size,void *out,uint16_t id) {
 assert(i==0 && size==sizeof(nwkKeyDesc) && id==ZCD_NV_NWK_ACTIVE_KEY_INFO);
 nwk_reads++;
 nwkKeyDesc *p=(nwkKeyDesc *)out;
 if(nwk_status!=SUCCESS){memset(p,0x42,sizeof(*p));return nwk_status;}
 p->keySeqNum=3;memset(p->key,0xA5,SEC_KEY_LEN);return SUCCESS;
}
uint16_t NLME_GetShortAddr(void) {return 1;}
extern ZStatus_t ZDSecMgrGenerateKeyFromSeed(uint8_t *,uint8_t,uint8_t *);
extern void ZDSecMgrTclkReq(ZDO_RequestKeyInd_t *);
extern ZStatus_t ZDSecMgrSendNwkKey(ZDSecMgrDevice_t *);
static void all(const uint8_t *p,uint8_t value) {
 for(int i=0;i<SEC_KEY_LEN;i++) assert(p[i]==value);
}
int main(void) {
 uint8_t ext[Z_EXTADDR_LEN]={0},out[SEC_KEY_LEN],other[8]={0};
 memset(out,0x88,sizeof(out));
 assert(ZDSecMgrGenerateKeyFromSeed(ext,0,out)==ZSuccess);
 for(int i=0;i<SEC_KEY_LEN;i++) assert(out[i]==i+1);
 memset(out,0x88,sizeof(out));
 assert(ZDSecMgrGenerateKeyFromSeed(ext,15,out)==ZSuccess);
 assert(out[0]==16 && out[1]==1);
 seed_status=1;
 memset(out,0x88,sizeof(out));
 assert(ZDSecMgrGenerateKeyFromSeed(ext,1,out)!=ZSuccess);
 all(out,0);
 assert(ZDSecMgrGenerateKeyFromSeed(ext,1,NULL)!=ZSuccess);
 assert(ZDSecMgrGenerateKeyFromSeed(NULL,1,out)!=ZSuccess);
 ZDO_RequestKeyInd_t req={.partExtAddr=other,.keyType=KEY_TYPE_APP_MASTER,.srcAddr=0x1234};
 tx_calls=0;
 ZDSecMgrTclkReq(&req);
 assert(tx_calls==0); /* never transmit derived key from failed seed read */
 seed_status=SUCCESS;
 ZDSecMgrTclkReq(&req);
 assert(tx_calls==1);
 assert(tx_key[0]==(uint8_t)(2^0xAA));
 ZDSecMgrDevice_t dev={.nwkAddr=0x2345,.extAddr=other,.parentAddr=1};
 nwk_status=1;tx_calls=0;
 assert(ZDSecMgrSendNwkKey(&dev)!=ZSuccess);
 assert(tx_calls==0); /* no zeroed NWK key fallback */
 nwk_status=SUCCESS;
 assert(ZDSecMgrSendNwkKey(&dev)==ZSuccess);
 assert(tx_calls==1);
 all(tx_key,0xA5);
 assert(nwk_reads==2 && seed_reads==4);
 puts("B3_ACTUAL_TI_SEED_FAILURE_AND_NWK_TRANSPORT_DENIAL_PASS");
 return 0;
}
