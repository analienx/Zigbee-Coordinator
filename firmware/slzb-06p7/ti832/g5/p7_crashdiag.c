/* Host-compilable reference implementation of p7_crashdiag.h.
 * On-target critical section: replace P7_CRIT_* with PRIMASK save/restore
 * (Hwi_disable/restore) at integration time; kept dependency-free here so
 * GitHub-hosted host tests compile the exact same ring/encode logic.
 * ISR path: fixed slot write + saturating counters only. */
#include "p7_crashdiag.h"
#include <string.h>
#define P7_CRIT_ENTER() do{}while(0)
#define P7_CRIT_EXIT()  do{}while(0)
volatile p7_diag_state_t p7_diag_state;
p7_diag_event_t p7_diag_ring[P7_DIAG_RING];
static uint32_t next_seq;
uint16_t p7_diag_crc16(const uint8_t *data, size_t len){
  uint16_t crc=0xFFFFu; for(size_t i=0;i<len;i++){ crc^=(uint16_t)data[i]<<8;
    for(int b=0;b<8;b++) crc=(crc&0x8000u)?(uint16_t)((crc<<1)^0x1021u):(uint16_t)(crc<<1);} return crc; }
void p7_diag_init(uint32_t gen, uint8_t rs, uint8_t known){
  P7_CRIT_ENTER(); memset(p7_diag_ring,0,sizeof p7_diag_ring);
  p7_diag_state.boot_generation=gen; p7_diag_state.dropped=0; p7_diag_state.total=0;
  p7_diag_state.head=0; p7_diag_state.count=0; p7_diag_state.nv_state=P7D_NVSTATE_UNKNOWN;
  p7_diag_state.reset_source=rs; p7_diag_state.reset_source_known=known?1u:0u;
  next_seq=1; P7_CRIT_EXIT();
  p7_diag_record(P7D_BOOT_ENTER,0,0);
  p7_diag_record(P7D_RESET_SOURCE, known?(uint16_t)rs:0xFFFFu,0);
}
static void record_common(uint16_t kind, uint16_t arg, uint32_t tick){
  P7_CRIT_ENTER();
  p7_diag_event_t *e=&p7_diag_ring[p7_diag_state.head];
  e->seq=next_seq++; e->tick=tick; e->kind=kind; e->arg=arg;
  p7_diag_state.head=(uint16_t)((p7_diag_state.head+1u)%P7_DIAG_RING);
  if(p7_diag_state.count<P7_DIAG_RING) p7_diag_state.count++;
  else if(p7_diag_state.dropped<0xFFFFFFFFu) p7_diag_state.dropped++;
  if(p7_diag_state.total<0xFFFFFFFFu) p7_diag_state.total++;
  if(kind==P7D_NV_RESTORED) p7_diag_state.nv_state=P7D_NVSTATE_RESTORED;
  if(kind==P7D_NV_NEW) p7_diag_state.nv_state=P7D_NVSTATE_NEW;
  if(kind==P7D_NV_AMBIGUOUS) p7_diag_state.nv_state=P7D_NVSTATE_AMBIGUOUS;
  P7_CRIT_EXIT();
}
void p7_diag_record(uint16_t k,uint16_t a,uint32_t t){ record_common(k,a,t); }
void p7_diag_record_isr(uint16_t k,uint16_t a,uint32_t t){ record_common(k,a,t); }
static void put16(uint8_t*o,uint16_t v){o[0]=(uint8_t)v;o[1]=(uint8_t)(v>>8);}
static void put32(uint8_t*o,uint32_t v){put16(o,(uint16_t)v);put16(o+2,(uint16_t)(v>>16));}
size_t p7_diag_snapshot(uint8_t *out, size_t cap){
  const size_t need=16u+(size_t)P7_DIAG_SNAPSHOT_EVENTS*12u+2u;
  if(!out||cap<need) return 0;
  uint16_t n=p7_diag_state.count; if(n>P7_DIAG_SNAPSHOT_EVENTS)n=P7_DIAG_SNAPSHOT_EVENTS;
  memcpy(out,"P7D1",4); out[4]=P7_DIAG_SCHEMA; out[5]=p7_diag_state.nv_state;
  out[6]=(uint8_t)n; out[7]=p7_diag_state.reset_source_known;
  put32(out+8,p7_diag_state.boot_generation); put32(out+12,p7_diag_state.dropped);
  /* retained window: oldest retained index, then skip to last n */
  uint16_t oldest=(uint16_t)((p7_diag_state.head+P7_DIAG_RING-p7_diag_state.count)%P7_DIAG_RING);
  uint16_t start=(uint16_t)((oldest+(p7_diag_state.count-n))%P7_DIAG_RING);
  for(uint16_t i=0;i<n;i++){
    const p7_diag_event_t *e=&p7_diag_ring[(start+i)%P7_DIAG_RING]; uint8_t *o=out+16u+(size_t)i*12u;
    put32(o,e->seq); put32(o+4,e->tick); put16(o+8,e->kind); put16(o+10,e->arg);
  }
  size_t len=16u+(size_t)n*12u; put16(out+len,p7_diag_crc16(out,len)); return len+2u;
}
