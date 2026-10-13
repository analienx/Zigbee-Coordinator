/* Reference implementation of p7_crashdiag.h (host + on-target logic).
 * Seqlock discipline: write_seq is odd only while record_common mutates
 * ring/state. record_isr drops (dropped++) instead of pre-empting an
 * in-progress task write. Snapshot retries a bounded number of times
 * and returns 0 if the ring never stabilises: no torn CRC-valid data. */
#include "p7_crashdiag.h"
#include <string.h>
volatile p7_diag_state_t p7_diag_state;
p7_diag_event_t p7_diag_ring[P7_DIAG_RING];
static uint32_t next_seq;
static volatile uint32_t write_seq;
static volatile uint32_t isr_dropped; /* ISR-only writer; snapshot sums it */
static uint32_t retained_magic;
static uint32_t retained_crc;
#define P7_RETAINED_MAGIC 0x50374449u
static uint32_t retained_compute(void){
  uint32_t v[4]; v[0]=p7_diag_state.boot_generation; v[1]=p7_diag_state.total;
  v[2]=(uint32_t)p7_diag_state.head|((uint32_t)p7_diag_state.count<<16); v[3]=next_seq;
  return (uint32_t)p7_diag_crc16((const uint8_t*)v,sizeof v) | ((uint32_t)p7_diag_state.count<<16);
}
static int retained_sane(void){
  if(retained_magic!=P7_RETAINED_MAGIC) return 0;
  if(p7_diag_state.count>P7_DIAG_RING || p7_diag_state.head>=P7_DIAG_RING) return 0;
  if(p7_diag_state.nv_state>3u || next_seq==0) return 0;
  return retained_crc==retained_compute();
}
uint16_t p7_diag_crc16(const uint8_t *data, size_t len){
  uint16_t crc=0xFFFFu; for(size_t i=0;i<len;i++){ crc^=(uint16_t)data[i]<<8;
    for(int b=0;b<8;b++) crc=(crc&0x8000u)?(uint16_t)((crc<<1)^0x1021u):(uint16_t)(crc<<1);} return crc; }
static uint32_t alloc_seq(void){ uint32_t s=next_seq; next_seq=(next_seq>=0xFFFFFFFFu)?1u:next_seq+1u; return s; }
static void apply_nv(uint8_t ns){
  uint8_t cur=p7_diag_state.nv_state;
  if(cur==P7D_NVSTATE_AMBIGUOUS) return; /* latched */
  if(cur!=P7D_NVSTATE_UNKNOWN && cur!=ns) p7_diag_state.nv_state=P7D_NVSTATE_AMBIGUOUS;
  else p7_diag_state.nv_state=ns;
}
static void record_common(uint16_t kind, uint16_t arg, uint32_t tick){
  write_seq++;
  p7_diag_event_t *e=&p7_diag_ring[p7_diag_state.head];
  e->seq=alloc_seq(); e->tick=tick; e->kind=kind; e->arg=arg;
  p7_diag_state.head=(uint16_t)((p7_diag_state.head+1u)%P7_DIAG_RING);
  if(p7_diag_state.count<P7_DIAG_RING) p7_diag_state.count++;
  else if(p7_diag_state.dropped<0xFFFFFFFFu) p7_diag_state.dropped++;
  if(p7_diag_state.total<0xFFFFFFFFu) p7_diag_state.total++;
  if(kind==P7D_NV_RESTORED) apply_nv(P7D_NVSTATE_RESTORED);
  if(kind==P7D_NV_NEW) apply_nv(P7D_NVSTATE_NEW);
  if(kind==P7D_NV_AMBIGUOUS) apply_nv(P7D_NVSTATE_AMBIGUOUS);
  retained_crc=retained_compute();
  write_seq++;
}
void p7_diag_record(uint16_t k,uint16_t a,uint32_t t){ record_common(k,a,t); }
void p7_diag_record_isr(uint16_t k,uint16_t a,uint32_t t){
  if(write_seq&1u){ if(isr_dropped<0xFFFFFFFFu) isr_dropped++; return; }
  record_common(k,a,t);
}
void p7_diag_init(uint32_t gen, uint8_t rs, uint8_t known){
  write_seq++;
  memset(p7_diag_ring,0,sizeof p7_diag_ring);
  p7_diag_state.boot_generation=gen; p7_diag_state.dropped=0; p7_diag_state.total=0;
  p7_diag_state.head=0; p7_diag_state.count=0; p7_diag_state.nv_state=P7D_NVSTATE_UNKNOWN;
  p7_diag_state.reset_source=rs; p7_diag_state.reset_source_known=known?1u:0u;
  next_seq=1; retained_magic=P7_RETAINED_MAGIC;
  write_seq++;
  p7_diag_record(P7D_BOOT_ENTER,0,0);
  p7_diag_record(P7D_RESET_SOURCE, known?(uint16_t)rs:0xFFFFu,0);
}
void p7_diag_init_preserving(uint32_t gen, uint8_t rs, uint8_t known, uint8_t retained_valid){
  /* retained_valid must come from a separately gated noinit-section check
   * at integration; here we additionally require magic + CRC + ranges so
   * corrupt retained RAM falls back to a clean init. */
  if(!retained_valid || !retained_sane() || p7_diag_state.count==0){ p7_diag_init(gen,rs,known); return; }
  write_seq++;
  p7_diag_state.boot_generation=gen;
  p7_diag_state.reset_source=rs; p7_diag_state.reset_source_known=known?1u:0u;
  retained_crc=retained_compute();
  write_seq++;
  p7_diag_record(P7D_BOOT_ENTER,0,0);
  p7_diag_record(P7D_RESET_SOURCE, known?(uint16_t)rs:0xFFFFu,0);
}
static void put16(uint8_t*o,uint16_t v){o[0]=(uint8_t)v;o[1]=(uint8_t)(v>>8);}
static void put32(uint8_t*o,uint32_t v){put16(o,(uint16_t)v);put16(o+2,(uint16_t)(v>>16));}
size_t p7_diag_snapshot(uint8_t *out, size_t cap){
  if(!out) return 0;
  for(int attempt=0;attempt<8;attempt++){
    uint32_t s1=write_seq; if(s1&1u) continue;
    uint16_t n=p7_diag_state.count; if(n>P7_DIAG_SNAPSHOT_EVENTS)n=P7_DIAG_SNAPSHOT_EVENTS;
    size_t need=(size_t)P7_DIAG_HDR+(size_t)n*12u+2u;
    if(cap<need) return 0;
    uint16_t count=p7_diag_state.count;
    uint16_t oldest=(uint16_t)((p7_diag_state.head+P7_DIAG_RING-count)%P7_DIAG_RING);
    uint16_t start=(uint16_t)((oldest+(count-n))%P7_DIAG_RING);
    memcpy(out,"P7D1",4); out[4]=P7_DIAG_SCHEMA; out[5]=p7_diag_state.nv_state;
    out[6]=(uint8_t)n; out[7]=p7_diag_state.reset_source_known;
    put32(out+8,p7_diag_state.boot_generation); put32(out+12,p7_diag_state.dropped+isr_dropped);
    out[16]=p7_diag_state.reset_source_known?p7_diag_state.reset_source:0; out[17]=p7_diag_state.reset_source_known;
    out[18]=0; out[19]=0;
    for(uint16_t i=0;i<n;i++){
      const p7_diag_event_t *e=&p7_diag_ring[(start+i)%P7_DIAG_RING]; uint8_t *o=out+P7_DIAG_HDR+(size_t)i*12u;
      put32(o,e->seq); put32(o+4,e->tick); put16(o+8,e->kind); put16(o+10,e->arg);
    }
    if(write_seq!=s1) continue;
    size_t len=(size_t)P7_DIAG_HDR+(size_t)n*12u; put16(out+len,p7_diag_crc16(out,len)); return len+2u;
  }
  return 0;
}
