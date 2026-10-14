/* Reference implementation of p7_crashdiag.h (host + on-target logic).
 * Writer ownership: writer_owned is claimed by one atomic exchange.
 * Task and ISR writers share the same try-claim: on contention the
 * event is dropped and p7_diag_contention_dropped increments; no
 * writer ever waits, spins, or interleaves a ring mutation. Snapshot readers
 * claim the same ownership: retrying a sequence number alone does not make
 * concurrent reads of ordinary C ring/state fields race-free.
 * On Cortex-M4 the C11 atomic exchange compiles to an LDREX/STREX
 * loop bounded to a single claim attempt in effect (a failed claim
 * observes ownership, it does not retry the write); the equivalent
 * TI-RTOS7 mapping is a PRIMASK/Hwi_disable test-and-set around the
 * claim and the release only. That mapping is specified here, not
 * claimed as hardware-qualified.
 * Record path cost is O(1): a rolling fold over the 12-byte event
 * plus state words. The full 768-byte ring CRC runs only inside
 * p7_diag_seal_retained() (task context) and the boot-time verify in
 * p7_diag_init_preserving(). */
#include "p7_crashdiag.h"
#include <string.h>
#include <stdatomic.h>
volatile p7_diag_state_t p7_diag_state;
p7_diag_event_t p7_diag_ring[P7_DIAG_RING];
_Atomic uint32_t p7_diag_contention_dropped;
#if defined(P7_DIAG_TEST_HOOKS) && P7_DIAG_TEST_HOOKS
void (*p7_diag_preempt_hook)(void);
#endif
/* Keep the seal/snapshot API linked even while the MT endpoint is
 * disabled, so BASE-vs-DIAG linked evidence covers the full chain. */
#if defined(__clang__) || defined(__GNUC__)
__attribute__((used))
#endif
static void *const p7_diag_keepalive[] = {
  (void *)p7_diag_seal_retained, (void *)p7_diag_snapshot,
  (void *)p7_diag_init_preserving, (void *)p7_diag_crc16 };
static uint32_t next_seq;
static _Atomic uint32_t write_seq;
static _Atomic uint32_t writer_owned;
static uint32_t rolling_fold;
static uint32_t retained_magic;
static uint32_t retained_crc;
static uint32_t retained_sealed;
#define P7_RETAINED_MAGIC 0x50374449u
static uint16_t crc16_byte(uint16_t crc, uint8_t b){
  crc=(uint16_t)(crc^((uint16_t)b<<8));
  for(int i=0;i<8;i++) crc=(crc&0x8000u)?(uint16_t)((crc<<1)^0x1021u):(uint16_t)(crc<<1);
  return crc;
}
uint16_t p7_diag_crc16(const uint8_t *data, size_t len){
  uint16_t crc=0xFFFFu; for(size_t i=0;i<len;i++) crc=crc16_byte(crc,data[i]); return crc; }
/* Full retained seal computation. Task/seal + boot-verify paths only;
 * never called from record_common or any ISR path. */
static uint32_t retained_compute(void){
  uint32_t v[7]; v[0]=p7_diag_state.boot_generation; v[1]=p7_diag_state.total;
  v[2]=(uint32_t)p7_diag_state.head|((uint32_t)p7_diag_state.count<<16); v[3]=next_seq;
  v[4]=p7_diag_state.dropped; v[5]=p7_diag_state.nv_state;
  v[6]=p7_diag_contention_dropped;
  uint16_t c=p7_diag_crc16((const uint8_t*)p7_diag_ring,sizeof p7_diag_ring);
  c^=p7_diag_crc16((const uint8_t*)v,sizeof v);
  return (uint32_t)c | ((uint32_t)p7_diag_state.count<<16);
}
static int retained_sane(void){
  if(retained_magic!=P7_RETAINED_MAGIC) return 0;
  if(!retained_sealed) return 0;
  if(p7_diag_state.count>P7_DIAG_RING || p7_diag_state.head>=P7_DIAG_RING) return 0;
  if(p7_diag_state.nv_state>3u || next_seq==0) return 0;
  return retained_crc==retained_compute();
}
/* O(1) rolling fold: 12 event bytes + 12 state bytes, fixed bound. */
static void fold_event(const p7_diag_event_t *e){
  uint16_t c=(uint16_t)rolling_fold;
  const uint8_t *p=(const uint8_t*)e;
  for(size_t i=0;i<sizeof(*e);i++) c=crc16_byte(c,p[i]);
  uint32_t v[3]; v[0]=p7_diag_state.total; v[1]=next_seq;
  v[2]=(uint32_t)p7_diag_state.head|((uint32_t)p7_diag_state.count<<16);
  const uint8_t *q=(const uint8_t*)v;
  for(size_t i=0;i<sizeof(v);i++) c=crc16_byte(c,q[i]);
  rolling_fold=c;
}
static int writer_try_claim(int count_drop){
  uint32_t expected=0;
  if(!atomic_compare_exchange_strong(&writer_owned,&expected,1u)){
    if(count_drop) atomic_fetch_add(&p7_diag_contention_dropped,1u);
    return 0;
  }
  atomic_fetch_add(&write_seq,1u); /* odd: write in progress */
  return 1;
}
static void writer_release(void){
  atomic_fetch_add(&write_seq,1u); /* even: stable */
  atomic_store(&writer_owned,0u);
}
static uint32_t alloc_seq(void){ uint32_t s=next_seq; next_seq=(next_seq>=0xFFFFFFFFu)?1u:next_seq+1u; return s; }
static void apply_nv(uint8_t ns){
  uint8_t cur=p7_diag_state.nv_state;
  if(cur==P7D_NVSTATE_AMBIGUOUS) return; /* latched */
  if(cur!=P7D_NVSTATE_UNKNOWN && cur!=ns) p7_diag_state.nv_state=P7D_NVSTATE_AMBIGUOUS;
  else p7_diag_state.nv_state=ns;
}
static void record_common(uint16_t kind, uint16_t arg, uint32_t tick){
  p7_diag_event_t *e=&p7_diag_ring[p7_diag_state.head];
  e->seq=alloc_seq();
#if defined(P7_DIAG_TEST_HOOKS) && P7_DIAG_TEST_HOOKS
  if(p7_diag_preempt_hook) p7_diag_preempt_hook(); /* host-test only, ownership held */
#endif
  e->tick=tick; e->kind=kind; e->arg=arg;
  p7_diag_state.head=(uint16_t)((p7_diag_state.head+1u)%P7_DIAG_RING);
  if(p7_diag_state.count<P7_DIAG_RING) p7_diag_state.count++;
  else if(p7_diag_state.dropped<0xFFFFFFFFu) p7_diag_state.dropped++;
  if(p7_diag_state.total<0xFFFFFFFFu) p7_diag_state.total++;
  if(kind==P7D_NV_RESTORED) apply_nv(P7D_NVSTATE_RESTORED);
  if(kind==P7D_NV_NEW) apply_nv(P7D_NVSTATE_NEW);
  if(kind==P7D_NV_AMBIGUOUS) apply_nv(P7D_NVSTATE_AMBIGUOUS);
  fold_event(e);
  retained_sealed=0; /* any post-seal record invalidates the seal */
}
void p7_diag_record(uint16_t k,uint16_t a,uint32_t t){
  if(!writer_try_claim(1)) return;
  record_common(k,a,t);
  writer_release();
}
void p7_diag_record_isr(uint16_t k,uint16_t a,uint32_t t){
  if(!writer_try_claim(1)) return; /* never preempts an owner */
  record_common(k,a,t);
  writer_release();
}
void p7_diag_seal_retained(void){
  if(!writer_try_claim(0)) return; /* leave unsealed on contention */
  retained_crc=retained_compute();
  retained_magic=P7_RETAINED_MAGIC;
  retained_sealed=1;
  writer_release();
}
void p7_diag_init(uint32_t gen, uint8_t rs, uint8_t known){
  if(gen==0) gen=1; /* generation 0 is reserved/invalid on the wire */
  /* Boot context: single-threaded by contract, ownership forced free. */
  atomic_store(&writer_owned,0u); atomic_store(&write_seq,0u);
  memset(p7_diag_ring,0,sizeof p7_diag_ring);
  p7_diag_state.boot_generation=gen; p7_diag_state.dropped=0; p7_diag_state.total=0;
  p7_diag_state.head=0; p7_diag_state.count=0; p7_diag_state.nv_state=P7D_NVSTATE_UNKNOWN;
  p7_diag_state.reset_source=rs; p7_diag_state.reset_source_known=known?1u:0u;
  next_seq=1; p7_diag_contention_dropped=0; rolling_fold=0xFFFFu;
  retained_magic=P7_RETAINED_MAGIC; retained_crc=0; retained_sealed=0;
  p7_diag_record(P7D_BOOT_ENTER,0,0);
  p7_diag_record(P7D_RESET_SOURCE, known?(uint16_t)rs:0xFFFFu,0);
}
void p7_diag_init_preserving(uint32_t gen, uint8_t rs, uint8_t known, uint8_t retained_valid){
  /* Boot-time verify (full CRC allowed here, never on record path).
   * Unsealed, post-seal-modified or corrupt history falls back. */
  if(!retained_valid || !retained_sane() || p7_diag_state.count==0 || gen<=p7_diag_state.boot_generation){ p7_diag_init(gen,rs,known); return; }
  if(!writer_try_claim(0)){ p7_diag_init(gen,rs,known); return; }
  p7_diag_state.boot_generation=gen;
  p7_diag_state.reset_source=rs; p7_diag_state.reset_source_known=known?1u:0u;
  retained_sealed=0; /* consumed; firmware must re-seal for next reset */
  writer_release();
  p7_diag_record(P7D_BOOT_ENTER,0,0);
  p7_diag_record(P7D_RESET_SOURCE, known?(uint16_t)rs:0xFFFFu,0);
}
static void put16(uint8_t*o,uint16_t v){o[0]=(uint8_t)v;o[1]=(uint8_t)(v>>8);}
static void put32(uint8_t*o,uint32_t v){put16(o,(uint16_t)v);put16(o+2,(uint16_t)(v>>16));}
size_t p7_diag_snapshot(uint8_t *out, size_t cap){
  size_t length=0;
  if(!out || !writer_try_claim(0)) return 0;
  /* One bounded copy under the existing guard; ISR writers still never wait. */
  {
    if(p7_diag_state.count==0) goto done; /* no snapshot before init */
    uint16_t n=p7_diag_state.count; if(n>P7_DIAG_SNAPSHOT_EVENTS)n=P7_DIAG_SNAPSHOT_EVENTS;
    size_t need=(size_t)P7_DIAG_HDR+(size_t)n*12u+2u;
    if(cap<need) goto done;
    uint16_t count=p7_diag_state.count;
    uint16_t oldest=(uint16_t)((p7_diag_state.head+P7_DIAG_RING-count)%P7_DIAG_RING);
    uint16_t start=(uint16_t)((oldest+(count-n))%P7_DIAG_RING);
    uint32_t contention=p7_diag_contention_dropped;
    memcpy(out,"P7D1",4); out[4]=P7_DIAG_SCHEMA; out[5]=p7_diag_state.nv_state;
    out[6]=(uint8_t)n; out[7]=p7_diag_state.reset_source_known;
    put32(out+8,p7_diag_state.boot_generation); put32(out+12,p7_diag_state.dropped);
    out[16]=p7_diag_state.reset_source_known?p7_diag_state.reset_source:0; out[17]=p7_diag_state.reset_source_known;
    out[18]=0; out[19]=0; put32(out+20,p7_diag_state.total); put32(out+24,contention);
    for(uint16_t i=0;i<n;i++){
      const p7_diag_event_t *e=&p7_diag_ring[(start+i)%P7_DIAG_RING]; uint8_t *o=out+P7_DIAG_HDR+(size_t)i*12u;
      put32(o,e->seq); put32(o+4,e->tick); put16(o+8,e->kind); put16(o+10,e->arg);
    }
    size_t len=(size_t)P7_DIAG_HDR+(size_t)n*12u;
    put16(out+len,p7_diag_crc16(out,len)); length=len+2u;
  }
done:
  writer_release();
  return length;
}
