/* Host test for the exact G5 ring/encode logic (no device, no radio). */
#include "../../firmware/slzb-06p7/ti832/g5/p7_crashdiag.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
static int hook_armed;
static void preempt_hook(void){
  if(!hook_armed) return;
  hook_armed=0; /* inject once: nested task + ISR attempts mid-write */
  p7_diag_record(9,0x77,999);
  p7_diag_record_isr(11,0x78,999);
}
int main(void){
  uint8_t buf[256];
  p7_diag_init(7,0,0);
  p7_diag_record(2,0,5); p7_diag_record(3,0,9); p7_diag_record(10,0,12);
  size_t n=p7_diag_snapshot(buf,sizeof buf);
  assert(n==28+5*12+2); assert(!memcmp(buf,"P7D1",4)); assert(buf[4]==1);
  printf("SNAPSHOT_HEX=");
  for(size_t i=0;i<n;i++) printf("%02x",buf[i]);
  printf("\n");
  assert(p7_diag_snapshot(buf,n)==n); assert(p7_diag_snapshot(buf,n-1)==0);
  p7_diag_record(4,0,20); assert(p7_diag_state.nv_state==3);
  p7_diag_record(3,0,21); assert(p7_diag_state.nv_state==3);
  /* CR1: injected preemption mid-write. Both nested attempts must
   * drop, count contention, and leave ring/snapshot consistent. */
  hook_armed=1; p7_diag_preempt_hook=preempt_hook;
  uint32_t total_before=p7_diag_state.total;
  uint32_t contention_before=p7_diag_contention_dropped;
  p7_diag_record(8,0x42,30);
  p7_diag_preempt_hook=0;
  assert(p7_diag_state.total==total_before+1); /* only outer landed */
  assert(p7_diag_contention_dropped==contention_before+2);
  n=p7_diag_snapshot(buf,sizeof buf); assert(n>0);
  /* CR2 sealed preservation: seal, then preserve keeps history. */
  p7_diag_seal_retained();
  uint16_t before=p7_diag_state.count;
  p7_diag_init_preserving(8,1,1,1);
  assert(p7_diag_state.boot_generation==8 && p7_diag_state.count>=before);
  assert(p7_diag_state.reset_source==1 && p7_diag_state.reset_source_known==1);
  for(int i=0;i<200;i++) p7_diag_record_isr(14,(uint16_t)i,(uint32_t)i);
  assert(p7_diag_state.count==64); assert(p7_diag_state.dropped>0);
  n=p7_diag_snapshot(buf,sizeof buf); assert(n<=28+8*12+2);
  assert(p7_diag_snapshot(buf,10)==0);
  /* CR2 adversarial: corrupt one ring byte after seal -> fallback. */
  p7_diag_init(20,0,0); p7_diag_record(3,0,1); p7_diag_seal_retained();
  p7_diag_ring[0].tick ^= 0xFFu;
  p7_diag_init_preserving(21,0,0,1);
  assert(p7_diag_state.boot_generation==21 && p7_diag_state.count==2);
  /* CR2 adversarial: record without seal -> fallback. */
  p7_diag_init(30,0,0); p7_diag_record(3,0,1);
  p7_diag_init_preserving(31,0,0,1);
  assert(p7_diag_state.boot_generation==31 && p7_diag_state.count==2);
  /* CR2 adversarial: post-seal record invalidates seal -> fallback. */
  p7_diag_init(40,0,0); p7_diag_record(3,0,1); p7_diag_seal_retained();
  p7_diag_record(9,0,2);
  p7_diag_init_preserving(41,0,0,1);
  assert(p7_diag_state.boot_generation==41 && p7_diag_state.count==2);
  /* CR2 positive control: sealed -> preserves. */
  p7_diag_init(50,0,0); p7_diag_record(3,0,1); p7_diag_seal_retained();
  uint16_t sealed_count=p7_diag_state.count;
  p7_diag_init_preserving(51,0,0,1);
  assert(p7_diag_state.boot_generation==51 && p7_diag_state.count>=sealed_count);
  printf("PASS_HOST_CRASHDIAG_RING snapshot=%zu dropped=%u contention=%u\n",
         n,(unsigned)p7_diag_state.dropped,(unsigned)p7_diag_contention_dropped);
  return 0;
}
