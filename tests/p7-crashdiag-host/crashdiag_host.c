/* Host test for the exact G5 ring/encode logic (no device, no radio). */
#include "../../firmware/slzb-06p7/ti832/g5/p7_crashdiag.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
int main(void){
  uint8_t buf[256];
  p7_diag_init(7,0,0);
  p7_diag_record(2,0,5); p7_diag_record(3,0,9); p7_diag_record(10,0,12);
  size_t n=p7_diag_snapshot(buf,sizeof buf);
  assert(n==16+4*12+2); assert(!memcmp(buf,"P7D1",4)); assert(buf[4]==1);
  /* overflow: ring saturates, dropped counts, snapshot stays bounded */
  for(int i=0;i<200;i++) p7_diag_record_isr(14,(uint16_t)i,(uint32_t)i);
  assert(p7_diag_state.count==64); assert(p7_diag_state.dropped>0);
  n=p7_diag_snapshot(buf,sizeof buf); assert(n<=16+8*12+2);
  assert(p7_diag_snapshot(buf,10)==0); /* too small -> nothing written */
  printf("PASS_HOST_CRASHDIAG_RING snapshot=%zu dropped=%u\n",n,(unsigned)p7_diag_state.dropped);
  return 0;
}
