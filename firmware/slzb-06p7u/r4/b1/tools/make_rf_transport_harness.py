"""Actual TI ZMac submission test: UART loss must not poison RF safety domain.

The ZMac request body is taken verbatim from the blob-pinned patched donor.
Only the MAC boundary is synthetic; all B1 management/NV latch C is linked.
"""
from pathlib import Path
import argparse
from make_zmac_harness import PREAMBLE, SYMBOLS, actual_function_body

HOST=r'''
#include "b1_management.h"
static unsigned irq_depth;
uintptr_t b1_management_test_disable(void)
{ assert(irq_depth==0);irq_depth=1;return 0x55u; }
void b1_management_test_restore(uintptr_t key)
{ assert(irq_depth==1 && key==0x55u);irq_depth=0; }
'''

MAIN=r'''
int main(int argc,char **argv)
{
  assert(argc==2);
  uint8_t data[3]={4,3,2};
  ZMacDataReq_t req={0};
  req.msduLength=sizeof(data);req.msdu=data;
  assert(!b1_nv_runtime_hold_active());
  assert(ZMacDataReqSec(&req,NULL)==ZSuccess);
  assert(mock_mac_submissions==1u);
  b1_management_transport_failed(B1_ERROR_NPI_RX_OVERFLOW);
  assert(b1_management_get_hold_active());
  assert(b1_management_transport_unavailable());
  assert(!b1_management_nv_security_hold_active());
  assert(!b1_nv_runtime_hold_active());
  /* No loss of coordinator's network TX solely from host-side overflow. */
  assert(ZMacDataReqSec(&req,NULL)==ZSuccess);
  assert(mock_mac_submissions==2u);
  if(strcmp(argv[1],"nv")==0) b1_nv_runtime_hold_latch();
  else if(strcmp(argv[1],"security")==0) b1_security_runtime_hold_latch();
  else return 2;
  assert(b1_management_nv_security_hold_active());
  assert(b1_nv_runtime_hold_active());
  assert(ZMacDataReqSec(&req,NULL)==MAC_NO_RESOURCES);
  assert(mock_mac_submissions==2u);
  ZMacSendNoData(0x1234u,0x55u);
  assert(mock_mac_submissions==2u);
  assert(irq_depth==0u);
  printf("B1_ACTUAL_ZMAC_UART_ONLY_CONTINUES_NV_SECURITY_STOPS_PASS %s\n",argv[1]);
  return 0;
}
'''


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    a=parser.parse_args()
    source=a.source.read_text(encoding="utf-8")
    bodies=[actual_function_body(source,sig) for sig in SYMBOLS]
    a.output.write_text(PREAMBLE+HOST+"\n\n".join(bodies)+MAIN,encoding="utf-8")
    print("B1_REAL_TI_ZMAC_DOMAIN_SEPARATION_EXTRACTED")

if __name__=="__main__":
    main()
