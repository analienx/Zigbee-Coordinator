"""Compile actual OSAL NV read wrappers; NVINTF readItem is the boundary."""
import argparse
from pathlib import Path
from patch_zdapp import extract_function

PREAMBLE = r'''
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define SUCCESS 0u
#define NVINTF_SUCCESS 0u
#define NVINTF_FAILURE 2u
#define NV_OPER_FAILED 10u
#define NVINTF_SYSID_ZSTACK 1u
#define ZCD_NV_EX_LEGACY 0u
typedef struct { uint16_t systemID,itemID,subID; } NVINTF_itemID_t;
typedef struct { struct { uint8_t (*readItem)(NVINTF_itemID_t,uint16_t,uint16_t,void*); } nvFps; } zstack_Config_t;
static zstack_Config_t config, *pZStackCfg=&config;
static uint8_t result; static unsigned called;
static uint8_t read_item(NVINTF_itemID_t id,uint16_t off,uint16_t len,void *dst)
{
  ++called; assert(id.systemID==1 && id.itemID==0 && id.subID==7 && off==0 && len==1);
  if(result==NVINTF_SUCCESS) memset(dst,0x51,len); return result;
}
'''
MAIN = r'''
int main(void)
{
  uint8_t value=0; config.nvFps.readItem=read_item;
  result=NVINTF_SUCCESS; assert(osal_nv_read(7,0,1,&value)==SUCCESS && value==0x51);
  for(unsigned status=1;status<256;++status) {
    result=(uint8_t)status; value=0xA5;
    assert(osal_nv_read(7,0,1,&value)==NV_OPER_FAILED && value==0xA5);
  }
  assert(called==256); pZStackCfg=NULL;
  assert(osal_nv_read(7,0,1,&value)==NV_OPER_FAILED && called==256);
  puts("B1_ACTUAL_OSAL_NV_ALL_READ_FAILURE_STATUSES_PASS"); return 0;
}
'''


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    s=a.source.read_text(encoding='utf-8')
    functions=[extract_function(s,'uint8_t osal_nv_read_ex( uint16_t id, uint16_t subId, uint16_t ndx, uint16_t len, void *buf )'),
               extract_function(s,'uint8_t osal_nv_read( uint16_t id, uint16_t ndx, uint16_t len, void *buf )')]
    a.output.write_text(PREAMBLE+'\n'.join(functions)+MAIN,encoding='utf-8')
    print('B1_ACTUAL_OSAL_NV_READ_FUNCTIONS_EXTRACTED')


if __name__=='__main__':
    main()
