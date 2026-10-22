"""Real ZDO marker publisher -> real OSAL initializer, production B1 state.

Only the NVINTF boundary is synthetic. This catches the tails-only policy
conflict that separate marker and capacity stubs previously concealed.
"""
import argparse
import hashlib
from pathlib import Path
import re
from patch_zdapp import extract_function
from make_network_ready_harness import PREAMBLE

BOUNDARY = r'''
#define SUCCESS 0u
#define NV_OPER_FAILED 10u
#define ZCD_NV_EX_ADDRMGR 1u
#define ZCD_NV_EX_BINDING_TABLE 2u
#define ZCD_NV_EX_DEVICE_LIST 3u
typedef struct {uint8_t systemID;uint16_t itemID,subID;} NVINTF_itemID_t;
static uint8_t absence_error;
static uint32_t get_len(NVINTF_itemID_t id)
{assert(id.systemID==1);return id.itemID==0&&id.subID==0x60?marker_length:0;}
static uint8_t read_item(NVINTF_itemID_t id,uint16_t off,uint16_t len,void *out)
{
 assert(id.systemID==1&&off==0);
 if(absence_error)return NVINTF_CORRUPT;
 if(id.itemID!=0||id.subID!=0x60||marker_length==0)return NVINTF_NOTFOUND;
 if(len!=1||marker_length!=1)return NVINTF_BADLENGTH;
 return osal_nv_read(0x60,0,1,out);
}
static uint8_t create_item(NVINTF_itemID_t id,uint32_t len,void *value)
{
 assert(id.systemID==1&&id.itemID==0&&id.subID==0x60&&len==1&&value!=NULL);
 assert(marker_length==0);++marker_creates;
 if(marker_init_fail)return NVINTF_LOWPOWER;
 marker_length=1;marker_value=*(uint8_t*)value;return NVINTF_SUCCESS;
}
static struct {struct {
 uint32_t(*getItemLen)(NVINTF_itemID_t);
 uint8_t(*createItem)(NVINTF_itemID_t,uint32_t,void*);
 uint8_t(*readItem)(NVINTF_itemID_t,uint16_t,uint16_t,void*);
}nvFps;} config={{get_len,create_item,read_item}},*pZStackCfg=&config;
void b1_nv_runtime_hold_latch(void) {b1_management_hold_nv(B1_ERROR_NV_BACKEND);}
static uint8_t b1_configured_init_active;
int b1_znp_configured_init_authorized(void);
'''

MAIN = r'''
int main(int argc,char **argv)
{
 assert(argc==2);const char *s=argv[1];uint8_t value=0x55,progress[32];
 existing_candidate=valid_security=FrameCounterUpdated=1;
 b1_management_note_nv_candidate();b1_management_note_mt_registered();
 marker_length=0;
 if(strcmp(s,"unauthorized")==0) {
  assert(osal_nv_item_init_ex(0,0x60,1,&value)==NV_OPER_FAILED);
  assert(marker_creates==0&&b1_nv_runtime_hold_active());return 0;
 }
 assert(b1_startup_admit(0x65,0x40));
 {const uint8_t ack[]={0xfe,1,0x65,0x40,0,0x24};
  b1_startup_tx_submit(ack,sizeof(ack));b1_startup_tx_accepted(sizeof(ack),1);
  b1_startup_tx_result(sizeof(ack),1);b1_startup_tx_eot();}
 assert(b1_startup_begin());
 if(strcmp(s,"existing")==0){marker_length=1;marker_value=0x55;}
 if(strcmp(s,"unconfigured")==0){marker_length=1;marker_value=0;}
 if(strcmp(s,"bad_length")==0)marker_length=2;
 if(strcmp(s,"create_error")==0)marker_init_fail=1;
 if(strcmp(s,"bad_readback")==0)marker_bad_readback=1;
 if(strcmp(s,"absence_error")==0)absence_error=1;
 ZDApp_ChangeState(DEV_ZB_COORD);
 assert(!b1_znp_configured_init_authorized()); /* capability always closes */
 if(strcmp(s,"missing")==0||strcmp(s,"existing")==0||strcmp(s,"unconfigured")==0) {
  assert(devState==DEV_ZB_COORD&&events==1&&marker_value==0x55);
  assert(!b1_nv_runtime_hold_active()&&b1_management_network_ready());
  assert(marker_creates==(strcmp(s,"missing")==0?1u:0u));
  unsigned writes=marker_creates+marker_writes;
  ZDApp_ChangeState(DEV_ZB_COORD);assert(writes==marker_creates+marker_writes);
 } else {
  assert(devState==DEV_INIT&&events==0&&b1_nv_runtime_hold_active());
  b1_startup_snapshot(progress);
  assert(progress[6]==B1_STARTUP_FAILED&&progress[9]!=0); /* no silent FAILED */
  if(strcmp(s,"bad_length")==0||strcmp(s,"absence_error")==0)assert(marker_creates==0);
 }
 puts("P7U_ACTUAL_ZDO_OSAL_CONFIGURED_MARKER_INTEGRATION_PASS");return 0;
}
'''


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--sdk',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    sdk=args.sdk
    zd=(sdk/'source/ti/zstack/stack/zdo/zd_app.c').read_text()
    osal=(sdk/'source/ti/zstack/osal/osal_nv.c').read_text()
    nvintf=(sdk/'source/ti/common/nv/nvintf.h').read_text()
    raw=nvintf.encode()
    if hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=\
            'ae6e751ef693584a052e879000bf1b8e7bf871d9':
        raise ValueError('CONFIGURED_MARKER_PINNED_NVINTF_HEADER_DRIFT')
    constants='\n'.join(re.findall(r'^#define\s+NVINTF_\w+\s+\d+\s*$',nvintf,re.M))+'\n'
    init_sig='static uint8_t osal_nv_item_init(uint16_t item,uint16_t len,void *value)'
    preamble=PREAMBLE.replace(extract_function(PREAMBLE,init_sig),
                             'uint8_t osal_nv_item_init(uint16_t item,uint16_t len,void *value);')
    bodies=[extract_function(osal,'uint8_t osal_nv_item_init_ex( uint16_t id, uint16_t subId, uint16_t len, void *buf )'),
            extract_function(osal,'uint8_t osal_nv_item_init( uint16_t id, uint16_t len, void *buf )'),
            extract_function(zd,'int b1_znp_configured_init_authorized(void)'),
            extract_function(zd,'static uint8_t b1_znp_publish_configured(void)'),
            extract_function(zd,'void ZDApp_ChangeState( devStates_t state )')]
    preamble+='#define ZCD_NV_EX_LEGACY 0u\n'
    args.output.write_text(constants+preamble+BOUNDARY+'\n'.join(bodies)+MAIN)


if __name__=='__main__':main()
