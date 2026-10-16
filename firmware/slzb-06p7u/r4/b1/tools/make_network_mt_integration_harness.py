"""Cross-source hosted N30: actual TI NPI/MT/SYS response after ZDO transition.

Reuses the existing exact-source generated NPI harness, adding the original
patched TI ZDApp_ChangeState() body and host-only durable-security inputs.
No UART hardware, radio, NVS image or RTOS scheduler is exercised.
"""
from pathlib import Path
import argparse
from make_management_harness import make
from patch_zdapp import extract_function

SUPPORT = r'''
typedef uint8_t devStates_t;
#define DEV_INIT 0u
#define DEV_ZB_COORD 9u
#define ZDO_STATE_CHANGE_EVT 0x100u
#define ZDAppTaskID 7u
static devStates_t devState=DEV_INIT;
static unsigned zdo_events;
static uint8_t FrameCounterUpdated=1u;
int b1_nv_existing_header_candidate(void) {return 1;}
int b1_sec_restored_network_validated(void) {return 1;}
static void OsalPort_setEvent(uint8_t task,uint32_t event)
{
  assert(task==ZDAppTaskID && event==ZDO_STATE_CHANGE_EVT);
  ++zdo_events;
}
'''

SCENARIO = r'''
    if(strcmp(s,"network_ready_e2e")==0) {
        static const uint8_t q[8]={'B','1','Q','1',1,8,0,0};
        b1_management_note_nv_candidate();
        b1_management_note_mt_registered();
        NPITask_Fxn(0,0);
        assert(process_started==1 && b1_management_npi_initialized());
        assert(!b1_management_network_ready());
        ZDApp_ChangeState(DEV_ZB_COORD);
        assert(zdo_events==1u && b1_management_network_ready());
        route(0x21,B1_STATUS_COMMAND,q,sizeof(q));
        assert(last_reply[0]==B1_STATUS_REPLY_SIZE && last_reply[9]==B1_STAGE_NETWORK_READY);
        assert((last_reply[12]&8u)!=0u && sent==1u && forwarded==0u);
        ZDApp_ChangeState(DEV_INIT);
        assert(!b1_management_network_ready());
        route(0x21,B1_STATUS_COMMAND,q,sizeof(q));
        assert((last_reply[12]&8u)==0u && sent==2u);
        ZDApp_ChangeState(DEV_ZB_COORD);
        route(0x21,B1_STATUS_COMMAND,q,sizeof(q));
        assert((last_reply[12]&8u)==0u && sent==3u);
        assert(zdo_events==3u && mutations==0u && live_alloc==0u);
        puts("B1_N30_ACTUAL_ZDO_NPI_MT_SYS_F1_ROUNDTRIP_SOURCE_PASS");
        return 0;
    }
'''


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    npi=make(a.sdk)
    zdapp=(a.sdk/"source/ti/zstack/stack/zdo/zd_app.c").read_text(encoding="utf-8")
    body=extract_function(zdapp,"void ZDApp_ChangeState( devStates_t state )")
    if "b1_management_note_zdo_state" not in body:
        raise RuntimeError("Native ZDO callback missing restored readiness")
    marker="int main(int argc,char **argv) {"
    if npi.count(marker)!=1:
        raise RuntimeError("NPI real harness main changed")
    npi=npi.replace(marker,SUPPORT+body+"\n"+marker+SCENARIO,1)
    a.output.write_text(npi,encoding="utf-8")
    print("B1_ZDO_NPI_MT_SOURCE_EMBEDDED_NO_HARDWARE")

if __name__=="__main__":
    main()
