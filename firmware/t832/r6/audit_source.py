"""Hosted audit of actual patched sources and intentionally unchanged paths."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from test_r5_pinned import function
from nv_contract import budget

def pristine(sdk,path):return subprocess.check_output(['git','-C',str(sdk),'show','HEAD:'+path],text=True)
def audit(a):
    uart='source/ti/zstack/npi/npi_tl_uart.c';actual=(a.sdk/uart).read_text();original=pristine(a.sdk,uart)
    cb=function(actual,'NPITLUART_writeCallBack')
    if a.variant=='DIAG':
        cb=cb.replace('    T832Diag_uartEvent(2u, (uint16_t)size, (int16_t)status);\n','').replace('    T832Diag_uartWriteComplete((uint16_t)size);\n','')
        event=function(actual,'NPITLUART_eventCallBack')
        if 'npiTransmitCB' in event or 'TxActive' in event or 'UART2_readCancel' in event:raise ValueError('DIAG wire observer changed functional completion')
    if cb!=function(original,'NPITLUART_writeCallBack'):raise ValueError('pristine UART completion policy changed')
    for path in ('source/ti/zstack/npi/npi_tl_uart.h','source/ti/zstack/stack/nwk/nwk_globals.c'):
        if (a.sdk/path).read_text()!=pristine(a.sdk,path):raise ValueError('unrequested queue/ISR capacity change '+path)
    opts=(a.sdk/'source/ti/zstack/apps/znp/znp_cnf.opts').read_text()
    for forbidden in ('CONCENTRATOR','MAX_RTG','MAX_NEIGHBOR','NVOCMP_RECOVER_FROM_COMPACT_FAILURE'):
        if '-D'+forbidden in opts:raise ValueError('nonminimal R6 functional policy '+forbidden)
    if a.variant=='DIAG':
        hook=(a.sdk/'source/ti/common/nv/nv_r6_probe.inc').read_text()
        for forbidden in ('ClockP_','OsalPort_','malloc(','printf(','NVOCMP_read(','NVS_'):
            if forbidden in hook:raise ValueError('heavy NV hot-path observer '+forbidden)
        runtime=(a.sdk/'source/ti/zstack/mt/t832_diag_impl.inc').read_text()
        if 'Memory_getStats(' in runtime:raise ValueError('heap scan reintroduced')
        if runtime.index('T832R6Nv_poll(now);')>runtime.index('if ((uint32_t)(now - t832Diag.last_export_ms)'):raise ValueError('NV sampling behind export gate')
    # The actual compiled TU carries cast-safe static assertions (rather than
    # trying to evaluate TI's NWK_MAX_ADDRESSES expression with Python eval).
    c=budget(a.profile);version=(a.sdk/'source/ti/zstack/mt/mt_version.c').read_text()
    if f'_Static_assert(NWK_MAX_ADDRESSES == {c["capacities"]["addresses"]}' not in version:raise ValueError('derived capacity compile assertion missing')
    return {'pristine_callback_policy':True,'pristine_queue_and_isr_capacity':True,'nv_hotpath_pod_only':a.variant=='DIAG',
            'compiled_assertions_required':True,'profile':c,'variant':a.variant,'hardware_validated':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--sdk',type=Path,required=True);p.add_argument('--examples',type=Path,required=True)
    p.add_argument('--profile',required=True);p.add_argument('--variant',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.write_text(json.dumps(audit(a),indent=2)+'\n')
