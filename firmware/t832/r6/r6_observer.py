"""R6 observation layer. Exact edits; pristine TI functional paths retained."""
from pathlib import Path
import shutil
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from apply_diag import Exact
HERE=Path(__file__).resolve().parent

def patch_nv(nv):
    ex=Exact();shutil.copy2(HERE/'nv_r6_probe.h',nv.parent/'nv_r6_probe.h')
    shutil.copy2(HERE/'nv_r6_probe.inc',nv.parent/'nv_r6_probe.inc')
    # NVPAGES default must have resolved before the header's fixed-size array.
    ex.replace(nv,'static uint8_t NVOCMP_failW;','static uint8_t NVOCMP_failW;\n#include "nv_r6_probe.h"','r6.nv.pod_header')
    ex.replace(nv,'  gAction = action;','  gAction = action;\n  T832R6Nv_capture(7u,0u,(uint16_t)action);','r6.nv.init_pod',count=3)
    for indent in ('    ','  '):
        old='\n'+indent+'status = NVOCMP_compact(pNvHandle);\n'
        ex.replace(nv,old,'\n'+indent+'T832R6Nv_capture(1u,nBytes,0u);'+old+
                   indent+'T832R6Nv_capture(status == NVINTF_SUCCESS ? 2u : 3u,nBytes,status);\n',
                   'r6.nv.compaction_pod.'+str(len(indent)))
    # Record each add attempt and result; create API may remap its result.
    for op in ('CREATE','UPDATE','WRITE'):
        marker=f'err = NVOCMP_addItem(&NVOCMP_nvHandle, &iHdr, pBuf, NVOCMP_{op});'
        ex.replace(nv,marker,'T832R6Nv_capture(5u,(uint16_t)len,0u);\n      '+marker+
                   '\n      T832R6Nv_capture(6u,(uint16_t)len,err);','r6.nv.write_pod.'+op)
    # Compaction's inner result precedes final page-state transitions. Capture
    # the topology again at the completed API boundary, under its existing NV
    # serialization, so the exporter cannot mistake intermediate state for
    # final free space. No synchronization policy is changed.
    for name in ('NVOCMP_compactNvApi','NVOCMP_createItemApi','NVOCMP_updateItemApi','NVOCMP_writeItemApi','NVOCMP_deleteItemApi','NVOCMP_initNvApi'):
        text=nv.read_text();match=re.search(r'static uint8_t '+name+r'\([^;]*?\)\s*\{',text)
        if not match:raise ValueError('API boundary missing '+name)
        end=match.end();depth=1
        while depth:
            depth+=(text[end]=='{')-(text[end]=='}');end+=1
        old=text[match.start():end]
        if name=='NVOCMP_initNvApi':
            index=old.rindex('return(NVOCMP_failF);')
            new=old[:index]+'T832R6Nv_capture(8u,0u,NVOCMP_failF);\n    '+old[index:]
        else:
            if old.count('NVOCMP_UNLOCK(err);')!=1:raise ValueError('API unlock mismatch '+name)
            new=old.replace('NVOCMP_UNLOCK(err);','T832R6Nv_capture(8u,t832R6Nv.requested,err);\n    NVOCMP_UNLOCK(err);')
        ex.replace(nv,old,new,'r6.nv.final_boundary.'+name)
    ex.append(nv,'#include "nv_r6_probe.inc"','r6.nv.pod_implementation')
    return ex.edits

def apply_observer(sdk):
    nv=sdk/'source/ti/common/nv/nvocmp.c';edits=patch_nv(nv);ex=Exact()
    mt=sdk/'source/ti/zstack/mt';impl=mt/'t832_diag_impl.inc';r5=mt/'t832_diag_r5.inc';header=mt/'t832_diag.h'
    shutil.copy2(HERE/'nv_r6_probe.h',mt/'nv_r6_probe.h')
    shutil.copy2(HERE/'r6_nv_export.inc',mt/'r6_nv_export.inc')
    ex.replace(header,'  T832_DIAG_EV_NWK_LIMIT\n','  T832_DIAG_EV_NWK_LIMIT,\n  T832_DIAG_EV_NV_TOPOLOGY,\n  T832_DIAG_EV_NV_SPACE,\n  T832_DIAG_EV_NV_COUNTERS,\n  T832_DIAG_EV_NV_RESULT,\n  T832_DIAG_EV_NPI_WRITE_COMPLETE\n','r6.events')
    ex.append(header,'void T832Diag_uartWriteComplete(uint16_t len);','r6.callback_declaration')
    # Observe TI callback completion as such; wire events never own a frame.
    ex.replace(impl,'void T832Diag_uartTxFinished(uint16_t len)','void T832Diag_uartWriteComplete(uint16_t len)','r6.callback_observer')
    ex.replace(impl,'  T832Diag_uartEvent(4u, len, 0);',
               '  t832R5.uart_accepted = 0u; /* Driver completion, not wire idle. */','r6.callback_release')
    ex.replace(impl,'T832Diag_record(T832_DIAG_EV_NPI_TX_FINISHED, len, age, t832Diag.normal_pending);',
               'T832Diag_record(T832_DIAG_EV_NPI_WRITE_COMPLETE, len, age, t832Diag.normal_pending);','r6.callback_event')
    ex.replace(impl,'if (subsystem == 1u) T832Diag_bootTiming(4u);','if (subsystem == 1u) T832Diag_bootTiming(6u);','r6.sys_callback_milestone')
    ex.replace(impl,'if (subsystem == 5u) T832Diag_bootTiming(5u);','if (subsystem == 5u) T832Diag_bootTiming(7u);','r6.zdo_callback_milestone')
    ex.replace(r5,'if (event == 4u) T832Diag_pipelineInflight(10u);\n        else t832R5.write_status = status;',
               'if (event == 6u) t832R5.write_status = status; /* Wire idle has no frame identity on pristine TI. */','r6.unbound_wire_event')
    ex.replace(r5,'        T832Diag_pipelineInflight(9u);','        /* TX_BEGIN is unbound on the pristine transport. */','r6.unbound_tx_begin')
    uart=sdk/'source/ti/zstack/npi/npi_tl_uart.c'
    ex.replace(uart,'        T832Diag_uartTxFinished(TransportTxLen);','        T832Diag_uartEvent(4u, 0u, 0);','r6.wire_observation_only')
    ex.replace(uart,'    T832Diag_uartEvent(2u, (uint16_t)size, (int16_t)status);',
               '    T832Diag_uartEvent(2u, (uint16_t)size, (int16_t)status);\n'
               '    T832Diag_uartWriteComplete((uint16_t)size);','r6.write_callback_observer')
    ex.replace(impl,'      T832_DIAG_CAP_RX_OVERFLOW | T832_DIAG_CAP_TX_FINISHED |',
               '      T832_DIAG_CAP_RX_OVERFLOW | (1u << 28) |','r6.callback_semantics_capability')
    ex.replace(impl,'void T832Diag_exportPoll(void)', '#include "r6_nv_export.inc"\n\nvoid T832Diag_exportPoll(void)','r6.nv.deferred_export')
    ex.replace(impl,'  T832Diag_sampleR5(now);','  T832Diag_sampleR5(now);\n  T832R6Nv_poll(now);','r6.nv.sample_before_gates')
    return edits+ex.edits
