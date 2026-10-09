"""R6/R11 observation layer. Exact edits; pristine TI functional paths retained."""
from pathlib import Path
import shutil
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from apply_diag import Exact
HERE=Path(__file__).resolve().parent

# F2 API classes (must match nv_r6_probe.h).
API_OF={'NVOCMP_compactNvApi':6,'NVOCMP_createItemApi':2,'NVOCMP_updateItemApi':3,
        'NVOCMP_writeItemApi':4,'NVOCMP_deleteItemApi':5,'NVOCMP_initNvApi':1}
ADDOP_API={'CREATE':2,'UPDATE':3,'WRITE':4}
KNOWN_ALL='T832R6NV_KNOWN_API|T832R6NV_KNOWN_ITEM|T832R6NV_KNOWN_SITE|T832R6NV_KNOWN_STATUS|T832R6NV_KNOWN_REQUESTED|T832R6NV_KNOWN_SYS|T832R6NV_KNOWN_SUB'
KNOWN_ATTEMPT='T832R6NV_KNOWN_API|T832R6NV_KNOWN_ITEM|T832R6NV_KNOWN_SITE|T832R6NV_KNOWN_REQUESTED|T832R6NV_KNOWN_SYS|T832R6NV_KNOWN_SUB'
KNOWN_COMPACT='T832R6NV_KNOWN_API|T832R6NV_KNOWN_SITE|T832R6NV_KNOWN_STATUS|T832R6NV_KNOWN_REQUESTED'

def patch_nv(nv):
    ex=Exact();shutil.copy2(HERE/'nv_r6_probe.h',nv.parent/'nv_r6_probe.h')
    shutil.copy2(HERE/'nv_r6_probe.inc',nv.parent/'nv_r6_probe.inc')
    # NVPAGES default must have resolved before the header's fixed-size array.
    ex.replace(nv,'static uint8_t NVOCMP_failW;','static uint8_t NVOCMP_failW;\n#include "nv_r6_probe.h"','r6.nv.pod_header')
    ex.replace(nv,'  gAction = action;','  gAction = action;\n  T832R6Nv_capture(7u,0u,(uint16_t)action);','r6.nv.init_pod',count=3)
    for indent in ('    ','  '):
        old='\n'+indent+'status = NVOCMP_compact(pNvHandle);\n'
        # F1: TI's own failure predicate (nvocmp.c:4145/:4319). SRCDONE1,
        # DSTDONE2 and BOTHDOE3 are successful progress and report stage 2;
        # only NVOCMP_COMPACT_FAILURE (0x10) reports stage 3. The raw
        # compact-domain status is preserved in the status argument.
        ex.replace(nv,old,'\n'+indent+'T832R6Nv_capture(1u,nBytes,0u);'+old+
                   indent+'T832R6Nv_capture(status == NVOCMP_COMPACT_FAILURE ? 3u : 2u,nBytes,status);\n',
                   'r11.nv.compaction_pod.'+str(len(indent)))
    # Record each add attempt and result with operation-aware item context
    # (F2). iHdr (sysid/itemid/subid) is RAM-populated by checkItem before
    # the lock; numeric metadata only, never value buffers. Installed AFTER
    # the existing NVOCMP_LOCK (these sites are inside the locked region).
    for op in ('CREATE','UPDATE','WRITE'):
        marker=f'err = NVOCMP_addItem(&NVOCMP_nvHandle, &iHdr, pBuf, NVOCMP_{op});'
        api=ADDOP_API[op]
        ex.replace(nv,marker,
                   f'T832R6Nv_captureCtx(5u,{api}u,T832R6NV_SITE_ADD_INNER,iHdr.itemid,iHdr.subid,iHdr.sysid,(uint16_t)len,0u,(T832R6NV_DOMAIN_NVINTF<<4u)|5u,{KNOWN_ATTEMPT});\n      '+marker+
                   f'\n      T832R6Nv_captureCtx(6u,{api}u,T832R6NV_SITE_ADD_INNER,iHdr.itemid,iHdr.subid,iHdr.sysid,(uint16_t)len,err,(T832R6NV_DOMAIN_NVINTF<<4u)|6u,{KNOWN_ALL});',
                   'r11.nv.write_pod.'+op)
    # Compaction's inner result precedes final page-state transitions. Capture
    # the topology again at the completed API boundary, under its existing NV
    # serialization, so the exporter cannot mistake intermediate state for
    # final free space. No synchronization policy is changed. The raw inner
    # addItem return (stage 6) stays distinct from the remapped final API
    # return (stage 8): CREATE remaps failures to FAILURE while UPDATE/WRITE
    # preserve their own semantics.
    for name in ('NVOCMP_compactNvApi','NVOCMP_createItemApi','NVOCMP_updateItemApi','NVOCMP_writeItemApi','NVOCMP_deleteItemApi','NVOCMP_initNvApi'):
        text=nv.read_text();match=re.search(r'static uint8_t '+name+r'\([^;]*?\)\s*\{',text)
        if not match:raise ValueError('API boundary missing '+name)
        end=match.end();depth=1
        while depth:
            depth+=(text[end]=='{')-(text[end]=='}');end+=1
        old=text[match.start():end]
        api=API_OF[name]
        if name=='NVOCMP_initNvApi':
            index=old.rindex('return(NVOCMP_failW);')
            new=old[:index]+f'T832R6Nv_captureCtx(8u,{api}u,T832R6NV_SITE_API_BOUNDARY,0u,0u,0u,0u,NVOCMP_failW,(T832R6NV_DOMAIN_NVINTF<<4u)|8u,{KNOWN_COMPACT});\n    '+old[index:]
        else:
            if old.count('NVOCMP_UNLOCK(err);')!=1:raise ValueError('API unlock mismatch '+name)
            if name=='NVOCMP_compactNvApi':
                ctx=f'T832R6Nv_captureCtx(8u,{api}u,T832R6NV_SITE_API_BOUNDARY,0u,0u,0u,minAvail,err,(T832R6NV_DOMAIN_NVINTF<<4u)|8u,{KNOWN_COMPACT});\n    '
            elif name=='NVOCMP_deleteItemApi':
                ctx=(f'T832R6Nv_captureCtx(8u,{api}u,T832R6NV_SITE_API_BOUNDARY,id.itemID,id.subID,id.systemID,0u,err,'
                     f'(T832R6NV_DOMAIN_NVINTF<<4u)|8u,{KNOWN_ALL});\n    ')
            else:
                ctx=(f'T832R6Nv_captureCtx(8u,{api}u,T832R6NV_SITE_API_BOUNDARY,id.itemID,id.subID,id.systemID,(uint16_t)len,err,'
                     f'(T832R6NV_DOMAIN_NVINTF<<4u)|8u,{KNOWN_ALL});\n    ')
            new=old.replace('NVOCMP_UNLOCK(err);',ctx+'NVOCMP_UNLOCK(err);')
        ex.replace(nv,old,new,'r11.nv.final_boundary.'+name)
    ex.append(nv,'#include "nv_r6_probe.inc"','r6.nv.pod_implementation')
    return ex.edits

def patch_startup(sdk,ex):
    """F3 8-site startup POD: pure POD writes, no branch/return changes."""
    r11=HERE/'r11_startup.h'
    mt=sdk/'source/ti/zstack/mt'
    startup=sdk/'source/ti/zstack/startup'
    zdo=sdk/'source/ti/zstack/stack/zdo'
    bdb=sdk/'source/ti/zstack/stack/bdb'
    for d in (mt,startup,zdo,bdb):
        shutil.copy2(r11,d/'r11_startup.h')
    main=startup/'main.c'
    ex.replace(main,'#include <string.h>','#include <string.h>\n#include "r11_startup.h"','r11.startup.main_include')
    ex.replace(main,
        '    if(zstack_user0Cfg.nvFps.initNV)\n    {\n        zstack_user0Cfg.nvFps.initNV(NULL);\n    }',
        '    if(zstack_user0Cfg.nvFps.initNV)\n    {\n'
        '        uint8_t t832r11InitStatus;\n'
        '        T832R11_enter(T832R11_SITE_MAIN_INIT);\n'
        '        t832r11InitStatus=zstack_user0Cfg.nvFps.initNV(NULL);\n'
        '        T832R11_exit(T832R11_SITE_MAIN_INIT,(uint16_t)t832r11InitStatus,T832R11_STATE_UNKNOWN,T832R11_STATE_UNKNOWN,T832R11_VALID_STATUS);\n'
        '    }',
        'r11.startup.site1_initnv')
    ex.replace(bdb,'#include "bdb.h"','#include "bdb.h"\n#include "r11_startup.h"','r11.startup.bdb_include')
    ex.replace(bdb,
        '      if(ZDOInitDevice(0) == ZDO_INITDEV_RESTORED_NETWORK_STATE)\n      {\n',
        '      T832R11_enter(T832R11_SITE_BDB_RESTORED);\n'
        '      if(ZDOInitDevice(0) == ZDO_INITDEV_RESTORED_NETWORK_STATE)\n      {\n'
        '        T832R11_exit(T832R11_SITE_BDB_RESTORED,1u,T832R11_STATE_UNKNOWN,T832R11_STATE_UNKNOWN,T832R11_VALID_STATUS);\n',
        'r11.startup.site2_restored')
    ex.replace(bdb,
        '#endif\n        return;\n      }\n      bdb_setNodeIsOnANetwork(FALSE);',
        '#endif\n        return;\n      }\n'
        '      T832R11_exit(T832R11_SITE_BDB_RESTORED,0u,T832R11_STATE_UNKNOWN,T832R11_STATE_UNKNOWN,T832R11_VALID_STATUS);\n'
        '      bdb_setNodeIsOnANetwork(FALSE);',
        'r11.startup.site2_new')
    zd=zdo/'zd_app.c'
    ex.replace(zd,'#include "osal_nv.h"','#include "osal_nv.h"\n#include "r11_startup.h"','r11.startup.zdo_include')
    ex.replace(zd,
        '\n      networkStateNV = ZDApp_ReadNetworkRestoreState();',
        '\n      T832R11_enter(T832R11_SITE_RESTORE_STATE);\n'
        '      networkStateNV = ZDApp_ReadNetworkRestoreState();\n'
        '      T832R11_exit(T832R11_SITE_RESTORE_STATE,networkStateNV,T832R11_STATE_UNKNOWN,T832R11_STATE_UNKNOWN,T832R11_VALID_STATUS);',
        'r11.startup.site3_touchlink')
    ex.replace(zd,
        '\n    networkStateNV = ZDApp_ReadNetworkRestoreState();',
        '\n    T832R11_enter(T832R11_SITE_RESTORE_STATE);\n'
        '    networkStateNV = ZDApp_ReadNetworkRestoreState();\n'
        '    T832R11_exit(T832R11_SITE_RESTORE_STATE,networkStateNV,T832R11_STATE_UNKNOWN,T832R11_STATE_UNKNOWN,T832R11_VALID_STATUS);',
        'r11.startup.site3_restore')
    ex.replace(zd,
        'uint8_t ZDApp_RestoreNetworkState( void )\n{\n  uint8_t nvStat;',
        'uint8_t ZDApp_RestoreNetworkState( void )\n{\n  uint8_t nvStat;\n  T832R11_enter(T832R11_SITE_RESTORE_NWK);',
        'r11.startup.site4_entry')
    ex.replace(zd,
        '  if ( nvStat == ZSUCCESS )\n    return ( ZDO_INITDEV_RESTORED_NETWORK_STATE );\n  else\n    return ( ZDO_INITDEV_NEW_NETWORK_STATE );',
        '  if ( nvStat == ZSUCCESS )\n  {\n'
        '    T832R11_exit(T832R11_SITE_RESTORE_NWK,(uint16_t)ZDO_INITDEV_RESTORED_NETWORK_STATE,T832R11_STATE_UNKNOWN,T832R11_STATE_UNKNOWN,T832R11_VALID_STATUS);\n'
        '    return ( ZDO_INITDEV_RESTORED_NETWORK_STATE );\n  }\n  else\n  {\n'
        '    T832R11_exit(T832R11_SITE_RESTORE_NWK,(uint16_t)ZDO_INITDEV_NEW_NETWORK_STATE,T832R11_STATE_UNKNOWN,T832R11_STATE_UNKNOWN,T832R11_VALID_STATUS);\n'
        '    return ( ZDO_INITDEV_NEW_NETWORK_STATE );\n  }',
        'r11.startup.site4_exit')
    ex.replace(zd,
        '    if ( NLME_RestoreFromNV() )\n    {\n',
        '    if ( NLME_RestoreFromNV() )\n    {\n      T832R11_nlme(1u);\n',
        'r11.startup.site4_nlme_restored')
    ex.replace(zd,
        '    else\n      nvStat = NV_ITEM_UNINIT;',
        '    else\n    {\n      T832R11_nlme(0u);\n      nvStat = NV_ITEM_UNINIT;\n    }',
        'r11.startup.site4_nlme_new')
    ex.replace(zd,
        '  ZDApp_SecInit( networkStateNV );',
        '  T832R11_enter(T832R11_SITE_SEC_INIT);\n'
        '  ZDApp_SecInit( networkStateNV );\n'
        '  T832R11_exit(T832R11_SITE_SEC_INIT,T832R11_STATUS_UNKNOWN,T832R11_STATE_UNKNOWN,T832R11_STATE_UNKNOWN,0u);',
        'r11.startup.site5_secinit')
    ex.replace(zd,
        '    ZDApp_NetworkInit( extendedDelay );',
        '    T832R11_enter(T832R11_SITE_NWK_INIT);\n'
        '    ZDApp_NetworkInit( extendedDelay );\n'
        '    T832R11_exit(T832R11_SITE_NWK_INIT,T832R11_STATUS_UNKNOWN,T832R11_STATE_UNKNOWN,T832R11_STATE_UNKNOWN,0u);',
        'r11.startup.site6_nwkinit')
    ex.replace(zd,
        'void ZDO_NetworkFormationConfirmCB( ZStatus_t Status )\n{\n  nwkStatus = (byte)Status;',
        'void ZDO_NetworkFormationConfirmCB( ZStatus_t Status )\n{\n  nwkStatus = (byte)Status;\n  T832R11_confirm((uint16_t)Status);',
        'r11.startup.site7_confirm')
    ex.replace(zd,
        '      //save NIB to NV before child joins if NV_RESTORE is defined\n      ZDApp_NwkWriteNVRequest();\n      ZDApp_ChangeState( DEV_ZB_COORD );',
        '      //save NIB to NV before child joins if NV_RESTORE is defined\n'
        '      T832R11_enter(T832R11_SITE_NWK_START_EVT);\n'
        '      ZDApp_NwkWriteNVRequest();\n'
        '      ZDApp_ChangeState( DEV_ZB_COORD );\n'
        '      T832R11_exit(T832R11_SITE_NWK_START_EVT,T832R11_STATUS_UNKNOWN,(uint8_t)devState,(uint8_t)_NIB.nwkState,(uint8_t)(T832R11_VALID_DEV|T832R11_VALID_NWK));',
        'r11.startup.site8_nwkstart')

def apply_observer(sdk):
    nv=sdk/'source/ti/common/nv/nvocmp.c';edits=patch_nv(nv);ex=Exact()
    mt=sdk/'source/ti/zstack/mt';impl=mt/'t832_diag_impl.inc';r5=mt/'t832_diag_r5.inc';header=mt/'t832_diag.h'
    shutil.copy2(HERE/'nv_r6_probe.h',mt/'nv_r6_probe.h')
    shutil.copy2(HERE/'r6_nv_export.inc',mt/'r6_nv_export.inc')
    shutil.copy2(HERE/'r11_startup.h',mt/'r11_startup.h')
    shutil.copy2(HERE/'r11_ext_export.inc',mt/'r11_ext_export.inc')
    ex.replace(header,'  T832_DIAG_EV_NWK_LIMIT,\n','  T832_DIAG_EV_NWK_LIMIT,\n  T832_DIAG_EV_NV_TOPOLOGY,\n  T832_DIAG_EV_NV_SPACE,\n  T832_DIAG_EV_NV_COUNTERS,\n  T832_DIAG_EV_NV_RESULT,\n  T832_DIAG_EV_NPI_WRITE_COMPLETE,\n','r6.events')
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
    ex.replace(impl,'      T832_DIAG_CAP_NV_COMPACT | T832_DIAG_CAP_AF_AGE |',
               '      (1u << 29) | T832_DIAG_CAP_AF_AGE |','r6.pod_nv_capability')
    # R11-DIAG extension capability bit30; bit31 stays clear (no retention).
    ex.replace(impl,'      T832_DIAG_CAP_NWK_PRESSURE | T832_DIAG_CAP_TASK_STATS;',
               '      T832_DIAG_CAP_NWK_PRESSURE | T832_DIAG_CAP_TASK_STATS |\n      T832_DIAG_CAP_R11_EXT;','r11.ext_capability')
    ex.replace(impl,'void T832Diag_exportPoll(void)',
               '#include "r11_startup.h"\n#include "r11_ext_export.inc"\n#include "r6_nv_export.inc"\n\nvoid T832Diag_exportPoll(void)',
               'r11.nv.deferred_export')
    ex.replace(impl,'  T832Diag_sampleR5(now);','  T832Diag_sampleR5(now);\n  T832R6Nv_poll(now);\n  T832R11Ext_sample(now);','r11.nv.sample_before_gates')
    # Atomic extension frames share the limiter and every export gate above.
    ex.replace(impl,'  /* Resources first: rarest cadence (60 s) always fits here (nbatch == 0),',
               '  /* R11-DIAG atomic extension frames (IDs 51..53): at most one frame per\n'
               '   * eligible poll through the same limiter and gates checked above. */\n'
               '  if(T832R11Ext_tryExport(now64,now))return;\n'
               '  /* Resources first: rarest cadence (60 s) always fits here (nbatch == 0),',
               'r11.ext.try_export')
    ex.replace(impl,'        /* Baselines advance only for accepted work. */',
               '        /* Baselines advance only for accepted work. */\n        T832R11Ext_noteLegacyAccepted();',
               'r11.ext.legacy_fairness')
    patch_startup(sdk,ex)
    return edits+ex.edits
