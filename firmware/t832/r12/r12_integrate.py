"""Inject R12-A0 into the exact, already-patched R11 TI source tree.

This is intentionally a *post-R11* exact-anchor patch: R11 security/NVS and
ZNP host behavior are not changed, except for extra diagnostic code.
Generated image is a candidate, NOT device-deployment authorization.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from apply_diag import Exact


def patch_r11_header(src: str) -> str:
    if '#include "r12_target.h"' in src:
        raise ValueError("R12 header already patched")
    src = src.replace('#include <stdint.h>\n',
                      '#include <stdint.h>\n#include "r12_target.h"\n', 1)
    functions = {
        "T832R11_enter": ("site", "T832_R11_PHASE_ENTRY"),
        "T832R11_exit": ("site", "T832_R11_PHASE_EXIT"),
        "T832R11_confirm": ("T832R11_SITE_FORM_CONFIRM", "T832_R11_PHASE_CONFIRM"),
    }
    for name, (site, phase) in functions.items():
        m = re.search(r"static inline void "+name+r"\([^)]*\)\s*\{", src)
        if not m:
            raise ValueError("missing exact R11 source function "+name)
        depth=1; pos=m.end()
        while depth:
            if pos >= len(src):
                raise ValueError("unterminated R11 source")
            depth += (src[pos] == "{")-(src[pos] == "}")
            pos += 1
        start, end = m.start(), pos
        old = src[start:end]
        needle = '    t832R11Startup.sequence++;\n}'
        if old.count(needle)!=1:
            raise ValueError("R11 function epilogue drift "+name)
        # A committed R11 SRAM milestone exists even if AUX recorder gates
        # fail. R12 does not alter Zigbee stack return/state branches.
        new = old.replace(needle,
              f'    t832R11Startup.sequence++;\n'
              f'    T832R12_mark({site},{phase},0u);\n}}')
        src = src[:start]+new+src[end:]
    return src


def install(sdk: Path) -> dict:
    mt=sdk/"source/ti/zstack/mt"
    st=sdk/"source/ti/zstack/startup"
    bdb=sdk/"source/ti/zstack/stack/bdb"
    zdo=sdk/"source/ti/zstack/stack/zdo"
    for d in (mt,st,bdb,zdo):
        if not (d/"r11_startup.h").is_file():
            raise ValueError("R11 observer must be applied before R12")
    for filename in ("r12_target.h","r12_aux_trace.h"):
        for d in (mt,st,bdb,zdo):
            shutil.copy2(HERE/filename,d/filename)
    for filename in ("r12_aux_trace.c","r12_aux_boot.h",
                     "r12_aux_boot.c","r12_target_impl.inc"):
        shutil.copy2(HERE/filename,mt/filename)
    entries=[]
    for d in (mt,st,bdb,zdo):
        f=d/"r11_startup.h"
        raw=f.read_text(encoding="utf-8")
        patched=patch_r11_header(raw)
        f.write_text(patched,encoding="utf-8")
        entries.append({"path":str(f),"sha256":hashlib.sha256(patched.encode()).hexdigest()})
    ex=Exact()
    # The original R11 exact startup hooks remain the only source of truth.
    main=st/"main.c"
    ex.replace(main,'    Board_initGeneral();\n',
               '    Board_initGeneral();\n'
               '    /* R12: read old AUX snapshot BEFORE any R11 startup markers. */\n'
               '    T832R12_boot((uint32_t)SysCtrlResetSourceGet());\n',
               "r12.boot_early_read")
    zd=zdo/"zd_app.c"
    ex.replace(zd,'    if ( NLME_RestoreFromNV() )\n',
               '    T832R12_mark(9u,0u,0u);\n'
               '    if ( NLME_RestoreFromNV() )\n',
               "r12.nlme_restore_entry")
    ex.replace(zd,'      T832R11_nlme(1u);',
               '      T832R12_mark(9u,1u,1u);\n'
               '      T832R11_nlme(1u);',
               "r12.nlme_restored")
    ex.replace(zd,'      T832R11_nlme(0u);',
               '      T832R12_mark(9u,1u,0u);\n'
               '      T832R11_nlme(0u);',
               "r12.nlme_not_restored")
    # Bracket inline MT→BDB synchronous call. SRSP is queued only after
    # this returns. Site 10 is explicit: MT_BDB_INLINE.
    mtz=mt/"mt_zdo.c"
    ex.replace(mtz,
               '    T832Diag_startup(2u, cmd0, cmd1);\n'
               '    bdb_StartCommissioning(BDB_COMMISSIONING_MODE_NWK_FORMATION);\n'
               '    T832Diag_startup(3u, cmd0, cmd1);',
               '    T832Diag_startup(2u, cmd0, cmd1);\n'
               '    T832R12_mark(10u,0u,0u);\n'
               '    bdb_StartCommissioning(BDB_COMMISSIONING_MODE_NWK_FORMATION);\n'
               '    T832R12_mark(10u,1u,0u);\n'
               '    T832Diag_startup(3u, cmd0, cmd1);',
               "r12.mt_inline_bdb")
    inc=mt/"r11_ext_export.inc"
    ex.replace(inc,'static uint8_t T832R11Ext_tryExport(uint64_t now64,uint32_t now)\n',
               '#include "r12_target_impl.inc"\n'
               'static uint8_t T832R11Ext_tryExport(uint64_t now64,uint32_t now)\n',
               "r12.previous_epoch_export_include")
    ex.replace(inc,'    f=T832R11_firstFault();',
               '    if(T832R12_tryExport(now64,now))return 1u;\n'
               '    f=T832R11_firstFault();',
               "r12.previous_epoch_export_priority")
    # R12 must be distinctly identified from the diagnostic R11 image:
    # preserve the custom product marker, bump only exact 4 revision bytes.
    ver=mt/"mt_version.c"
    ex.replace(ver,"8320052u >>","8320062u >>",
               "r12.firmware_revision",count=4)
    return {
      "schema":"r12-integrated-source-candidate-v1",
      "r11_header":entries,
      "r12":ex.edits,
      "security_contract":"unchanged R11 NV/network restore policy",
      "aux_address_qualification":"UNPROVEN -- DO NOT FLASH",
      "radio_reset_retention_qualification":"UNPROVEN -- DO NOT FLASH",
      "r12_revision":8320062
    }


if __name__=="__main__":
    a=argparse.ArgumentParser()
    a.add_argument("--sdk",required=True,type=Path)
    a.add_argument("--evidence",type=Path)
    args=a.parse_args()
    result=install(args.sdk)
    if args.evidence:
        args.evidence.parent.mkdir(parents=True,exist_ok=True)
        args.evidence.write_text(json.dumps(result,indent=2))
    print(json.dumps({"status":"SOURCE_PATCHED_DEPLOYMENT_BLOCKED",
                      "r12_revision":8320062,
                      "edit_count":len(result["r12"]),
                      "aux_ownership":result["aux_address_qualification"]}))
