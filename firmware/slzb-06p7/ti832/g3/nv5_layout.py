#!/usr/bin/env python3
"""Offline *prototype* TI8.32 P7 NVOCMP 5-page source adaptation.

Input: unmodified pinned TI SDK linker cmd, TI examples .syscfg and .projectspec.
Output: three isolated copied files. Never overwrites inputs. Never accesses
a coordinator, Zigbee service, network state, radio, bootloader, or flash.

WARNING: A five-page NVOCMP region moves its BASE from 0xAA000 to 0xA4000.
Old two-page NV contents DO NOT map directly. The resulting image is a
prototype only, cannot preserve a production network without an independently
proved migration and exact security-counter backup/restore procedure.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

PAGES=5
SECTOR=0x2000
FLASH_END=0xB0000
CCFG_SECTOR_BASE=0xAE000
NV_BYTES=PAGES*SECTOR
NV_BASE=CCFG_SECTOR_BASE-NV_BYTES
APP_END=NV_BASE
OLD_NV_BASE=0xAA000
OLD_PAGES=2
OLD_NV_BYTES=OLD_PAGES*SECTOR
OLD_APP_END=OLD_NV_BASE
TRUST_CENTER_KEYS=192
NWK_LIST=96
NWK_ADDRESSES=298
CANDIDATE="G3_NV5_TI_LAUNCHPAD_PROTOTYPE_NOT_FLASHABLE"
SYSCFG_SCOPE="LP_CC1352P7_4_P7_ARM_ONLY_NON_P7_ARMS_UNPATCHED"
SDK_LINK="source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd"
EXAMPLE_SYSCFG="examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/znp.syscfg"
EXAMPLE_PROJSPEC=("examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/"
                  "ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec")
REFERENCE_TI_SDK_COMMIT="6499c3f53fc5fb5806213be695450a7b43fbaf3d"
REFERENCE_EXAMPLE_COMMIT="87ff5b638b632050228a7504f35cf3b95581c278"

def must(v:bool,message:str)->None:
    if not v:
        raise ValueError(message)

def single(original:str,old:str,new:str,label:str)->str:
    must(original.count(old)==1,label+"_EXPECTED_ONCE")
    must(new not in original,label+"_TARGET_ALREADY_PRESENT")
    return original.replace(old,new)

def patch_linker(old:str)->str:
    out=old
    for source,target,name in (
        ("#define FLASH_SIZE              0xAA000",
         "#define FLASH_SIZE              0xA4000","FLASH_APP"),
        ("#define FLASH_NV_BASE           0xAA000",
         "#define FLASH_NV_BASE           0xA4000","FLASH_NV_BASE"),
        ("#define FLASH_NV_SIZE           0x4000",
         "#define FLASH_NV_SIZE           0xA000","FLASH_NV_SIZE"),
    ):
        out=single(out,source,target,name)
    # Do NOT move CCFG, the last 8KiB sector, or app's 0x00000000 vectors.
    must(out.count("#define FLASH_LAST_BASE         0xAE000")==1,"CCFG_LAST_MOVED")
    must(out.count("#define FLASH_LAST_SIZE         0x2000")==1,"CCFG_SIZE_MOVED")
    return out

def patch_projectspec(old:str)->str:
    a=single(old,"-DNVOCMP_NVPAGES=2","-DNVOCMP_NVPAGES=5","COMPILER_NV_DEFINE")
    b=single(a,"--define=NVOCMP_NVPAGES=2",
             "--define=NVOCMP_NVPAGES=5","LINKER_NV_DEFINE")
    must(b.count("NVOCMP_NVPAGES=5")==2,"PROJECTSPEC_NV_DEFINE_COUNT")
    return b

def patch_syscfg(old:str)->str:
    # Scope is fail-closed: only the LP_CC1352P7_4 initial + P7 arms are
    # patched. The trailing 2674/fallback arm deliberately keeps 0x4000;
    # consuming this file for any non-P7 deviceName without re-running
    # nv5_effective.check_generated_config would silently diverge (NVS
    # 2 pages vs NVOCMP 5 pages). SYSCFG_SCOPE records that boundary.
    # There are three regionSize=0x4000 occurrences in the original:
    # initial default, P7-specific branch, and fallback for older silicon.
    # Only the initial default and P7 branch must change; do NOT touch the
    # fallback or P10/R10 arm of the conditional.
    marker='if (deviceName.includes("R7") || deviceName.includes("P7"))'
    next_arm='else if (deviceName.includes("2674")'
    must(old.count(marker)==1 and old.count(next_arm)==1,"DEVICE_BRANCH_NOT_UNIQUE")
    start=old.index(marker);end=old.index(next_arm,start)
    initial=old[:start];p7=old[start:end];tail=old[end:]
    size='NVS1.internalFlash.regionSize = 0x4000;'
    patched_initial=single(initial,size,'NVS1.internalFlash.regionSize = 0xA000;',
                           "SYSCFG_INITIAL_SIZE")
    patched_p7=single(p7,'NVS1.internalFlash.regionBase = 0xAA000;',
                      'NVS1.internalFlash.regionBase = 0xA4000;', "SYSCFG_P7_BASE")
    patched_p7=single(patched_p7,size,
                      'NVS1.internalFlash.regionSize = 0xA000;',
                      "SYSCFG_P7_SIZE")
    return patched_initial+patched_p7+tail

def check_safety()->None:
    must(PAGES==5 and NV_BASE==0xA4000 and APP_END==0xA4000,
         "NV_GEOMETRY_UNEXPECTED")
    must(NV_BASE+NV_BYTES==CCFG_SECTOR_BASE,
         "NV_CCFG_OVERLAP_OR_GAP")
    must(CCFG_SECTOR_BASE+SECTOR==FLASH_END,
         "CCFG_LAST_ERASE_SECTOR_CHANGED")
    must((OLD_NV_BASE,NV_BASE)!=(NV_BASE,NV_BASE),
         "NO_BASE_MIGRATION_WARNING")
    must(APP_END % SECTOR == 0 and NV_BASE % SECTOR == 0,"NOT_ERASE_ALIGNED")

def ti_nv_estimate()->dict:
    # TI Z-Stack user's guide published entry estimates (older SDK); these
    # are directional, NOT proof of this SDK's serialized NVOCMP layout.
    estimates={"trust_center_entry_bytes":27,"nwk_list_entry_bytes":23,
               "address_entry_bytes":19,"other_nv_bytes_estimate":2300}
    target=192*27+96*23+298*19+2300
    storage=(PAGES-1)*SECTOR
    return {"basis":"TI historical Z-Stack capacity planning figures, not measured SDK 8.32 record image",
            "tc_entries":TRUST_CENTER_KEYS,"nwk_entries":NWK_LIST,
            "address_entries":NWK_ADDRESSES,
            "illustrative_total_bytes":target,
            "stock_one_storage_sector_bytes":(OLD_PAGES-1)*SECTOR,
            "nv5_four_storage_sector_bytes":storage,
            "nv5_nominal_after_estimated_items_bytes":storage-target,
            "nv5_runtime_qualified":False,
            "nv5_power_failure_qualified":False,
            "nv5_existing_network_migration_qualified":False,
            "max_pages_basis":"TI guide documents up to five pages; the pinned nvocmp.c permits configurable page count",
            "assumptions":estimates}

def candidate_manifest(inputs:dict[str,bytes],outputs:dict[str,bytes])->dict:
    return {
        "qualification":CANDIDATE,"silicon_reference":"CC1352P7 LaunchPad (2.4 GHz compatibility only)",
        "real_smlight_board_qualified":False,"flash_authorized":False,
        "nv_migration_authorized":False,"coordinator_restore_verified":False,
        "source_sdk_commit":REFERENCE_TI_SDK_COMMIT,
        "source_examples_commit":REFERENCE_EXAMPLE_COMMIT,
        "nv_pages":PAGES,"erase_sector_bytes":SECTOR,"syscfg_scope":SYSCFG_SCOPE,
        "app_region":{"base":"0x00000","end_exclusive":hex(APP_END),"bytes":APP_END},
        "nv_region":{"base":hex(NV_BASE),"end_exclusive":hex(CCFG_SECTOR_BASE),
                     "bytes":NV_BYTES,"storage_page_count":PAGES-1,
                     "compaction_page_count":1},
        "ccfg_sector":{"base":hex(CCFG_SECTOR_BASE),"end_exclusive":hex(FLASH_END)},
        "stock_old_nv_base":hex(OLD_NV_BASE),"stock_old_nv_pages":OLD_PAGES,
        "nv_base_has_moved":True,
        "old_network_nv_not_directly_interchangeable":True,
        "requires_verified_key_and_counter_migration_before_use":True,
        "sources":{key:{"input_sha256":hashlib.sha256(inputs[key]).hexdigest(),
                        "patched_sha256":hashlib.sha256(outputs[key]).hexdigest()}
                   for key in sorted(inputs)},
        "planning_only":ti_nv_estimate(),
    }

def generate(sdk:Path,examples:Path,out:Path)->dict:
    check_safety()
    entries={
        "sdk_linker":(sdk/SDK_LINK,patch_linker),
        "example_syscfg":(examples/EXAMPLE_SYSCFG,patch_syscfg),
        "example_projectspec":(examples/EXAMPLE_PROJSPEC,patch_projectspec),
    }
    src={};dst={}
    for name,(file,fn) in entries.items():
        must(file.is_file(),"INPUT_MISSING_"+name)
        src[name]=file.read_bytes()
        result=fn(src[name].decode("utf-8"))
        dst[name]=result.encode("utf-8")
        must(src[name]!=dst[name],"UNMODIFIED_"+name)
    # Caller-supplied output folder must be distinct from authoritative trees.
    out_real=out.resolve()
    sdk_real, ex_real = sdk.resolve(), examples.resolve()
    probes = [(out / "sdk" / SDK_LINK).resolve(),
              (out / "examples" / EXAMPLE_SYSCFG).resolve(),
              (out / "examples" / EXAMPLE_PROJSPEC).resolve()]
    must(not(out_real==sdk_real or out_real==ex_real or
        sdk_real in out_real.parents or ex_real in out_real.parents)
        and all(sdk_real not in q.parents and ex_real not in q.parents
                for q in probes),
        "REFUSE_TO_MODIFY_PINNED_INPUT_SOURCE")
    for name,(file,_) in entries.items():
        base=sdk if name=="sdk_linker" else examples
        target=out / ("sdk" if name=="sdk_linker" else "examples") /file.relative_to(base)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(dst[name])
    report=candidate_manifest(src,dst)
    (out/"NV5-CANDIDATE-SOURCE-MANIFEST.json").write_text(
        json.dumps(report,sort_keys=True,indent=2)+"\n")
    return report

def selftest()->None:
    check_safety()
    l="\n".join([
       "#define FLASH_SIZE              0xAA000",
       "#define FLASH_NV_BASE           0xAA000",
       "#define FLASH_NV_SIZE           0x4000",
       "#define FLASH_LAST_BASE         0xAE000",
       "#define FLASH_LAST_SIZE         0x2000"
    ])
    p='-DNVOCMP_NVPAGES=2\n--define=NVOCMP_NVPAGES=2\n'
    syscfg='NVS1.internalFlash.regionSize = 0x4000;\n' +\
       'if (deviceName.includes("R7") || deviceName.includes("P7"))\n{\n' +\
       'NVS1.internalFlash.regionBase = 0xAA000;\n' +\
       'NVS1.internalFlash.regionSize = 0x4000;\n}\n' +\
       'else if (deviceName.includes("2674")' +\
       'NVS1.internalFlash.regionSize = 0x4000;\n'
    must("0xA4000" in patch_linker(l),"POSITIVE_LINK")
    must("NVPAGES=5" in patch_projectspec(p),"POSITIVE_PROJECT")
    v=patch_syscfg(syscfg)
    must(v.count("regionSize = 0xA000;")==2,"POSITIVE_SYSCFG")
    must(v.count("regionSize = 0x4000;")==1,"FALLBACK_CHANGED")
    must("2674" in v and SYSCFG_SCOPE.startswith("LP_CC1352P7_4"),"SYSCFG_SCOPE_LOST")
    _m=candidate_manifest({"a":b"x"},{"a":b"y"})
    must(_m["syscfg_scope"]==SYSCFG_SCOPE,"MANIFEST_SCOPE_NOT_EMITTED")
    examples=[
        lambda:patch_linker(l.replace("0xAA000","0xAB000",1)),
        lambda:patch_linker(l.replace("FLASH_LAST_SIZE         0x2000",
                                      "FLASH_LAST_SIZE         0x4000")),
        lambda:patch_linker(p),
        lambda:patch_projectspec(p.replace("-DNVOCMP_NVPAGES=2",
                                           "-DNVOCMP_NVPAGES=3")),
        lambda:patch_projectspec(p+"-DNVOCMP_NVPAGES=2\n"),
        lambda:patch_projectspec(p.replace("--define=NVOCMP_NVPAGES=2","")),
        lambda:patch_syscfg(syscfg.replace('includes("P7")','includes("P10")')),
        lambda:patch_syscfg(syscfg.replace("0xAA000","0xFD800")),
        lambda:patch_syscfg(syscfg.replace("NVS1.internalFlash.regionSize = 0x4000;","NVS1.internalFlash.regionSize = 0xA000;",1)),
    ]
    for index,fn in enumerate(examples):
        try:fn()
        except ValueError:continue
        raise AssertionError(f"NV5_NEGATIVE_CONTROL_{index}_ACCEPTED")
    m=ti_nv_estimate()
    must(m["illustrative_total_bytes"]==15354,"CAP192_TI_ESTIMATE_ARITHMETIC")
    must(m["nv5_nominal_after_estimated_items_bytes"]>10000,"NV5_ESTIMATE")
    print(f"PASS P7 NV5 isolated layout source geometry and {len(examples)} mutation tests")

def main()->None:
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path)
    p.add_argument("--examples",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    if a.selftest:selftest()
    if a.sdk or a.examples or a.out:
        must(bool(a.sdk and a.examples and a.out),"REQUIRE_ALL_INPUTS")
        report=generate(a.sdk,a.examples,a.out)
        print(json.dumps(report,indent=2,sort_keys=True))
if __name__=="__main__":
    main()
