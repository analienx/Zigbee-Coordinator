"""Experimental fitted-P7U 20260311 DC/DC+VDDR SysConfig-C differential.

Source-only; does NOT change any CCS project, generate ELF, flash, or
interact with radios. Strictly transform the *pinned* TI 8.33 generated
ti_devices_config.c from R4 on disk into a NEW offline candidate file.

NOTE: The CCS project regenerates ti_devices_config.c from SysConfig.
This tool is NOT integrated into the native compiler pipeline and must
not be represented as a compiled firmware fix until the exact new output
is linked and checked independently.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

KNOWN_TI833_GENERATED_SHA = "ae1c3e90f0370fc6a934932e216835fbb7905ab6d036dfaa3cc578400950f191"
PAIRS = (
    ("#define CCFG_FORCE_VDDR_HH                              0x0",
     "#define CCFG_FORCE_VDDR_HH                              0x1"),
    ("#define SET_CCFG_MODE_CONF_DCDC_RECHARGE                0x1",
     "#define SET_CCFG_MODE_CONF_DCDC_RECHARGE                0x0"),
    ("#define SET_CCFG_MODE_CONF_DCDC_ACTIVE                  0x1",
     "#define SET_CCFG_MODE_CONF_DCDC_ACTIVE                  0x0"),
)

def deny(text):
    raise ValueError("FITTED_P7U_CCFG_SOURCE_BLOCKED_"+text)

def transform(source:str)->str:
    if not isinstance(source,str) or not source:
        deny("SOURCE_NOT_TEXT")
    after=source
    for idx,(before,new) in enumerate(PAIRS):
        if after.count(before)!=1 or after.count(new)!=0:
            deny("PINNED_TI_SOURCE_DRIFT_"+str(idx))
        after=after.replace(before,new,1)
    if after.count("SET_CCFG_IMAGE_VALID_CONF_IMAGE_VALID           0x00000000")!=1:
        deny("DIRECT_ROM_NATIVE_VECTOR_MISSING")
    if after.count('#include DeviceFamily_constructPath(startup_files/ccfg.c)')!=1:
        deny("TI_PROVIDED_CCFG_INCLUDE_MISSING")
    return after

def prepare(path:Path,output:Path,receipt:Path)->dict:
    if (output.exists() or receipt.exists() or path.is_symlink()
        or output.is_symlink() or receipt.is_symlink()):
        deny("NO_OVERWRITE_OR_SYMLINK")
    data=path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=KNOWN_TI833_GENERATED_SHA:
        deny("REAL_TI833_GENERATED_SOURCE_SHA_PIN")
    source=data.decode("utf-8")
    after=transform(source).encode("utf-8")
    result={
      "schema":"r4-p7u-fitted-20260311-source-diff-v1",
      "original_sha256":hashlib.sha256(data).hexdigest(),
      "modified_sha256":hashlib.sha256(after).hexdigest(),
      "sets_CCFG_FORCE_VDDR_HH_1":True,
      "sets_DCDC_RECHARGE_AND_ACTIVE_0":True,
      "compiled_into_native_R4":False,
      "flash_performed":False,
      "flash_authorized":False,
      "known_factory_mode_conf":"0xF1B9C1FF",
      "known_factory_mode_conf_1":"0xFFC00010",
      "qualification":"SOURCE_ONLY_NEEDS_NATIVE_CCFG_88_BYTES_EXACT_MATCH",
    }
    output.parent.mkdir(parents=True,exist_ok=True)
    receipt.parent.mkdir(parents=True,exist_ok=True)
    output.write_bytes(after)
    receipt.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--generated-ti-devices-c",type=Path,required=True)
    p.add_argument("--out-c",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(prepare(a.generated_ti_devices_c,a.out_c,a.receipt),sort_keys=True))
if __name__=="__main__":
    main()
