#!/usr/bin/env python3
"""Offline P7 G5 crash-diagnostic overlay (source only, NOT_FLASHABLE).
Mirrors the G3/G4 fail-closed single-purpose overlay discipline: copies the
flight-recorder sources into an isolated staging tree, refuses to modify
pinned inputs, and emits a manifest. It does NOT patch any TI SDK file,
linker, SysConfig, CCFG or NV region in this slice, and does NOT wire the
recorder into a CCS build: on-target Hwi/Clock integration and the MT SYS
endpoint stay gated until (a) the pinned-SDK 0xF0 collision grep in CI and
(b) board evidence exist. Candidate CMD 0xF0 collision = UNKNOWN."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

CANDIDATE="G5_CRASHDIAG_RAM_RECORDER_NOT_FLASHABLE"
SCHEMA=1; RING=64; SNAPSHOT_MAX_BYTES=16+8*12+2
MT_CANDIDATE=0xF0; COLLISION="UNKNOWN"  # pinned mt_sys.c not vendored here
ENDPOINT_ENABLED=False  # gated: UNKNOWN collision + no board evidence
SOURCES=["p7_crashdiag.h","p7_crashdiag.c","p7_diag_decode.py"]
FORBIDDEN_TOKENS=[b"nvs_write",b"flash_write",b"nvocmp_write",b"malloc",b"calloc",b"realloc",b"free",b"printf",b"fprintf",b"sprintf"]

def must(v: bool, m: str) -> None:
    if not v: raise ValueError(m)

def audit_source(name: str, data: bytes) -> None:
    if name.endswith((".h",".c")):
        squashed=b"".join(data.split()).lower()
        for tok in FORBIDDEN_TOKENS: must(tok not in squashed, f"FORBIDDEN_TOKEN_{tok.decode()}_IN_{name}")
        must(b"P7_DIAG_RING 64" in data or name.endswith(".c"), "RING_PIN_MISSING")

def stage(src_dir: Path, out: Path) -> dict:
    must(src_dir.is_dir(), "INPUT_MISSING_g5_dir")
    out_real, src_real = out.resolve(), src_dir.resolve()
    must(out_real != src_real and src_real not in out_real.parents, "REFUSE_TO_MODIFY_SOURCE")
    inputs={}
    for name in SOURCES:
        f=src_dir/name; must(f.is_file(), "INPUT_MISSING_"+name)
        data=f.read_bytes(); audit_source(name,data); inputs[name]=data
    for name, data in inputs.items():
        t=out/name; t.parent.mkdir(parents=True, exist_ok=True); t.write_bytes(data)
    manifest={"qualification":CANDIDATE,"schema":SCHEMA,"ring_events":RING,
      "snapshot_max_bytes":SNAPSHOT_MAX_BYTES,"isr_allocation":"none",
      "nv_writes":"none","ccfg_changes":"none",
      "mt_sys_candidate_cmd":hex(MT_CANDIDATE),"mt_sys_collision_check":COLLISION,
      "mt_endpoint_enabled":ENDPOINT_ENABLED,"runtime_qualified":False,"flash_authorized":False,
      "sources":{k:{"sha256":hashlib.sha256(v).hexdigest()} for k,v in sorted(inputs.items())}}
    (out/"CRASHDIAG-CANDIDATE-SOURCE-MANIFEST.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
    return manifest

def selftest() -> None:
    import tempfile
    here=Path(__file__).parent
    with tempfile.TemporaryDirectory() as td:
        m=stage(here, Path(td)/"staged")
        must(m["mt_endpoint_enabled"] is False and m["mt_sys_collision_check"]=="UNKNOWN","ENDPOINT_MUST_STAY_GATED")
        must((Path(td)/"staged"/"CRASHDIAG-CANDIDATE-SOURCE-MANIFEST.json").is_file(),"MANIFEST_MISSING")
        try: stage(here, here/"inside")
        except ValueError: pass
        else: raise AssertionError("ISOLATION_GUARD_ACCEPTED")
    for bad in (b"xx malloc( yy", b"printf( x", b"calloc(1,2)", b"malloc (1)", b"NVOCMP_writeItem(x)"):
        try: audit_source("x.c", bad)
        except ValueError: continue
        raise AssertionError("FORBIDDEN_TOKEN_ACCEPTED")
    print("PASS P7 G5 crashdiag overlay; endpoint gated disabled (collision UNKNOWN)")

def main() -> None:
    p=argparse.ArgumentParser(); p.add_argument("--src",type=Path); p.add_argument("--out",type=Path)
    p.add_argument("--selftest",action="store_true"); a=p.parse_args()
    if a.selftest: selftest()
    if a.src or a.out:
        must(bool(a.src and a.out),"REQUIRE_ALL_INPUTS"); print(json.dumps(stage(a.src,a.out),indent=2,sort_keys=True))

if __name__=="__main__": main()
