"""G6 native resource comparison: ISR/task sites use the new owner-clock writer."""
import argparse, json, hashlib, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"g5"))
from diag_build_compare import parse_map, symbols, must
REQUIRED=("p7_diag_record","p7_g6_record","p7_diag_init","p7_diag_state","p7_diag_ring")

def compare(base_map,diag_map,base_syms,diag_syms,base_size,diag_size):
    b,d=parse_map(base_map),parse_map(diag_map)
    bs,ds=symbols(base_syms),symbols(diag_syms)
    for name in REQUIRED:
        must(name in ds,"G6_SYMBOL_MISSING_"+name)
        must(name not in bs,"G6_SYMBOL_LEAKED_TO_BASE_"+name)
    delta={}
    for group in ("regions","sections"):
        for key in sorted(set(b[group])&set(d[group])):delta[key]=d[group][key]-b[group][key]
    return {"qualification":"G6_LINKED_REFERENCE_NOT_FLASHABLE",
        "runtime_qualified":False,"hardware_qualified":False,"flash_authorized":False,
        "base":b,"diag":d,"delta_diag_minus_base":delta,
        "elf_size_bytes":{"base":base_size,"diag":diag_size,"delta":diag_size-base_size},
        "diag_symbols_present":list(REQUIRED),"base_symbols_absent":list(REQUIRED),
        "isr_writer":"p7_g6_record (clock sampled after claim); unused legacy ISR API may be removed by linker"}

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in ("base-map","diag-map","base-symbols","diag-symbols","base-elf","diag-elf","out"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    r=compare(a.base_map.read_text(),a.diag_map.read_text(),a.base_symbols.read_text(),a.diag_symbols.read_text(),
              a.base_elf.stat().st_size,a.diag_elf.stat().st_size)
    r["map_sha256"]={"base":hashlib.sha256(a.base_map.read_bytes()).hexdigest(),
        "diag":hashlib.sha256(a.diag_map.read_bytes()).hexdigest()}
    a.out.write_text(json.dumps(r,indent=2)+"\n");print(json.dumps(r,indent=2))
