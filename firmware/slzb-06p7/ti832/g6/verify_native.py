"""HOSTED ONLY: actual ELF/HEX/map proof, CCFG identity and per-track NV geometry."""
import argparse, hashlib, json, sys
from pathlib import Path
TI=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TI/"g2")); import validate_elf_hex as stock
sys.path.insert(0,str(TI/"g3")); import nv5_verify_linked as nv5
sys.path.insert(0,str(TI/"g5")); import diag_build_compare as maps

def verify(base,cand,profile):
    be=(base/"BASE-NOT-FLASHABLE.out").read_bytes()
    ce=(cand/"DIAG-NOT-FLASHABLE.out").read_bytes()
    bh=(base/"BASE-NOT-FLASHABLE.hex").read_text()
    ch=(cand/"DIAG-NOT-FLASHABLE.hex").read_text()
    cm=(cand/"DIAG-NOT-FLASHABLE.map").read_text()
    bmem,_=stock.read_elf(be)
    base_audit=stock.audit(be,bh)
    if profile=="cap192":
        audit=nv5.validate(ce,ch,cm); cmem,_=nv5.load_elf(ce)
        nv_base,nv_size=0xa4000,0xa000
    else:
        audit=stock.audit(ce,ch); cmem,_=stock.read_elf(ce)
        nv_base,nv_size=0xaa000,0x4000
    br=bytes(bmem[a] for a in range(0xaffa8,0xb0000))
    cr=bytes(cmem[a] for a in range(0xaffa8,0xb0000))
    if cr!=br:raise ValueError("CCFG_CHANGED")
    if any(nv_base<=a<0xae000 for a in cmem):raise ValueError("NV_IMAGE_WRITE")
    syms=maps.symbols((cand/"DIAG-symbols.txt").read_text())
    required={"p7_g6_now","p7_g6_response","p7_g6_rx_resync", "p7_g6_reset_parser",
              "p7_g6_discard_ring","p7_g6_discard_tl","Clock_getTicks"}
    if not required<=syms:raise ValueError("G6_SYMBOLS_MISSING:"+str(required-syms))
    if "p7_diag_preempt_hook" in syms or any(s.startswith("__atomic_") for s in syms):
        raise ValueError("TEST_HOOK_OR_LIBATOMIC_LINKED")
    region=maps.parse_map(cm)["regions"]
    if region["flash_nv_size"]!=nv_size or region["flash_nv_used"]!=nv_size:
        raise ValueError("NV_LINKER_RESERVATION_CHANGED")
    return {"profile":profile,"qualification":"G6_SOURCE_AND_NATIVE_ONLY_NOT_FLASHABLE",
        "flash_authorized":False,"hardware_qualified":False,"runtime_qualified":False,
        "base_audit":base_audit,"candidate_audit":audit,"nv_base":nv_base,"nv_size":nv_size,
        "nv_initialized_bytes":0,"ccfg_equal":True,"ccfg_sha256":hashlib.sha256(cr).hexdigest(),
        "g6_symbols":sorted(required),"candidate_resources":region,
        "clock_and_uart_runtime_on_original_board":"UNPROVEN"}

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--base",type=Path,required=True)
    p.add_argument("--candidate",type=Path,required=True);p.add_argument("--profile",choices=("stock","cap192"),required=True)
    p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    result=verify(a.base,a.candidate,a.profile);a.out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
