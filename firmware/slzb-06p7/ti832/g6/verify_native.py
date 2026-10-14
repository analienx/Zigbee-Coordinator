"""HOSTED ONLY: actual ELF/HEX/map proof, CCFG identity and per-track NV geometry."""
import argparse, hashlib, json, sys, re, struct
from pathlib import Path
TI=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TI/"g2")); import validate_elf_hex as stock
sys.path.insert(0,str(TI/"g3")); import nv5_verify_linked as nv5
sys.path.insert(0,str(TI/"g5")); import diag_build_compare as maps
P7U=Path(__file__).resolve().parents[3]/"slzb-06p7u"/"ti832"
sys.path.insert(0,str(P7U)); import p7u_stock_ccfg as p7u

def verify(base,cand,profile):
    be=(base/"BASE-NOT-FLASHABLE.out").read_bytes()
    ce=(cand/"DIAG-NOT-FLASHABLE.out").read_bytes()
    bh=(base/"BASE-NOT-FLASHABLE.hex").read_text()
    ch=(cand/"DIAG-NOT-FLASHABLE.hex").read_text()
    cm=(cand/"DIAG-NOT-FLASHABLE.map").read_text()
    syms=maps.symbols((cand/"DIAG-symbols.txt").read_text())
    print("G6_CLOCK_SYMBOLS",sorted(s for s in syms if "Clock" in s and ("Ticks" in s or "Period" in s)))
    em,_=(nv5.load_elf(ce) if profile=="cap192" else stock.read_elf(ce))
    hm=stock.read_hex(ch)
    print("G6_IMAGE_COUNTS",json.dumps({"elf":len(em),"hex":len(hm),
        "hex_missing_first32":[hex(a) for a in sorted(set(em)-set(hm))[:32]],
        "hex_extra_first32":[hex(a) for a in sorted(set(hm)-set(em))[:32]]}))
    # Diagnostic only: identify the actual initialized-section boundaries
    # around missing bytes. Keep the strict audit below unchanged.
    missing=sorted(set(em)-set(hm))
    if missing:
        hdr=struct.unpack_from("<HHIIIIIHHHHHH",ce,16)
        shoff,shsize,shnum,shstr=hdr[5],hdr[10],hdr[11],hdr[12]
        rows=[struct.unpack_from("<IIIIIIIIII",ce,shoff+i*shsize) for i in range(shnum)]
        names=rows[shstr]; strings=ce[names[4]:names[4]+names[5]]
        nearby=[]
        for row in rows:
            name=strings[row[0]:].split(b'\0',1)[0].decode(errors='replace')
            start,size=row[3],row[5]
            if row[2]&2 and any(start-32<=a<start+size+32 for a in missing):
                nearby.append({"name":name,"type":row[1],"flags":row[2],"address":hex(start),"size":size,"end":hex(start+size)})
        print("G6_IMAGE_GAP_CONTEXT",json.dumps({"missing_values":[[hex(a),em[a]] for a in missing[:32]],"sections":nearby}))
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
    if profile=="p7u-stock":
        binding=json.loads((P7U.parent/"board"/"stock-20240710-ccfg-binding.json").read_text())
        vendor_ccfg=p7u.validate_linked_ccfg(br,cr,binding)
    else:
        if cr!=br:raise ValueError("CCFG_CHANGED")
        vendor_ccfg=None
    if any(nv_base<=a<0xae000 for a in cmem):raise ValueError("NV_IMAGE_WRITE")
    required={"p7_g6_now","p7_g6_record","p7_g6_response","p7_g6_rx_resync", "p7_g6_reset_parser",
              "p7_g6_discard_ring","p7_g6_discard_tl"}
    if not required<=syms:raise ValueError("G6_SYMBOLS_MISSING:"+str(required-syms))
    # Actual approved P7 BASE symbol artifact uses TI's namespaced API symbol.
    # Accept only these exact API forms, and prove the G6 getter branches to it.
    clocks={"Clock_getTicks","ti_sysbios_knl_Clock_getTicks"}&syms
    if not clocks:raise ValueError("LINKED_CLOCK_API_MISSING")
    dis=(cand/"DIAG-disassembly.txt").read_text()
    body=re.search(r'<p7_g6_now>:(.*?)(?=^\s*[0-9a-fA-F]+\s+<|\Z)',dis,re.S|re.M)
    if not body or not any(re.search(r'\b(?:b(?:\.[wn])?|bl(?:\.w)?|blx)\s+[^\n]*<'+
            re.escape(clock)+r'>',body.group(1)) for clock in clocks):
        raise ValueError("G6_GETTER_CLOCK_CALL_NOT_PROVEN")
    if "p7_diag_preempt_hook" in syms or any(s.startswith("__atomic_") for s in syms):
        raise ValueError("TEST_HOOK_OR_LIBATOMIC_LINKED")
    region=maps.parse_map(cm)["regions"]
    if region["flash_nv_size"]!=nv_size or region["flash_nv_used"]!=nv_size:
        raise ValueError("NV_LINKER_RESERVATION_CHANGED")
    return {"profile":profile,"qualification":"G6_SOURCE_AND_NATIVE_ONLY_NOT_FLASHABLE",
        "flash_authorized":False,"hardware_qualified":False,"runtime_qualified":False,
        "base_audit":base_audit,"candidate_audit":audit,"nv_base":nv_base,"nv_size":nv_size,
        "nv_initialized_bytes":0,"ccfg_equal":cr==br,"ccfg_sha256":hashlib.sha256(cr).hexdigest(),
        "p7u_vendor_ccfg_evidence":vendor_ccfg,
        "g6_symbols":sorted(required),"clock_symbols":sorted(clocks),
        "clock_call_from_g6_getter_verified":True,"candidate_resources":region,
        "clock_and_uart_runtime_on_original_board":"UNPROVEN"}

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--base",type=Path,required=True)
    p.add_argument("--candidate",type=Path,required=True);p.add_argument("--profile",choices=("stock","cap192","p7u-stock"),required=True)
    p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    result=verify(a.base,a.candidate,a.profile);a.out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
