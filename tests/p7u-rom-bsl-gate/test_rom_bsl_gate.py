#!/usr/bin/env python3
"""Hostile synthetic anti-brick HEX parser and P7U source-image gate tests."""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "firmware/slzb-06p7u/qualification/p7u_rom_bsl_image_gate.py"
spec = importlib.util.spec_from_file_location("anti_brick", PATH)
gate = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(gate)
plan_src = ROOT / "firmware/slzb-06p7u/qualification/p7u_app_sector_plan.py"
plan_spec = importlib.util.spec_from_file_location("sector", plan_src)
sector = importlib.util.module_from_spec(plan_spec)
assert plan_spec.loader
plan_spec.loader.exec_module(sector)


def record(addr: int, kind: int, payload: bytes = b"") -> str:
    raw = bytes([len(payload), (addr >> 8) & 255, addr & 255, kind]) + payload
    return ":" + (raw + bytes([-sum(raw) & 255])).hex().upper()

def make_map() -> tuple[dict[int,int],bytes]:
    data = {i: (i * 7) % 256 for i in range(1536)}
    data.update({i: b for i,b in enumerate(
        (0x20010000).to_bytes(4, "little") + (0x101).to_bytes(4, "little"))})
    ccfg = bytearray([0xff] * gate.CCFG_SIZE)
    ccfg[gate.BL_CONFIG_OFFSET:gate.BL_CONFIG_OFFSET+4] = bytes.fromhex("C50FFEC5")
    ccfg[gate.IMAGE_VALID_OFFSET:gate.IMAGE_VALID_OFFSET+4] = b"\x00\x00\x00\x00"
    data.update({gate.CCFG_START+i:b for i,b in enumerate(ccfg)})
    return data,bytes(ccfg)

def ihex(data:dict[int,int])->bytes:
    by_window:dict[int,list[int]]={}
    for addr in sorted(data):
        by_window.setdefault(addr>>16,[]).append(addr)
    out = []
    for upper,addrs in sorted(by_window.items()):
        out.append(record(0,4,upper.to_bytes(2,"big")))
        i=0
        while i<len(addrs):
            batch=[addrs[i]]
            j=i+1
            while j<len(addrs) and addrs[j]==batch[-1]+1 and len(batch)<16:
                batch.append(addrs[j]);j+=1
            out.append(record(batch[0]&0xFFFF,0,bytes(data[a] for a in batch)))
            i=j
    return ("\n".join(out+[record(0,1)])+"\n").encode()

def reject(callback, expected):
    try:callback()
    except gate.PreflightError as exc:
        assert str(exc)==expected, (str(exc),expected)
    else:raise AssertionError("Expected "+expected)

def main():
    data,ccfg=make_map()
    digest=hashlib.sha256(ccfg).hexdigest()
    raw=ihex(data)
    assert gate.parse_hex(raw)==data
    for profile in ("p7u-f07-stock","p7u-cap192-f07"):
        result=gate.candidate_audit(gate.parse_hex(raw),profile,digest,ccfg)
        assert result["flash_authorized"] is False
        assert result["nv_loaded_bytes"]==0
        assert result["backdoor_ti_dio"]==15
        assert result["ccfg_88_bytes_exact_vendor"] is True
        assert result["target_bsl_entry_verified"] is False
    for profile in ("p7u-f07-stock", "p7u-cap192-f07"):
        app_only = gate.application_only_hex(data,profile)
        recovered = gate.parse_hex(app_only)
        assert recovered == {k:v for k,v in data.items() if k < (
            gate.NV2_BASE if profile=="p7u-f07-stock" else gate.NV5_BASE)}
        assert all(k < gate.NV5_BASE for k in recovered)
        assert not any(gate.CCFG_START <= k < gate.CCFG_END for k in recovered)
        assert gate.application_only_hex(data,profile)==app_only
    reject(lambda:gate.application_only_hex(data,"p10"),"P7U_PROFILE_MISMATCH")

    for profile in ("p7u-f07-stock","p7u-cap192-f07"):
        original=gate.candidate_audit(data,profile,digest,ccfg)
        app_bytes=gate.application_only_hex(data,profile)
        original["derived_app_only_hex_sha256"]=hashlib.sha256(app_bytes).hexdigest()
        original["derived_app_only_never_flash_with_bank_erase"]=True
        original["qualification"]="SOURCE_HEX_BSL_GEOMETRY_PASS_NOT_FLASHABLE"
        proposal=sector.plan(app_bytes,original)
        assert proposal["flash_authorized"] is False
        assert proposal["execution_implemented"] is False
        assert proposal["explicit_application_sector_erase_addresses"]==["0x00000"]
        assert all(int(v,16)<gate.NV5_BASE for v in
                   proposal["explicit_application_sector_erase_addresses"])
        bad=dict(original);bad["flash_authorized"]=True
        reject(lambda:sector.plan(app_bytes,bad),"PLAN_FULL_IMAGE_NOT_QUALIFIED")
        bad=dict(original);bad["derived_app_only_hex_sha256"]="0"*64
        reject(lambda:sector.plan(app_bytes,bad),"PLAN_NOT_SAME_VALIDATED_APP")
        bad=dict(original);bad["derived_app_only_never_flash_with_bank_erase"]=False
        reject(lambda:sector.plan(app_bytes,bad),"PLAN_BANK_ERASE_WARNING_MISSING")
        dangerous=dict(gate.parse_hex(app_bytes))
        dangerous[gate.CCFG_START]=1
        reject(lambda:sector.plan(ihex(dangerous),original),
               "PLAN_NOT_SAME_VALIDATED_APP")

    reject(lambda:gate.candidate_audit(data,"p7u-f07-stock"),"IMAGE_CCFG_VENDOR_HASH_MISMATCH")
    reject(lambda:gate.candidate_audit(data,"p10",digest),"P7U_PROFILE_MISMATCH")
    reject(lambda:gate.candidate_audit(data,"p7u-f07-stock",digest,b"FF"),"INSTALLED_CCFG_BAD_LENGTH")
    reject(lambda:gate.candidate_audit(data,"p7u-f07-stock",digest,b"X"*88),"INSTALLED_CCFG_DIFFERS_STOP")

    def changed(addr:int,value:int,profile="p7u-cap192-f07",ccfg_digest=None):
        d=dict(data);d[addr]=value
        return lambda:gate.candidate_audit(d,profile,ccfg_digest or digest)

    reject(changed(gate.NV5_BASE,2),"IMAGE_WRITES_NV_OR_PROTECTED_FLASH")
    reject(changed(gate.NV2_BASE,2,"p7u-f07-stock"),"IMAGE_WRITES_NV_OR_PROTECTED_FLASH")
    reject(changed(gate.CCFG_SECTOR,2),"IMAGE_WRITES_NV_OR_PROTECTED_FLASH")
    reject(changed(gate.RADIO_SIZE,2),"IMAGE_WRITES_NV_OR_PROTECTED_FLASH")
    d=dict(data);del d[gate.CCFG_START]
    reject(lambda:gate.candidate_audit(d,"p7u-f07-stock",digest),"IMAGE_MISSING_EXACT_CCFG")
    d=dict(data);d[gate.CCFG_START]^=1
    reject(lambda:gate.candidate_audit(d,"p7u-f07-stock",digest),"IMAGE_CCFG_VENDOR_HASH_MISMATCH")
    for address, byte,code in (
        (gate.CCFG_START+gate.BL_CONFIG_OFFSET,0,"ROM_BOOTLOADER_DISABLED"),
        (gate.CCFG_START+gate.BL_CONFIG_OFFSET+1,14,"ROM_BACKDOOR_WRONG_DIO_OR_POLARITY"),
        (gate.CCFG_START+gate.BL_CONFIG_OFFSET+2,255,"ROM_BACKDOOR_WRONG_DIO_OR_POLARITY"),
        (gate.CCFG_START+gate.ERASE_CONF_OFFSET,254,"ROM_BANK_ERASE_DISABLED"),
    ):
        d=dict(data);d[address]=byte
        altered=bytes(d[gate.CCFG_START+i] for i in range(88))
        reject(lambda d=d,altered=altered:gate.candidate_audit(
            d,"p7u-f07-stock",hashlib.sha256(altered).hexdigest()),code)
    reject(changed(4,0x00,ccfg_digest=digest),"IMAGE_RESET_HANDLER_OUTSIDE_APP")
    d=dict(data);d[0:0] if False else None
    for x in range(4): d[x]=0x00
    reject(lambda:gate.candidate_audit(d,"p7u-f07-stock",digest),"IMAGE_INITIAL_STACK_UNPLAUSIBLE")

    reject(lambda:gate.parse_hex(b""),"HEX_EMPTY")
    reject(lambda:gate.parse_hex(b"garbage"),"HEX_BAD_RECORD")
    reject(lambda:gate.parse_hex(raw.replace(b":",b"!",1)),"HEX_BAD_RECORD")
    reject(lambda:gate.parse_hex(raw[:-1].rsplit(b"\n",2)[0]+b"\n"),"HEX_NO_EOF")
    corrupt=raw.replace(b"00",b"01",1)
    reject(lambda:gate.parse_hex(corrupt),"HEX_CHECKSUM")
    duplicate=raw.decode().splitlines()
    duplicate.insert(2,duplicate[2])
    reject(lambda:gate.parse_hex(("\n".join(duplicate)+"\n").encode()),"HEX_DUPLICATE_BYTE")
    reject(lambda:gate.parse_hex(raw+record(0,0,b"\x00").encode()),"HEX_AFTER_EOF")
    entry=(record(0,5,b"\x00\x00\x00\x00")+"\n"+record(0,1)+"\n").encode()
    reject(lambda:gate.parse_hex(entry),"HEX_ENTRY_POINT_UNSUPPORTED")
    with tempfile.TemporaryDirectory() as temp:
        out=Path(temp)/"image.hex"
        out.write_bytes(raw)
        assert gate.parse_hex(out.read_bytes())==data
    print("P7U_ROM_BSL_ANTIBRICK_HOSTILE_HOST_PASS_NO_FLASH")

if __name__=="__main__":
    main()
