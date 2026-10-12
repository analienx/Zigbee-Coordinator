#!/usr/bin/env python3
"""Fail-closed Intel HEX app-sector plan tests. NO hardware or flash interface."""
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"firmware"/"t832"/"min"))
from harden_real import hex_spans, NVS_BEGIN, CCFG_BEGIN

def record(kind, address, payload=b""):
    head=bytes([len(payload),(address>>8)&0xff,address&0xff,kind])+payload
    return ":"+(head+bytes([(-sum(head))&255])).hex().upper()

def payload(parts):
    return "\n".join(parts)+"\n"

def inspect(data):
    with tempfile.TemporaryDirectory() as d:
        f=Path(d)/"test.hex"
        f.write_text(data,encoding="ascii")
        return hex_spans(f)

def prefix():
    return [record(4,0,(0).to_bytes(2,"big")),
            record(0,0,b"\x01\x02\x03"),
            record(0,0x0800,b"\x08\x09"),
            record(4,0x0000,(0xF).to_bytes(2,"big")),
            record(0,0x97FE,b"\xAA\xBB"),
            record(4,0x0000,(CCFG_BEGIN >>16).to_bytes(2,"big")),
            record(0,0x0000,b"\xC5\xFF")]

def rejected(data):
    try:
        inspect(data)
    except ValueError:
        return
    raise AssertionError("unsafe or malformed flash plan accepted")

def main():
    valid=payload(prefix()+[record(1,0)])
    result=inspect(valid)["nv_sector_policy"]
    assert result["operation"]=="OFFLINE_PLAN_ONLY_NEVER_EXECUTE"
    assert not result["bank_erase_permitted"]
    assert not result["ccfg_erase_permitted"]
    assert not result["flash_authorized"]
    assert result["protected_nv_start"]==hex(NVS_BEGIN)
    assert result["app_sector_erase_start_addresses"]==["0x0","0x800","0xf9000"]
    assert all(int(x,16)+2048<=NVS_BEGIN for x in result["app_sector_erase_start_addresses"])
    assert result["app_sector_count"]==3

    # A single byte in the protected NVS upper 13 pages must fail closed.
    rejected(payload([record(4,0,(0xF).to_bytes(2,"big")),
                      record(0,0x9800,b"\xFF"),
                      record(4,0,(CCFG_BEGIN>>16).to_bytes(2,"big")),
                      record(0,0,b"\xC5"),record(1,0)]))
    # A data record crossing into NV must also be rejected.
    rejected(payload([record(4,0,(0xF).to_bytes(2,"big")),
                      record(0,0x97FF,b"\x01\x02"),record(1,0)]))
    # Illegal CCFG+1page, missing CCFG, duplicate app bytes, bad checksum.
    rejected(payload(prefix()[:-1]+[record(0,0x0800,b"\x00"),record(1,0)]))
    rejected(payload(prefix()[:-2]+[record(1,0)]))
    rejected(payload(prefix()+[record(0,0x0000,b"\xC5"),record(1,0)]))
    rejected(valid.replace("010203","010204",1))
    rejected(valid+record(0,0,b"\x01")+"\n")
    print("PASS strict P10 HEX sector geometry: app-only erases, protected NV/CCFG, bad input")

if __name__=="__main__":
    main()
