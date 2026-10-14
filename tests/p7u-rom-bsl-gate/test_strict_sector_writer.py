#!/usr/bin/env python3
"""Compiled real Python fake-ROM fault suite, never opens a device."""
import asyncio
import binascii
import hashlib
import importlib.util
import inspect
import json
import sys
from pathlib import Path

BASE=Path(__file__).resolve().parents[2]/"firmware/slzb-06p7u/qualification"
sys.path.insert(0,str(BASE))
import p7u_strict_sector_writer as s
import p7u_stock_rollback as stock
import p7u_rom_transport as transport
import p7u_flash_spare as cli

def reject(f,reason):
    try:f()
    except ValueError as e:
        assert str(e)==reason,(str(e),reason)
    else:raise AssertionError("Expected "+reason)

class FakeROM:
    def __init__(self):
        self.flash=bytearray(b"\xff"*s.gate.RADIO_SIZE)
        self.fc={
            s.FCFG_ICEPICK_ID:bytes((0,0x70,0xb7,0x0b)),
            s.FLASH_SIZE_REG:bytes((0x58,0,0,0)),
            s.FCFG_PRIMARY_IEEE:b"abcdefgh",
        }
        cfg=bytearray(b"\xff"*s.gate.CCFG_SIZE)
        cfg[s.gate.BL_CONFIG_OFFSET:s.gate.BL_CONFIG_OFFSET+4]=bytes.fromhex("c50ffec5")
        cfg[s.gate.IMAGE_VALID_OFFSET:s.gate.IMAGE_VALID_OFFSET+4]=b"\x00"*4
        self.flash[s.gate.CCFG_START:s.gate.CCFG_END]=cfg
        self.ccfg=bytes(cfg)
        self.nv=bytes(self.flash[s.gate.NV5_BASE:s.gate.CCFG_SECTOR])
        self.calls=[]
        self.erases=[]
        self.expected_download=None
        self.fail_send_once=False
        self.fail_at_command=0
        self.bad_crc_addr=None
        self.change_ccfg=False
        self.counters={"erase":0,"data":0,"read":0}
    async def get_chip_id(self):return 0xB7
    async def read_word(self,addr):
        self.counters["read"]+=1
        for start,blob in self.fc.items():
            if start<=addr<=start+len(blob)-4:
                return blob[addr-start:addr-start+4]
        return bytes(self.flash[addr:addr+4])
    async def crc32(self,addr,length):
        if self.bad_crc_addr==addr:return 42
        return binascii.crc32(self.flash[addr:addr+length]) & 0xffffffff
    async def erase_sector(self,addr):
        self.calls.append(("SECTOR_ERASE",addr))
        assert addr%8192==0 and addr+8192<=s.gate.NV5_BASE
        self.counters["erase"]+=1
        self.erases.append(addr)
        self.flash[addr:addr+8192]=b"\xff"*8192
        if self.change_ccfg:
            self.flash[s.gate.CCFG_START]^=1
        return True
    async def begin_download(self,addr,length):
        self.calls.append(("DOWNLOAD",addr,length))
        assert length==8192 and addr%8192==0
        self.expected_download=(addr,length,0)
        return True
    async def send_data(self,packet):
        self.counters["data"]+=1
        if self.fail_send_once and self.counters["data"]==self.fail_at_command:
            return False
        a,n,at=self.expected_download
        assert at+len(packet)<=n and 0<len(packet)<=s.PACKET
        self.flash[a+at:a+at+len(packet)]=packet
        self.expected_download=(a,n,at+len(packet))
        self.calls.append(("SEND_DATA",len(packet)))
        return True

def make_bundle():
    data={i:(i*37)%251 for i in range(1600)}
    # Valid MSP/PC, and initialized data in three contiguous erase sectors.
    data.update({i:b for i,b in enumerate((0x20023000).to_bytes(4,"little")+
                                        (0x101).to_bytes(4,"little"))})
    for start in (0x2100,0x4100):
        data.update({start+i:(i*13)%253 for i in range(600)})
    raw=s.gate.application_only_hex(data,"p7u-cap192-f07")
    source={"qualification":"SOURCE_HEX_BSL_GEOMETRY_PASS_NOT_FLASHABLE",
            "profile":"p7u-cap192-f07","flash_authorized":False,
            "ccfg_88_bytes_exact_vendor":True,"nv_loaded_bytes":0,
            "rom_backdoor_enabled":True,"bootloader_enabled":True,
            "derived_app_only_hex_sha256":s.sha(raw),
            "derived_app_only_never_flash_with_bank_erase":True}
    proposal=s.sector.plan(raw,source)
    return s.load_bundle(raw,source,proposal),raw,source,proposal

async def tests():
    rom=FakeROM()
    b,raw,source,proposal=make_bundle()
    assert [p[0] for p in b.sectors]==[0,8192,16384]
    assert len(b.sectors)==3
    candidate=await s.preflight(rom,b,"COM31")
    assert candidate["flash_authorized"] is False
    assert candidate["sectors"][0]["address"]=="0x00000"
    assert candidate["identity"]["silicon_wafer"]=="CC13x2x7_CC26x2x7_0xBB77"
    assert candidate["identity"]["ccfg_sha256"]==s.sha(rom.ccfg)
    before=len(rom.erases)
    result=await s.write_checked(rom,b,candidate,candidate["approval_digest"],"COM31")
    assert result["sectors_written"]==3 and result["sectors_skipped_same_crc"]==0
    assert rom.erases==[8192,16384,0],"vector sector must be programmed LAST"
    assert bytes(rom.flash[s.gate.CCFG_START:s.gate.CCFG_END])==rom.ccfg
    assert bytes(rom.flash[s.gate.NV5_BASE:s.gate.CCFG_SECTOR])==rom.nv
    for a,x in b.sectors:
        assert await rom.crc32(a,8192)==(binascii.crc32(x)&0xffffffff)
    assert (await s.write_checked(rom,b,candidate,candidate["approval_digest"],"COM31"))["sectors_skipped_same_crc"]==3
    assert len(rom.erases)==before+3

    # A real interrupted write returns an error without resetting the radio,
    # and resume skips previously completed sectors after independent CRC.
    partial=FakeROM()
    prior=await s.preflight(partial,b,"socket://sparep7u.local:6638")
    partial.fail_send_once=True
    partial.fail_at_command=37
    try:await s.write_checked(partial,b,prior,prior["approval_digest"],"socket://sparep7u.local:6638")
    except s.StrictError as exc:assert str(exc)=="ROM_SEND_DATA_REJECTED"
    else:raise AssertionError("Fault injection failed")
    assert partial.erases==[8192,16384] and partial.flash[s.gate.CCFG_START:s.gate.CCFG_END]==rom.ccfg
    partial.fail_send_once=False
    resumed=await s.write_checked(partial,b,prior,prior["approval_digest"],"socket://sparep7u.local:6638",allow_resume=True)
    assert resumed["sectors_written"]==2 and resumed["sectors_skipped_same_crc"]==1
    assert partial.erases[-1]==0
    assert partial.flash[s.gate.NV5_BASE:s.gate.CCFG_SECTOR]==rom.nv
    assert partial.flash[s.gate.CCFG_START:s.gate.CCFG_END]==rom.ccfg

    bad=dict(prior);bad["approval_digest"]="0"*64
    try:await s.write_checked(FakeROM(),b,bad,"0"*64,"socket://sparep7u.local:6638")
    except s.StrictError as exc:assert str(exc)=="APPROVAL_FILE_TAMPERED"
    else:raise AssertionError("Approval tampering accepted")
    try:await s.write_checked(FakeROM(),b,prior,prior["approval_digest"],"COM99")
    except s.StrictError as exc:assert str(exc)=="APPROVAL_TARGET_OR_IMAGE_CHANGED"
    else:raise AssertionError("Endpoint swap allowed")
    identity_changed=FakeROM()
    identity_changed.fc[s.FCFG_PRIMARY_IEEE]=b"ijklmnop"
    try:await s.write_checked(identity_changed,b,prior,prior["approval_digest"],"socket://sparep7u.local:6638")
    except s.StrictError as exc:assert str(exc)=="TARGET_IDENTITY_OR_CCFG_CHANGED"
    else:raise AssertionError("IEEE swap allowed")
    changed=FakeROM(); changed.flash[0]=0
    try:await s.write_checked(changed,b,prior,prior["approval_digest"],"socket://sparep7u.local:6638")
    except s.StrictError as exc:assert str(exc)=="FLASH_STATE_CHANGED_SINCE_INSPECTION"
    else:raise AssertionError("Unapproved state change allowed")
    # End-to-end rollback after custom firmware: independent stock-target
    # preflight, new approval, identical strict per-sector writer.
    stock_data={i:(i*17)%239 for i in range(1600)}
    stock_data.update({i:v for i,v in enumerate((0x20023000).to_bytes(4,"little")+
                                      (0x101).to_bytes(4,"little"))})
    for start in (0x2100,0x4100):
        stock_data.update({start+i:(i*11)%251 for i in range(600)})
    stock_raw=s.gate.application_only_hex(stock_data,"p7u-cap192-f07")
    stock_source=dict(source)
    stock_source["derived_app_only_hex_sha256"]=s.sha(stock_raw)
    stock_plan=s.sector.plan(stock_raw,stock_source)
    restore=s.load_bundle(stock_raw,stock_source,stock_plan)
    rollback_approval=await s.preflight(rom,restore,"COM31")
    assert rollback_approval["app_hex_sha256"]!=candidate["app_hex_sha256"]
    undo=await s.write_checked(rom,restore,rollback_approval,
                               rollback_approval["approval_digest"],"COM31")
    assert undo["sectors_written"]==3
    assert bytes(rom.flash[s.gate.CCFG_START:s.gate.CCFG_END])==rom.ccfg
    assert bytes(rom.flash[s.gate.NV5_BASE:s.gate.CCFG_SECTOR])==rom.nv

    # Failure to verify sector CRC stops immediately; retains bootloader.
    mismatch=FakeROM();before=await s.preflight(mismatch,b,"COM31")
    original=mismatch.crc32
    mismatch.bad_crc_addr=8192
    try:await s.write_checked(mismatch,b,before,before["approval_digest"],"COM31",allow_resume=True)
    except s.StrictError as exc:assert str(exc)=="PROGRAMMED_SECTOR_CRC_MISMATCH"
    else:raise AssertionError("CRC mismatch passed")
    ccfg_bad=FakeROM();snapshot=await s.preflight(ccfg_bad,b,"COM31")
    ccfg_bad.change_ccfg=True
    try:await s.write_checked(ccfg_bad,b,snapshot,snapshot["approval_digest"],"COM31")
    except s.StrictError as exc:assert str(exc)=="CCFG_CHANGED_DURING_PROGRAMMING"
    else:raise AssertionError("CCFG corruption ignored")

    # Different family/chip, flash geometry and disabled backdoor are rejected.
    wrong=FakeROM();wrong.fc[s.FCFG_ICEPICK_ID]=bytes((0,0,0,0))
    try:await s.observe(wrong)
    except s.StrictError as exc:assert str(exc)=="NOT_CC26X2X7_SILICON"
    else:raise AssertionError("Wrong wafer accepted")
    wrong=FakeROM();wrong.fc[s.FLASH_SIZE_REG]=bytes((64,0,0,0))
    try:await s.observe(wrong)
    except s.StrictError as exc:assert str(exc)=="NOT_704K_P7_FLASH"
    else:raise AssertionError("Wrong flash accepted")
    wrong=FakeROM();wrong.flash[s.gate.CCFG_START+s.gate.BL_CONFIG_OFFSET]=0
    try:await s.observe(wrong)
    except s.StrictError as exc:assert str(exc)=="INSTALLED_ROM_BSL_DISABLED"
    else:raise AssertionError("Disabled ROM BSL accepted")

    reject(lambda:s.load_bundle(raw,source,{**proposal,"sector_count":123}),
           "SECTOR_PLAN_NOT_REDERIVED_EXACTLY")
    altered=dict(source);altered["flash_authorized"]=True
    reject(lambda:s.load_bundle(raw,altered,proposal),"SOURCE_BUNDLE_INVALID")
    reject(lambda:s.load_bundle(raw+b"0",source,proposal),"SOURCE_BUNDLE_INVALID")
    reject(lambda:stock.extract(b"not vendor","p7u-cap192-f07"),"STOCK_VENDOR_SOURCE_HASH_MISMATCH")
    transport_source=inspect.getsource(transport.SmlightRom)
    for forbidden in ("cmdBankErase(","erase_bank(","cmdReset(","set_ieee_address(",
                      "disable_bootloader(","cmdEraseSector(0xAE000"):
        assert forbidden not in transport_source,forbidden
    assert not hasattr(transport.SmlightRom,"erase_bank")
    print("P7U_RESTRICTED_ROM_SECTOR_WRITER_HOST_FAULTS_PASS_NO_HARDWARE")

if __name__=="__main__":
    asyncio.run(tests())
