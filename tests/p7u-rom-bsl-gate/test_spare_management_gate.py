#!/usr/bin/env python3
"""Zero-device management gate tests; deny P10/MR4U before any radio BSL reset."""
import asyncio
import sys
import types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"firmware/slzb-06p7u/qualification"))
import p7u_rom_transport as target

class FakeInfo:
    model="SLZB-06p7U"
    MAC="aa:bb:cc:dd:ee:ff"
class FakeApi:
    info=FakeInfo()
    need_auth=False
    bsl_ack=True
    writes=0
    def __init__(self,host):self.host=host
    async def __aenter__(self):return self
    async def __aexit__(self,*a):pass
    async def get_info(self):return self.info
    async def check_auth_needed(self):return self.need_auth
    async def set_cmd(self,value):
        FakeApi.writes+=1
        return self.bsl_ack

class FakeSerial:
    opens=0
    async def open(self,*args):FakeSerial.opens+=1
    async def synchronize(self):return True
    async def close(self):pass

def install_stubs():
    pkg=types.ModuleType("pysmlight");pkg.__path__=[]
    const=types.ModuleType("pysmlight.const"); const.Commands=types.SimpleNamespace(CMD_ZB_BSL=2)
    web=types.ModuleType("pysmlight.web"); web.Api2=FakeApi
    sys.modules["pysmlight"]=pkg
    sys.modules["pysmlight.const"]=const
    sys.modules["pysmlight.web"]=web

async def should_reject(mac=None, info=None, auth=False, expected="MANAGEMENT_MODEL_NOT_EXACT_SPARE_P7U"):
    FakeApi.writes=0;FakeSerial.opens=0
    FakeApi.info=info or FakeInfo()
    FakeApi.need_auth=auth
    try:
        async with target.LiveSmlightSession("socket://spare-p7u.local:6638",mac) as rom:
            raise AssertionError("Allowed bad target into BSL")
    except target.BslConnectionError as exc:
        assert str(exc)==expected,(str(exc),expected)
    else:raise AssertionError("Unsafe BSL entry")
    assert FakeApi.writes==0 and FakeSerial.opens==0, "Radio was reset before identity gate"

async def tests():
    install_stubs()
    target.SmlightRom=FakeSerial
    assert target.normalized_mac("AA:BB:CC:DD:EE:FF")=="AABBCCDDEEFF"
    assert target.normalized_mac("aa-bb-cc-dd-ee-ff")=="AABBCCDDEEFF"
    for value in ("aa:bb","INVALID","aabbccddeeff00",""):
        try:target.normalized_mac(value)
        except target.BslConnectionError:pass
        else:raise AssertionError("Accepted malformed management MAC")

    await should_reject(None,expected="SPARE_MAC_REQUIRED_BEFORE_BSL_ENTRY")
    await should_reject("aa:bb:cc:dd:ee:ff",
                        info=types.SimpleNamespace(model="SLZB-MR4U",MAC="aa:bb:cc:dd:ee:ff"))
    await should_reject("aa:bb:cc:dd:ee:ff",
                        info=types.SimpleNamespace(model="SLZB-06P10U",MAC="aa:bb:cc:dd:ee:ff"))
    await should_reject("aa:bb:cc:dd:ee:ff",
                        info=types.SimpleNamespace(model=None,MAC="aa:bb:cc:dd:ee:ff"))
    await should_reject("aa:bb:cc:dd:ee:ff",
                        info=types.SimpleNamespace(model="SLZB-06P7U",MAC=None),
                        expected="MANAGEMENT_MAC_NOT_EXPECTED_SPARE")
    await should_reject("aa:bb:cc:dd:ee:00",expected="MANAGEMENT_MAC_NOT_EXPECTED_SPARE")
    await should_reject("aa:bb:cc:dd:ee:ff",auth=True,
                        expected="SMLIGHT_API_AUTH_NOT_SUPPORTED_STOP")
    FakeApi.info=FakeInfo();FakeApi.need_auth=False;FakeApi.writes=0
    FakeSerial.opens=0
    async with target.LiveSmlightSession("socket://spare-p7u.local:6638",
                                         "AA-BB-CC-DD-EE-FF") as conn:
        assert isinstance(conn,FakeSerial)
    assert FakeApi.writes==1 and FakeSerial.opens==1
    print("P7U_SPARE_MANAGEMENT_MODEL_AND_MAC_PRE_BSL_GATE_PASS")

if __name__=="__main__":
    asyncio.run(tests())
