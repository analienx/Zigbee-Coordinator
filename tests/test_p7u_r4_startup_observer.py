"""Offline source-bound startup evidence and split TCP frame regressions."""
import socket
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7u/r4/release"))
from p7u_r4_startup_observer import (
    FramedZnp, EvidenceError, decode_e1, verify_success_frames)

SOURCE="8f52d3936bee49be91ab63887f5847666ba6b125"

def mkframe(payload,sub=1,cmd=241):
    raw=bytes((len(payload),0x60|sub,cmd))+payload
    check=0
    for x in raw:check^=x
    return b"\xfe"+raw+bytes((check,))

def evidence():
    raw=bytearray(128);raw[:4]=b"B1E1";raw[4]=1;raw[5]=128
    raw[6]=4;raw[7]=7;raw[8:12]=bytes.fromhex(SOURCE[:8])
    required=(0,1,2,3,4,5,6,7,8,9,10,11,12,13,15,16,17,18,19,20,21,22)
    mask=sum(1<<i for i in required)
    raw[12:16]=mask.to_bytes(4,"little")
    raw[40]=0;raw[42]=1;raw[43]=9;raw[44]=0;raw[45]=0
    raw[46]=5;raw[47]=4
    for j in range(7):raw[48+2*j:50+2*j]=(1).to_bytes(2,"little")
    raw[62]=22
    raw[88:112]=b"\xff"*24
    for order,i in enumerate(required,1):
        raw[64+i]=order;raw[88+i]=0
    return bytes(raw)

def terminal():
    e=evidence()
    p=bytearray(32);p[:6]=b"B1P1\x01\x20";p[6]=4;p[12:16]=bytes.fromhex(SOURCE[:8])
    s=bytearray(24);s[:6]=b"B1S1\x01\x18"
    s[6]=5;s[9]=8;s[12:16]=bytes.fromhex(SOURCE[:8])
    return {"B1E1":e.hex(),"B1P1":bytes(p).hex(),"B1S1":bytes(s).hex(),
            "UTIL":(bytes([0]*12)+bytes([9,0])).hex(),
            "MARKER":b"\x00\x01\x55".hex()}

class Clock:
    def __init__(self):self.now=0.
    def __call__(self):return self.now

class FragmentSocket:
    def __init__(self,clock,frame,available=17.8):
        self.clock=clock;self.frame=frame;self.available=available
        self.timeout=.75;self.sent=[]
    def settimeout(self,value):self.timeout=value
    def sendall(self,frame):self.sent.append(frame)
    def recv(self,length):
        if self.clock.now < self.available:
            self.clock.now+=self.timeout
            raise socket.timeout()
        if not self.frame:return b""
        out=self.frame[:min(2,length)]
        self.frame=self.frame[len(out):]
        return out

class ObserverTests(unittest.TestCase):
    def test_source_bound_real_ready_frame_accepts(self):
        s=terminal();verified=verify_success_frames(s,SOURCE)
        self.assertEqual(verified["state"],4)

    def test_missing_confirmation_milestone_rejected(self):
        s=terminal();e=bytearray.fromhex(s["B1E1"])
        e[12:16]=(int.from_bytes(e[12:16],"little")&~(1<<13)).to_bytes(4,"little")
        e[64+13]=0;e[88+13]=255
        s["B1E1"]=e.hex()
        with self.assertRaises(EvidenceError):
            verify_success_frames(s,SOURCE)

    def test_genuine_router_named_coordinator_confirmation_accepted(self):
        s=terminal()
        e=bytearray.fromhex(s["B1E1"])
        mask=int.from_bytes(e[12:16],"little")
        e[12:16]=((mask & ~(1<<13)) | (1<<14)).to_bytes(4,"little")
        e[64+14]=e[64+13];e[64+13]=0
        e[88+14]=0;e[88+13]=255
        s["B1E1"]=e.hex()
        self.assertEqual(verify_success_frames(s,SOURCE)["confirmation"],0)

    def test_router_confirm_after_start_post_is_not_ready(self):
        s=terminal()
        e=bytearray.fromhex(s["B1E1"])
        mask=int.from_bytes(e[12:16],"little")
        e[12:16]=((mask & ~(1<<13)) | (1<<14)).to_bytes(4,"little")
        e[64+14]=e[64+15];e[64+15]=e[64+13]
        e[64+13]=0;e[88+14]=0;e[88+13]=255
        s["B1E1"]=e.hex()
        with self.assertRaises(EvidenceError):
            verify_success_frames(s,SOURCE)

    def test_fake_ready_with_no_frames_rejected(self):
        with self.assertRaisesRegex(EvidenceError,"NO_RECORDED_TERMINAL_FRAMES"):
            verify_success_frames(None,SOURCE)

    def test_fragmented_response_after_17_seconds(self):
        clock=Clock();sock=FragmentSocket(clock,mkframe(evidence()))
        transport=FramedZnp(sock,clock=clock)
        got=transport.request(1,241,b"B1Q1\x01\x08\x03\x00",deadline=80.)
        self.assertEqual(got,evidence())
        self.assertGreaterEqual(clock.now,17)
        self.assertEqual(len(sock.sent),1)
        self.assertEqual(transport.buffer,bytearray())

    def test_unrelated_frame_kept_until_matching_response(self):
        clock=Clock()
        unsent=mkframe(b"unsolicited",sub=5,cmd=9)
        sock=FragmentSocket(clock,unsent+mkframe(evidence()),available=0)
        z=FramedZnp(sock,clock=clock)
        self.assertEqual(z.request(1,241,b"",deadline=80),evidence())
        self.assertEqual(len(z.unsolicited),1)

if __name__=="__main__":
    unittest.main()
