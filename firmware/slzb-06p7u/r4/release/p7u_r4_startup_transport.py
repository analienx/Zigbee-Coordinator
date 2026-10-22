"""Source-checked ZNP transport and durable-first R4 retained observer.

One outstanding request, permanent ambiguity latch, private metadata only.
No firmware writes, resets, startup retries or secondary UART ownership.
"""
from __future__ import annotations
import socket
import time
import json
import os
from pathlib import Path

Q0=b"B1Q1\x01\x08\x00\x00"
Q2=b"B1Q1\x01\x08\x02\x00"
Q3=b"B1Q1\x01\x08\x03\x00"
EXPECTED={Q0:(b"B1S1",24),Q2:(b"B1P1",32),Q3:(b"B1E1",128)}

class PrivateEvidenceJournal:
    """Crash-durable append-only private snapshots, never used as an ACK.

    Caller must create this before its one retained startup request. It cannot
    open an existing file; interruption permanently consumes this journal.
    """
    def __init__(self, path: Path, source: str):
        self.path=Path(path)
        self.source=source
        self.file=self.path.open("xb")

    def __call__(self, name: str, data: bytes, request: dict):
        record={"source":self.source,"response":name,"payload_hex":data.hex(),
                "transport":request}
        self.file.write((json.dumps(record,sort_keys=True,separators=(",",":"))+"\n").encode())
        self.file.flush()
        os.fsync(self.file.fileno())

    def close(self):
        self.file.close()


class FramedZnp:
    def __init__(self,sock,*,source=None,unsolicited=None,clock=time.monotonic):
        self.sock=sock
        self.source=source
        self.clock=clock
        self.buffer=bytearray()
        self.unsolicited=unsolicited if unsolicited is not None else []
        self.outstanding=False
        self.unusable=False
        self.history=[]
        self._current=None

    @staticmethod
    def frame(sub,cmd,payload):
        from p7u_r4_startup_observer import require
        require(len(payload)<=250 and 0<=sub<=15 and 0<=cmd<=255,
                "ZNP_REQUEST_INVALID")
        raw=bytes((len(payload),0x20|sub,cmd))+payload
        fcs=0
        for v in raw: fcs^=v
        return b"\xfe"+raw+bytes((fcs,))

    def _next(self,deadline):
        from p7u_r4_startup_observer import require
        while self.clock()<deadline:
            while self.buffer:
                if self.buffer[0]!=0xfe:
                    del self.buffer[0]
                    continue
                if len(self.buffer)<5:
                    break
                size=5+self.buffer[1]
                if len(self.buffer)<size:
                    break
                wire=bytes(self.buffer[:size])
                del self.buffer[:size]
                fcs=0
                for v in wire[1:]:fcs^=v
                require(fcs==0,"ZNP_CHECKSUM_MISMATCH")
                return wire[2],wire[3],wire[4:-1]
            if self._current is not None:
                self._current["partial_buffer"]=len(self.buffer)
                self._current["expected_total"]=(
                    5+self.buffer[1] if len(self.buffer)>=2 and self.buffer[0]==0xfe else None)
            self.sock.settimeout(min(.75,max(.01,deadline-self.clock())))
            try:
                data=self.sock.recv(512)
            except (socket.timeout,TimeoutError):
                continue
            require(data!=b"","ZNP_CONNECTION_CLOSED_UNKNOWN_STATE")
            if self._current is not None:
                t=round(self.clock()-self._current["started"],3)
                if self._current["first_receive_elapsed"] is None:
                    self._current["first_receive_elapsed"]=t
                self._current["last_receive_elapsed"]=t
                self._current["received_bytes"]+=len(data)
            self.buffer.extend(data)
        raise TimeoutError("ZNP_OUTSTANDING_RESPONSE_DEADLINE")

    def request(self,sub,cmd,payload=b"",*,deadline):
        from p7u_r4_startup_observer import checked, require
        require(not self.unusable,"ZNP_CONNECTION_PERMANENTLY_UNUSABLE")
        require(not self.outstanding,"ZNP_OVERLAPPING_REQUEST")
        require(self.clock()<deadline,"ZNP_ABSOLUTE_DEADLINE")
        shape=EXPECTED.get(payload) if sub==1 and cmd==241 else None
        now=self.clock()
        entry={"operation":payload.hex() if payload else f"{sub:02x}:{cmd:02x}",
               "expected":shape[0].decode() if shape else None,
               "expected_length":shape[1] if shape else None,
               "transmission_completed":False,"received_bytes":0,
               "unrelated_frames":0,"partial_buffer":len(self.buffer),
               "expected_total":None,"first_receive_elapsed":None,
               "last_receive_elapsed":None,"started":now,"result":"IN_PROGRESS"}
        self.history.append(entry)
        self._current=entry
        self.outstanding=True
        try:
            self.sock.settimeout(min(2,max(.01,deadline-self.clock())))
            self.sock.sendall(self.frame(sub,cmd,payload))
            entry["transmission_completed"]=True
            while self.clock()<deadline:
                typ,command,data=self._next(deadline)
                if typ==(0x60|sub) and command==cmd:
                    if shape is not None:
                        tag,length=shape
                        require(len(data)==length and data[:4]==tag and
                                data[4]==1 and data[5]==length,
                                "ZNP_MATCHING_F1_SHAPE_MISMATCH")
                        if self.source is not None:
                            checked(data,tag,length,self.source)
                    entry["result"]="COMPLETE"
                    entry["response_length"]=len(data)
                    return data
                entry["unrelated_frames"]+=1
                self.unsolicited.append((typ,command,data.hex()))
            raise TimeoutError("ZNP_OUTSTANDING_RESPONSE_DEADLINE")
        except (TimeoutError, OSError, ValueError, RuntimeError) as error:
            self.unusable=True
            entry["result"]=type(error).__name__+":"+str(error)[:96]
            entry["partial_buffer"]=len(self.buffer)
            if len(self.buffer)>=2 and self.buffer[0]==0xfe:
                entry["expected_total"]=5+self.buffer[1]
            raise
        finally:
            entry.pop("started",None)
            self.outstanding=False
            self._current=None


def observe_after_srsp(znp,source,srsp_received,*,absolute_seconds=80.,sleep=time.sleep,
                       save=None):
    """Retained one-shot read-only observer; save sees each response immediately.

    save(name, data, detail) may fsync an append-only private receipt before
    ANY next query. The caller must not reissue the consumed startup.
    """
    from p7u_r4_startup_observer import (decode_e1,checked,verify_success_frames,
                                          EvidenceError)
    znp.source=source
    deadline=srsp_received+absolute_seconds
    frames={}
    counts={"B1E1":0,"B1P1":0,"B1S1":0,"UTIL":0,"MARKER":0}
    e_snapshots=0
    ready=False

    def record(name,data):
        frames[name]=data.hex()
        counts[name]+=1
        if save is not None:
            save(name,data,dict(znp.history[-1]))
    def outcome(category,status="FAILED_STOP_NO_RETRY"):
        return {"status":status,"failure_category":category,
                "frames":dict(frames),"frame_counts":dict(counts),
                "snapshots":e_snapshots,"ready_observed":ready,
                "transport":list(znp.history)}

    while znp.clock()<deadline:
        try:
            raw=znp.request(1,241,Q3,deadline=deadline)
            info=decode_e1(raw,source)
            record("B1E1",raw)
            e_snapshots+=1
        except (TimeoutError,OSError,EvidenceError,RuntimeError,ValueError):
            return outcome("DEADLINE_NOT_READY" if e_snapshots
                           else "OBSERVER_TIMEOUT_STATE_UNKNOWN")
        if info["state"]==5 or info["first_error"]!=0:
            return outcome("FIRMWARE_FAILED")
        if info["state"]==4:
            ready=True
            break
        sleep(min(.75,max(0,deadline-znp.clock())))
    if not ready:
        return outcome("DEADLINE_NOT_READY" if e_snapshots
                       else "OBSERVER_TIMEOUT_STATE_UNKNOWN")

    # Physical READY observation is not acceptance. Terminal reads have their
    # own absolute 10s budget; preserve all earlier evidence on any ambiguity.
    terminal=znp.clock()+10.
    try:
        p=znp.request(1,241,Q2,deadline=terminal)
        checked(p,b"B1P1",32,source)
        record("B1P1",p)
        s=znp.request(1,241,Q0,deadline=terminal)
        checked(s,b"B1S1",24,source)
        record("B1S1",s)
        u=znp.request(7,0,deadline=terminal)
        record("UTIL",u)
        m=znp.request(1,8,b"\x60\x00\x00",deadline=terminal)
        record("MARKER",m)
        verify_success_frames(frames,source)
    except (TimeoutError,OSError,EvidenceError,RuntimeError,ValueError):
        return outcome("READY_OBSERVED_VERIFICATION_INCOMPLETE")
    return outcome(None,"COORDINATOR_STATE9_MARKER_PASS")
