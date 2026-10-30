"""One-outstanding-request, source-bound retained-startup ZNP observer.

No firmware writing, no resets, no service control and no retry of a
consumed startup. Caller owns application boot and exact one startup request.
"""
from __future__ import annotations
import hashlib
import socket
import time

Q0 = b"B1Q1\x01\x08\x00\x00"
Q2 = b"B1Q1\x01\x08\x02\x00"
Q3 = b"B1Q1\x01\x08\x03\x00"
TERMINAL_REQUIRE = (0,1,2,3,4,5,6,7,8,9,10,11,12,15,16,17,18,19,20,21,22)

class EvidenceError(RuntimeError):
    pass

def require(value, text):
    if not value:
        raise EvidenceError(text)

def uint16(raw, offset):
    return int.from_bytes(raw[offset:offset+2], "little")

def uint32(raw, offset):
    return int.from_bytes(raw[offset:offset+4], "little")

def checked(raw: bytes, tag: bytes, length: int, source: str):
    require(len(raw) == length and raw[:4] == tag
            and raw[4] == 1 and raw[5] == length,
            "RESPONSE_SCHEMA_INVALID_" + tag.decode())
    require(raw[8:12] == bytes.fromhex(source[:8]) if tag == b"B1E1"
            else raw[12:16] == bytes.fromhex(source[:8]),
            "SOURCE_DIGEST_MISMATCH_" + tag.decode())
    return raw

def decode_e1(raw: bytes, source: str) -> dict:
    checked(raw, b"B1E1", 128, source)
    mask = uint32(raw, 12)
    first = list(raw[64:88])
    statuses = list(raw[88:112])
    orders = [first[i] for i in range(24) if mask & (1 << i)]
    require(len(orders) == len(set(orders)) and
            set(orders) == set(range(1,len(orders)+1)),
            "EVIDENCE_MILESTONE_ORDER_INVALID")
    require(all((first[i] == 0 and statuses[i] == 255) for i in range(24)
                if not(mask & (1 << i))),
            "EVIDENCE_UNOBSERVED_FIELDS_INVALID")
    return {"state": raw[6], "flags": raw[7], "milestones": mask,
            "activity": uint32(raw,16), "stack_wakes": uint32(raw,20),
            "zdapp_loops": uint32(raw,24),
            "pending_zdapp": uint32(raw,32), "npi_wakes": uint32(raw,36),
            "first_error": raw[40], "bdb_branch": raw[41],
            "restore_result": raw[42], "dev_state": raw[43],
            "confirmation": raw[44], "nlme": raw[45],
            "stack_priority": raw[46], "npi_priority": raw[47],
            "counters": [uint16(raw,48+2*i) for i in range(7)],
            "last_milestone": raw[62], "first_order": first,
            "first_status": statuses, "dispatch_enter": uint32(raw,112),
            "dispatch_exit": uint32(raw,116),
            "last_dispatch_input": uint32(raw,120),
            "last_dispatch_returned": uint32(raw,124)}

def verify_success_frames(frames: dict, source: str) -> dict:
    require(isinstance(frames, dict), "NO_RECORDED_TERMINAL_FRAMES")
    try:
        p=bytes.fromhex(frames["B1P1"])
        e=bytes.fromhex(frames["B1E1"])
        s=bytes.fromhex(frames["B1S1"])
        u=bytes.fromhex(frames["UTIL"])
        m=bytes.fromhex(frames["MARKER"])
    except (ValueError,TypeError,KeyError) as exc:
        raise EvidenceError("RECORDED_TERMINAL_FRAME_INVALID") from exc
    checked(p,b"B1P1",32,source)
    info=decode_e1(e,source)
    checked(s,b"B1S1",24,source)
    require(p[6]==4 and p[9]==0 and
            info["state"]==4 and info["first_error"]==0 and
            info["flags"] & 7 == 7 and
            info["stack_priority"]==5 and
            info["npi_priority"]==(6 if source=="c442a27f82a1147c089aa65fdbf9c79abd7c39fb" else 4),
            "STARTUP_RUNNING_OR_FAILURE_MISLABELED_READY")
    mask=info["milestones"]
    require(all(mask & (1 << n) for n in TERMINAL_REQUIRE),
            "RETAINED_TRANSACTION_MILESTONES_INCOMPLETE")
    # Pinned native MODE_RESUME uses NLME_StartRouterRequest. The genuine
    # completion may arrive at formation-named (13) or router-named (14)
    # ZDO callback. Require one successful, causally preceding START_POST;
    # never invent or backfill missing native confirmations.
    confirmations = [n for n in (13,14) if mask & (1 << n)]
    require(bool(confirmations), "COORDINATOR_NATIVE_CONFIRMATION_ABSENT")
    first_confirm = min(confirmations,key=lambda n: info["first_order"][n])
    require(info["first_status"][first_confirm]==0 and
            info["first_order"][11] < info["first_order"][first_confirm] <
            info["first_order"][15], "COORDINATOR_CONFIRMATION_UNVERIFIED")
    require(info["first_status"][11]==0 and
            info["first_status"][21]==0 and
            info["nlme"]==0 and info["confirmation"]==0,
            "NLME_CONFIRM_OR_MARKER_NOT_SUCCESSFUL")
    counters=info["counters"]
    require(counters[0]>=1 and counters[1]==1 and counters[4]==1
            and counters[5]==1 and counters[6]==1
            and counters[2]==1 and counters[3]==1,
            "DUPLICATE_OR_MISSING_NETWORK_REQUEST")
    require(info["first_order"][11] < info["first_order"][19] <
            info["first_order"][20] < info["first_order"][21] <
            info["first_order"][22],
            "READY_MILESTONE_CAUSAL_ORDER_INVALID")
    require(s[6]==5 and s[7]==0 and s[10]==0 and
            (s[9] & 8)==8 and not(s[8] & (4|8|16)),
            "B1S1_NOT_READY_OR_HOLD")
    require(len(u)>=14 and u[0]==0 and u[12]==9,
            "UTIL_NOT_COORDINATOR_STATE9")
    require(len(m)==3 and m==b"\x00\x01\x55",
            "CONFIGURED_MARKER_NOT_VERIFIED")
    return info

from p7u_r4_startup_transport import FramedZnp, observe_after_srsp
