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
Q4 = b"B1Q1\x01\x08\x04\x00"
Q5 = b"B1Q1\x01\x08\x04\x01"
Q6 = b"B1Q1\x01\x08\x04\x02"
Q7 = b"B1Q1\x01\x08\x04\x03"
Q8 = b"B1Q1\x01\x08\x04\x04"
Q9 = b"B1Q1\x01\x08\x04\x05"
TERMINAL_REQUIRE = (0,1,2,3,4,5,6,7,8,9,10,11,12,15,16,17,18,19,20,21,22)

# V50 keeps the armed sole NPI owner at priority6 for the whole boot and
# answers RAM-only B1E2 (op4) Stack-service evidence. Older firmware must
# still report the original priority4 at READY and has no B1E2.
V50_SOURCES = frozenset({"a70ae24ff45e708e13969cd341c9ecb494d1570f", "8ec1439786e3e98151d2796e6797675bb9ef5965",
                         "20a2474a67c1d420b6614b3fcb2f7ed543b1420e"})
# V51 (same NPI floor and B1E2) adds the B1E3 (op4 page1) onset record and
# the B1E4/B1E5 (op4 page2/3) 5-minute and 60-minute trend rings.
V51_SOURCES = frozenset({"a70ae24ff45e708e13969cd341c9ecb494d1570f", "8ec1439786e3e98151d2796e6797675bb9ef5965",
                         "20a2474a67c1d420b6614b3fcb2f7ed543b1420e"})
# V52 adds B1E6 (op4 page4): NPI->MT->UART progress, OSAL timer evidence and
# the live in-flight Stack dispatch, and frees expired OSAL timers per dispatch.
V52_SOURCES = frozenset({"a70ae24ff45e708e13969cd341c9ecb494d1570f", "8ec1439786e3e98151d2796e6797675bb9ef5965",
                         "20a2474a67c1d420b6614b3fcb2f7ed543b1420e"})
# V53 adds B1E7 (op4 page5): the NV read cache that removes the per-frame NV
# storm, its counters and the costliest NV items (IDs/counts only, never data).
# V54 keeps every V50-V53 behaviour and only guards that cache (B1 HOLD, TCLK seed).
V53_SOURCES = frozenset({"8ec1439786e3e98151d2796e6797675bb9ef5965",
                         "20a2474a67c1d420b6614b3fcb2f7ed543b1420e"})

def expected_ready_npi_priority(source: str) -> int:
    return 6 if source in V50_SOURCES else 4

def stack_evidence_supported(source: str) -> bool:
    return source in V50_SOURCES

def onset_evidence_supported(source: str) -> bool:
    return source in V51_SOURCES

def pipeline_evidence_supported(source: str) -> bool:
    return source in V52_SOURCES

def nv_cache_evidence_supported(source: str) -> bool:
    return source in V53_SOURCES

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
    require(raw[8:12] == bytes.fromhex(source[:8])
            if tag in (b"B1E1", b"B1E2", b"B1E3", b"B1E4", b"B1E5", b"B1E6", b"B1E7")
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

def decode_e2(raw: bytes, source: str) -> dict:
    """V50 B1E2: Stack selection/CPU, per-service and MAC counters (evidence)."""
    require(stack_evidence_supported(source), "STACK_EVIDENCE_UNSUPPORTED_SOURCE")
    checked(raw, b"B1E2", 248, source)
    count = raw[6]
    require(1 <= count <= 12 and raw[7] & 0x7f in (1, 2) and
            raw[78:80] == b"\x00\x00" and uint32(raw,16) > 0,
            "STACK_EVIDENCE_SCHEMA_INVALID")
    require(all(uint32(raw,80+4*i) == 0 and uint32(raw,128+4*i) == 0 and
                uint32(raw,176+4*i) == 0 and uint16(raw,224+2*i) == 0
                for i in range(count, 12)), "STACK_EVIDENCE_UNUSED_SLOTS_INVALID")
    services = [{"dispatches": uint32(raw,80+4*i), "busy_ticks": uint32(raw,128+4*i),
                 "inputs": uint32(raw,176+4*i), "longest_ms": uint16(raw,224+2*i)}
                for i in range(count)]
    return {"now": uint32(raw,12), "tick_period_us": uint32(raw,16),
            "wakes": uint32(raw,20), "empty": uint32(raw,24), "aged": uint32(raw,28),
            "returned": uint32(raw,32), "busy_ticks": uint32(raw,36),
            "current_age_ticks": uint32(raw,40),
            "current_service": raw[44] - 1 if raw[44] else None,
            "max_skip": raw[45], "npi_priority": raw[46], "stack_priority": raw[47],
            "npi_armed": bool(raw[7] & 0x80), "npi_arm_tick": uint32(raw,72),
            "table_fallback": bool(raw[7] & 2),
            "mac": {"data_req": uint32(raw,48), "data_req_ok": uint32(raw,52),
                    "data_cnf": uint32(raw,56), "data_cnf_failed": uint32(raw,60),
                    "data_ind": uint32(raw,64), "events": uint32(raw,68),
                    "last_req_failure": raw[76], "last_cnf_failure": raw[77]},
            "services": services}

E3_READY, E3_SETTLED, E3_ONSET, E3_LONG = 0x01, 0x02, 0x04, 0x08
E3_NV_HOOKED, E3_AFTER_CALM, E3_HEAP = 0x10, 0x20, 0x40
NV_KINDS = {0: None, 1: "read", 2: "write", 3: "delete", 4: "compact"}

def decode_e3(raw: bytes, source: str) -> dict:
    """V51 B1E3: latched onset record. Evidence only, never acceptance.

    Ticks use the B1E2 tick period. Thresholds are fixed in firmware: a
    10 s window is saturated at >=90% Stack busy and calm below 50%; the
    long-dispatch latch is >=1 s. Unlatched records must be all zero.
    """
    require(onset_evidence_supported(source), "ONSET_EVIDENCE_UNSUPPORTED_SOURCE")
    checked(raw, b"B1E3", 248, source)
    flags = raw[6]
    zero = lambda a, b: not any(raw[a:b])
    require(raw[7] == 10 and not flags & 0x80 and raw[117] == 0 and
            raw[67] in NV_KINDS and raw[78] in NV_KINDS and
            (flags & E3_ONSET or zero(100, 140)) and
            (flags & E3_LONG or zero(140, 160)) and
            (flags & E3_HEAP or zero(92, 100)) and
            (flags & E3_READY or (zero(16, 52) and zero(160, 180))) and
            not (flags & (E3_SETTLED | E3_ONSET | E3_LONG | E3_HEAP) and
                 not flags & E3_READY) and
            not (flags & E3_AFTER_CALM and not flags & E3_ONSET),
            "ONSET_EVIDENCE_SCHEMA_INVALID")
    def service(value):
        return value - 1 if value else None
    def dispatch(offset, present=True):
        if not present:
            return None
        return {"end_tick": uint32(raw, offset), "ms": uint16(raw, offset + 4),
                "service": service(raw[offset + 6]), "nv_ops": raw[offset + 7],
                "input": uint32(raw, offset + 8), "returned": uint32(raw, offset + 12),
                "nv_ticks": uint32(raw, offset + 16)}
    onset = None
    if flags & E3_ONSET:
        onset = {"end_tick": uint32(raw, 100), "busy_ticks": uint32(raw, 104),
                 "elapsed_ticks": uint32(raw, 108), "dispatches": uint32(raw, 112),
                 "top_service": service(raw[116]), "mac_cnf_failed": uint16(raw, 118),
                 "top_service_busy_ticks": uint32(raw, 120),
                 "top_service_inputs": uint32(raw, 124), "nv_ticks": uint32(raw, 128),
                 "mac_data_req": uint16(raw, 132), "mac_data_ind": uint16(raw, 134),
                 "heap_free": uint32(raw, 136), "after_calm": bool(flags & E3_AFTER_CALM)}
    return {"flags": flags, "ready": bool(flags & E3_READY),
            "settled": bool(flags & E3_SETTLED), "nv_hooked": bool(flags & E3_NV_HOOKED),
            "now": uint32(raw, 12), "windows": uint32(raw, 16),
            "saturated_windows": uint32(raw, 20), "busy_windows": uint32(raw, 24),
            "consecutive_saturated": uint16(raw, 28),
            "max_consecutive_saturated": uint16(raw, 30),
            "peak": {"busy_ticks": uint32(raw, 32), "elapsed_ticks": uint32(raw, 36),
                     "end_tick": uint32(raw, 40)},
            "ready_tick": uint32(raw, 44), "settle_tick": uint32(raw, 48),
            "nv": {"reads": uint32(raw, 52), "writes": uint32(raw, 56),
                   "deletes": uint16(raw, 60), "compactions": uint16(raw, 62),
                   "failures": uint16(raw, 64), "last_failure": raw[66],
                   "last_failure_kind": NV_KINDS[raw[67]], "ticks": uint32(raw, 68),
                   "other_context_ticks": uint32(raw, 72), "longest_ms": uint16(raw, 76),
                   "longest_kind": NV_KINDS[raw[78]], "longest_service": service(raw[79]),
                   "service_ticks": [uint32(raw, 200 + 4 * i) for i in range(10)]},
            "heap": {"total": uint32(raw, 80), "free": uint32(raw, 84),
                     "largest_free": uint32(raw, 88),
                     "low_water": uint32(raw, 92) if flags & E3_HEAP else None,
                     "low_water_tick": uint32(raw, 96) if flags & E3_HEAP else None},
            "onset": onset,
            "first_long": dispatch(140, bool(flags & E3_LONG)),
            "run_worst": dispatch(160, bool(flags & E3_READY)),
            "boot_worst": dispatch(180),
            "task_stack": {"stack_used": uint16(raw, 240), "stack_size": uint16(raw, 242),
                           "npi_used": uint16(raw, 244), "npi_size": uint16(raw, 246)}}

TREND_ENTRIES = 17

def decode_trend(raw: bytes, source: str) -> dict:
    """V51 B1E4 (17 x 5 min) or B1E5 (17 x 60 min) ring, oldest first."""
    require(onset_evidence_supported(source), "ONSET_EVIDENCE_UNSUPPORTED_SOURCE")
    tag = bytes(raw[:4])
    require(tag in (b"B1E4", b"B1E5"), "TREND_EVIDENCE_TAG_INVALID")
    checked(raw, tag, 248, source)
    count = raw[6]
    require(raw[7] == (5 if tag == b"B1E4" else 60) and count <= TREND_ENTRIES and
            uint32(raw, 16) >= count and not any(raw[36 + 12 * count:248]),
            "TREND_EVIDENCE_SCHEMA_INVALID")
    def entry(offset):
        return {"busy_permille": uint16(raw, offset),
                "top_service": raw[offset + 2] - 1 if raw[offset + 2] else None,
                "mac_cnf_failed": raw[offset + 3], "max_dispatch_ms": uint16(raw, offset + 4),
                "nv_ms": uint16(raw, offset + 6),
                "heap_low": uint16(raw, offset + 8) * 16 if uint16(raw, offset + 8) else None,
                "mac_data_req": uint16(raw, offset + 10)}
    return {"period_min": raw[7], "now": uint32(raw, 12), "pushed": uint32(raw, 16),
            "partial_ticks": uint32(raw, 20), "partial": entry(24),
            "entries": [entry(36 + 12 * i) for i in range(count)]}

V43_FIELDS = ("sreq_admitted", "mt_entered", "mt_exited", "uart_submit_ok",
              "uart_submit_failed", "uart_tx_complete", "uart_tx_failed", "uart_tx_short",
              "flags", "rx_bytes", "first_fault_kind", "first_fault_status",
              "first_fault_expected", "first_fault_actual", "first_fault_flags",
              "first_fault_tick", "first_fault_command", "npi_wakes", "startup_state",
              "tick_period_us")
NWK_STORM_BITS = ("RTG_TIMER_EVENT", "NWK_DATABUF_SEND", "NWK_BCAST_TIMER_EVT",
                  "NWK_BROADCAST_MSG_EVT")

def decode_e6(raw: bytes, source: str) -> dict:
    """V52 B1E6: NPI->MT->UART progress (B4_V43), OSAL timers, live dispatch.

    Answered by the NPI owner, so it stays readable while a Stack handler
    never returns. Evidence only, never acceptance.
    """
    require(pipeline_evidence_supported(source), "PIPELINE_EVIDENCE_UNSUPPORTED_SOURCE")
    checked(raw, b"B1E6", 248, source)
    flags, current = raw[6], raw[200]
    require(raw[7] == 0 and not flags & ~3 and bool(flags & 1) == (raw[134] != 0xFF) and
            bool(flags & 2) == (current != 0) and
            (current or (raw[201] == 0 and not any(raw[204:216]))),
            "PIPELINE_EVIDENCE_SCHEMA_INVALID")
    v43 = {name: uint32(raw, 16 + 4 * i) for i, name in enumerate(V43_FIELDS)}
    v43["first_fault_status"] = int.from_bytes(raw[60:64], "little", signed=True)
    v43["npi_tx_active"] = bool(v43["flags"] & 1)
    v43["transport_unavailable"] = bool(v43["flags"] & 2)
    v43["mt_active"] = bool(v43["flags"] & 4)
    v43["last_command"] = v43["flags"] >> 16
    t = 96
    timers = {"one_shot_starts": uint32(raw, t), "reload_starts": uint32(raw, t + 4),
              "restarts": uint32(raw, t + 8), "expiries": uint32(raw, t + 12),
              "create_failures": uint32(raw, t + 16), "cleanups": uint32(raw, t + 20),
              "freed": uint32(raw, t + 24), "deferred": uint16(raw, t + 28),
              "deferred_max": uint16(raw, t + 30), "freed_max": uint16(raw, t + 32),
              "active": uint16(raw, t + 34), "active_max": uint16(raw, t + 36),
              "probe_task": None if raw[t + 38] == 0xFF else raw[t + 38],
              "last_failure_task": None if raw[t + 39] == 0xFF else raw[t + 39],
              "nwk_bit_starts": {bit: uint16(raw, t + 40 + 2 * bit) for bit in range(16)
                                 if uint16(raw, t + 40 + 2 * bit)},
              "nwk_bit_min_timeout_ms": {bit: uint16(raw, t + 72 + 2 * bit) for bit in range(16)
                                         if uint16(raw, t + 40 + 2 * bit)}}
    inflight = {"service": current - 1 if current else None, "nv_ops": raw[201],
                "input": uint32(raw, 204), "age_ticks": uint32(raw, 208),
                "nv_ticks": uint32(raw, 212)}
    return {"now": uint32(raw, 12), "tick_wraps": raw[202], "ready_epoch": raw[203],
            "epochs": {"onset": raw[244], "first_long": raw[245], "heap_low": raw[246],
                       "settle": raw[247]},
            "npi_mt_uart": v43, "timers": timers, "inflight": inflight,
            "open_window": {"busy_ticks": uint32(raw, 216), "elapsed_ticks": uint32(raw, 220),
                            "dispatches": uint32(raw, 224)},
            "nwk_dispatch_bits": {name: uint32(raw, 228 + 4 * i)
                                  for i, name in enumerate(NWK_STORM_BITS)}}

E7_KINDS = {1: "read", 2: "write", 3: "delete"}

def decode_e7(raw: bytes, source: str) -> dict:
    """V53 B1E7: NV read-cache counters and the costliest NV items.

    Item IDs, counts and driver ticks only; the page never carries NV bytes.
    """
    require(nv_cache_evidence_supported(source), "NV_CACHE_EVIDENCE_UNSUPPORTED_SOURCE")
    checked(raw, b"B1E7", 248, source)
    require(raw[7] == 8 and raw[6] <= 8 and not any(raw[224:248]), "NV_CACHE_EVIDENCE_SCHEMA_INVALID")
    hot = []
    for i in range(8):
        e = raw[32 + 24 * i:56 + 24 * i]
        if not e[7]:
            require(not any(e), "NV_CACHE_EVIDENCE_SCHEMA_INVALID")
            continue
        require(e[7] == 1 and e[6] in E7_KINDS and not any(e[20:24]), "NV_CACHE_EVIDENCE_SCHEMA_INVALID")
        hot.append({"system": e[0], "item": uint16(e, 2), "sub": uint16(e, 4),
                    "kind": E7_KINDS[e[6]], "last_status": e[1], "count": uint32(e, 8),
                    "ticks": uint32(e, 12), "max_ticks": uint32(e, 16)})
    hot.sort(key=lambda h: -h["ticks"])
    hits, misses = uint32(raw, 16), uint32(raw, 20)
    return {"now": uint32(raw, 12), "lines_used": raw[6], "hits": hits, "misses": misses,
            "inserts": uint32(raw, 24), "invalidations": uint32(raw, 28),
            "hit_ratio": round(hits / (hits + misses), 4) if hits + misses else None,
            "hot_items": hot}

def onset_summary(e3: dict, tick_period_us: int) -> dict:
    """Human-scale view of a decoded B1E3 (needs the B1E2 tick period)."""
    ms = lambda ticks: ticks * tick_period_us // 1000
    age = lambda tick: ms((e3["now"] - tick) & 0xffffffff) // 1000
    onset = e3["onset"]
    stack = e3["task_stack"]
    pct = lambda used, size: round(100.0 * used / size, 1) if size else None
    return {"ready_age_s": age(e3["ready_tick"]) if e3["ready"] else None,
            "onset_age_s": age(onset["end_tick"]) if onset else None,
            "onset_busy_percent": (round(100.0 * onset["busy_ticks"] / onset["elapsed_ticks"], 1)
                                   if onset and onset["elapsed_ticks"] else None),
            "onset_top_service": onset["top_service"] if onset else None,
            "onset_nv_ms": ms(onset["nv_ticks"]) if onset else None,
            "onset_after_calm": onset["after_calm"] if onset else None,
            "saturated_windows": e3["saturated_windows"], "windows": e3["windows"],
            "nv_ms": ms(e3["nv"]["ticks"]),
            "nv_service_ms": [ms(t) for t in e3["nv"]["service_ticks"]],
            "heap_free": e3["heap"]["free"], "heap_low_water": e3["heap"]["low_water"],
            "heap_largest_free": e3["heap"]["largest_free"],
            "stack_high_water_percent": pct(stack["stack_used"], stack["stack_size"]),
            "npi_high_water_percent": pct(stack["npi_used"], stack["npi_size"])}

def stack_profile(first: dict, last: dict) -> dict:
    """Deltas between two B1E2 samples. Evidence only, never acceptance."""
    elapsed = (last["now"] - first["now"]) & 0xffffffff
    busy = (last["busy_ticks"] - first["busy_ticks"]) & 0xffffffff
    if last["current_service"] is not None:
        busy += last["current_age_ticks"]
    services = []
    for a, b in zip(first["services"], last["services"]):
        services.append({"dispatches": (b["dispatches"] - a["dispatches"]) & 0xffffffff,
                         "busy_ticks": (b["busy_ticks"] - a["busy_ticks"]) & 0xffffffff,
                         "inputs": b["inputs"], "longest_ms": b["longest_ms"]})
    mac = {k: (last["mac"][k] - first["mac"][k]) & 0xffffffff
           for k in ("data_req","data_req_ok","data_cnf","data_cnf_failed","data_ind","events")}
    return {"elapsed_ms": elapsed * last["tick_period_us"] // 1000,
            "stack_busy_percent": round(100.0 * min(busy, elapsed) / elapsed, 1) if elapsed else None,
            "wakes": (last["wakes"] - first["wakes"]) & 0xffffffff,
            "aged": (last["aged"] - first["aged"]) & 0xffffffff,
            "current_service": last["current_service"], "services": services, "mac": mac,
            "last_req_failure": last["mac"]["last_req_failure"],
            "last_cnf_failure": last["mac"]["last_cnf_failure"]}

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
            info["npi_priority"]==expected_ready_npi_priority(source),
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
