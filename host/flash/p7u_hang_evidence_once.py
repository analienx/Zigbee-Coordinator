"""Read-only coordinator hang evidence, BEFORE any ROM/BSL recovery.

The ROM round trip that restores service erases the firmware's RAM, and with
it the V51 B1E3 onset record of the hours-long collapse. This captures it
first: only after the sole Z2M owner is stopped and the TTY is proven
quiescent, through the qualified StartupSerial/FramedZnp owner, with only
B1Q1 read-only queries (answered by the priority-6 NPI owner, never the
Stack task): the B1E3 onset record, B1E6 NPI->MT->UART / OSAL timer /
in-flight dispatch page, B1E2 live Stack profile, B1E5/B1E4 trend rings,
B1E1 and B1S1, then B1E2 and B1E6 again 1 s later, then one final SYS_PING
probing the MT/Stack path. Every reply is
fsynced before the next request. No reset, BSL entry, radio restart,
startup request, NV access, host start or retry; a fresh directory per run.
"""
import os
import time

ROOT_PREFIX = "hang-evidence-"
REQUEST_SECONDS = 3.0
TOTAL_SECONDS = 25.0
LIVE_GAP_SECONDS = 1.0
STUCK_DISPATCH_MS = 6000
TIMER_BACKLOG = 64
HEAP_LARGEST_LOW = 512


def _labels(result):
    """Evidence labels, most decisive first; never an acceptance or recovery gate.

    They separate CPU saturation, a handler that never returns, deferred OSAL
    timer frees / heap pressure, an MT stall and UART delivery faults.
    """
    labels = []
    replies = result["replies"]
    if not {"B1E3", "B1E6", "B1E2"} & set(replies):
        return ["NPI_OWNER_UNRESPONSIVE"]
    live = result.get("stack_live")
    period = live["tick_period_us"] if live else 10
    pipe = result.get("pipeline") or {}
    later = pipe.get("later") or pipe.get("first")
    inflight = later["inflight"] if later else None
    if (inflight and inflight["service"] is not None and
            inflight["age_ticks"] * period // 1000 >= STUCK_DISPATCH_MS) or \
            (live and live["current_service"] is not None and
             live["current_age_ticks"] * period // 1000 >= STUCK_DISPATCH_MS):
        labels.append("STACK_DISPATCH_STUCK")
    if later:
        if later["timers"]["create_failures"]:
            labels.append("TIMER_ALLOCATION_FAILED")
        if later["timers"]["deferred"] >= TIMER_BACKLOG:
            labels.append("TIMER_FREE_BACKLOG")
        if later["npi_mt_uart"]["first_fault_kind"]:
            labels.append("UART_OR_TRANSPORT_FAULT_LATCHED")
        first = pipe.get("first")
        if (first and later["npi_mt_uart"]["mt_active"] and first["npi_mt_uart"]["mt_active"] and
                later["npi_mt_uart"]["mt_entered"] == first["npi_mt_uart"]["mt_entered"]):
            labels.append("MT_HANDLER_NOT_PROGRESSING")
    heap = (result.get("onset_record") or {}).get("decoded", {}).get("heap")
    if heap and heap["total"] and heap["largest_free"] < HEAP_LARGEST_LOW:
        labels.append("HEAP_EXHAUSTED_OR_FRAGMENTED")
    profile = result.get("stack_profile")
    if profile and (profile["stack_busy_percent"] or 0) >= 90:
        labels.append("STACK_SATURATED")
    if result["mt_ping"] != "RESPONDED":
        labels.append("MT_PATH_UNRESPONSIVE")
    return labels or ["LOCAL_QUERIES_ANSWERED"]


def capture(ns, package, package_pin, plan_pin, ha):
    need = ns["need"]
    from p7u_paired_hold import verified_pair_package
    writer = verified_pair_package(ns, plan_pin)
    written = ns["verified_write"](writer, plan_pin)
    started = ns["load"](ns["PRIVATE"] / "started-pending-serving.json")
    need(started.get("source") == ns["SOURCE"], "HANG_EVIDENCE_SOURCE_NOT_INSTALLED")
    ns["modules"](package)
    from p7u_r4_startup_observer import (Q0, Q3, Q4, Q5, Q6, Q7, Q8, Q9, EvidenceError, checked,
                                         decode_e1, decode_e2, decode_e3, decode_e6, decode_e7,
                                         decode_trend, onset_evidence_supported,
                                         nv_cache_evidence_supported, onset_summary,
                                         pipeline_evidence_supported,
                                         stack_profile)
    from p7u_r4_startup_transport import FramedZnp, PrivateEvidenceJournal
    source = ns["SOURCE"]
    need(onset_evidence_supported(source), "HANG_EVIDENCE_REQUIRES_B1E3_SOURCE")
    pipeline = pipeline_evidence_supported(source)
    nvcache = nv_cache_evidence_supported(source)
    ha.policy()
    owner = ha.inspect()
    need(not owner["running"] and owner["image"] == ns["IMAGE"], "HANG_EVIDENCE_OWNER_RUNNING")
    ha.proof(False)
    need(ha.management() == written["management_sha256"], "HANG_EVIDENCE_BOARD")
    stamp = time.strftime("%Y%m%dt%H%M%Sz", time.gmtime())
    root = ns["PRIVATE"] / (ROOT_PREFIX + stamp + "-" + os.urandom(4).hex())
    need(not root.exists(), "HANG_EVIDENCE_CONSUMED")
    root.mkdir(mode=0o700)
    ns["durable"](root, "intent.json", {
        "source": source, "plan_sha256": plan_pin, "package_pin": package_pin, "owner": owner,
        "queries": (["B1E3"] + (["B1E6"] if pipeline else []) + (["B1E7"] if nvcache else []) +
                    ["B1E2", "B1E5", "B1E4", "B1E1", "B1S1", "B1E2"] +
                    (["B1E6"] if pipeline else []) + (["B1E7"] if nvcache else []) + ["SYS_PING"]),
        "reset_authorized": False, "bsl_authorized": False, "startup_authorized": False,
        "host_start_authorized": False, "at": time.time()})
    replies, failure, port, journal, znp = {}, None, None, None, None
    try:
        port = ns["StartupSerial"]()
        znp = FramedZnp(port, source=source)
        journal = PrivateEvidenceJournal(root / "evidence.jsonl", source)
        os.chmod(root / "evidence.jsonl", 0o600)
        end = time.monotonic() + TOTAL_SECONDS

        def ask(name, sub, cmd, payload=b""):
            raw = znp.request(sub, cmd, payload,
                              deadline=min(end, time.monotonic() + REQUEST_SECONDS))
            journal(name, raw, dict(znp.history[-1]))
            replies[name] = raw

        # Most valuable first: one timeout latches the transport unusable.
        first = ([("B1E3", Q5)] + ([("B1E6", Q8)] if pipeline else []) +
                 ([("B1E7", Q9)] if nvcache else []))
        for name, query in first + [("B1E2", Q4), ("B1E5", Q7), ("B1E4", Q6),
                                    ("B1E1", Q3), ("B1S1", Q0)]:
            ask(name, 1, 241, query)
        time.sleep(LIVE_GAP_SECONDS)
        ask("B1E2_LATER", 1, 241, Q4)
        if pipeline:
            ask("B1E6_LATER", 1, 241, Q8)
        if nvcache:
            ask("B1E7_LATER", 1, 241, Q9)
        ask("SYS_PING", 1, 1)
    except (TimeoutError, OSError, ValueError, RuntimeError) as error:
        failure = type(error).__name__ + ":" + str(error)[:96]
    finally:
        if journal is not None:
            journal.close()
        if port is not None:
            port.close()
    result = {"status": "HANG_EVIDENCE_CAPTURED" if failure is None else "HANG_EVIDENCE_PARTIAL",
              "source": source, "first_failure": failure, "replies": sorted(replies),
              "transport": list(znp.history) if znp is not None else [],
              "unsolicited_frames": len(znp.unsolicited) if znp is not None else 0,
              "mt_ping": "RESPONDED" if "SYS_PING" in replies else
                         ("NO_RESPONSE" if ("B1E7_LATER" if nvcache else
                                           "B1E6_LATER" if pipeline else "B1E2_LATER") in replies
                          else "NOT_ATTEMPTED"),
              "decode_errors": {}}

    def decoded(name, fn):
        if name not in replies:
            return None
        try:
            return fn(replies[name], source)
        except (EvidenceError, ValueError) as error:
            result["decode_errors"][name] = str(error)[:96]
            return None

    e3 = decoded("B1E3", decode_e3)
    first = decoded("B1E2", decode_e2)
    later = decoded("B1E2_LATER", decode_e2)
    pipe_first = decoded("B1E6", decode_e6)
    pipe_later = decoded("B1E6_LATER", decode_e6)
    if pipe_first is not None or pipe_later is not None:
        result["pipeline"] = {"first": pipe_first, "later": pipe_later}
    cache_first = decoded("B1E7", decode_e7)
    cache_later = decoded("B1E7_LATER", decode_e7)
    if cache_first is not None or cache_later is not None:
        result["nv_cache"] = {"first": cache_first, "later": cache_later}
    coarse = decoded("B1E5", decode_trend)
    fine = decoded("B1E4", decode_trend)
    if coarse is not None or fine is not None:
        result["trend"] = {"coarse_60min": coarse, "fine_5min": fine}
    e1 = decoded("B1E1", decode_e1)
    status = decoded("B1S1", lambda raw, src: checked(raw, b"B1S1", 24, src))
    live = later or first
    if live is not None:
        result["stack_live"] = live
    if first is not None and later is not None:
        result["stack_profile"] = stack_profile(first, later)
    if e3 is not None:
        result["onset_record"] = {"decoded": e3}
        if live is not None:
            result["onset_record"]["summary"] = onset_summary(e3, live["tick_period_us"])
    if e1 is not None:
        result["b1e1"] = {k: e1[k] for k in ("state", "dev_state", "first_error",
                                              "stack_priority", "npi_priority",
                                              "dispatch_enter", "dispatch_exit",
                                              "last_dispatch_input")}
    if status is not None:
        result["b1s1"] = {"state": status[6], "detail_hex": status[7:11].hex()}
    result["labels"] = _labels(result)
    result["classification"] = result["labels"][0]
    ns["durable"](root, "result.json", result)
    return {"status": result["status"], "classification": result["classification"],
            "labels": result["labels"],
            "first_failure": failure, "mt_ping": result["mt_ping"],
            "onset_summary": result.get("onset_record", {}).get("summary"),
            "stack_busy_percent": (result.get("stack_profile") or {}).get("stack_busy_percent"),
            "evidence_dir": root.name, "reset_issued": False, "host_started": False}
