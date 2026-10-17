"""B4 experimental, guarded overlay on real pinned TI SDK (DISPOSABLE CI ONLY).

Does not touch production coordinators or flashing. Source-qualified metrics:
SRSP and AREQ NPI queue depth/high-water and sync enqueue count, each at the
actual pinned producer/consumer with preexisting TI critical sections.
No UART completion, radio boot identity or unqualified RF/NV telemetry.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

TI_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
MT_SYS = "source/ti/zstack/mt/mt_sys.c"
NPI_TASK = "source/ti/zstack/npi/npi_task.c"
NPI_CLIENT = "source/ti/zstack/npi/npi_client_mt.c"
NPI_FRAME = "source/ti/zstack/npi/npi_frame_mt.c"
NPI_OPTS = "source/ti/zstack/apps/znp/znp_cnf.opts"
SYNC_COMPILE_GUARD = """#if !defined(NPI_SREQRSP)
#error B4_SYNC_NPI_BUILD_UNQUALIFIED_NO_SRSP_PRODUCERS
#endif
"""
MARKER = "B4_EXPERIMENTAL_DIAG_READ_ONLY"

B4_FUNCTION = SYNC_COMPILE_GUARD + r"""
/* B4_EXPERIMENTAL_DIAG_READ_ONLY: snapshot preexisting NPI queue metrics. */
extern volatile uint32_t B4_NpiSrspDepth;
extern volatile uint32_t B4_NpiSrspHighWater;
extern volatile uint32_t B4_NpiAsyncDepth;
extern volatile uint32_t B4_NpiAsyncHighWater;
extern volatile uint32_t B4_NpiSrspEnqueued;
static uint32_t B4_DiagSampleSequence = 0;
static void B4_DiagPutU32(uint8_t *dest, uint32_t v)
{
    dest[0] = (uint8_t)v;
    dest[1] = (uint8_t)(v >> 8);
    dest[2] = (uint8_t)(v >> 16);
    dest[3] = (uint8_t)(v >> 24);
}
__attribute__((noinline)) static void B4_SysReadOnlyDiagnostics(void)
{
    uint8_t payload[132] = {0};
    uint32_t srsp_depth;
    uint32_t srsp_high_water;
    uint32_t async_depth;
    uint32_t async_high_water;
    uint32_t srsp_enqueued;
    uint32_t seq;
    uint32_t key = OsalPort_enterCS();
    srsp_depth = B4_NpiSrspDepth;
    srsp_high_water = B4_NpiSrspHighWater;
    async_depth = B4_NpiAsyncDepth;
    async_high_water = B4_NpiAsyncHighWater;
    srsp_enqueued = B4_NpiSrspEnqueued;
    seq = ++B4_DiagSampleSequence;
    OsalPort_leaveCS(key);
    payload[0] = 'R';
    payload[1] = '4';
    payload[2] = 'D';
    payload[3] = '3';
    payload[4] = 3;     /* exact version 3; no minor version implied */
    payload[6] = 132;   /* full u16 LE length 132 */
    payload[12] = 0x0C; /* async queue: validity bits 2,3 always compiled */
#if defined(NPI_SREQRSP)
    payload[12] = 0x1F; /* sync depth/HWM + async depth/HWM + sync enqueue */
    B4_DiagPutU32(payload + 32, srsp_depth);
    B4_DiagPutU32(payload + 36, srsp_high_water);
    B4_DiagPutU32(payload + 48, srsp_enqueued);
#endif
    /* capabilities=0, radio_boot_id=0 and uptime_ms=0: epoch UNKNOWN */
    B4_DiagPutU32(payload + 28, seq);
    B4_DiagPutU32(payload + 40, async_depth);
    B4_DiagPutU32(payload + 44, async_high_water);
    /* Neither reported depth nor UART callback proves physical delivery. */
    MT_BuildAndSendZToolResponse(MT_SRSP_SYS, 0xF0, sizeof(payload), payload);
}
"""

def _git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args],
                                   stderr=subprocess.DEVNULL)

def build_patches(root):
    if not root.is_dir() or not str(root.resolve()).startswith("/tmp/"):
        raise ValueError("B4 native patch requires disposable /tmp SDK checkout")
    if _git(root, "rev-parse", "HEAD").decode().strip() != TI_SHA:
        raise ValueError("not the pinned TI 8.33 SDK")
    initial = {}
    for path in (MT_SYS, NPI_TASK, NPI_CLIENT, NPI_FRAME, NPI_OPTS):
        actual = (root / path).read_bytes()
        pristine = _git(root, "show", TI_SHA + ":" + path)
        if actual != pristine:
            raise ValueError("source modified before B4 overlay: " + path)
        initial[path] = actual.decode("utf-8")
    sys = initial[MT_SYS]
    task = initial[NPI_TASK]
    client = initial[NPI_CLIENT]
    frame = initial[NPI_FRAME]
    opts = initial[NPI_OPTS]
    # The pinned example ZNP projectspec copies SDK znp_cnf.opts into
    # the global compiler option set. It has no stock NPI_SREQRSP flag.
    # Opt-in changes stock synchronous priority/watchdog logic; DISPOSABLE
    # experimental B4 compilation only, never the sealed B0 build.
    if ("-DNPI_SREQRSP" in opts or
            opts.count("-DMT_SYS_FUNC") != 1 or
            frame.count("#if defined(NPI_SREQRSP)") < 2 or
            task.count("#if defined(NPI_SREQRSP)") < 2):
        raise ValueError("cannot qualify pinned TI NPI synchronous option baseline")
    opts = opts.rstrip("\n") + "\n-DNPI_SREQRSP\n"
    frame = SYNC_COMPILE_GUARD + frame
    task = SYNC_COMPILE_GUARD + task
    if ("void MT_BuildAndSendZToolResponse(" not in client or
            "OsalPort_msgAllocate(" not in client or
            "#if !defined(NPI)" not in _git(root, "show", TI_SHA + ":source/ti/zstack/mt/mt.c").decode()):
        raise ValueError("NPI response producer not independently sourced")
    dispatch = "    case MT_SYS_VERSION:\n      MT_SysVersion();\n      break;"
    if sys.count(dispatch) != 1:
        raise ValueError("SYS_VERSION dispatch drift")
    if sys.count("uint8_t MT_SysCommandProcessing(uint8_t *pBuf)") != 1:
        raise ValueError("MT SYS dispatcher drift")
    if "case 0xF0:" in sys or MARKER in sys:
        raise ValueError("F0 handler collision")
    if "#define MT_SYS_PING" in sys:
        raise ValueError("unexpected SYS symbol redefinition")
    sys = sys.replace("uint8_t MT_SysCommandProcessing(uint8_t *pBuf)",
                      B4_FUNCTION + "\nuint8_t MT_SysCommandProcessing(uint8_t *pBuf)", 1)
    sys = sys.replace(dispatch, dispatch + """
    case 0xF0:
      if (pBuf[MT_RPC_POS_LEN] != 0)
        status = MT_RPC_ERR_LENGTH;
      else
        B4_SysReadOnlyDiagnostics();
      break;""", 1)
    task_anchor = "void NPITask_sendToHost(uint8_t *pMsg)"
    if task.count(task_anchor) != 1:
        raise ValueError("NPI sender drift")
    task = task.replace(task_anchor,
        "/* " + MARKER + ": RAM queue metrics updated in preexisting CS. */\n"
        "volatile uint32_t B4_NpiSrspDepth = 0;\n"
        "volatile uint32_t B4_NpiSrspHighWater = 0;\n"
        "volatile uint32_t B4_NpiAsyncDepth = 0;\n"
        "volatile uint32_t B4_NpiAsyncHighWater = 0;\n"
        "volatile uint32_t B4_NpiSrspEnqueued = 0;\n" + task_anchor, 1)
    # Both real source producers enqueue the same synchronous response
    # queue: NPITask_sendToHost() and NPITask_processStackMsg(). Each
    # already owns an OsalPort critical section. Never count one and silently
    # omit the other (source-shape invariant prevents partial instrumentation).
    enqueue = "Queue_enqueue(npiSyncTxQueue, &recPtr->_elem);"
    if task.count(enqueue) != 2:
        raise ValueError("NPI SRSP queue producer count drift (expected exactly two)")
    for function_name in ("void NPITask_sendToHost(uint8_t *pMsg)",
                          "static void NPITask_processStackMsg(uint8_t *pMsg)"):
        # Match a function *definition*, never its earlier prototype.
        start = task.find(function_name + "\n{")
        end = task.find(enqueue, start)
        if start < 0 or end < 0 or end - start > 5500:
            raise ValueError("unqualified SRSP producer: " + function_name)
        scope = task[start:end]
        if ("OsalPort_enterCS()" not in scope or
                "#if defined(NPI_SREQRSP)" not in scope):
            raise ValueError("missing preexisting critical section for " + function_name)
    task = task.replace(enqueue,
        enqueue + "\n                ++B4_NpiSrspEnqueued; /* existing OsalPort CS */"
        "\n                if (B4_NpiSrspDepth != 0xFFFFFFFFu) ++B4_NpiSrspDepth;"
        "\n                if (B4_NpiSrspDepth > B4_NpiSrspHighWater)"
        "\n                    B4_NpiSrspHighWater = B4_NpiSrspDepth;")
    if task.count("++B4_NpiSrspEnqueued;") != 2:
        raise ValueError("cannot prove both synchronous response producer increments")

    # Two actual async NPI TX producers, same guarded critical sections.
    async_enqueue = "Queue_enqueue(npiTxQueue, &recPtr->_elem);"
    if task.count(async_enqueue) != 2:
        raise ValueError("NPI ASYNC TX queue producer count drift")
    task = task.replace(async_enqueue,
        async_enqueue +
        "\n                if (B4_NpiAsyncDepth != 0xFFFFFFFFu) ++B4_NpiAsyncDepth;"
        "\n                if (B4_NpiAsyncDepth > B4_NpiAsyncHighWater)"
        "\n                    B4_NpiAsyncHighWater = B4_NpiAsyncDepth;")
    # Single existing consumer for each TX queue. Preserve TI scheduling;
    # never invoke Queue_dequeue independently or change empty handling.
    for queue, name, function in (
            ("npiSyncTxQueue", "B4_NpiSrspDepth",
             "static void NPITask_ProcessSyncTXQ(void)"),
            ("npiTxQueue", "B4_NpiAsyncDepth",
             "static void NPITask_ProcessTXQ(void)")):
        anchor = "recPtr = Queue_dequeue(" + queue + ");"
        if task.count(anchor) != 1:
            raise ValueError("TX queue dequeue consumer drift: " + queue)
        start = task.find(function + "\n{")
        stop = task.find(anchor, start)
        if start < 0 or stop < 0 or stop - start > 1500:
            raise ValueError("source consumer definition missing: " + function)
        scope = task[start:stop]
        if "OsalPort_enterCS()" not in scope:
            raise ValueError("dequeue not protected by existing CS")
        after = task[stop + len(anchor):stop + len(anchor) + 160]
        if "if (recPtr != NULL)" not in after:
            raise ValueError("unexpected existing TI dequeue branch")
        task = task.replace(anchor,
            anchor + "\n    if (recPtr != NULL && " + name +
            " != 0u) --" + name + "; /* preexisting CS */", 1)
    for name in ("B4_NpiSrspDepth", "B4_NpiAsyncDepth"):
        if task.count("++" + name) != 2 or task.count("--" + name) != 1:
            raise ValueError("incomplete NPI TX queue depth instrumentation: " + name)
    # Compile-time (not symbol-only) proof for every affected translation unit.
    if (opts.count("-DNPI_SREQRSP") != 1 or
            any("B4_SYNC_NPI_BUILD_UNQUALIFIED_NO_SRSP_PRODUCERS" not in x
                for x in (frame, sys, task))):
        raise ValueError("unqualified synchronous NPI build after overlay")
    return {MT_SYS: (initial[MT_SYS], sys),
            NPI_TASK: (initial[NPI_TASK], task),
            NPI_FRAME: (initial[NPI_FRAME], frame),
            NPI_OPTS: (initial[NPI_OPTS], opts)}

def apply(root):
    patches = build_patches(root)
    receipt = {"stage": "PATCHED_DISPOSABLE_SDK_NOT_LINKED", "ti_sha": TI_SHA,
               "f0_opcode": "0xF0", "payload_bytes": 132,
               "valid_counter_indices": [0, 1, 2, 3, 4], "radio_boot_identity": "UNKNOWN",
               "sync_npi_compiled_required": True,
               "sync_transport_changed_from_stock": True,
               "written": {}}
    # All anchors, files and Git pins are verified BEFORE the first write.
    for name, (old, new) in patches.items():
        (root / name).write_text(new, encoding="utf-8", newline="")
        receipt["written"][name] = {
            "before_sha256": hashlib.sha256(old.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(new.encode()).hexdigest(),
        }
    return receipt

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    a = parser.parse_args()
    receipt = apply(a.sdk)
    a.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))

if __name__ == "__main__":
    main()
