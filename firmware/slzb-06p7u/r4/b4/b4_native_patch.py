"""B4 experimental, guarded overlay on real pinned TI SDK (DISPOSABLE CI ONLY).

Does not touch repo worktrees, production coordinators or flashing. The only
native measurement initially qualified is successful NPI SRSP queue enqueue.
All other P10-layout counters have validity=0. Boot ID cap is always 0.
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
MARKER = "B4_EXPERIMENTAL_DIAG_READ_ONLY"

B4_FUNCTION = r"""
/* B4_EXPERIMENTAL_DIAG_READ_ONLY: read-only, static RAM, no radio or NV. */
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
    uint32_t count;
    uint32_t seq;
    uint32_t key = OsalPort_enterCS();
    count = B4_NpiSrspEnqueued;
    seq = ++B4_DiagSampleSequence;
    OsalPort_leaveCS(key);
    payload[0] = 'R';
    payload[1] = '4';
    payload[2] = 'D';
    payload[3] = '3';
    payload[4] = 3;     /* exact version 3, no minor version implied */
    payload[6] = 132;   /* full u16 LE length 132 */
#if defined(NPI_SREQRSP)
    payload[12] = 0x10; /* only counter 4 (srsp_enqueued) is known */
#endif
    /* capabilities=0, radio_boot_id=0 and uptime_ms=0: epoch UNKNOWN */
    B4_DiagPutU32(payload + 28, seq);
    B4_DiagPutU32(payload + 32 + (4 * 4), count);
    /* The MT response path can fail when NPI is starved; no guarantee. */
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
    for path in (MT_SYS, NPI_TASK, NPI_CLIENT):
        actual = (root / path).read_bytes()
        pristine = _git(root, "show", TI_SHA + ":" + path)
        if actual != pristine:
            raise ValueError("source modified before B4 overlay: " + path)
        initial[path] = actual.decode("utf-8")
    sys = initial[MT_SYS]
    task = initial[NPI_TASK]
    client = initial[NPI_CLIENT]
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
        "/* " + MARKER + ": RAM-only counter; updates inside preexisting CS. */\n"
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
        start = task.find(function_name)
        end = task.find(enqueue, start)
        if start < 0 or end < 0 or end - start > 5500:
            raise ValueError("unqualified SRSP producer: " + function_name)
        scope = task[start:end]
        if ("OsalPort_enterCS()" not in scope or
                "#if defined(NPI_SREQRSP)" not in scope):
            raise ValueError("missing preexisting critical section for " + function_name)
    task = task.replace(enqueue,
        enqueue + "\n                ++B4_NpiSrspEnqueued; /* existing OsalPort CS */")
    if task.count("++B4_NpiSrspEnqueued;") != 2:
        raise ValueError("cannot prove both synchronous response producer increments")
    return {MT_SYS: (initial[MT_SYS], sys), NPI_TASK: (initial[NPI_TASK], task)}

def apply(root):
    patches = build_patches(root)
    receipt = {"stage": "PATCHED_DISPOSABLE_SDK_NOT_LINKED", "ti_sha": TI_SHA,
               "f0_opcode": "0xF0", "payload_bytes": 132,
               "valid_counter_indices": [4], "radio_boot_identity": "UNKNOWN",
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
