"""B4 fail-closed audit of pinned TI MT and herdsman *source*.

This audit does not claim a native B4 implementation or installed Z2M API.
It compares real checked-out upstream source, and rejects any SYS F0
collision, altered owner invariant, unpinned checkout or missing hook.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

TI_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
HERDSMAN_SHA = "0968f979d558874b17396c96b66382d4236bbdcd"
TI_MT = "source/ti/zstack/mt/"
TI_NPI = "source/ti/zstack/npi/"
HERDSMAN_ZNP = "src/adapter/z-stack/znp/"
HERDSMAN_ADAPTER = "src/adapter/z-stack/adapter/"
NPI_CLIENT = "source/ti/zstack/npi/npi_client_mt.c"

def _read(root, path):
    target = root / path
    if not target.is_file() or target.is_symlink():
        raise ValueError("missing or symlinked source: " + path)
    return target.read_text(encoding="utf-8")

def _pin(root, expected):
    try:
        actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"],
                                         text=True, stderr=subprocess.DEVNULL).strip()
    except (subprocess.CalledProcessError, OSError):
        raise ValueError("upstream git HEAD cannot be verified") from None
    if actual != expected:
        raise ValueError("upstream checkout SHA mismatch")

def verify_ti(mt_h, mt_sys, npi_task, uart, npi_client=None):
    """Return source proof anchors only, never fabricated counter validity."""
    # Match both decimal and hexadecimal definitions: an alias changing
    # to decimal 240 must never bypass the SYS F0 collision gate.
    defs = dict((name, int(n, 0)) for name, n in
                re.findall(r"^\s*#define\s+(MT_SYS_[A-Z0-9_]+)\s+(0[xX][0-9a-fA-F]+|[1-9][0-9]*|0)\b",
                           mt_h, re.M))
    if defs.get("MT_SYS_PING") != 1 or defs.get("MT_SYS_VERSION") != 2:
        raise ValueError("stock SYS_PING / SYS_VERSION definition drift")
    if 0xF0 in defs.values():
        raise ValueError("SYS F0 already assigned by TI dictionary")
    start = mt_sys.find("uint8_t MT_SysCommandProcessing(uint8_t *pBuf)")
    if start < 0:
        raise ValueError("missing TI SYS dispatch")
    end = mt_sys.find("return status;", start)
    if end < 0 or end - start > 15_000:
        raise ValueError("unbounded or missing TI SYS switch")
    dispatch = mt_sys[start:end]
    cases = re.findall(r"\bcase\s+(MT_SYS_[A-Z0-9_]+|0x[0-9a-fA-F]+)\s*:", dispatch)
    if not cases or any(c not in defs and not c.startswith("0x") for c in cases):
        raise ValueError("unresolved SYS case alias")
    if any((int(c, 16) if c.startswith("0x") else defs[c]) == 0xF0 for c in cases):
        raise ValueError("SYS F0 dispatch collision")
    for label in ("MT_SYS_PING", "MT_SYS_VERSION"):
        if label not in cases:
            raise ValueError("stock SYS path removed: " + label)
    if "status = MT_RPC_ERR_COMMAND_ID" not in dispatch:
        raise ValueError("stock unknown command handling changed")
    funcs = ("NPITask_sendToHost", "NPITask_ProcessTXQ",
             "NPITask_incomingFrameCB", "NPITask_processStackMsg")
    for name in funcs:
        if name not in npi_task:
            raise ValueError("missing genuine NPI hook: " + name)
    if ("NPITLUART_writeCallBack" not in uart or "UART2_write(" not in uart
            or "npiTransmitCB" not in uart or "status" not in uart):
        raise ValueError("missing UART2 callback / accepted-write evidence")
    if npi_client is not None and ("void MT_BuildAndSendZToolResponse(" not in npi_client
                                  or "OsalPort_msgSend(" not in npi_client):
        raise ValueError("linked NPI-specific MT response producer not sourced")
    return {
        "sys_f0_unassigned": True,
        "ping_version_preserved": True,
        "npi_hook_names": list(funcs),
        "uart_status": "CALLBACK_SOURCE_IDENTIFIED; TX_FINISHED_EVENT_NOT_PROVEN",
        "mt_response_producer": ("NPI_CLIENT_SOURCE_VERIFIED" if npi_client is not None
                                 else "NOT_MEASURED"),
    }

def verify_herdsman(definition, znp, adapter):
    anchor = definition.find("[Subsystem.SYS]: [")
    if anchor < 0:
        raise ValueError("SYS definition not found")
    end = definition.find("[Subsystem.MAC]:", anchor)
    if end < 0 or end - anchor > 40_000:
        raise ValueError("SYS definition boundary not proved")
    sys_dict = definition[anchor:end]
    ids = [int(n) for n in re.findall(r"\bID:\s*(\d+)\s*[,}]", sys_dict)]
    if not ids or 240 in ids:
        raise ValueError("herdsman SYS F0 collision or unknown dictionary")
    if 1 not in ids or 2 not in ids or 128 not in ids:
        raise ValueError("stock herdsman SYS commands missing")
    required = ("public request(", "ZpiObject.createRequest(", "this.queue.run",
                "this.waitress.waitFor(", "this.unpiWriter.writeFrame(")
    for token in required:
        if token not in znp:
            raise ValueError("pinned owner/waiter path drift: " + token)
    if "private znp: Znp;" not in adapter:
        raise ValueError("private ZStackAdapter znp ownership changed")
    return {
        "sys_f0_unassigned": True,
        "single_owner_path": "Znp.request -> ZpiObject.createRequest -> AsyncMutex/Waitress",
        "external_z2m_extension_raw_request": "UNSUPPORTED",
        "source_only": True,
    }

def verify(ti, herdsman):
    _pin(ti, TI_SHA)
    _pin(herdsman, HERDSMAN_SHA)
    return {
        "evidence": "SOURCE_PROVEN",
        "sdk_sha": TI_SHA,
        "herdsman_sha": HERDSMAN_SHA,
        "ti": verify_ti(_read(ti, TI_MT + "mt.h"),
                        _read(ti, TI_MT + "mt_sys.c"),
                        _read(ti, TI_NPI + "npi_task.c"),
                        _read(ti, TI_NPI + "npi_tl_uart.c"),
                        _read(ti, NPI_CLIENT)),
        "herdsman": verify_herdsman(
            _read(herdsman, HERDSMAN_ZNP + "definition.ts"),
            _read(herdsman, HERDSMAN_ZNP + "znp.ts"),
            _read(herdsman, HERDSMAN_ADAPTER + "zStackAdapter.ts")),
        "native_f0_linked": False,
        "host_f0_installed": False,
        "radio_boot_epoch_source": "UNKNOWN",
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ti", type=Path, required=True)
    p.add_argument("--herdsman", type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(verify(args.ti, args.herdsman), sort_keys=True))

if __name__ == "__main__":
    main()
