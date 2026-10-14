#!/usr/bin/env python3
"""Hosted counterexamples for the exact linked guard audit, pinned TI SDK8.32."""
import argparse
import importlib.util
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


s1=load(ROOT/"firmware/slzb-06p7/ti832/f07/f07_nib_gate.py","slice1")
s2=load(ROOT/"firmware/slzb-06p7/ti832/f07/f07_restore_guard.py","slice2")
s3=load(ROOT/"firmware/slzb-06p7/ti832/f07/f07_nwk_counter_escrow.py","slice3")
audit=load(ROOT/"firmware/slzb-06p7/ti832/f07/verify_composed_native.py","audit")


def must_reject(f, token):
    try:
        f()
    except ValueError as e:
        if token not in str(e):
            raise AssertionError("WRONG_FAIL_CLOSED_REASON: "+str(e))
    else:
        raise AssertionError("MISSING_FAIL_CLOSED_REJECTION: "+token)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",required=True,type=Path)
    a=p.parse_args()
    original=(a.sdk/s1.ZDO_PATH).read_text()
    text=s3.patch(s2.patch(s1.patch(original)))
    result=audit.verify_source(text)
    assert result["raw_nv_success_only"] is True
    must_reject(lambda: audit.verify_source(text.replace(
        "pZStackCfg->nvFps.readItem(id, 0, sizeof(nwkIB_t), copy) == NVINTF_SUCCESS",
        "osal_nv_read(ZCD_NV_NIB, 0, sizeof(nwkIB_t), copy) == SUCCESS")),
        "F07_REQUIRED_SOURCE_ANCHOR_MISSING")
    must_reject(lambda: audit.verify_source(text.replace(
        "if (!p7_f07_commit_nib_before_ready())",
        "if (1)")), "F07_NIB_GUARD_CALLSITE_AMBIGUOUS")
    must_reject(lambda: audit.verify_source(text.replace(
        "if (networkStateNV != ZDO_INITDEV_RESTORED_NETWORK_STATE)",
        "if (networkStateNV == ZDO_INITDEV_NEW_NETWORK_STATE)",
        1)), "F07_RESTORE_FAIL_CLOSED_ORDER_BROKEN")
    with tempfile.TemporaryDirectory() as directory:
        tmp=Path(directory)
        src=tmp/"zd_app.c"
        src.write_text(text)
        can=tmp/"linked"
        can.mkdir()
        sym="\n".join(f"00000100 t {name}" for name in (
          "ZDApp_NetworkStartEvt","p7_f07_commit_nib_before_ready",
          "ZDOInitDeviceEx","p7_f07_nv_restore_preflight",
          "ZDApp_RestoreNetworkState","p7_f07_nwk_counter_escrow"))+"\n"
        (can/"DIAG-symbols.txt").write_text(sym)
        dis="\n".join([
          "00000100 <ZDApp_NetworkStartEvt>:",
          "  104: f000 f800 bl 180 <p7_f07_commit_nib_before_ready>",
          "00000180 <p7_f07_commit_nib_before_ready>:",
          "  184: 4770 bx lr",
          "000001a0 <ZDOInitDeviceEx>:",
          "  1a4: f000 f800 bl 200 <p7_f07_nv_restore_preflight>",
          "00000200 <p7_f07_nv_restore_preflight>:",
          "  204: 4770 bx lr",
          "00000240 <ZDApp_RestoreNetworkState>:",
          "  244: f000 f800 bl 2c0 <p7_f07_nwk_counter_escrow>",
          "000002c0 <p7_f07_nwk_counter_escrow>:",
          "  2c4: 4770 bx lr",
          ""])
        (can/"DIAG-disassembly.txt").write_text(dis)
        assert audit.verify(can,src,"p7u-f07-stock")["flash_authorized"] is False
        assert audit.verify(can,src,"p7u-cap192-f07")["flash_authorized"] is False
        must_reject(lambda: audit.verify(can,src,"other"),"F07_INTEGRATION_PROFILE")
        (can/"DIAG-disassembly.txt").write_text(dis.replace(
           "bl 200 <p7_f07_nv_restore_preflight>",
           "bl 200 <something_else>"))
        must_reject(lambda: audit.verify(can,src,"cap192-f07"),
                    "F07_NATIVE_CALL_EDGE_MISSING")
        (can/"DIAG-disassembly.txt").write_text(dis)
        must_reject(lambda: audit.verify_source(text.replace(
            "if (!p7_f07_nwk_counter_escrow()","if (1)")),
            "F07_COUNTER_ESCROW_CALLSITE_AMBIGUOUS")
        (can/"DIAG-disassembly.txt").write_text(dis.replace(
            "bl 2c0 <p7_f07_nwk_counter_escrow>",
            "bl 2c0 <wrong_escrow>"))
        must_reject(lambda: audit.verify(can,src,"p7u-cap192-f07"),
                    "F07_NATIVE_CALL_EDGE_MISSING")
        (can/"DIAG-disassembly.txt").write_text(dis)
        (can/"DIAG-symbols.txt").write_text(sym.replace(
           "00000100 t p7_f07_commit_nib_before_ready\n",""))
        must_reject(lambda: audit.verify(can,src,"p7u-f07-stock"),
                    "F07_LINKED_GUARD_SYMBOL_MISSING")
    print("G7_F07_INTEGRATION_HOST_MUTATION_GATES_PASS_NOT_FLASHABLE")

if __name__=="__main__":
    main()
