"""One new no-write ROM round-trip for failed *instrumented* V6 startup.

Not a replay of previous ROM recovery roots or a stock/firmware restore.
This source-bound follow-on requires both old no-write recovery holds and
the new exactly captured initial SYS ping failure. No automatic retry.
"""
import asyncio
import json
import os
from pathlib import Path
import time
import zlib
import p7u_v6_rom_recovery as rom
import p7u_v6_startup_capture_once as startup

V6=rom.V6_SOURCE
HOST=startup.HOST
IMAGE=startup.IMAGE
ROOT="rom-v6-instrumented-fresh-20261030"
MAX_AGE=1800


def evidence(ns,package,package_pin,write_pin,ha):
    need=ns["need"]
    meta=ns["sealed_tree"](package,"PACKAGE.json",package_pin)
    need(meta["firmware_source_sha"]==V6 and
         meta["paired_host_source_sha"]==HOST and
         meta["paired_host_image"]==IMAGE and
         ns["SOURCE"]==V6 and ns["IMAGE"]==IMAGE,
         "FRESH_ROM_EXACT_PAIR")
    from p7u_paired_hold import verified_pair_package
    writer=verified_pair_package(ns,write_pin)
    written=ns["verified_write"](writer,write_pin)
    ha.policy()
    ha.proof(False)
    current=ha.inspect()
    need(not current["running"] and current["image"]==IMAGE,
         "FRESH_ROM_OWNER_STOPPED")
    info=ha.info(ns["OWNER"])
    need(info["version"]==info["version_latest"]=="0.2.1-"+HOST[:12] and
         info["state"] in ("error","stopped") and info["boot"]=="manual" and
         info["watchdog"] is False and info["build"] is False,
         "FRESH_ROM_SUPERVISOR_HOST")
    need(ha.management()==written["management_sha256"],
         "FRESH_ROM_BOARD_IDENTITY")
    control=rom.control_source(need)
    fresh=ns["PRIVATE"]/startup.START_ROOT
    ns["private_root"](fresh)
    result=ns["load"](fresh/"result.json")
    need(result["status"]=="STARTUP_FAILED_HELD_NO_RETRY" and
         result["expected_image_seen"] is True and
         result["radio_resets"]==result["flash_writes"]==0 and
         (fresh/"start-intent.json").is_file(),
         "FRESH_ROM_EXACT_STARTUP_FAILURE")
    log=(fresh/"first-startup.log").read_bytes()
    need(b"P7U_STARTUP_TRACE" in log and b"OWNER_OPEN_FAILED" in log and
         b"P7U HOLD_EXISTING_NV: ping unavailable" in log and
         len(log)<1000000,
         "FRESH_ROM_REAL_HOST_TRACE")
    prior=ns["PRIVATE"]/"rom-recovery-v6-open-first"
    ns["private_root"](prior)
    failure=ns["load"](prior/"failure.json")
    proof=ns["load"](prior/"rom-result.json")
    boot=ns["load"](prior/"boot-ready.json")
    need(failure["status"]=="HELD_NO_AUTOMATIC_RETRY" and
         proof=={"chip_id":"0xf000","read_only":True,
                 "all88_crc_verified":True,"security_pass":True,
                 "app_written":False,"nv_written":False,"ccfg_written":False} and
         boot["fresh_reset_ind"] is True,
         "FRESH_ROM_OLD_CONSUMED_HOLD")
    # The earlier root cannot be re-executed; it is evidence for this new one.
    from p7u_v6_startup_host_config import sha256
    installed=Path("/addons/local/p7u_r4_native_host/config.yaml")
    need(ns["file_sha"](installed)==startup.CONFIG_SHA,"FRESH_ROM_STARTUP_CONFIG")
    writer_package=writer
    transition,security,_reconcile,factory,sparse,_forward,expected=ns["forward_transition"](writer_package)
    need(len(expected)==720896,"FRESH_ROM_APP_LENGTH")
    addresses=(0,0xAC000,0xAE000)
    crcs={str(a):zlib.crc32(expected[a:a+8192]) & 0xffffffff for a in addresses}
    base={"source":V6,"host":HOST,"image":IMAGE,
        "owner":current,"board_sha256":written["management_sha256"],
        "control_sha256":control,"write_pin":write_pin,
        "write_receipt_sha256":ns["file_sha"](ns["PRIVATE"]/"verified-write.json"),
        "prior_recovery_failure_sha256":ns["file_sha"](prior/"failure.json"),
        "prior_recovery_rom_sha256":ns["file_sha"](prior/"rom-result.json"),
        "new_start_failure_sha256":ns["file_sha"](fresh/"result.json"),
        "new_start_log_sha256":ns["file_sha"](fresh/"first-startup.log"),
        "config_sha256":startup.CONFIG_SHA,"crc32":crcs,
        "scope":"ONE_USB_OPEN_FIRST_ROM_READONLY_SECURITY_APP_BOOT_AND_HOST_ONCE",
        "flash_writes":0,"nv_writes":0,"ccfg_writes":0,
        "host_starts":1,"radio_boots":1,"rom_entries":1}
    deps=(transition,security,factory,sparse,expected)
    return base,writer,deps


def plan(ns,package,package_pin,write_pin,ha):
    b,_,_=evidence(ns,package,package_pin,write_pin,ha)
    root=ns["PRIVATE"]/ROOT
    ns["need"](not root.exists() and not root.is_symlink(),
               "FRESH_ROM_PREVIOUS_PLAN")
    root.mkdir(mode=0o700)
    record=dict(b,package_pin=package_pin,created_at=time.time())
    ns["durable"](root,"plan.json",record)
    return {"status":"INSTRUMENTED_ROM_PLAN_READY_NO_LIVE_EFFECTS",
            "pin":ns["sha"](ns["canonical"](record))}


def boot_and_verify_native_state9(ns,root,ha):
    """Keep sole temporary UART owner from *before* APP reset through state 9.

    A SYS_RESET_IND proves reset, not network readiness. Require the real
    B1 checks, retained IEEE/key match, non-forming startup and state9 marker
    from the existing source-qualified observer before any Z2M host start.
    """
    from p7u_r4_startup_transport import FramedZnp, PrivateEvidenceJournal
    need=ns["need"]
    port=None
    evidence=None
    try:
        port=ns["StartupSerial"]()  # USB opens BEFORE the single APP boot.
        znp=FramedZnp(port,source=V6)
        evidence=PrivateEvidenceJournal(root/"startup-evidence.jsonl",V6)
        os.chmod(root/"startup-evidence.jsonl",0o600)
        ns["durable"](root,"app-boot-intent.json",{
            "at":time.time(),"attempts":1,"usb_open_before_boot":True,
            "rom_closed":True,"consumed_before_send":True,
            "network_formation_authorized":False,
        })
        ha.restart_radio()
        deadline=time.monotonic()+20
        while True:
            typ,command,data=znp._next(deadline)
            if typ==0x41 and command==0x80:
                need(len(data)==6,"INSTRUMENTED_ROM_FRESH_RESET_IND_SHAPE")
                break
        ns["durable"](root,"boot-ready.json",{
            "fresh_reset_ind":True,"usb_open_before_boot":True,
            "external_startup_requests":0,"at":time.time()
        })
        backup=ns["load"](ns["PRIVATE"]/"owner-backup-before-stop.json")
        result=ns["resume_pristine"](
            znp,root,backup,evidence,source=V6
        )
        need(result["status"]=="COORDINATOR_STATE9_MARKER_PASS",
             "INSTRUMENTED_ROM_NATIVE_STATE9_NOT_PROVEN")
        ns["durable"](root,"state9-accepted.json",{
            "state9":True,"retained_network":True,"at":time.time(),
            "startup_result_sha256":ns["file_sha"](root/"startup-result.json"),
        })
        return result
    finally:
        if evidence is not None:
            evidence.close()
        if port is not None:
            port.close()


def execute(ns,package,package_pin,write_pin,pin,ha):
    need=ns["need"]
    root=ns["PRIVATE"]/ROOT
    ns["private_root"](root)
    need({f.name for f in root.iterdir()}=={"plan.json"},
         "INSTRUMENTED_ROM_ALREADY_CONSUMED")
    p=ns["load"](root/"plan.json")
    need(ns["sha"](ns["canonical"](p))==pin and
         p["package_pin"]==package_pin and
         0<=time.time()-p["created_at"]<MAX_AGE,
         "INSTRUMENTED_ROM_PLAN_PIN_TTL")
    actual,writer,deps=evidence(ns,package,package_pin,write_pin,ha)
    need(all(p.get(k)==v for k,v in actual.items()),
         "INSTRUMENTED_ROM_DRIFT")
    ns["durable"](root,"execute-intent.json",{
        "pin":pin,"at":time.time(),"consumed_before_send":True,
        "rom_entries":1,"radio_boots":1,"host_starts":1,
        "flash_writes":0,"nv_writes":0,"ccfg_writes":0})
    try:
        ns["_recovery_writer"]=writer
        asyncio.run(rom._rom_observe(ns,root,ha,deps,p["crc32"]))
        ha.policy();ha.proof(False)
        need(ha.management()==p["board_sha256"],"INSTRUMENTED_ROM_BOARD_CHANGED")
        state9=boot_and_verify_native_state9(ns,root,ha)
        need(state9["status"]=="COORDINATOR_STATE9_MARKER_PASS"
             and (root/"state9-accepted.json").is_file(),
             "INSTRUMENTED_ROM_STATE9_MANDATORY")
        ha.policy();ha.proof(False)
        ns["durable"](root,"host-start-intent.json",{
            "pin":pin,"at":time.time(),"consumed_before_send":True,
            "attempts":1,"external_startup_requests":0})
        ack=True
        try:ha.owner_action("start")
        except Exception:ack=False
        # Host returns only after startup; never replay an ambiguous response.
        last=ha.info(ns["OWNER"])
        try:
            raw=json.loads(ns["run"](["docker","inspect","app_"+ns["OWNER"]]))[0]
            need(raw["Image"]==IMAGE,"INSTRUMENTED_ROM_NEW_HOST_IMAGE")
            container={"id":raw["Id"][:12],"running":raw["State"]["Running"],
                       "exit_code":raw["State"]["ExitCode"]}
        except Exception:
            container={"observation":"unavailable"}
        try:log=ns["run"](["docker","logs","app_"+ns["OWNER"]],30)
        except Exception:log=b""
        ns["durable"](root,"startup.log",log)
        result={"status":"INSTRUMENTED_ROM_HOST_START_PENDING_SERVING" if
                last["state"] in ("started","startup") else
                "INSTRUMENTED_ROM_HOST_FAILED_HELD_NO_RETRY",
                "host_ack":ack,"container":container,"log_bytes":len(log),
                "native_state9":True,"radio_writes":0,"network_restore":False}
        ns["durable"](root,"result.json",result)
        return result
    except BaseException as error:
        ns["durable"](root,"failure.json",{
            "status":"INSTRUMENTED_ROM_HELD_NO_RETRY",
            "error_type":type(error).__name__,"at":time.time()})
        raise
