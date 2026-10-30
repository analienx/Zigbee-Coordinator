"""Fixed, source-bound V6 startup-capture host-only installation (STOPPED ONLY).

This does not reset, flash, start, or open the coordinator serial port.
Every effect belongs to a separate, fsynced, consumed-before-send phase;
failure requires private inspection, never an automatic replay.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time

import p7u_v6_startup_host_config as config

FW = "66ed700c2818c7a0963dad9160d55109009bbaac"
HOST = "2c2d96d6334b424f6364a982ad976a674b260e04"
OLD_IMAGE = "sha256:b79b875e32819ff9544f2844ba9573c795b9f28694218de0816f35fb00a9f78c"
NEW_IMAGE = config_image = "sha256:d00b59b26e28872e4027f2eab16800b00560876ce592fd81bae503871ec96367"
ARCHIVE_SHA = "7aeb65f86735bb63d8f9d750605b10e4baa2727f416f5da02494b674baca60f8"
OP_ROOT = "startup-capture-host-install-v1"
TAG = "localhost:50144/p7u-r4-diagnostic:" + config.NEW_VERSION
CONFIG = Path("/addons/local/p7u_r4_native_host/config.yaml")
RELEASE_ROOT = Path("/share/p7u-v6-startup-host-2c2d96d6334b")
MAX_AGE = 1800


def _run(argv, timeout=45):
    p = subprocess.run(argv, capture_output=True, timeout=timeout)
    if p.returncode != 0:
        raise ValueError("HOST_INSTALL_COMMAND_FAILED_" + argv[0].upper())
    return p.stdout


def _sha_file(file):
    with file.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def preflight(ns, package, package_pin, writer_plan_pin, ha):
    need = ns["need"]
    meta = ns["sealed_tree"](package,"PACKAGE.json",package_pin)
    need(ns["SOURCE"] == FW and
         meta["firmware_source_sha"] == FW and
         meta["paired_host_source_sha"] == HOST and
         meta["paired_host_image"] == NEW_IMAGE and
         meta["f2_wire_contract"] == "R4D4_MINOR4_R4D5_PAGED_AND_R4D6_OWNED_V1",
         "HOST_INSTALL_EXACT_PAIR")
    from p7u_paired_hold import verified_pair_package
    original = verified_pair_package(ns,writer_plan_pin)
    receipt = ns["verified_write"](original,writer_plan_pin)
    ha.policy()
    ha.proof(False)
    owner = ha.inspect()
    info = ha.info(ns["OWNER"])
    need(not owner["running"] and owner["image"] == OLD_IMAGE and
         info["version"] == config.OLD_VERSION and
         info["state"] in ("error","stopped") and
         info["watchdog"] is False and info["boot"] == "manual",
         "HOST_INSTALL_OLD_STOPPED")
    need(ha.management() == receipt["management_sha256"],"HOST_INSTALL_BOARD_CHANGED")
    approval = ns["load"](ns["DATA"]/".p7u-approved.json")
    need(approval["database_sha256"] == ns["file_sha"](ns["DATA"]/"database.db"),
         "HOST_INSTALL_DATABASE_CHANGED")
    manifest = ns["load"](RELEASE_ROOT/"RELEASE.json")
    profile = manifest["profiles"]["diagnostic"]
    need(manifest["schema"] == "p7u-host-release-v1" and
         manifest["source_sha"] == HOST and
         manifest["live_mutation"] is False and
         profile["slug"] == ns["OWNER"] and
         profile["version"] == config.NEW_VERSION and
         profile["image_id"] == NEW_IMAGE and
         profile["config_sha256"] == config.SOURCE_SHA256 and
         profile["image_archive_sha256"] == ARCHIVE_SHA,
         "HOST_INSTALL_RELEASE_MANIFEST")
    base = (RELEASE_ROOT/"config.yaml").read_bytes()
    need(config.sha256(base) == config.SOURCE_SHA256,
         "HOST_INSTALL_RELEASE_CONFIG")
    rendered = config.render(CONFIG.read_bytes(),base)
    archive = RELEASE_ROOT/"image.docker.tar"
    need(not archive.is_symlink() and
         archive.is_file() and _sha_file(archive)==ARCHIVE_SHA,
         "HOST_INSTALL_ARCHIVE_SHA")
    registry = json.loads(_run(["docker","inspect","p7u_hostfix_registry_e063f6b_v2"]))[0]
    need(registry["State"]["Running"] and
         registry["HostConfig"]["PortBindings"]["5000/tcp"] ==
         [{"HostIp":"127.0.0.1","HostPort":"50144"}],
         "HOST_INSTALL_REGISTRY_LOCAL_ONLY")
    data = {
        "firmware_source":FW,"host_source":HOST,"new_image":NEW_IMAGE,
        "old_owner":owner,"old_version":config.OLD_VERSION,
        "old_config_sha256":config.OLD_SHA256,
        "new_config_sha256":config.sha256(rendered),
        "release_sha256":ns["file_sha"](RELEASE_ROOT/"RELEASE.json"),
        "archive_sha256":ARCHIVE_SHA,"write_plan_pin":writer_plan_pin,
        "write_receipt_sha256":ns["file_sha"](ns["PRIVATE"]/"verified-write.json"),
        "database_sha256":approval["database_sha256"],
        "board_sha256":receipt["management_sha256"],
        "package_pin":package_pin,
        "scope":"PUBLISH_PREBUILT_INSTALL_STOPPED_ONLY",
        "radio_actions":0,"host_starts":0,
    }
    return data, rendered


def plan(ns, package, package_pin, writer_plan_pin, ha):
    data,_ = preflight(ns,package,package_pin,writer_plan_pin,ha)
    root=ns["PRIVATE"]/OP_ROOT
    ns["need"](not root.exists(),"HOST_INSTALL_PLAN_ALREADY_EXISTS")
    root.mkdir(mode=0o700)
    p=dict(data,created_at=time.time())
    ns["durable"](root,"plan.json",p)
    return {"status":"HOST_STARTUP_CAPTURE_INSTALL_PLAN_READY",
            "plan_pin":ns["sha"](ns["canonical"](p)),
            "no_radio_actions":True}


def _phase(ns, package, package_pin, writer_plan_pin, phase_pin, ha, phase):
    root=ns["PRIVATE"]/OP_ROOT
    ns["private_root"](root)
    need=ns["need"]
    expected={"plan.json"} if phase=="publish" else {
        "plan.json","publish-intent.json","publish-result.json"
    }
    need({p.name for p in root.iterdir()} == expected,
         "HOST_INSTALL_PHASE_ALREADY_CONSUMED")
    actual,rendered=preflight(ns,package,package_pin,writer_plan_pin,ha)
    plan=ns["load"](root/"plan.json")
    need(ns["sha"](ns["canonical"](plan))==phase_pin and
         all(plan.get(k)==v for k,v in actual.items()) and
         0<=time.time()-plan["created_at"]<MAX_AGE,
         "HOST_INSTALL_PLAN_EXPIRED_OR_DRIFTED")
    return root,plan,rendered


def publish(ns, package, package_pin, writer_plan_pin, phase_pin, ha):
    root,plan,_=_phase(ns,package,package_pin,writer_plan_pin,phase_pin,ha,"publish")
    ns["durable"](root,"publish-intent.json",
                  {"pin":phase_pin,"at":time.time(),"consumed_before_send":True,
                   "scope":"LOAD_AND_PUSH_PINNED_LOCAL_LOOPBACK_IMAGE"})
    _run(["docker","load","--input",str(RELEASE_ROOT/"image.docker.tar")],240)
    image=json.loads(_run(["docker","image","inspect",TAG]))[0]
    ns["need"](image["Id"]==NEW_IMAGE and image["Architecture"]=="arm64",
               "HOST_INSTALL_LOADED_IMAGE")
    _run(["docker","push",TAG],240)
    ns["durable"](root,"publish-result.json",
                  {"status":"PINNED_IMAGE_PUBLISHED_HOST_STOPPED","pin":phase_pin,
                   "image":NEW_IMAGE,"at":time.time()})
    return {"status":"PINNED_IMAGE_PUBLISHED_HOST_STOPPED","no_radio_actions":True}


def install_stopped(ns, package, package_pin, writer_plan_pin, phase_pin, ha):
    root,plan,rendered=_phase(ns,package,package_pin,writer_plan_pin,phase_pin,ha,"install")
    need=ns["need"]
    need(ns["load"](root/"publish-result.json")["pin"]==phase_pin,
         "HOST_INSTALL_PUBLISH_PROOF")
    # Preserve the stopped owner's private startup evidence before replacement.
    owner=plan["old_owner"]
    need(owner["started_at"] is not None,"HOST_INSTALL_OLD_LOG_EPOCH")
    logs=_run(["docker","logs","--since",owner["started_at"],
               "app_"+ns["OWNER"]],40)
    ns["durable"](root,"prior-host.log",logs)
    for name in ("database.db","coordinator_backup.json","configuration.yaml",
                 ".p7u-approved.json"):
        file=ns["DATA"]/name
        need(file.is_file() and not file.is_symlink(),"HOST_INSTALL_BACKUP_FILE")
        ns["durable"](root,"backup-"+name.lstrip(".").replace(".","-")+".bin",file.read_bytes())
    ns["durable"](root,"old-config.bin",CONFIG.read_bytes())
    ns["durable"](root,"install-intent.json",
                  {"pin":phase_pin,"at":time.time(),"consumed_before_send":True,
                   "supervisor_updates":1,"host_starts":0,"radio_actions":0})
    temp=CONFIG.with_name(".p7u-v6-startup-capture-2c2d96d6334b")
    with temp.open("xb") as f:
        os.fchmod(f.fileno(),0o600)
        f.write(rendered);f.flush();os.fsync(f.fileno())
    need(config.sha256(CONFIG.read_bytes())==config.OLD_SHA256,
         "HOST_INSTALL_CONFIG_CHANGED_BEFORE_COMMIT")
    os.replace(temp,CONFIG)
    fd=os.open(CONFIG.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    _run(["ha","store","reload"],90)
    updated=ha.info(ns["OWNER"])
    need(updated["version_latest"]==config.NEW_VERSION and
         updated["state"] in ("error","stopped"),
         "HOST_INSTALL_STORE_METADATA")
    ns["durable"](root,"supervisor-update-intent.json",
                  {"pin":phase_pin,"at":time.time(),"consumed_before_send":True,
                   "attempts":1,"host_starts":0})
    # One mutation only. If CLI returns ambiguously, inspect, never replay.
    try:_run(["ha","apps","update",ns["OWNER"]],180)
    except Exception:pass
    info=ha.info(ns["OWNER"])
    owner=ha.inspect()
    need(info["version"]==config.NEW_VERSION and
         info["state"] in ("error","stopped") and
         not owner["running"] and owner["image"]==NEW_IMAGE and
         config.sha256(CONFIG.read_bytes())==plan["new_config_sha256"],
         "HOST_INSTALL_UPDATE_UNPROVEN_NO_RETRY")
    ha.proof(False)
    # Installation must actually activate the new opt-in, not merely update
    # a config file or Supervisor version label.
    code = ("import json; e=json.load(open('/data/apps.json'))"
            "['system']['local_p7u_r4_native_host']['environment'];"
            " print(json.dumps({k:e.get(k) for k in "
            "['P7U_B4_COLLECTOR','P7U_B4_FLIGHT_V5',"
            "'P7U_B4_STAGE_V6','P7U_B4_STARTUP_CAPTURE']}))")
    env=json.loads(_run(["docker","exec","hassio_supervisor","python3","-c",code]))
    need(env=={"P7U_B4_COLLECTOR":"1","P7U_B4_FLIGHT_V5":"1",
               "P7U_B4_STAGE_V6":"1","P7U_B4_STARTUP_CAPTURE":"1"},
         "HOST_INSTALL_CAPTURE_NOT_ACTIVE")
    result={"status":"STARTUP_CAPTURE_HOST_INSTALLED_STOPPED",
            "host_source":HOST,"image":NEW_IMAGE,
            "config_sha256":plan["new_config_sha256"],
            "radio_actions":0,"host_starts":0}
    ns["durable"](root,"install-result.json",result)
    return result
