"""One guarded, diagnostic-first startup of the *installed* V6 capture host.

No radio reset, BSL, second serial owner, firmware write or retry. The source-
qualified Supervisor start recreates the old stopped container from the new
verified image. Logs remain in the private operation directory.
"""
import json
from pathlib import Path
import time

V6="66ed700c2818c7a0963dad9160d55109009bbaac"
HOST="2c2d96d6334b424f6364a982ad976a674b260e04"
IMAGE="sha256:d00b59b26e28872e4027f2eab16800b00560876ce592fd81bae503871ec96367"
OLD="sha256:b79b875e32819ff9544f2844ba9573c795b9f28694218de0816f35fb00a9f78c"
CONFIG_SHA="905f680661419765dfe72ff7625ca79b2b9ff3e7de67728c490a459efa38ad3b"
PACKAGE_PUBLISH="b9a876e1fd34539e45bba88684bb9d7266cd48d0d3795c24f0e191a7311127b4"
PUBLISHED_ROOT="startup-capture-host-install-v1"
INSTALL_ROOT="startup-capture-host-install-v1-continuation"
START_ROOT="startup-capture-first-start-v1"
MAX_PLAN_AGE=1800
OLD_CONTAINER="5667f59fea984ea44812d7c9da19947e45f03c231af31158c73ba613c88318cb"
EXPECTED_ENV={"P7U_B4_COLLECTOR":"1","P7U_B4_FLIGHT_V5":"1",
              "P7U_B4_STAGE_V6":"1","P7U_B4_STARTUP_CAPTURE":"1"}


def _get_current(ns,ha):
    need=ns["need"]
    need(ns["SOURCE"]==V6 and ns["IMAGE"]==IMAGE and
         ns["PAIRED_HOST_VERSION"]=="0.2.1-"+HOST[:12],
         "START_CAPTURE_EXACT_PAIR")
    ha.policy()
    ha.proof(False)
    old=ha.inspect()
    need(old["id"]==OLD_CONTAINER and old["image"]==OLD and
         old["running"] is False,"START_CAPTURE_OLD_STOPPED_OWNER")
    a=ha.info(ns["OWNER"])
    need(a["version"]==a["version_latest"]=="0.2.1-"+HOST[:12] and
         a["state"] in ("error","stopped") and not a["build"] and
         a["boot"]=="manual" and a["watchdog"] is False and a["auto_update"] is False,
         "START_CAPTURE_SUPERVISOR_VERSION")
    config=Path("/addons/local/p7u_r4_native_host/config.yaml")
    need(ns["file_sha"](config)==CONFIG_SHA,"START_CAPTURE_CONFIG")
    source=Path("/share/p7u-v6-startup-host-2c2d96d6334b")
    release=ns["load"](source/"RELEASE.json")
    need(release["source_sha"]==HOST and
         release["profiles"]["diagnostic"]["image_id"]==IMAGE,
         "START_CAPTURE_RELEASE")
    image=json.loads(ns["run"](["docker","image","inspect",
       "localhost:50144/p7u-r4-diagnostic:0.2.1-"+HOST[:12]]))[0]
    need(image["Id"]==IMAGE and image["Architecture"]=="arm64",
         "START_CAPTURE_PINNED_IMAGE")
    env_code=("import json; e=json.load(open('/data/apps.json'))"
       "['system']['local_p7u_r4_native_host']['environment'];"
       " print(json.dumps({k:e.get(k) for k in "
       "['P7U_B4_COLLECTOR','P7U_B4_FLIGHT_V5',"
       "'P7U_B4_STAGE_V6','P7U_B4_STARTUP_CAPTURE']}))")
    env=json.loads(ns["run"](["docker","exec","hassio_supervisor",
                               "python3","-c",env_code]))
    need(env==EXPECTED_ENV,"START_CAPTURE_ACTUAL_ENV")
    from p7u_paired_hold import verified_pair_package
    writer=verified_pair_package(ns,ns["_write_plan_pin"])
    write=ns["verified_write"](writer,ns["_write_plan_pin"])
    need(ha.management()==write["management_sha256"],"START_CAPTURE_BOARD")
    install=ns["PRIVATE"]/INSTALL_ROOT
    publish=ns["PRIVATE"]/PUBLISHED_ROOT
    ns["private_root"](install)
    ns["private_root"](publish)
    need({p.name for p in install.iterdir()}=={
        "continuation-intent.json","prior-host.log",
        "backup-configuration-yaml.bin","backup-coordinator-backup-json.bin",
        "backup-database-db.bin","backup-p7u-approved-json.bin",
        "old-config.bin","install-intent.json","supervisor-update-intent.json"
    },"START_CAPTURE_CONSUMED_INSTALL_SHAPE")
    original=ns["load"](publish/"plan.json")
    need(original.get("package_pin")==PACKAGE_PUBLISH and
         original["new_image"]==IMAGE and
         ns["load"](publish/"publish-result.json")["pin"]==
         ns["sha"](ns["canonical"](original)),
         "START_CAPTURE_PUBLISH_PROVENANCE")
    # Immutable pre-start database: no silent Zigbee database changes.
    db=ns["DATA"]/"database.db"
    need(ns["file_sha"](db)==ns["file_sha"](
         install/"backup-database-db.bin"),"START_CAPTURE_DATABASE_DRIFT")
    return {
        "source":V6,"host":HOST,"image":IMAGE,"old_container":OLD_CONTAINER,
        "old_image":OLD,"installed_config_sha256":CONFIG_SHA,
        "release_sha256":ns["file_sha"](source/"RELEASE.json"),
        "prior_publish_sha256":ns["file_sha"](publish/"publish-result.json"),
        "prior_install_intent_sha256":ns["file_sha"](install/"install-intent.json"),
        "prior_update_intent_sha256":ns["file_sha"](install/"supervisor-update-intent.json"),
        "database_sha256":ns["file_sha"](db),
        "write_plan_sha256":ns["_write_plan_pin"],
        "write_receipt_sha256":ns["file_sha"](ns["PRIVATE"]/"verified-write.json"),
        "scope":"ONE_SUPERVISOR_START_NO_RADIO_RESET_CAPTURE_PRIVATE_LOGS",
        "radio_resets":0,"flash_writes":0,"nv_writes":0,"host_start_attempts":1
    }


def plan(ns,package,package_pin,write_pin,ha):
    ns["sealed_tree"](package,"PACKAGE.json",package_pin)
    ns["_write_plan_pin"]=write_pin
    data=_get_current(ns,ha)
    root=ns["PRIVATE"]/START_ROOT
    ns["need"](not root.exists() and not root.is_symlink(),
               "START_CAPTURE_ALREADY_PLANNED")
    root.mkdir(mode=0o700)
    record=dict(data,created_at=time.time(),package_pin=package_pin)
    ns["durable"](root,"plan.json",record)
    return {"status":"START_CAPTURE_ONE_SHOT_PLAN_READY",
            "pin":ns["sha"](ns["canonical"](record)),
            "no_live_effects":True}


def execute(ns,package,package_pin,write_pin,pin,ha):
    ns["sealed_tree"](package,"PACKAGE.json",package_pin)
    ns["_write_plan_pin"]=write_pin
    root=ns["PRIVATE"]/START_ROOT
    ns["private_root"](root)
    need=ns["need"]
    need({p.name for p in root.iterdir()}=={"plan.json"},
         "START_CAPTURE_ACTION_ALREADY_CONSUMED")
    saved=ns["load"](root/"plan.json")
    need(ns["sha"](ns["canonical"](saved))==pin and
         saved["package_pin"]==package_pin and
         0<=time.time()-saved["created_at"]<MAX_PLAN_AGE,
         "START_CAPTURE_PLAN_PIN_OR_TTL")
    actual=_get_current(ns,ha)
    need(all(saved.get(k)==v for k,v in actual.items()),
         "START_CAPTURE_PRESTART_DRIFT")
    ns["durable"](root,"start-intent.json",{
        "pin":pin,"attempts":1,"consumed_before_send":True,"at":time.time(),
        "radio_resets":0,"nv_writes":0,"external_startup_requests":0,
        "supervisor_owner_starts":1
    })
    start_ack=False
    try:
        ha.owner_action("start")
        start_ack=True
    except Exception:
        # Ambiguous acknowledgements are never retried.
        pass
    # Wait through the normal 60-second stateChangeInd timeout, plus margin.
    deadline=time.monotonic()+95
    image_seen=False
    running_seen=False
    last=None
    while time.monotonic()<deadline:
        try:
            raw=json.loads(ns["run"](["docker","inspect","app_"+ns["OWNER"]]))[0]
            image=raw["Image"]
            need(image==IMAGE,"START_CAPTURE_UNEXPECTED_CONTAINER_IMAGE")
            image_seen=True
            last={"container":raw["Id"][:12],"running":raw["State"]["Running"],
                  "exit_code":raw["State"]["ExitCode"]}
            if raw["State"]["Running"]:running_seen=True
            if running_seen and not raw["State"]["Running"]:break
        except Exception:
            # The old stopped container can be briefly removed while Supervisor
            # creates the new one. This is a read-only inspection, not a retry.
            pass
        time.sleep(1.0)
    logs=b""
    try:
        logs=ns["run"](["docker","logs","app_"+ns["OWNER"]],30)
    except Exception:
        pass
    ns["durable"](root,"first-startup.log",logs)
    result={"status":"STARTUP_OBSERVED_PENDING_SERVING" if running_seen and
            last is not None and last["running"] else "STARTUP_FAILED_HELD_NO_RETRY",
            "host_start_ack":start_ack,"expected_image_seen":image_seen,
            "running_seen":running_seen,"last":last,"log_bytes":len(logs),
            "logs_private":True,"radio_resets":0,"flash_writes":0}
    ns["durable"](root,"result.json",result)
    return result
