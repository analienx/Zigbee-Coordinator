"""Persistent independent HA watchdog. DRY RUN by default. Never opens ZNP.

Single owner + no automatic retry after ambiguous side effect. Operates through
Supervisor/API and SMLIGHT existing control plane only. All runtime evidence
is sanitized, private, and bounded. No network action when options disabled.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError

from policy import State, Observation, evaluate
from executor import dispatch
from ha_adapter import SupervisorClient, SmlightControl, Configuration, HAActuator
from observer import PassiveObserver, start_failure_kind

DATA = Path("/data")
Z2M_ADDON = "45df7312_zigbee2mqtt"
POLL_SECONDS = 20


def atomic_json(path: Path, obj: dict):
    p = path.with_name(path.name + ".new")
    with p.open("x", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True, separators=(",", ":"))
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    p.replace(path)
    directory = os.open(str(path.parent), os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def load_options() -> dict:
    obj = json.loads((DATA / "options.json").read_text())
    expected = ("enabled", "dry_run", "maintenance",
                "slzb_url", "allow_private_http_fallback")
    if not all(k in obj for k in expected):
        raise RuntimeError("INVALID_ADDON_OPTIONS")
    return obj


def load_state(path: Path) -> tuple[State, dict]:
    if not path.exists():
        return State(), {}
    data = json.loads(path.read_text())
    if data.get("schema") != "p7u-recovery-state-v1":
        raise RuntimeError("INCOMPATIBLE_WATCHDOG_STATE")
    # Fields are intentionally strictly selected; never deserialize arbitrary
    # objects or execute state-file contents.
    fields = State.__dataclass_fields__
    state = State(**{k:v for k,v in data["state"].items() if k in fields})
    return state, dict(data.get("receipts") or {})


def save_state(path: Path, state: State, receipts: dict):
    atomic_json(path, {"schema":"p7u-recovery-state-v1",
                       "state":asdict(state), "receipts":receipts})


def handle_action(observer, evidence_dir):
    def capture():
        data = observer.sample()
        receipt = {"schema": "p7u-recovery-evidence-v1",
                   "recorded_utc":datetime.now(timezone.utc).isoformat(),
                   "mq_connected":data.get("mqtt_reachable"),
                   "fresh_topic_count":data.get("fresh_device_topics_120s"),
                   "srsp_count":data.get("srsp_120s"),
                   "distinct_failed_devices":data.get("affected_devices_120s"),
                   "epoch_start_utc":data.get("epoch_start_utc")}
        stamp = int(time.time())
        path = evidence_dir / f"evidence-{stamp}.json"
        # A stable marker exists before returning ACK; no sensitive packets.
        with path.open("x", encoding="utf-8") as f:
            json.dump(receipt,f)
            f.flush();os.fsync(f.fileno())
        return True
    return capture


def service_main():
    opts = load_options()
    supervisor = SupervisorClient(os.environ.get("SUPERVISOR_TOKEN", ""))
    cfg = Configuration(
        slzb_url=opts.get("slzb_url", "http://192.168.50.59"),
        addon_slug=Z2M_ADDON,
        esp_restart_entity=opts.get("esp_restart_entity", ""),
        zigbee_restart_entity=opts.get("zigbee_restart_entity", ""),
        allow_private_http_fallback=bool(opts["allow_private_http_fallback"]),
    )
    slzb = SmlightControl(cfg)
    observer = PassiveObserver()
    evidence_dir = DATA / "evidence"
    evidence_dir.mkdir(exist_ok=True, mode=0o700)
    journal_path = DATA / "watchdog-state.json"

    # Supervisor service discovery; the MQTT credentials never reach stdout.
    broker = supervisor.call("/services/mqtt")
    if not isinstance(broker,dict) or broker.get("result") != "ok":
        raise RuntimeError("MQTT_SERVICE_NOT_DISCOVERED")
    data = broker.get("data", {})
    observer.start(data.get("host", ""), int(data.get("port",1883)),
                   data.get("username", ""), data.get("password", ""))
    actor = HAActuator(cfg, supervisor, slzb,
                       handle_action(observer, evidence_dir))
    state, receipts = load_state(journal_path)
    active = bool(opts["enabled"]) and not bool(opts["dry_run"])
    print("P7U_WATCHDOG_STARTED",
          "MODE="+("ENABLED" if active else "DRY_RUN"),
          "FIRST=ESP32",flush=True)
    if active and state.phase not in ("MONITOR","SUSPECT","COMPLETE","HOLD"):
        print("RECOVERY_PENDING_AFTER_HOST_RESTART_NO_REPLAY",state.phase,flush=True)

    try:
        while True:
            now = int(time.time())
            try:
                addon = supervisor.addon_state(cfg.addon_slug)
                logs = supervisor.log_text(cfg.addon_slug)
                observer.read_log(logs, now)
                telem = observer.sample(now)
                hardware = supervisor.hardware_has_port(cfg.expected_by_id)
                try:
                    slzb.identity()
                    identity = True
                except Exception:
                    identity = False
                # Observe maintenance flags from *configuration* first,
                # not a guessed dynamic OTA packet that could allow a flash.
                blocked = bool(opts["maintenance"])
                ota = any(
                    text in logs[-30000:].lower()
                    for text in ("ota update started", "starting ota update",
                                 "updating firmware of"))
                error = start_failure_kind(logs, now) if addon in ("error","stopped") else ""
                # For running errors, require errors from live app epoch;
                # retained errors from before the latest startup are ignored
                # by timestamp expiry inside observer.
                o = Observation(
                    utc=now, addon=addon, adapter_error=error,
                    mode="USB", expected_identity=identity,
                    expected_usb=hardware, esp_reachable=identity,
                    ha_reachable=True, mqtt_reachable=telem["mqtt_reachable"],
                    maintenance=blocked, ota_active=ota,
                    firmware_flash_active=False,
                    serial_owner_exclusive=True,
                    app_uptime_s=telem["app_uptime_s"],
                    srsp_120s=telem["srsp_120s"],
                    affected_devices_120s=telem["affected_devices_120s"],
                    fresh_device_topics_120s=telem["fresh_device_topics_120s"],
                    health_fresh=telem["health_fresh"],
                    bridge_online_fresh=telem["bridge_online_fresh"],
                    herdsman_started_fresh=telem["herdsman_started_fresh"],
                    saved_evidence=bool(receipts.get("CAPTURE_EVIDENCE")),
                    stopped_receipt=bool(receipts.get("STOP_Z2M")),
                    radio_reset_ack=bool(receipts.get("RESET_RADIO")),
                    esp_restart_ack=bool(receipts.get("RESTART_ESP")),
                    z2m_start_ack=bool(receipts.get("START_Z2M") or
                                       receipts.get("START_Z2M_RADIO")),
                )
                decision = evaluate(o, state)
                if not active:
                    # DRY RUN must not lock an actual recovery incident, and
                    # cannot call the HA actuator. We still inspect the full
                    # source policy and record sanitized health transitions.
                    if decision.action not in ("NONE",):
                        print("DRY_RUN_PROPOSAL", decision.action,
                              decision.reason, flush=True)
                    state = State(last_sample_utc=now,
                                  recovery_attempts_24h=state.recovery_attempts_24h,
                                  last_recovery_utc=state.last_recovery_utc)
                    save_state(journal_path,state,{})
                else:
                    # Durable decision state first. Every side effect gets
                    # a distinct exclusive write-ahead journal in executor.
                    save_state(journal_path,decision.state,receipts)
                    state = decision.state
                    if decision.action in (
                        "CAPTURE_EVIDENCE","STOP_Z2M","RESTART_ESP",
                        "RESET_RADIO","START_Z2M"
                    ):
                        if decision.action == "START_Z2M":
                            ack_key = ("START_Z2M_RADIO" if
                                       state.phase=="RADIO_START_PENDING" else "START_Z2M")
                        else:
                            ack_key = decision.action
                        report = dispatch(decision,o,actor,evidence_dir,enabled=True)
                        if report.status == "COMMAND_ACCEPTED_NOT_YET_VERIFIED":
                            receipts[ack_key] = True
                            save_state(journal_path,state,receipts)
                        else:
                            print("HOLD_AMBIGUOUS_ACTION",
                                  report.status,report.detail,flush=True)
                            state = State(**{**asdict(state),"phase":"HOLD",
                                            "reason":"AMBIGUOUS_ACTION"})
                            save_state(journal_path,state,receipts)
                    elif decision.action in ("ALERT_HUMAN","RECOVERY_SUCCEEDED"):
                        print(decision.action,decision.reason,flush=True)
                        if decision.action=="RECOVERY_SUCCEEDED":
                            receipts = {}
                            save_state(journal_path,state,receipts)
                # Rate-limit normal log output: no raw MQTT payloads or names.
                if now % 180 < POLL_SECONDS:
                    print("SAMPLE", "addon="+addon,
                          "fresh_topics="+str(telem["fresh_device_topics_120s"]),
                          "srsp="+str(telem["srsp_120s"]),
                          "phase="+state.phase,flush=True)
            except (HTTPError,URLError,TimeoutError,ValueError,RuntimeError) as exc:
                print("PASSIVE_POLL_UNAVAILABLE_NO_RESET",
                      type(exc).__name__,flush=True)
                # Fail closed. Don't advance phases or reset on an unknown
                # supervisor, bridge or broker state.
            time.sleep(POLL_SECONDS)
    finally:
        observer.close()


if __name__=="__main__":
    with (DATA/"p7u-watcher-owner.lock").open("a+") as f:
        try: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise SystemExit("SECOND_RECOVERY_OWNER_FORBIDDEN")
        service_main()
