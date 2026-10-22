"""Independent P7U recovery guard. No serial owner; reset execution defaults off."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from contextlib import ExitStack
import itertools
import json
import os
import re
from pathlib import Path
import time
import uuid

from policy import State, Observation, evaluate
from executor import dispatch, accepted_receipt
from persistence import atomic_json, load_ledger, save_ledger, reconcile_pending
from ha_adapter import (SupervisorClient, SmlightControl, Configuration, HAActuator,
                        verify_native_binding)
from observer import PassiveObserver
from alerts import HAIncidentReporter
from forensics import PassiveForensics

DATA = Path("/data")
CONFIG = Path("/homeassistant/zigbee2mqtt/configuration.yaml")
Z2M_ADDON = "45df7312_zigbee2mqtt"
POLL_SECONDS = 20
ACTIONS = frozenset(("CAPTURE_EVIDENCE", "STOP_Z2M", "RESTART_ESP",
                     "RESET_RADIO", "START_Z2M"))


def load_options(path: Path | None = None) -> dict:
    obj = json.loads((path or DATA / "options.json").read_text())
    for key in ("enabled", "dry_run", "maintenance", "allow_private_http_fallback"):
        if type(obj.get(key)) is not bool:
            raise ValueError("INVALID_ADDON_BOOLEAN_OPTION")
    for key in ("notify_on_confirmed_hang", "firmware_flash_active", "serial_owner_approved"):
        if type(obj.get(key, False)) is not bool:
            raise ValueError("INVALID_ADDON_BOOLEAN_OPTION")
    return obj


def configuration(opts: dict) -> Configuration:
    return Configuration(
        slzb_url=opts.get("slzb_url", "http://192.168.50.59"), addon_slug=Z2M_ADDON,
        esp_restart_entity=opts.get("esp_restart_entity", ""),
        zigbee_restart_entity=opts.get("zigbee_restart_entity", ""),
        allow_private_http_fallback=opts["allow_private_http_fallback"],
        expected_mac=opts.get("expected_mac", ""),
        expected_sw_version=opts.get("expected_sw_version", "v3.4.3.dev1"),
        expected_js_sha256=opts.get("expected_js_sha256", ""),
    )


def owner_configuration_valid(info: dict, cfg: Configuration) -> bool:
    options = info.get("options") or {}
    serial = options.get("serial") or {}
    return bool(serial.get("port") == "/dev/serial/by-id/" + cfg.expected_by_id
        and serial.get("adapter") == "zstack" and serial.get("baudrate") == 115200
        and serial.get("rtscts") is False
        and (options.get("socat") or {}).get("enabled") is False
        and info.get("watchdog") is False)


def active_admission(opts: dict, cfg: Configuration) -> bool:
    return bool(opts["enabled"] and not opts["dry_run"]
        and opts.get("serial_owner_approved") is True
        and opts.get("notify_on_confirmed_hang") is True
        and cfg.expected_mac and cfg.expected_sw_version
        and ((cfg.esp_restart_entity and cfg.zigbee_restart_entity)
             or (cfg.allow_private_http_fallback and cfg.expected_js_sha256)))


def verify_controls(cfg, supervisor):
    """Read-only admission of BOTH controls before quiescing the live owner."""
    need_private = False
    for action, entity in (("RESTART_ESP", cfg.esp_restart_entity),
                           ("RESET_RADIO", cfg.zigbee_restart_entity)):
        if entity:
            verify_native_binding(cfg, action, entity)
            supervisor.button_available(entity)
        elif cfg.allow_private_http_fallback:
            need_private = True
        else:
            raise RuntimeError("BOTH_RECOVERY_CONTROLS_REQUIRED")
    if need_private:
        SmlightControl(cfg).verify_private_control()


def action_receipts(state: State, receipts: dict) -> dict:
    """Acknowledge only this exact incident and original action phase."""
    return {
        "saved_evidence": accepted_receipt(receipts, state, "CAPTURE_EVIDENCE", "CAPTURE_PENDING"),
        "stopped_receipt": accepted_receipt(receipts, state, "STOP_Z2M", "STOP_PENDING"),
        "esp_restart_ack": accepted_receipt(receipts, state, "RESTART_ESP", "ESP_RESET_PENDING"),
        "radio_reset_ack": accepted_receipt(receipts, state, "RESET_RADIO", "RADIO_RESET_PENDING"),
        "z2m_start_ack": accepted_receipt(receipts, state, "START_Z2M",
            "RADIO_START_PENDING" if state.phase.startswith("RADIO_") else "ESP_START_PENDING"),
    }


class GuardRunner:
    """Testable runner boundary; shadow decisions cannot reach the actuator."""
    def __init__(self, data: Path, actor, reporter, observer, pre_action=None, passive=None):
        self.data, self.actor, self.reporter, self.observer = data, actor, reporter, observer
        self.pre_action = pre_action
        self.passive = passive
        self.evidence = data / "evidence"
        self.evidence.mkdir(mode=0o700, exist_ok=True)
        self.real_path, self.shadow_path = data / "watchdog-state.json", data / "dry-run-state.json"
        self.state, self.receipts = load_ledger(self.real_path)
        self.state = reconcile_pending(self.state, self.receipts, self.evidence)
        save_ledger(self.real_path, self.state, self.receipts)
        self.shadow, _ = load_ledger(self.shadow_path)

    def _report(self, state, notify):
        if not notify or not state.incident_since:
            return
        kind = ("RECOVERY_FAILED" if state.phase == "HOLD" else
                "OBSERVED_RECOVERED" if state.phase == "COMPLETE"
                    and state.reason == "PASSIVE_OBSERVED_RECOVERED" else
                "RECOVERED" if state.phase == "COMPLETE" else "DETECTED")
        print("RECOVERY_NOTIFICATION", kind,
              self.reporter.report(kind, state.incident_since, state.reason), flush=True)

    def hold(self, reason: str, notify: bool):
        self.state = replace(self.state, phase="HOLD", stable_since=0, reason=reason)
        save_ledger(self.real_path, self.state, self.receipts)
        self._report(self.state, notify)

    def step(self, observation: Observation, *, active=False, notify=False):
        if self.state.phase == "HOLD":
            self._report(self.state, notify)
        if not active:
            # Warning-only incidents are durable and have no physical actions.
            # Require real continuous receive evidence before marking recovery.
            if self.shadow.phase == "COMPLETE":
                self._report(self.shadow, notify)
                self.shadow = State(
                    recovery_attempts_24h=self.state.recovery_attempts_24h,
                    last_recovery_utc=self.state.last_recovery_utc)
            if self.shadow.phase == "CAPTURE_PENDING":
                if notify and self.passive:
                    try:
                        self.passive.incident(self.shadow, observation)
                    except Exception as exc:
                        # Intent may already be durable. Never retry as a new
                        # incident or invent a physical capture receipt.
                        print("PASSIVE_EVIDENCE_NOT_CONFIRMED",type(exc).__name__,flush=True)
                healthy = bool(
                    observation.addon == "started"
                    and observation.rx_valid and observation.observation_valid
                    and observation.health_fresh and observation.mqtt_reachable
                    and observation.expected_identity and observation.expected_usb
                    and observation.srsp_120s == 0
                    and observation.fresh_device_topics_120s >= 3)
                contiguous = (0 <= observation.utc - self.shadow.last_sample_utc <= 60)
                since = (self.shadow.stable_since if healthy and contiguous
                         and self.shadow.stable_since else
                         observation.utc if healthy else 0)
                self.shadow = replace(self.shadow, stable_since=since,
                                      last_sample_utc=observation.utc)
                if healthy and since and observation.utc - since >= 120:
                    self.shadow = replace(self.shadow, phase="COMPLETE",
                                          reason="PASSIVE_OBSERVED_RECOVERED")
                    save_ledger(self.shadow_path, self.shadow, {})
                    self._report(self.shadow, notify)
                else:
                    self._report(self.shadow, notify)
            else:
                if self.shadow.phase == "HOLD" and not self.shadow.incident_id:
                    self.shadow = State()
                decision = evaluate(observation, self.shadow)
                self.shadow = decision.state
                if decision.action == "CAPTURE_EVIDENCE":
                    self.shadow = replace(self.shadow, incident_id=uuid.uuid4().hex,
                                          reason=decision.reason, stable_since=0)
                    print("DRY_RUN_WOULD_RECOVER", decision.reason, flush=True)
                    save_ledger(self.shadow_path, self.shadow, {})
                    # Capture also occurs after restart from CAPTURE_PENDING.
                    if notify and self.passive:
                        try:
                            self.passive.incident(self.shadow, observation)
                        except Exception as exc:
                            print("PASSIVE_EVIDENCE_NOT_CONFIRMED",type(exc).__name__,flush=True)
                    self._report(self.shadow, notify)
            save_ledger(self.shadow_path, self.shadow, {})
            return self.shadow

        observation = replace(observation, **action_receipts(self.state, self.receipts))
        decision = evaluate(observation, self.state)
        previous = self.state
        self.state = decision.state
        if decision.action == "CAPTURE_EVIDENCE":
            self.state = replace(self.state, incident_id=uuid.uuid4().hex, reason=decision.reason)
            decision = replace(decision, state=self.state)
        save_ledger(self.real_path, self.state, self.receipts)
        if self.state.phase == "HOLD":
            self._report(self.state, notify)
            return self.state
        if decision.action == "CAPTURE_EVIDENCE":
            self._report(self.state, notify)
        if decision.action in ACTIONS:
            try:
                fresh = self.pre_action(self.state) if self.pre_action else observation
                fresh = replace(fresh, utc=observation.utc,
                                **action_receipts(self.state, self.receipts))
                if decision.action == "START_Z2M":
                    self.observer.begin_startup(observation.utc)
                report = dispatch(decision, fresh, self.actor, self.evidence, enabled=True)
                if report.outcome:
                    self.receipts[report.action_key] = report.outcome
                save_ledger(self.real_path, self.state, self.receipts)
                if report.status != "COMMAND_ACCEPTED_NOT_YET_VERIFIED":
                    self.hold("AMBIGUOUS_ACTION", notify)
            except Exception:
                self.hold("ACTION_ADMISSION_OR_JOURNAL_FAILURE", notify)
        elif decision.action == "RECOVERY_SUCCEEDED":
            self._report(self.state, notify)
        elif previous.phase == "COMPLETE" and self.state.phase == "MONITOR":
            self.receipts = {}
            save_ledger(self.real_path, self.state, self.receipts)
        return self.state


def capture_callback(observer, evidence_dir):
    def capture():
        sample = observer.sample()
        keys = ("mqtt_reachable", "rx_valid", "observation_valid", "epoch_id",
                "fresh_device_topics_120s", "srsp_120s", "affected_devices_120s",
                "epoch_start_utc", "ota_active", "ota_unknown")
        atomic_json(evidence_dir / ("evidence-" + uuid.uuid4().hex + ".json"), {
            "schema": "p7u-recovery-evidence-v2",
            "recorded_utc": datetime.now(timezone.utc).isoformat(),
            **{k: sample.get(k) for k in keys}})
        return True
    return capture


def seed_history(observer, prefix, now):
    """Replay matching current logs transiently without exporting packet payloads."""
    observer.seed_process_epoch(prefix, now)
    from observer import timestamp
    starts = [timestamp(line) for line in prefix.splitlines()
              if "Starting Zigbee2MQTT version" in line]
    start = next((t for t in starts if t is not None), None)
    if start is None:
        return False
    root = CONFIG.parent / "log"
    folder = datetime.fromtimestamp(start, timezone.utc).astimezone().strftime("%Y-%m-%d.%H-%M-%S")
    candidates = [root / folder / "log.log"] + sorted(root.glob("*/log.log"), reverse=True)[:8]
    for path in dict.fromkeys(candidates):
        if not path.is_file():
            continue
        segments, markers, total = [], [], 0
        for segment in path.parent.iterdir():
            if not segment.is_file() or not re.fullmatch(r"log\d*\.log", segment.name):
                continue
            total += segment.stat().st_size
            if total > 512 * 1024 * 1024 or len(segments) >= 100:
                raise RuntimeError("CURRENT_LOG_HISTORY_TOO_LARGE")
            with segment.open(encoding="utf-8", errors="replace") as stream:
                beginning = [stream.readline() for _ in range(40)]
            times = [timestamp(line) for line in beginning if timestamp(line) is not None]
            markers.extend(timestamp(line) for line in beginning
                           if "Starting Zigbee2MQTT version" in line)
            if times:
                segments.append((min(times), segment))
        if start not in markers:
            continue
        # Z2M rotates log.log into log1.log, log2.log, etc. Numeric names
        # do not establish chronological order; use original record time.
        with ExitStack() as opened:
            streams = [opened.enter_context(segment.open(encoding="utf-8", errors="replace"))
                       for _, segment in sorted(segments)]
            observer.seed_process_history(itertools.chain.from_iterable(streams), now)
        return True
    return False


def service_main():
    opts = load_options()
    cfg = configuration(opts)
    supervisor = SupervisorClient(os.environ.get("SUPERVISOR_TOKEN", ""))
    from mqtt_settings import load_broker_settings
    broker = load_broker_settings(CONFIG)
    observer = PassiveObserver(broker.base_topic, last_seen_epoch=broker.last_seen_epoch)
    observer.start(broker.host, broker.port, broker.username, broker.password)
    evidence_dir = DATA / "evidence"
    evidence_dir.mkdir(mode=0o700, exist_ok=True)
    reporter = HAIncidentReporter(supervisor, evidence_dir)
    actor = HAActuator(cfg, supervisor, SmlightControl(cfg), capture_callback(observer, evidence_dir))

    def observe(*, refresh_logs=True):
        current = load_options()
        if configuration(current) != cfg:
            raise RuntimeError("CONTROL_BINDING_CHANGED_RESTART_GUARD_REQUIRED")
        info = supervisor.addon_info(cfg.addon_slug)
        if refresh_logs:
            prefix, tail = supervisor.log_window(cfg.addon_slug)
            observer.seed_process_epoch(prefix, time.time())
            before = observer.sample()
            epoch = before.get("epoch_id")
            if (getattr(observe, "history_epoch", None) != epoch
                or before.get("log_gap") or before.get("ota_unknown")):
                if seed_history(observer, prefix, time.time()):
                    observe.history_epoch = epoch
            observer.read_log(tail, time.time())
        if load_broker_settings(CONFIG) != broker:
            raise RuntimeError("BROKER_OR_RECEIVE_CONFIGURATION_CHANGED_RESTART_GUARD_REQUIRED")
        sample = observer.sample()
        identity = False
        try:
            SmlightControl(cfg).identity()
            identity = True
        except Exception:
            pass
        return Observation(
            utc=int(time.time()), addon=str(info.get("state", "unknown")),
            adapter_error=sample.get("adapter_error", ""), mode="USB",
            expected_identity=identity,
            expected_usb=supervisor.hardware_has_port(cfg.expected_by_id),
            esp_reachable=identity, ha_reachable=True,
            mqtt_reachable=sample["mqtt_reachable"], maintenance=current["maintenance"],
            ota_active=sample.get("ota_active", True) or sample.get("ota_unknown", True),
            firmware_flash_active=current.get("firmware_flash_active", False),
            serial_owner_exclusive=owner_configuration_valid(info, cfg),
            observation_valid=sample.get("observation_valid", False),
            rx_valid=sample.get("rx_valid", False),
            **{key: sample[key] for key in (
                "app_uptime_s", "srsp_120s", "affected_devices_120s",
                "fresh_device_topics_120s", "health_fresh", "bridge_online_fresh",
                "herdsman_started_fresh")}), current, sample

    def pre_action(state):
        fresh, current, _ = observe(refresh_logs=False)
        if not active_admission(current, cfg):
            raise RuntimeError("ACTIVE_RECOVERY_ADMISSION_REVOKED")
        verify_controls(cfg, supervisor)
        return fresh

    passive = PassiveForensics(DATA, supervisor, cfg.addon_slug)
    runner = GuardRunner(DATA, actor, reporter, observer, pre_action, passive)
    print("P7U_WATCHDOG_STARTED VERSION=0.2.2 FIRST=ESP32 RESETS_DEFAULT_OFF", flush=True)
    previous_clock = None
    poll_number = 0
    try:
        while True:
            notify = False
            try:
                observation, current, sample = observe()
                active = active_admission(current, cfg)
                notify = current.get("notify_on_confirmed_hang", False)
                if current["enabled"] and not current["dry_run"] and not active:
                    raise RuntimeError("ACTIVE_RECOVERY_REQUIRES_VERIFIED_ADMISSION")
                clocks = (time.time(), time.monotonic())
                if previous_clock and abs((clocks[0]-previous_clock[0])-(clocks[1]-previous_clock[1])) > 30:
                    if active:
                        runner.hold("CLOCK_DISCONTINUITY", notify)
                    raise RuntimeError("CLOCK_DISCONTINUITY")
                previous_clock = clocks
                # Observations are private, bounded and passive even when
                # notifications and resets are independently disabled.
                passive.record({
                    "utc":observation.utc, "epoch_id":sample.get("epoch_id"),
                    "epoch_start_utc":sample.get("epoch_start_utc"),
                    "phase":runner.state.phase,
                    "observation_valid":sample.get("observation_valid"),
                    "rx_valid":sample.get("rx_valid"),
                    "mqtt_reachable":sample.get("mqtt_reachable"),
                    "srsp_120s":sample.get("srsp_120s"),
                    "affected_devices_120s":sample.get("affected_devices_120s"),
                    "fresh_device_topics_120s":sample.get("fresh_device_topics_120s"),
                    "ota_active":sample.get("ota_active"),
                    "ota_unknown":sample.get("ota_unknown"),
                    "resets_enabled":active})
                result = runner.step(observation, active=active, notify=notify)
                reporter.retry_pending()
                atomic_json(DATA / "status.json", {
                    "schema": "p7u-recovery-status-v2", "utc": observation.utc,
                    "version": "0.2.2", "resets_enabled": active, "phase": result.phase,
                    **{k: sample.get(k) for k in (
                        "epoch_id", "epoch_start_utc", "observation_valid", "rx_valid",
                        "mqtt_reachable", "fresh_device_topics_120s", "srsp_120s",
                        "affected_devices_120s", "ota_active", "ota_unknown")}})
                if poll_number % 3 == 0:
                    print("SAMPLE", "addon="+observation.addon,
                          "rx_devices="+str(observation.fresh_device_topics_120s),
                          "rx_valid="+str(observation.rx_valid),
                          "observer_valid="+str(observation.observation_valid),
                          "srsp="+str(observation.srsp_120s), "phase="+result.phase,
                          "resets_enabled="+str(active), flush=True)
                poll_number += 1
            except Exception as exc:
                print("GUARD_POLL_FAILED_NO_RESET", type(exc).__name__, flush=True)
                if runner.state.phase not in ("MONITOR", "SUSPECT", "COMPLETE", "HOLD"):
                    try:
                        runner.hold("OBSERVATION_OR_PERSISTENCE_FAILURE", notify)
                    except Exception:
                        print("GUARD_STORAGE_UNAVAILABLE_NO_ACTIONS", flush=True)
            time.sleep(POLL_SECONDS)
    finally:
        observer.close()


if __name__ == "__main__":
    import fcntl
    with (DATA / "p7u-watcher-owner.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("SECOND_RECOVERY_OWNER_FORBIDDEN")
        service_main()
