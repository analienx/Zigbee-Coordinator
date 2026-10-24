#!/usr/bin/env python3
"""One operator-authorized ESP-after-radio exception for the retained incident.

Fixed native Core button, followed by a separately planned original-host start.
No radio reset, serial open, firmware/NV change, automatic arming or new incident.
Every apply uses the global manager lock, exact history and fresh host-PID proof.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import Request, build_opener, HTTPRedirectHandler

INCIDENT = "b2660c9538f540b295896864ed178210"
ROOT = Path("/share/p7u-lifecycle/private/source-3921b7923025")
DATA = Path("/config/zigbee2mqtt")
TARGET = "button.slzb_06p7u_core_restart"
ORIGINAL = "45df7312_zigbee2mqtt"
INSPECTOR = "local_p7u_r4_owner_inspector"
GUARD_IMAGE = "sha256:9a61186a57af776a39c17321aece53973cee6b472a69461c931e5af8c2915b4d"
INSPECTOR_IMAGE = "sha256:ce5c229254f0863d2f51a0655bb5dac9a40d97992fd28764ace521177f708865"
FAILED_CONTAINER = "325ef203ea49d483032258a4d202c88d4e563d2ec5a3967e1ecaa0b0d9e8de40"
ORIGINAL_IMAGE = "sha256:fce455a33bcb66d379022c18cafb8a899d513f170014c3be4d574a5b35e0c3a4"
BACKUP_SHA = "8609d816976863702517d82bc80597b082e741e70747e008c0854b6c802f8de4"
LOG_SHA = "54e7f55f4bba16bd3335101ed6de2ae658e94b0829bfecd44b04b7d0a4fcf72b"
JOURNALS = {"source-3921b7923025": "b44213ae2b18e7246fe4326635eb83e82ce76aa86b15f85378ba39fa4a228354",
            "source-a5ce68b3b6a4": "f589697ed9f05af5bb607f3646a6da4f7c414f4d63c3f0fa1425aa49fcba4319"}
PORT = "/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00"
STAGES = {"esp": "native-post-radio-esp-only", "start": "native-post-radio-esp-original-start"}


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_private(path):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size < 8_000_000, "PRIVATE_EVIDENCE_UNSAFE")
    return path.read_bytes()


def unique(path, document):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(document, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError("REDIRECT_FORBIDDEN")


class Backend:
    def __init__(self):
        self.opener = build_opener(NoRedirect())

    def api(self, path, payload=None):
        allowed = {"/addons/" + INSPECTOR + "/start": {},
                   "/addons/" + ORIGINAL + "/start": {},
                   "/core/api/services/button/press": {"entity_id": TARGET}}
        if payload is not None:
            require(path in allowed and payload == allowed[path], "SIDE_EFFECT_NOT_ALLOWED")
        req = Request("http://supervisor" + path, method="POST" if payload is not None else "GET",
                      data=json.dumps(payload).encode() if payload is not None else None,
                      headers={"Authorization": "Bearer " + os.environ["SUPERVISOR_TOKEN"], "Content-Type": "application/json"})
        with self.opener.open(req, timeout=100 if path.endswith("/start") else 15) as response:
            raw = response.read(2_000_001)
        require(len(raw) <= 2_000_000, "RESPONSE_TOO_LARGE")
        return raw.decode() if path.endswith("/logs") else json.loads(raw)

    def info(self, slug):
        result = self.api("/addons/" + slug + "/info")
        require(result.get("result") == "ok", "SUPERVISOR_INFO_FAILED")
        return result["data"]

    def docker(self, slug):
        p = subprocess.run(["docker", "inspect", "app_" + slug], capture_output=True, text=True, timeout=15)
        if p.returncode:
            require("no such" in p.stderr.lower(), "DOCKER_INSPECTION_UNKNOWN")
            return None
        return json.loads(p.stdout)[0]

    def guard_admission(self):
        code = r"""
import os,json,time
from pathlib import Path
from run import load_options,configuration,verify_controls
from ha_adapter import SupervisorClient,SmlightControl
opts=load_options();cfg=configuration(opts);s=SupervisorClient(os.environ['SUPERVISOR_TOKEN'])
assert opts['enabled'] is False and opts['dry_run'] is True and opts['serial_owner_approved'] is False
assert opts['allow_private_http_fallback'] is False and opts['maintenance'] is False and opts.get('firmware_flash_active',False) is False
assert cfg.esp_restart_entity=='button.slzb_06p7u_core_restart' and cfg.zigbee_restart_entity=='button.slzb_06p7u_zigbee_restart'
assert cfg.expected_mac.lower()=='70:af:09:a5:dc:30' and cfg.slzb_url=='http://192.168.50.59'
assert s.hardware_has_port(cfg.expected_by_id)
verify_controls(cfg,s);SmlightControl(cfg).identity()
status=json.loads(Path('/data/status.json').read_text());assert 0<=time.time()-status['utc']<65
assert status['mqtt_reachable'] is True and status['resets_enabled'] is False and status['ota_active'] is False and status['ota_unknown'] is False
out={}
for phase,action in [('RADIO_RESET_PENDING','RESET_RADIO'),('RADIO_START_PENDING','START_Z2M')]:
 p=Path('/data/evidence')/('p7u-recovery-b2660c9538f540b295896864ed178210-'+phase+'-'+action+'.result.json')
 d=json.loads(p.read_text());assert d['incident_id']=='b2660c9538f540b295896864ed178210' and d['phase']==phase and d['action']==action
 assert d['status']=='COMMAND_ACCEPTED_NOT_YET_VERIFIED'
 out[phase]=d
print(json.dumps(out))
"""
        p = subprocess.run(["docker", "exec", "-i", "app_local_p7u_recovery", "python", "-"],
                           input=code, capture_output=True, text=True, timeout=45)
        require(p.returncode == 0, "LIVE_NATIVE_GUARD_ADMISSION_FAILED")
        return json.loads(p.stdout)

    def owners(self):
        result = {}
        for slug in [ORIGINAL, "local_p7u_r4_native_host", "local_p7u_r4_fallback", "local_p7u_r4_lifecycle_manager"]:
            info = self.info(slug)
            c = self.docker(slug)
            require(info["state"] in ("error", "stopped") and info["boot"] == "manual" and info["watchdog"] is False,
                    "COMPETING_OWNER_OR_STARTER")
            require(c is None or c["State"]["Running"] is False, "OWNER_RUNNING")
            result[slug] = c["Id"] if c else None
        c = self.docker(ORIGINAL)
        require(c["Id"] == FAILED_CONTAINER and c["Image"] == ORIGINAL_IMAGE, "ORIGINAL_EPOCH_CHANGED")
        owner = self.info(ORIGINAL)
        require(owner["version"] == "2.14.0-1", "ORIGINAL_VERSION_CHANGED")
        options = owner.get("options") or {}
        serial = options.get("serial") or {}
        require(serial.get("port") == PORT and serial.get("adapter") == "zstack" and serial.get("baudrate") == 115200 and
                serial.get("rtscts") is False and (options.get("socat") or {}).get("enabled") is False, "SERIAL_CONFIG_CHANGED")
        guard = self.docker("local_p7u_recovery")
        require(guard and guard["State"]["Running"] and guard["Image"] == GUARD_IMAGE, "GUARD_IMAGE_CHANGED")
        for entity in ["automation.boot_deterministic_emqx_then_zigbee2mqtt", "automation.zigbee2mqtt_mesh_communication_outage_alert"]:
            state = self.api("/core/api/states/" + entity)
            require(state["state"] == "off" and state["attributes"]["current"] == 0, "COMPETING_AUTOMATION")
        return result

    def host_proof(self):
        proofs = []
        for _ in range(3):
            info = self.info(INSPECTOR)
            require(info["state"] != "started" and info["protected"] is False and info["host_pid"] is True,
                    "INSPECTOR_NOT_QUALIFIED")
            old = self.docker(INSPECTOR)
            reply = self.api("/addons/" + INSPECTOR + "/start", {})
            require(reply.get("result") == "ok", "INSPECTOR_START_NOT_ACKNOWLEDGED")
            for tick in range(30):
                time.sleep(.5)
                if self.info(INSPECTOR)["state"] != "started":
                    break
            c = self.docker(INSPECTOR)
            require(c and not c["State"]["Running"] and c["State"]["ExitCode"] == 0 and
                    c["Image"] == INSPECTOR_IMAGE and c["HostConfig"]["PidMode"] == "host" and
                    (old is None or c["Id"] != old["Id"]), "HOST_INSPECTOR_EPOCH_INVALID")
            records = []
            for line in self.api("/addons/" + INSPECTOR + "/logs").splitlines():
                try:
                    document = json.loads(line)
                except ValueError:
                    continue
                if document.get("schema") == "p7u-host-tty-cgroup-evidence-v2":
                    records.append(document)
            require(bool(records), "HOST_PROOF_MISSING")
            proof = records[-1]
            require(proof.get("exclusive_owner_verified") is True and proof.get("serial_opened") is False and
                    proof.get("tty_holders_pids") == [] and set(proof.get("slots", {})) == {"official", "diagnostic", "fallback"} and
                    all(v.get("running") is False for v in proof["slots"].values()), "HOST_OWNERSHIP_NOT_PROVEN")
            proofs.append({"container_id": c["Id"], "utc": time.time(), "proof": proof})
        return proofs


def snapshot(root, backend, stage, source):
    require(stage in STAGES, "STAGE_FORBIDDEN")
    require(root.is_dir() and not root.is_symlink(), "INCIDENT_ROOT_UNSAFE")
    base = STAGES[stage]
    for suffix in ("intent", "result"):
        p = root / (base + "." + suffix + ".json")
        require(not p.exists() and not p.is_symlink(), "ALREADY_CONSUMED_NO_REPLAY")
    hashes = {}
    for folder, expected in JOURNALS.items():
        raw = read_private(root.parent / folder / "journal/events.jsonl")
        require(hashlib.sha256(raw).hexdigest() == expected and json.loads(raw.splitlines()[-1])["phase"] == "HOLD",
                "OLD_HOLD_HISTORY_CHANGED")
        hashes[folder] = expected
    for name in ("native-radio-fallback.intent.json", "native-original-final-start.intent.json", "manual-esp-restart.intent.json"):
        raw = read_private(root / name)
        require(json.loads(raw).get("incident_id") == INCIDENT, "HISTORY_INCIDENT_MISMATCH")
        hashes[name] = hashlib.sha256(raw).hexdigest()
    warning = json.loads(read_private(root / "native-final-warning.intent.json"))
    require(warning.get("operation") == "report_recovery_exhausted" and warning.get("physical_action") is False,
            "PRIOR_HOLD_WARNING_INVALID")
    require(hashlib.sha256(read_private(root / "native-final-start.private.log")).hexdigest() == LOG_SHA, "FAILED_LOG_CHANGED")
    data = DATA  # Database lives outside incident evidence; never written.
    manifest = json.loads(read_private(data / ".p7u-approved.json"))
    require(hashlib.sha256(read_private(data / "database.db")).hexdigest() == manifest["database_sha256"] and
            manifest["devices"] == 107 and manifest["rows"] == 128 and
            not (data / "database.db.tmp").exists() and not (data / ".p7u-approved.json.pending").exists(), "DATABASE_NOT_ADMITTED")
    require(hashlib.sha256(read_private(data / "coordinator_backup.json")).hexdigest() == BACKUP_SHA, "BACKUP_CHANGED")
    events = [json.loads(line) for line in read_private(root / "journal/events.jsonl").splitlines()]
    cold = next(e["evidence"]["cold_backup"] for e in events if e["phase"] == "DB_APPROVED")
    archive = root / cold["archive"]
    require(archive.resolve().is_relative_to(root.resolve()) and not archive.is_symlink(), "COLD_ARCHIVE_PATH_UNSAFE")
    with archive.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == cold["sha256"], "COLD_ARCHIVE_CHANGED")
    owners = backend.owners()
    receipts = backend.guard_admission()
    button_state = backend.api("/core/api/states/" + TARGET).get("state")
    require(button_state is not None and button_state != "unavailable", "ESP_BUTTON_UNAVAILABLE")
    if stage == "esp" and button_state != "unknown":
        from datetime import datetime
        require(datetime.fromisoformat(button_state).timestamp() <=
                datetime.fromisoformat(receipts["RADIO_RESET_PENDING"]["recorded_utc"]).timestamp(),
                "ESP_ALREADY_PRESSED_AFTER_RADIO_NO_REPEAT")
    if stage == "start":
        prior = json.loads(read_private(root / (STAGES["esp"] + ".result.json")))
        require(prior.get("status") == "ACKNOWLEDGED" and prior.get("incident_id") == INCIDENT and
                prior.get("target") == TARGET and prior.get("source_sha") == source,
                "ESP_RECEIPT_NOT_ACKNOWLEDGED")
        age = time.time() - prior["utc"]
        require(20 <= age < 900, "ESP_GRACE_OR_RECEIPT_AGE")
        state = backend.api("/core/api/states/" + TARGET)
        require(state.get("state") == prior["button_state"] and state["state"] != prior["before_button_state"],
                "ESP_BUTTON_NOT_INDEPENDENTLY_CONFIRMED")
    return {"operation": "once_esp_after_native_radio_and_failed_zdo", "incident_id": INCIDENT,
            "stage": stage, "source_sha": source, "target": TARGET if stage == "esp" else ORIGINAL,
            "history_sha256": hashes, "database_sha256": manifest["database_sha256"],
            "owners": owners, "before_button_state": button_state, "radio_receipts_sha256": digest(receipts)}


def perform(root, backend, stage, plan, expected):
    require(digest(plan) == expected, "PLAN_HASH_NOT_MATCHED")
    proofs = backend.host_proof()
    require(time.time() - proofs[0]["utc"] < 20, "HOST_PROOF_STALE")
    require(snapshot(root, backend, stage, plan["source_sha"]) == plan, "STATE_CHANGED_AFTER_PLAN")
    require(time.time() - proofs[0]["utc"] < 30, "HOST_PROOF_STALE_AFTER_ADMISSION")
    before = backend.api("/core/api/states/" + TARGET)["state"] if stage == "esp" else None
    require(stage != "esp" or before == plan["before_button_state"], "ESP_STATE_CHANGED_BEFORE_ACTION")
    marker = root / (STAGES[stage] + ".intent.json")
    unique(marker, {**plan, "plan_sha256": expected, "host_proofs": proofs, "utc": time.time()})
    print(json.dumps({"event": "ONE_SHOT_INTENT_DURABLE", "stage": stage, "plan_sha256": expected}), flush=True)
    status = "AMBIGUOUS_NO_RETRY"
    error = None
    try:
        if stage == "esp":
            reply = backend.api("/core/api/services/button/press", {"entity_id": TARGET})
            acknowledged = isinstance(reply, list)
        else:
            reply = backend.api("/addons/" + ORIGINAL + "/start", {})
            acknowledged = isinstance(reply, dict) and reply.get("result") == "ok"
        status = "ACKNOWLEDGED" if acknowledged else "NOT_ACKNOWLEDGED_NO_RETRY"
    except Exception as exc:
        error = type(exc).__name__
    button = None
    if stage == "esp" and status == "ACKNOWLEDGED":
        try:
            button = backend.api("/core/api/states/" + TARGET)["state"]
        except Exception:
            status = "BUTTON_READBACK_UNKNOWN_NO_RETRY"
    result = {"schema": "p7u-post-radio-esp-followup-v2", "incident_id": INCIDENT, "source_sha": plan["source_sha"],
              "stage": stage, "target": plan["target"], "status": status, "utc": time.time(), "error_class": error,
              "button_state": button, "before_button_state": before, "plan_sha256": expected}
    unique(root / (STAGES[stage] + ".result.json"), result)
    print(json.dumps(result), flush=True)
    return 0 if status == "ACKNOWLEDGED" else 2


def remote_main(mode, stage, expected, source):
    import fcntl
    require(mode in ("plan", "apply") and stage in STAGES, "MODE_FORBIDDEN")
    lock = os.open(ROOT.parent / "exclusive-manager.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        backend = Backend()
        plan = snapshot(ROOT, backend, stage, source)
        print(json.dumps({"event": "ESP_FOLLOWUP_PLAN", "sha256": digest(plan), **plan}), flush=True)
        return 0 if mode == "plan" else perform(ROOT, backend, stage, plan, expected)
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "apply"))
    parser.add_argument("--stage", choices=tuple(STAGES), default="esp")
    parser.add_argument("--expected-plan-hash", default="")
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--remote", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(len(args.source_sha) == 40 and all(c in "0123456789abcdef" for c in args.source_sha), "BAD_SOURCE_SHA")
    if args.remote:
        return remote_main(args.mode, args.stage, args.expected_plan_hash, args.source_sha)
    raw = Path(__file__).read_bytes()
    relative = "host/recovery/incident_native_esp_followup.py"
    pinned = subprocess.check_output(["git", "show", args.source_sha + ":" + relative])
    require(hashlib.sha256(raw).digest() == hashlib.sha256(pinned).digest(), "HELPER_NOT_EXACT_SOURCE")
    checks = json.loads(subprocess.check_output(["gh", "api", "repos/analienx/Zigbee-Coordinator/commits/" + args.source_sha + "/check-runs?per_page=100"]))["check_runs"]
    for name in ("unittest", "Policy and one-shot journal regressions", "release"):
        matches = [c for c in checks if c["name"] == name]
        require(matches and all(c["status"] == "completed" and c["conclusion"] == "success" for c in matches), "HOSTED_QUALIFICATION_MISSING_" + name)
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "ha", "python3", "-", args.mode,
           "--stage", args.stage, "--source-sha", args.source_sha, "--remote"]
    if args.expected_plan_hash:
        cmd += ["--expected-plan-hash", args.expected_plan_hash]
    proc = subprocess.run(cmd, input=raw.decode(), text=True, capture_output=True, timeout=240)
    print(proc.stdout, end="")
    if proc.returncode:
        print("HOLD_NO_REPLAY: " + proc.stderr[-600:], file=sys.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
