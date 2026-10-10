from __future__ import annotations
import argparse, copy, hashlib, json, os, re, shlex, sys, zipfile
from pathlib import Path

DEPLOY = Path(__file__).resolve().parent
sys.path.insert(0, str(DEPLOY))
from p10_data_bundle import verify as verify_bundle, load_ha, addon_info
from p10_ha_state import addon_quiescent


# Parameters are provided at invocation; no private addresses or backup values
# are embedded in the committed code. The behavior below is the previously
# validated 2026-10-06 Herdsman restore (with fresh attempt path/floor guards).
IMAGE = "ghcr.io/zigbee2mqtt/zigbee2mqtt-aarch64:2.14.0-1"
HERDSMAN_MARGIN = 2500
UINT32_MAX = 0xFFFFFFFF
COUNTER_JUMP = 0x10000000


def configure(args):
    global BUNDLE, SCRIPT, LOCAL_ROOT, REMOTE_ROOT, HOST_ROOT
    global ENDPOINT, EXPECTED_REVISION, FACTORY_IEEE, COUNTER_JUMP
    if not re.fullmatch(r"p10-restore-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{4,12}", args.attempt_id):
        raise ValueError("Invalid attempt ID; use p10-restore-YYYYMMDDTHHMMSSZ-unique")
    if not re.fullmatch(r"[0-9A-Fa-f]{16}", args.factory_ieee):
        raise ValueError("factory IEEE must be 16 hex digits, no prefix")
    if not (args.endpoint.startswith("tcp://") or args.endpoint.startswith("/dev/serial/by-id/")):
        raise ValueError("unexpected transport; verify actual P10 endpoint")
    if not re.fullmatch(r"[0-9]{4,20}", str(args.expected_revision)):
        raise ValueError("invalid expected vendor ZNP revision")
    BUNDLE = args.cold_bundle.resolve(strict=True)
    SCRIPT = Path(__file__).with_suffix(".js")
    root = Path("C:/Workspace/.analienx/sonoff-private").resolve()
    if root not in BUNDLE.parents:
        raise ValueError("Cold backup must stay in private Sonoff workspace")
    LOCAL_ROOT = root / "issues" / "p10-recovery-kit-20261010" / "attempts" / args.attempt_id
    REMOTE_ROOT = "/homeassistant/p10-flash-ready/" + args.attempt_id
    HOST_ROOT = "/mnt/data/supervisor/homeassistant/p10-flash-ready/" + args.attempt_id
    ENDPOINT = args.endpoint
    EXPECTED_REVISION = args.expected_revision
    FACTORY_IEEE = args.factory_ieee.lower()
    COUNTER_JUMP = args.counter_jump


def plan_only(args):
    proof = verify_bundle(BUNDLE)
    with zipfile.ZipFile(BUNDLE) as z:
        raw = z.read("data/coordinator_backup.json")
    backup = json.loads(raw)
    devices = backup.get("devices", [])
    keyed = [d for d in devices if d.get("link_key")]
    if proof.get("cold_consistent") is not True or len(keyed) < 103:
        raise RuntimeError("Cold backup not verified or fewer than 103 key records")
    counters = [backup["network_key"]["frame_counter"]] + [d["link_key"]["tx_counter"] for d in keyed]
    if not all(isinstance(n, int) and 0 <= n <= UINT32_MAX for n in counters):
        raise RuntimeError("Invalid security counter in input")
    if max(counters) + COUNTER_JUMP + HERDSMAN_MARGIN > UINT32_MAX:
        raise RuntimeError("Cannot apply required counter jump without overflow")
    return {
        "mode": "DRY_PLAN_ONLY_NO_NETWORK",
        "original_backup_sha256": sha(raw),
        "cold_archive_sha256": hashlib.sha256(BUNDLE.read_bytes()).hexdigest(),
        "restore_program_sha256": sha(SCRIPT.read_bytes()),
        "coordinator_devices": len(devices),
        "link_keys": len(keyed),
        "cold_consistent": True,
        "counter_jump": COUNTER_JUMP,
        "counter_room_sufficient": True,
        "unique_local_attempt_dir": str(LOCAL_ROOT),
        "unique_remote_attempt_dir": REMOTE_ROOT,
        "current_live_security_counters_read": False,
        "required_before_execute": ["Z2M quiescent", "correct blank vendor P10",
                                    "matching coordinator backup currently on HA",
                                    "minimum network+per-key TC TX floors from preflash read-only radio receipt",
                                    "explicit operator authorization"],
        "flash_authorized": False,
    }

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())

def sftp_write_new(sftp, path: str, raw: bytes) -> None:
    try:
        sftp.stat(path)
        raise RuntimeError(f"remote path already exists: {path}")
    except FileNotFoundError:
        pass
    with sftp.open(path, "wb") as f:
        f.write(raw)
        f.flush()
    sftp.chmod(path, 0o600)

def main() -> None:
    if not PARAMS.execute or PARAMS.approval != "RECOVER_ORIGINAL_ZIGBEE_NETWORK":
        raise SystemExit("restore requires explicit --execute plus exact approval token")
    if PARAMS.min_network_counter is None or PARAMS.min_link_tx_counter is None:
        raise SystemExit("current, independent pre-flash counter floors are required")
    if not SCRIPT.is_file():
        raise RuntimeError("Pinned Herdsman restore script missing")

    proof = verify_bundle(BUNDLE)
    if proof.get("cold_consistent") is not True:
        raise RuntimeError("cold bundle integrity/quiescence proof failed")
    with zipfile.ZipFile(BUNDLE) as z:
        original_raw = z.read("data/coordinator_backup.json")
    original = json.loads(original_raw)
    if len(original.get("devices") or []) != 104:
        raise RuntimeError("unexpected device count")
    keyed = [x for x in original["devices"] if x.get("link_key")]
    if len(keyed) != 103:
        raise RuntimeError("unexpected link-key count")
    working = copy.deepcopy(original)

    nw_old = int(original["network_key"]["frame_counter"])
    if nw_old + COUNTER_JUMP + HERDSMAN_MARGIN > UINT32_MAX:
        raise RuntimeError("network frame counter would overflow")
    working["network_key"]["frame_counter"] = nw_old + COUNTER_JUMP
    if working["network_key"]["frame_counter"] < PARAMS.min_network_counter + HERDSMAN_MARGIN:
        raise RuntimeError("restore TX frame counter does not clear captured live floor")
    tx_checked = 0
    for dev in working["devices"]:
        lk = dev.get("link_key")
        if not lk:
            continue
        old_tx = int(lk["tx_counter"])
        if old_tx + COUNTER_JUMP + HERDSMAN_MARGIN > UINT32_MAX:
            raise RuntimeError("link-key TX counter would overflow")
        lk["tx_counter"] = old_tx + COUNTER_JUMP
        if lk["tx_counter"] < PARAMS.min_link_tx_counter + HERDSMAN_MARGIN:
            raise RuntimeError("TC link TX counter does not clear captured live floor")
        tx_checked += 1
    if tx_checked != 103:
        raise RuntimeError("not all link-key TX counters were bounded")
    working_raw = (json.dumps(working, sort_keys=True, separators=(",", ":")) + "\n").encode()

    plan = {
        "operation": "p10_vendor_original_restore_v1",
        "endpoint": ENDPOINT,
        "expected_revision": EXPECTED_REVISION,
        "factory_ieee": FACTORY_IEEE,
        "tx_power": 15,
        "device_count": 104,
        "key_count": 103,
        "counter_jump": COUNTER_JUMP,
        "herdsman_margin": HERDSMAN_MARGIN,
        "original_backup_sha256": sha(original_raw),
        "working_backup_sha256": sha(working_raw),
        "script_sha256": sha(SCRIPT.read_bytes()),
        "image": IMAGE,
        "remote_root": REMOTE_ROOT,
    }
    plan_raw = (json.dumps(plan, sort_keys=True) + "\n").encode()
    LOCAL_ROOT.mkdir(parents=True, exist_ok=False)
    write_new(LOCAL_ROOT / "plan.private.json", plan_raw)

    client = load_ha()
    try:
        quiet = addon_quiescent(client, addon_info(client))
        if quiet.get("addon_quiescent") is not True:
            raise RuntimeError("Zigbee2MQTT not quiescent")

        sftp = client.open_sftp()
        with sftp.open("/homeassistant/zigbee2mqtt/coordinator_backup.json", "rb") as f:
            live_backup_raw = f.read()
        if sha(live_backup_raw) != sha(original_raw):
            raise RuntimeError("logical live coordinator backup changed since cold capture")

        try:
            sftp.stat(REMOTE_ROOT)
            raise RuntimeError("remote attempt root already exists; one-shot retry prohibited")
        except FileNotFoundError:
            pass
        for p in (REMOTE_ROOT, REMOTE_ROOT + "/input", REMOTE_ROOT + "/output"):
            sftp.mkdir(p, 0o700)
            sftp.chmod(p, 0o700)

        sftp_write_new(sftp, REMOTE_ROOT + "/input/original.json", original_raw)
        sftp_write_new(sftp, REMOTE_ROOT + "/input/working.json", working_raw)
        sftp_write_new(sftp, REMOTE_ROOT + "/input/restore.js", SCRIPT.read_bytes())
        sftp_write_new(sftp, REMOTE_ROOT + "/input/plan.json", plan_raw)

        # Supervisor error can remove the add-on's container entirely.
        # Validate the exact cached Herdsman runtime image, not a container
        # that may no longer exist after a Zigbee2MQTT crash.
        _, out, err = client.exec_command(
            "docker image inspect --format '{{.Id}}' " + IMAGE, timeout=15
        )
        image_id = out.read().decode().strip()
        _ = err.read()
        if out.channel.recv_exit_status() != 0 or not image_id.startswith("sha256:"):
            raise RuntimeError("Pinned local Zigbee2MQTT runtime image unavailable")

        _, out, err = client.exec_command("docker ps --format '{{.Names}}'", timeout=10)
        running = out.read().decode().splitlines()
        _ = err.read()
        if out.channel.recv_exit_status() != 0 or any("zigbee2mqtt" in x.lower() for x in running):
            raise RuntimeError("Zigbee2MQTT container is running")

        q = shlex.quote
        command = (
            "docker run --rm --network host --entrypoint node "
            f"-v {q(HOST_ROOT + '/input')}:/input:ro "
            f"-v {q(HOST_ROOT + '/output')}:/output "
            f"{q(IMAGE)} /input/restore.js"
        )
        _, out, err = client.exec_command(command, timeout=None)
        out.channel.settimeout(None)
        err.channel.settimeout(None)
        stdout = out.read().decode("utf-8", "replace")
        stderr = err.read().decode("utf-8", "replace")
        rc = out.channel.recv_exit_status()
        if rc != 0:
            failure = {
                "ok": False, "container_exit": rc, "stderr_present": bool(stderr),
                "stdout_tail": stdout.splitlines()[-5:], "remote_root": REMOTE_ROOT,
                "retry_authorized": False
            }
            write_new(LOCAL_ROOT / "result.private.json", (json.dumps(failure, indent=2) + "\n").encode())
            print(json.dumps({"ok": False, "container_exit": rc, "stderr_present": bool(stderr), "retry_authorized": False}))
            raise SystemExit(2)

        lines = [line for line in stdout.splitlines() if line.strip()]
        result = json.loads(lines[-1]) if lines else {}
        required = (
            result.get("ok") is True and result.get("paused_before_startup") is True and
            result.get("restored_devices", 0) >= 104 and result.get("restored_link_keys") == 103 and
            result.get("identity_match") is True and result.get("network_key_match") is True and
            result.get("counter_floors_verified") is True and result.get("formation_count") == 1 and
            result.get("permit_join_sent") is False and result.get("startupFromApp_sent") is False
        )
        if not required:
            raise RuntimeError("restore result failed pause/identity/counter invariants")
        receipt = {
            "ok": True, "backup_sha256": plan["original_backup_sha256"],
            "working_backup_sha256": plan["working_backup_sha256"],
            "counter_jump": COUNTER_JUMP, "herdsman_margin": HERDSMAN_MARGIN,
            "z2m_quiescent": True, "remote_root": REMOTE_ROOT,
            "restored_devices": result["restored_devices"],
            "restored_link_keys": result["restored_link_keys"],
            "identity_match": True, "network_key_match": True,
            "counter_floors_verified": True, "formation_count": 1,
            "permit_join_sent": False, "startupFromApp_sent": False,
            "retry_authorized": False
        }
        write_new(LOCAL_ROOT / "result.private.json", (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
        print(json.dumps(receipt, indent=2, sort_keys=True))
    finally:
        client.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Deterministic single-attempt existing-network restore; read-only plan by default")
    p.add_argument("--cold-bundle", required=True, type=Path)
    p.add_argument("--attempt-id", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--factory-ieee", required=True)
    p.add_argument("--expected-revision", type=int, default=20240716)
    p.add_argument("--counter-jump", type=lambda v: int(v, 0), default=0x10000000)
    p.add_argument("--min-network-counter", type=int)
    p.add_argument("--min-link-tx-counter", type=int)
    p.add_argument("--use-historical-counter-floor-on-blank-radio", action="store_true",
                   help="For proven blank NIB only: use last verified Oct 6 NWK floor plus backup per-device TX floors; enforce 0x10000000 jump. NOT proof of latest live counters.")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--approval", default="")
    PARAMS = p.parse_args()
    try:
        configure(PARAMS)
        if PARAMS.use_historical_counter_floor_on_blank_radio:
            if PARAMS.min_network_counter is not None or PARAMS.min_link_tx_counter is not None:
                raise ValueError("Historical fallback cannot mix with supposed live floors")
            if PARAMS.counter_jump < 0x10000000:
                raise ValueError("Historical fallback needs at least 0x10000000 counter margin")
            with zipfile.ZipFile(BUNDLE) as archive:
                saved = json.loads(archive.read("data/coordinator_backup.json"))
            if len([e for e in saved.get("devices", []) if e.get("link_key")]) != 103:
                raise ValueError("Historical fallback requires all 103 device keys")
            # Last real radio read-back from Oct 6 restore receipt, NOT Oct 10 live.
            PARAMS.min_network_counter = max(saved["network_key"]["frame_counter"], 349847756)
            PARAMS.min_link_tx_counter = max(
                e["link_key"]["tx_counter"] for e in saved["devices"] if e.get("link_key")
            )
            print(json.dumps({"counter_floor_source":"HISTORICAL_OCT6_RADIO_AND_COLD_BACKUP",
                              "independent_current_floor_proven":False,
                              "counter_jump":PARAMS.counter_jump,
                              "requires_truly_blank_NIB":True}, sort_keys=True))
        if not PARAMS.execute:
            print(json.dumps(plan_only(PARAMS), indent=2, sort_keys=True))
        else:
            main()
    except (OSError, ValueError, RuntimeError, KeyError, OverflowError, zipfile.BadZipFile) as exc:
        print(json.dumps({"ok": False, "error_type": type(exc).__name__,
                          "reason": str(exc)[:200], "attempt_executed": PARAMS.execute},
                          sort_keys=True))
        raise SystemExit(2)
