#!/usr/bin/env python3
"""RETIRED legacy P7U cutover (read-only inspection only).

Default is read-only preflight. --execute changes HA add-on ownership ONCE.
Never opens UART, flashes firmware, restores counters, restarts hardware, or
starts a second owner. Compatible with the pinned 2026-10-23 HA deployment.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import time

OLD = "45df7312_zigbee2mqtt"
NEW = "local_p7u_r4_native_host"
GUARD = "local_p7u_recovery"
BACKUP = pathlib.Path("/backup/p7u-native-host-admission-20261023/z2m-host-before.tar.gz")
BACKUP_HASH = "cdf0040c2a65ace7056b2d79247d7a83962e8750616de256bc19fbae1b8bbcc2"
HISTORY = pathlib.Path("/config/zigbee2mqtt/p7u-b4-diagnostics/history.json")
LAST_GOOD = HISTORY.with_name("last-good.json")


def run(*cmd, timeout=90):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError("PROCESS_FAILED " + str(cmd[:3]) + " " + p.stderr[-160:])
    return p.stdout


def addon(name):
    value = json.loads(run("ha", "apps", "info", name, "--raw-json"))
    if value.get("result") != "ok":
        raise RuntimeError("ADDON_METADATA_MISSING " + name)
    return value["data"]


def running(name):
    p = subprocess.run(("docker", "inspect", "app_" + name),
                       capture_output=True, text=True, timeout=20)
    if p.returncode != 0:
        if "No such object" in p.stderr or "No such container" in p.stderr:
            return False
        raise RuntimeError("DOCKER_OWNER_STATE_UNAVAILABLE")
    return bool(json.loads(p.stdout)[0]["State"]["Running"])


def backup_valid():
    if not BACKUP.is_file():
        return False
    digest = hashlib.sha256()
    with BACKUP.open("rb") as source:
        for data in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest() == BACKUP_HASH


def preflight():
    old, new, guard = addon(OLD), addon(NEW), addon(GUARD)
    policy = guard["options"]
    assert old["state"] == "started" and running(OLD), "ORIGINAL_NOT_HEALTHY"
    assert new["state"] == "stopped" and not running(NEW), "CANDIDATE_NOT_STOPPED"
    assert new["version"] == "0.1.0" and new["boot"] == "manual"
    assert new["watchdog"] is False
    assert old["options"] == new["options"], "SERIAL_MQTT_OPTIONS_DIFFER"
    assert old["options"]["data_path"] == "/config/zigbee2mqtt"
    assert old["options"]["serial"]["port"].startswith("/dev/serial/by-id/")
    assert old["options"]["serial"]["adapter"] == "zstack"
    assert policy["enabled"] is False and policy["dry_run"] is True
    assert policy["serial_owner_approved"] is False
    assert policy["allow_private_http_fallback"] is False
    assert backup_valid(), "PRIVATE_PRECUTOVER_BACKUP_HASH_FAILED"
    print("PREFLIGHT_PASS_ORIGINAL_SINGLE_OWNER_CANDIDATE_STOPPED", flush=True)


def quiet_owner(timeout_sec, allow_bounded_termination):
    run("ha", "apps", "stop", OLD, timeout=90)
    for _ in range(max(1, timeout_sec // 2)):
        if not running(OLD):
            break
        time.sleep(2)
    if running(OLD):
        if not allow_bounded_termination:
            raise RuntimeError("GRACEFUL_STOP_STUCK_AND_FORCE_NOT_APPROVED")
        # After the Supervisor stop request Z2M may hang on herdsman
        # permitJoin(0)/backup()/adapter.stop(). Kill ONLY this host container.
        # This is NOT a Zigbee firmware reset, serial probe or NV restore.
        print("GRACEFUL_STOP_STUCK_BOUND_HOST_PROCESS_EXIT", flush=True)
        run("docker", "kill", "--signal=SIGKILL", "app_" + OLD, timeout=30)
    for _ in range(10):
        if not running(OLD):
            break
        time.sleep(2)
    assert not running(OLD), "OLD_DOCKER_SERIAL_OWNER_NOT_RELEASED"


def valid_native_samples(cutover_ms):
    if not HISTORY.exists():
        return [], 0
    data = json.loads(HISTORY.read_text())
    assert data["schema"] == "p7u-b4-native-history-v1"
    rows = data.get("rows", [])
    accepted = [r for r in rows if r.get("kind") == "VALID" and
                r.get("utc", 0) >= cutover_ms and r.get("abi") == 4 and
                r.get("probeLatencyMs") is not None and
                r.get("monotonicReceiveNs") is not None]
    return accepted, sum(r.get("kind") == "SKIPPED" and
                         r.get("utc", 0) >= cutover_ms for r in rows)


def completed(samples):
    if len(samples) < 3 or not LAST_GOOD.exists():
        return False
    last = samples[-3:]
    tags = {r.get("radioEpochTag") for r in last}
    seq = [r["sequence"] for r in last]
    return len(tags) == 1 and None not in tags and seq[0] < seq[1] < seq[2] and (
        json.loads(LAST_GOOD.read_text()).get("sequence") == seq[-1])


def restore_old():
    print("ROLLBACK_BEGIN", flush=True)
    if running(NEW):
        run("ha", "apps", "stop", NEW, timeout=90)
        for _ in range(10):
            if not running(NEW):
                break
            time.sleep(2)
        if running(NEW):
            run("docker", "kill", "--signal=SIGKILL", "app_" + NEW, timeout=30)
    assert not running(NEW), "ROLLBACK_CANDIDATE_SERIAL_OWNER_NOT_EXITED"
    if not running(OLD):  # NO unconditional restart against an existing owner.
        run("ha", "apps", "start", OLD, timeout=90)
    assert running(OLD) and not running(NEW), "ROLLBACK_FAILED"
    print("ROLLBACK_COMPLETE_ORIGINAL_SOLE_OWNER_NO_NV_TOUCH", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true",
                        help="Allow exactly one managed host handover")
    parser.add_argument("--allow-bounded-host-termination", action="store_true",
                        help="Permit kill of OLD Docker process after Supervisor stop stalls")
    parser.add_argument("--grace-seconds", type=int, default=20)
    parser.add_argument("--observe-seconds", type=int, default=1200)
    args = parser.parse_args()
    assert 10 <= args.grace_seconds <= 120
    assert 180 <= args.observe_seconds <= 3600
    # RV-P1-03/04/05: the legacy implementation can kill a reused Docker
    # name, lacks a durable owner journal and strict committed-DB admission,
    # and treats absent F2 as a reason to restart a healthy serving host.
    # It is NOT an executable rollout mechanism, including under python -O.
    # Replace it only after the separate identity-pinned lifecycle manager
    # passes exact-SHA GitHub Actions, a guarded dry-run, and review.
    if args.execute:
        raise RuntimeError("P7U_HOLD_LEGACY_CUTOVER_RETIRED_NO_HOST_ACTION")
    preflight()
    if not args.execute:
        print("PREFLIGHT_ONLY_NO_CHANGE", flush=True)
        return

    old_was_stopped = False
    admitted = False
    try:
        old_was_stopped = True  # stop command may partially commit before error
        quiet_owner(args.grace_seconds, args.allow_bounded_host_termination)
        assert not running(OLD)
        cutover_ms = int(time.time() * 1000)
        run("ha", "apps", "start", NEW, timeout=90)
        assert running(NEW) and not running(OLD), "SECOND_OWNER_OR_START_FAILED"
        print("DIAGNOSTIC_HOST_STARTED_ONE_OWNER", flush=True)
        end = time.monotonic() + args.observe_seconds
        while time.monotonic() < end:
            time.sleep(20)
            if not running(NEW) or running(OLD):
                raise RuntimeError("SERIAL_OWNER_INVARIANT_LOST")
            records, skipped = valid_native_samples(cutover_ms)
            print("NATIVE_F2_VALID", len(records), "SAFELY_SKIPPED",
                  skipped, flush=True)
            if completed(records):
                mask = records[-1].get("validityMask")
                print("F2_THREE_SAME_BOOT_MONOTONIC; LAST_MASK", mask,
                      "SRSP_COUNTERS_VALID", bool(mask & 0x13 == 0x13), flush=True)
                admitted = True
                break
        if not admitted:
            raise RuntimeError("NATIVE_COLLECTION_OBSERVATION_LIMIT")
    finally:
        if old_was_stopped and not admitted:
            restore_old()
    print("MANAGED_NATIVE_HOST_ACCEPTED_PHYSICAL_RESET_STILL_DISABLED",
          flush=True)


if __name__ == "__main__":
    main()
