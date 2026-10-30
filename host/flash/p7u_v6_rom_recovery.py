"""V6-only, no-write ROM/BSL recovery from a previously verified deployed image.

The *existing* sealed HA operator provides device, security, image and USB ownership
primitives. This module adds a fresh, immutable recovery operation, not a retry of
the consumed native-boot action. It must run on the authorized HA host, never on a
GitHub-hosted runner. No secrets, flash payload or raw private evidence are exported.
"""
import asyncio
import gzip
import hashlib
import json
import os
import time
import urllib.request
import zlib

V6_SOURCE = "66ed700c2818c7a0963dad9160d55109009bbaac"
ROOT_NAME = "rom-recovery-v6"
MAX_PLAN_AGE_SECONDS = 1800
CONTROL_SOURCE_SHA256 = "2d50552d71bf55f8f87aeabece9f4dae01d589d9e2e88699ec0b15e8e8e600ed"


def control_source(need):
    """Check the installed OS and its actual opcode source before any action."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://192.168.50.59/ha_info", timeout=8) as response:
        info = json.load(response)["Info"]
    need(info.get("sw_version") == "v3.4.3.dev1", "RECOVERY_CONTROL_OS")
    with opener.open("http://192.168.50.59/js/httpApi.js", timeout=8) as response:
        raw = response.read(65537)
    need(len(raw) <= 65536, "RECOVERY_CONTROL_SOURCE_SIZE")
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    need(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == CONTROL_SOURCE_SHA256,
         "RECOVERY_CONTROL_SOURCE")
    return CONTROL_SOURCE_SHA256


def _checked(ns, package, plan_pin, ha):
    need = ns["need"]
    need(ns["SOURCE"] == V6_SOURCE, "RECOVERY_V6_SOURCE")
    from p7u_paired_hold import verified_pair_package
    original = verified_pair_package(ns, plan_pin)
    write = ns["verified_write"](original, plan_pin)
    private = ns["PRIVATE"]
    prior = ns["load"](private / "native-boot" / "startup-result.json")
    hold = ns["load"](private / "native-boot" / "hold.json")
    need(
        prior["status"] == "FAILED_STOP_NO_RETRY"
        and prior["failure_category"] == "OBSERVER_TIMEOUT_STATE_UNKNOWN"
        and prior["ready_observed"] is False
        and hold["phase"] == "NATIVE_BOOT"
        and hold["automatic_retry"] is False
        and hold["automatic_boot"] is False
        and (private / "boot-intent.json").is_file()
        and not (private / "start-intent.json").exists()
        and not (private / "started-pending-serving.json").exists(),
        "RECOVERY_EXACT_HELD_STARTUP",
    )
    ha.policy()
    owner = ha.inspect()
    need(
        not owner["running"] and owner["image"] == ns["IMAGE"],
        "RECOVERY_SOLE_HOST_STOPPED",
    )
    ha.proof(False)
    management = ha.management()
    need(management == write["management_sha256"], "RECOVERY_DEVICE_CHANGED")
    control = control_source(need)
    guard_file = ns["CANDIDATE"] / "host" / "p7u-startup-hold.json"
    guard = ns["load"](guard_file)
    need(guard.get("retained_only") is True
         and guard.get("mandatory_readonly_f1") is True
         and guard.get("restore_automatically_allowed") is False
         and guard.get("virgin_commissioning_allowed") is False,
         "RECOVERY_PROTECTED_HOST_STARTUP")
    info = ha.info(ns["OWNER"])
    need(
        info["state"] in ("error", "stopped")
        and info["boot"] == "manual"
        and info["watchdog"] is False,
        "RECOVERY_HOST_METADATA",
    )
    transition, security, _reconcile, factory, sparse, _forward, expected = (
        ns["forward_transition"](original)
    )
    need(len(expected) == 720896, "RECOVERY_IMAGE_LENGTH")
    sectors = (0, 0xAC000, 0xAE000)
    expected_crc = {
        str(address): zlib.crc32(expected[address : address + 8192]) & 0xFFFFFFFF
        for address in sectors
    }
    evidence = {
        "source": V6_SOURCE,
        "image": ns["IMAGE"],
        "owner": owner,
        "management_sha256": management,
        "control_source_sha256": control,
        "host_startup_guard_sha256": ns["file_sha"](guard_file),
        "write_plan_sha256": plan_pin,
        "failed_boot_sha256": ns["file_sha"](
            private / "native-boot" / "startup-result.json"
        ),
        "written_receipt_sha256": ns["file_sha"](private / "verified-write.json"),
        "expected_crc32": expected_crc,
        "scope": "USB_OPEN_FIRST_ROM_READONLY_APP_BOOT_PROTECTED_HOST_ONCE",
        "firmware_writes": 0,
        "nv_writes": 0,
        "ccfg_writes": 0,
        "external_startup_requests": 0,
    }
    return original, owner, evidence, (transition, security, factory, sparse, expected)


def plan(ns, package, package_pin, write_plan_pin, ha):
    need = ns["need"]
    ns["sealed_tree"](package, "PACKAGE.json", package_pin)
    _original, _owner, evidence, _deps = _checked(
        ns, package, write_plan_pin, ha
    )
    root = ns["PRIVATE"] / ROOT_NAME
    need(not root.exists() and not root.is_symlink(), "RECOVERY_ALREADY_PLANNED")
    root.mkdir(mode=0o700)
    record = dict(evidence, created_at=time.time(), schema="p7u-v6-rom-recovery-v1")
    ns["durable"](root, "plan.json", record)
    return {
        "status": "V6_ROM_RECOVERY_PLAN_READY",
        "recovery_plan_sha256": ns["sha"](ns["canonical"](record)),
        "no_radio_actions": True,
    }


async def _rom_observe(ns, root, ha, dep, expected_crc):
    transition, security_model, factory, sparse, expected = dep
    rom = factory()
    try:
        await asyncio.wait_for(rom.open(ns["SERIAL"], 115200), timeout=10)
        ns["durable"](
            root, "bsl-entry-intent.json",
            {"attempts": 1, "usb_already_open": True, "consumed_before_send": True},
        )
        ha.enter_bsl()
        await asyncio.sleep(1)
        discarded = 0
        for _ in range(48):
            try:
                chunk = await asyncio.wait_for(rom.reader.read(128), 0.015)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            discarded += len(chunk)
            ns["need"](discarded <= 4096, "RECOVERY_STALE_BYTE_BOUND")
        ns["need"](
            await asyncio.wait_for(rom.synchronize(), 10), "RECOVERY_ROM_SYNC"
        )
        ns["need"](
            await asyncio.wait_for(rom.get_chip_id(), 10) == 0xF000,
            "RECOVERY_ROM_CHIP",
        )
        for address, checksum in expected_crc.items():
            actual = await asyncio.wait_for(rom.crc32(int(address), 8192), 10)
            ns["need"](actual == checksum, "RECOVERY_APP_CCFG_CRC")
        await rom.enable_fast_reads()
        capture = await sparse(
            rom,
            prior_full_verified=expected,
            expected_identity_sha256=ns["ROM_ID"],
            total_timeout_seconds=60,
        )
        await rom.assert_read_status()
        before = ns["read"](ns["PRIVATE"] / "fresh-sparse-snapshot.bin")
        candidate = ns["candidate"]()
        abi = ns["load"](ns["CANDIDATE"] / "security-native-abi.json")
        # ARM64 reader belongs to the separately sealed writer package.
        reader = ns["_recovery_writer"] / "security-reader-aarch64"
        bindings = {
            "capture_sha256": ns["sha"](capture.snapshot),
            "baseline_capture_sha256": ns["sha"](before),
            "abi_sha256": ns["sha"](security_model.abi_tool.canonical(abi)),
            "reader_sha256": ns["file_sha"](reader),
            "profile_sha256": candidate["profile_sha256"],
            "native_manifest_sha256": candidate["native_manifest_sha256"],
        }
        result = security_model.preflight(
            capture=capture.snapshot, baseline=before, abi=abi, reader=reader,
            bindings=bindings, runtime_upgrade=True,
            runtime_inventory_peers=ns["runtime_inventory_peers"](),
        )
        ns["durable"](root, "fresh-rom-snapshot.bin", capture.snapshot)
        ns["durable"](root, "security-receipt.json", result)
        ns["need"](
            result["status"] == "PASS_RETAINED_SECURITY_OFFLINE_ONLY",
            "RECOVERY_SECURITY_FAILED",
        )
        ns["durable"](
            root, "rom-result.json",
            {
                "chip_id": "0xf000", "read_only": True, "all88_crc_verified": True,
                "security_pass": True, "app_written": False,
                "nv_written": False, "ccfg_written": False,
            },
        )
    finally:
        await rom.close()


def execute(ns, package, package_pin, write_plan_pin, recovery_plan_pin, ha):
    need = ns["need"]
    ns["sealed_tree"](package, "PACKAGE.json", package_pin)
    writer, prior_owner, evidence, dep = _checked(
        ns, package, write_plan_pin, ha
    )
    root = ns["PRIVATE"] / ROOT_NAME
    ns["private_root"](root)
    need(
        {x.name for x in root.iterdir()} == {"plan.json"},
        "RECOVERY_PHASE_ALREADY_CONSUMED",
    )
    record = ns["load"](root / "plan.json")
    need(
        ns["sha"](ns["canonical"](record)) == recovery_plan_pin
        and all(record.get(key) == value for key, value in evidence.items())
        and 0 <= time.time() - record["created_at"] < MAX_PLAN_AGE_SECONDS,
        "RECOVERY_PLAN_EXPIRED_OR_DRIFTED",
    )
    ns["durable"](
        root, "execute-intent.json",
        {"at": time.time(), "consumed_before_send": True,
         "rom_entries": 1, "app_boots": 1, "host_starts": 1,
         "flash_writes": 0, "nv_writes": 0, "ccfg_writes": 0},
    )
    try:
        ns["_recovery_writer"] = writer
        asyncio.run(_rom_observe(ns, root, ha, dep, record["expected_crc32"]))
        ha.policy()
        ha.proof(False)
        need(
            ha.management() == record["management_sha256"],
            "RECOVERY_BOARD_CHANGED_AFTER_ROM",
        )
        ns["durable"](
            root, "app-boot-intent.json",
            {"at": time.time(), "attempts": 1, "rom_closed": True,
             "consumed_before_send": True},
        )
        ha.restart_radio()
        time.sleep(4)
        need(
            ns["Path"](ns["SERIAL"]).is_char_device(),
            "RECOVERY_USB_NOT_RETURNED",
        )
        ha.policy()
        ha.proof(False)
        ns["durable"](
            root, "host-start-intent.json",
            {"at": time.time(), "attempts": 1, "consumed_before_send": True,
             "external_startup_requests": 0},
        )
        ack = True
        try:
            ha.owner_action("start")
        except Exception:
            ack = False
        deadline = time.monotonic() + 30
        current = None
        while time.monotonic() < deadline:
            try:
                current = ha.inspect()
            except Exception:
                current = None
            if (
                current and current["running"] and current["image"] == ns["IMAGE"]
                and current != prior_owner
            ):
                break
            time.sleep(0.5)
        need(
            current is not None and current["running"]
            and current["image"] == ns["IMAGE"]
            and current != prior_owner,
            "RECOVERY_HOST_START_UNKNOWN_NO_RETRY",
        )
        ha.proof(True)
        result = {
            "status": "V6_ROM_ROUNDTRIP_HOST_RUNNING_PENDING_SERVING",
            "source": V6_SOURCE, "host_ack": ack,
            "firmware_writes": 0, "nv_writes": 0, "ccfg_writes": 0,
        }
        ns["durable"](root, "result.json", result)
        return result
    except BaseException as exc:
        ns["durable"](
            root, "failure.json",
            {"status": "HELD_NO_AUTOMATIC_RETRY",
             "error_type": type(exc).__name__, "at": time.time()},
        )
        raise
