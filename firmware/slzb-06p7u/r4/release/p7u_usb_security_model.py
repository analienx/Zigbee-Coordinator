"""Independent, zero-write owner-to-silicon network security reconciliation.

This is an OFFLINE safety gate, not a TI NV reader, firmware restoration proof,
or authorization to flash. Raw owner backups and TI reader outputs are secret.
Public reports expose only counts and reason codes; never IEEE, PAN, keys or
unredacted per-peer results.

The genuine native TI reader must separately parse the actual NVOCMP image.
The firmware's compiled trust-center checks must independently PASS as well.
No missing historical identity is waived by matching the fresh backup.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import hashlib
import json

SCHEMA = "p7u-usb-owner-security-reconciliation-v1"
HISTORICAL_REQUIRED = 107


class SecurityHold(ValueError):
    """Safe reason codes only; never interpolate secret-bearing values."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise SecurityHold(code)


def hex_bytes(value: Any, size: int, *, code: str) -> bytes:
    require(type(value) is str, code)
    s = value.removeprefix("0x").removeprefix("0X")
    require(len(s) == size * 2, code)
    try:
        b = bytes.fromhex(s)
    except ValueError:
        raise SecurityHold(code) from None
    require(len(b) == size, code)
    return b


def counter(value: Any, *, code: str) -> int:
    require(type(value) is int and 0 <= value <= 0xffffffff, code)
    return value


def byte_number(value: Any, *, code: str) -> int:
    if type(value) is int:
        require(0 <= value <= 0xffff, code)
        return value
    require(type(value) is str, code)
    try:
        n = int(value, 16)
    except ValueError:
        raise SecurityHold(code) from None
    require(0 <= n <= 0xffff, code)
    return n


@dataclass(frozen=True)
class Backup:
    coordinator: bytes
    pan: int
    extended_pan: bytes
    channel: int
    update: int
    level: int
    network_key: bytes
    sequence: int
    frame_counter: int
    seed: bytes
    # Keys are always indexed by peer IEEE. Never compare unordered key sets.
    peers: dict[bytes, tuple[bytes | None, int | None, int | None, bool]]


def parse_backup(raw: dict) -> Backup:
    """Strict backup decoder: absent counters remain absent, never zero-filled."""
    require(type(raw) is dict and type(raw.get("devices")) is list,
            "OWNER_BACKUP_SCHEMA_INVALID")
    key = raw.get("network_key")
    specific = raw.get("stack_specific")
    require(type(key) is dict and type(specific) is dict and
            type(specific.get("zstack")) is dict, "OWNER_SECURITY_FIELDS_MISSING")
    devices = {}
    for row in raw["devices"]:
        require(type(row) is dict, "OWNER_DEVICE_INVALID")
        ieee = hex_bytes(row.get("ieee_address"), 8, code="OWNER_IEEE_INVALID")
        require(ieee not in devices and ieee not in (bytes(8), b"\xff" * 8),
                "OWNER_DUPLICATE_OR_INVALID_IEEE")
        link = row.get("link_key")
        require(link is None or type(link) is dict, "OWNER_LINK_SCHEMA_INVALID")
        material = None
        tx = rx = None
        if link is not None:
            if link.get("key") is not None:
                material = hex_bytes(link["key"], 16, code="OWNER_LINK_KEY_INVALID")
            if "tx_counter" in link:
                tx = counter(link["tx_counter"], code="OWNER_LINK_COUNTER_INVALID")
            if "rx_counter" in link:
                rx = counter(link["rx_counter"], code="OWNER_LINK_COUNTER_INVALID")
        require(type(row.get("is_child")) is bool, "OWNER_DEVICE_ROLE_MISSING")
        devices[ieee] = (material, tx, rx, row["is_child"])
    ch = raw.get("channel")
    update = raw.get("nwk_update_id")
    level = raw.get("security_level")
    seq = key.get("sequence_number")
    for val, hi, name in ((ch, 26, "OWNER_CHANNEL_INVALID"),
                          (update, 255, "OWNER_UPDATE_INVALID"),
                          (level, 7, "OWNER_SECURITY_LEVEL_INVALID"),
                          (seq, 255, "OWNER_SEQUENCE_INVALID")):
        require(type(val) is int and 0 <= val <= hi, name)
    require(11 <= ch <= 26, "OWNER_CHANNEL_INVALID")
    require(type(raw.get("channel_mask")) is list and
            ch in raw["channel_mask"], "OWNER_CHANNEL_MASK_MISMATCH")
    return Backup(
        hex_bytes(raw.get("coordinator_ieee"), 8, code="OWNER_COORDINATOR_INVALID"),
        byte_number(raw.get("pan_id"), code="OWNER_PAN_INVALID"),
        hex_bytes(raw.get("extended_pan_id"), 8, code="OWNER_EXTENDED_PAN_INVALID"),
        ch, update, level,
        hex_bytes(key.get("key"), 16, code="OWNER_NETWORK_KEY_INVALID"),
        seq, counter(key.get("frame_counter"), code="OWNER_NWK_COUNTER_MISSING"),
        hex_bytes(specific["zstack"].get("tclk_seed"), 16, code="OWNER_SEED_INVALID"),
        devices)


def _load_ti():
    # Imports resolve in the sealed release package, not a mutable worktree.
    import stock20260311_security_preflight as ti
    return ti


def _silicon_owner_fields(records: dict, abi: dict) -> dict:
    """Diagnostic read-only projection, not inspect_state/firmware PASS."""
    ti = _load_ti()
    nib = ti.get(records, 0, 0x21, abi["structs"]["nwkIB_t"]["size"])
    netkey = ti.get(records, 0, 0x3a, abi["structs"]["nwkKeyDesc"]["size"])
    aps = {}
    headers = ti.get(records, 0, 0x4c)
    hdr = abi["structs"]["nvDeviceListHdr_t"]["size"]
    item = abi["structs"]["ZDSecMgrEntry_t"]["size"]
    count = ti.number(headers[:hdr], abi, "nvDeviceListHdr_t", "numRecs")
    require(count <= 3 and len(headers) >= hdr + 3 * item,
            "SILICON_APS_HEADER_INVALID")
    addresses = {}
    for (system, resource, sub), raw in records.items():
        if system != 1 or resource != 1:
            continue
        user = ti.number(raw, abi, "AddrMgrEntry_t", "user")
        peer = ti.field(raw, abi, "AddrMgrEntry_t", "extAddr")
        if user == 0xff and raw == b"\xff" * len(raw):
            continue
        if user == 0 or not ti.real(peer):
            continue
        identity = peer[::-1]
        require(identity not in addresses.values(),
                "SILICON_DUPLICATE_ADDRESS_IDENTITY")
        addresses[sub] = identity
    for index in range(3):
        entry = headers[hdr + index * item:hdr + (index + 1) * item]
        ami = ti.number(entry, abi, "ZDSecMgrEntry_t", "ami")
        if ami == 0xfffe:
            continue
        keyid = ti.number(entry, abi, "ZDSecMgrEntry_t", "keyNvId")
        require(ami in addresses and keyid < 3 and addresses[ami] not in aps,
                "SILICON_APS_ASSOCIATION_INVALID")
        row = ti.get(records, 6, keyid, abi["structs"]["APSME_ApsLinkKeyNVEntry_t"]["size"])
        aps[addresses[ami]] = (
            ti.field(row, abi, "APSME_ApsLinkKeyNVEntry_t", "key"),
            ti.number(row, abi, "APSME_ApsLinkKeyNVEntry_t", "txFrmCntr"),
            ti.number(row, abi, "APSME_ApsLinkKeyNVEntry_t", "rxFrmCntr"))
    require(len(aps) == count, "SILICON_APS_LIVE_COUNT_MISMATCH")
    return {
        "coordinator": ti.get(records, 0, 1, 8)[::-1],
        "trust_center_raw": ti.get(records, 0, 0x71, 8),
        "pan": ti.number(nib, abi, "nwkIB_t", "nwkPanId"),
        "extended_pan": ti.field(nib, abi, "nwkIB_t", "extendedPANID")[::-1],
        "channel": ti.number(nib, abi, "nwkIB_t", "nwkLogicalChannel"),
        "update": ti.number(nib, abi, "nwkIB_t", "nwkUpdateId"),
        "level": ti.number(nib, abi, "nwkIB_t", "SecurityLevel"),
        "network_key": ti.field(netkey, abi, "nwkKeyDesc", "key"),
        "sequence": ti.number(netkey, abi, "nwkKeyDesc", "keySeqNum"),
        "seed": ti.get(records, 0, 0x101, 16),
        "addresses": frozenset(addresses.values()),
        "aps": aps,
    }


def reconcile(*, historical: dict, fresh: dict, records: dict, abi: dict,
              native_preflight_pass: bool = False,
              candidate_restoration_pass: bool = False,
              baseline_counter_floor: int | None = None) -> dict:
    """Independent owner mapping; conservatively HOLD absent genuine proofs.

    Caller must run actual TI reader on authenticated current bytes first.
    On failure this report carries codes and counts only, never secrets.
    """
    report = {"schema": SCHEMA, "status": "HOLD",
              "flash_authorized": False, "nv_write_authorized": False,
              "historical_expected": HISTORICAL_REQUIRED,
              "native_preflight_pass": native_preflight_pass is True,
              "candidate_restoration_pass": candidate_restoration_pass is True,
              "reason_codes": []}
    reasons = []
    def check(ok, code):
        if not ok and code not in reasons:
            reasons.append(code)
    try:
        old, now = parse_backup(historical), parse_backup(fresh)
        live = _silicon_owner_fields(records, abi)
        old_ids, fresh_ids, silicon_ids = set(old.peers), set(now.peers), set(live["addresses"])
        report.update(historical_devices=len(old_ids), fresh_devices=len(fresh_ids),
                      silicon_devices=len(silicon_ids),
                      silicon_matching_historical=len(old_ids & silicon_ids),
                      missing_historical=len(old_ids - silicon_ids),
                      fresh_missing_historical=len(old_ids - fresh_ids),
                      aps_associations_checked=len(live["aps"]))
        check(len(old_ids) == HISTORICAL_REQUIRED, "HISTORICAL_107_REQUIRED")
        check(old_ids <= fresh_ids, "FRESH_BACKUP_HISTORICAL_INVENTORY_MISSING")
        check(old_ids <= silicon_ids, "SILICON_HISTORICAL_INVENTORY_MISSING")
        check(fresh_ids <= old_ids and silicon_ids <= old_ids,
              "UNEXPECTED_PEER_MEMBERSHIP")
        for name in ("coordinator", "pan", "extended_pan", "channel", "update",
                     "level", "network_key", "sequence", "seed"):
            check(getattr(old, name) == getattr(now, name),
                  "OWNER_HISTORICAL_NETWORK_OR_KEY_CHANGED")
            check(getattr(now, name) == live[name],
                  "SILICON_OWNER_NETWORK_OR_KEY_MISMATCH")
        check(live["trust_center_raw"] == live["coordinator"][::-1],
              "SILICON_TC_NOT_COORDINATOR")
        check(old.frame_counter <= now.frame_counter,
              "OWNER_NETWORK_COUNTER_REGRESSION")
        check(type(baseline_counter_floor) is int and
              baseline_counter_floor > 0 and baseline_counter_floor >= now.frame_counter,
              "SILICON_NETWORK_COUNTER_FLOOR_NOT_PROVEN")
        check(native_preflight_pass is True, "NATIVE_SECURITY_PREFLIGHT_NOT_PASS")
        check(candidate_restoration_pass is True, "CANDIDATE_RESTORATION_NOT_PASS")
        # Bind both owner snapshots by peer, never by unordered key material.
        for ieee in old_ids & fresh_ids:
            old_link, old_tx, old_rx, old_child = old.peers[ieee]
            new_link, new_tx, new_rx, new_child = now.peers[ieee]
            check(old_child == new_child, "OWNER_PEER_ROLE_CHANGED")
            check(old_link == new_link, "OWNER_PEER_KEY_REASSIGNED")
            for before, after in ((old_tx, new_tx), (old_rx, new_rx)):
                if before is not None:
                    check(after is not None and after >= before,
                          "OWNER_PEER_COUNTER_REGRESSION")
        for ieee, (key, tx, rx) in live["aps"].items():
            check(ieee in now.peers and ieee in old.peers,
                  "APS_REFERENCES_UNKNOWN_HISTORICAL_PEER")
            if ieee not in now.peers or ieee not in old.peers:
                continue
            original = old.peers[ieee]
            latest = now.peers[ieee]
            check(original[0] is not None and key == original[0] == latest[0],
                  "APS_PEER_KEY_ASSOCIATION_CHANGED")
            # Backup counters can prove a floor only when present.
            for observed, before, after in ((tx, original[1], latest[1]),
                                            (rx, original[2], latest[2])):
                check(before is not None and after is not None and
                      observed >= before and observed >= after,
                      "APS_PEER_COUNTER_FLOOR_NOT_PROVEN")
    except (SecurityHold, KeyError, TypeError, IndexError, ValueError) as err:
        reasons.append(str(err) if isinstance(err, SecurityHold) else
                       "OWNER_OR_SILICON_SCHEMA_HOLD")
    report["reason_codes"] = sorted(set(reasons))
    report["status"] = "PASS_OWNER_SECURITY_OFFLINE_ONLY" if not reasons else "HOLD"
    return report
