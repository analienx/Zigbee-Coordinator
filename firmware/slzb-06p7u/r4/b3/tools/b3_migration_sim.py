#!/usr/bin/env python3
"""R4 B3 offline-only, SYNTHETIC migration consistency judge.

No hardware, no network, no restore operations and no original archive extraction.
The external --sha256 pin is required; manifest hashes are binding, not signatures.
All possible outcomes deny restore, flash and network mutation.
"""
import argparse
import hashlib
import io
import json
import re
import stat
import sys
import zipfile
import zlib
from datetime import datetime

SCHEMA = "r4-b3-synthetic-v1"
MEMBERS = ("manifest.json", "coordinator_backup.json", "z2m_database.json", "z2m_config.json")
MAX_ARCHIVE = 2_000_000
MAX_MEMBER = 500_000
MAX_COUNTER = 0xFFFFFFFF
SIM = re.compile(r"^SIM-[A-Z0-9_-]{1,64}$")
SHA = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_LAYOUTS = frozenset(("NV2", "NV3", "NV5"))


class EvidenceError(Exception):
    """Nonsecret failure code only."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def require(condition, code):
    if not condition:
        raise EvidenceError(code)


def json_strict(raw):
    def unique(pairs):
        out = {}
        for k, v in pairs:
            require(k not in out, "DUPLICATE_JSON_KEY")
            out[k] = v
        return out

    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeDecodeError, TypeError, RecursionError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("BAD_JSON") from None


def validate_archive(raw, expected_sha):
    require(isinstance(raw, bytes) and len(raw) <= MAX_ARCHIVE, "ARCHIVE_SIZE")
    require(isinstance(expected_sha, str) and bool(SHA.fullmatch(expected_sha)), "EXTERNAL_SHA_REQUIRED")
    require(hashlib.sha256(raw).hexdigest() == expected_sha, "EXTERNAL_SHA_MISMATCH")
    require(raw.startswith(bytes((0x50, 0x4B, 0x03, 0x04))),
            "ZIP_NON_CANONICAL_PREAMBLE")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            require(archive.comment == b"", "ZIP_COMMENT_FORBIDDEN")
            names = archive.namelist()
            require(len(names) == len(set(names)), "ZIP_DUPLICATE_MEMBER")
            require(len(names) == len(MEMBERS) and set(names) == set(MEMBERS),
                    "ZIP_MEMBER_SELECTION")
            contents = {}
            for entry in archive.infolist():
                mode = entry.external_attr >> 16
                require(not stat.S_ISLNK(mode), "ZIP_SYMLINK")
                require(entry.filename in MEMBERS and not entry.is_dir(), "ZIP_MEMBER_SELECTION")
                require(entry.file_size <= MAX_MEMBER and entry.compress_size <= MAX_ARCHIVE,
                        "ZIP_BOMB_LIMIT")
                try:
                    with archive.open(entry, "r") as fd:
                        data = fd.read(MAX_MEMBER + 1)
                except (OSError, RuntimeError, zipfile.BadZipFile, EOFError, zlib.error, ValueError):
                    raise EvidenceError("ZIP_CRC_FAILURE") from None
                require(len(data) == entry.file_size and len(data) <= MAX_MEMBER,
                        "ZIP_BOMB_LIMIT")
                contents[entry.filename] = data
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, OSError, zlib.error, ValueError):
        raise EvidenceError("INVALID_ARCHIVE") from None

    manifest = json_strict(contents["manifest.json"])
    require(isinstance(manifest, dict) and manifest.get("schema") == SCHEMA
            and manifest.get("synthetic") is True, "NON_SYNTHETIC_BUNDLE")
    require(set(manifest) == {"schema", "synthetic", "target_layout", "member_sha256"},
            "UNRECOGNIZED_MANIFEST_FIELDS")
    hashes = manifest.get("member_sha256")
    require(isinstance(hashes, dict) and set(hashes) == set(MEMBERS) - {"manifest.json"},
            "MANIFEST_MEMBERS")
    for member, digest in hashes.items():
        require(isinstance(digest, str) and bool(SHA.fullmatch(digest))
                and hashlib.sha256(contents[member]).hexdigest() == digest,
                "MEMBER_HASH_MISMATCH")
    payload = {name: json_strict(contents[name]) for name in MEMBERS if name != "manifest.json"}
    return manifest, payload


def sim(value):
    require(isinstance(value, str) and bool(SIM.fullmatch(value)), "NON_SYNTHETIC_ID")
    return value


def counter(value):
    require(type(value) is int and 0 <= value <= MAX_COUNTER, "INVALID_TX_COUNTER")
    return value


def identity(src):
    require(isinstance(src, dict), "INVALID_NETWORK_IDENTITY")
    keys = ("coordinator", "pan", "extpan", "channel", "nwk_key_ref", "key_sequence")
    require(set(src) == set(keys), "INVALID_NETWORK_IDENTITY")
    for key in ("coordinator", "pan", "extpan", "nwk_key_ref"):
        sim(src[key])
    require(type(src["channel"]) is int and 11 <= src["channel"] <= 26,
            "INVALID_NETWORK_IDENTITY")
    require(type(src["key_sequence"]) is int and 0 <= src["key_sequence"] <= 255,
            "INVALID_NETWORK_IDENTITY")
    return tuple(src[k] for k in keys)


def evaluate(manifest, data):
    findings = set()
    backups = data["coordinator_backup.json"]
    database = data["z2m_database.json"]
    config = data["z2m_config.json"]
    require(isinstance(backups, dict) and set(backups) == {"snapshots"}, "INVALID_BACKUP_SCHEMA")
    snapshots = backups["snapshots"]
    require(isinstance(snapshots, list) and 1 <= len(snapshots) <= 16,
            "INVALID_SNAPSHOT_COUNT")
    require(isinstance(database, dict) and set(database) == {"network", "devices"},
            "INVALID_DB_SCHEMA")
    require(isinstance(config, dict) and set(config) == {"network", "active_radio"},
            "INVALID_CONFIG_SCHEMA")
    base = identity(config["network"])
    require(identity(database["network"]) == base, "CROSS_NETWORK_CONFLICT")
    sim(config["active_radio"])
    devices = database["devices"]
    require(isinstance(devices, list) and len(devices) == len(set(map(str, devices)))
            and len(devices) <= 192, "INVALID_DEVICE_ROSTER")
    roster = set(sim(d) for d in devices)
    current = None
    floors = {}
    observed = {}
    dates = []
    highest_nwk_counter = 0
    for snap in snapshots:
        require(isinstance(snap, dict) and set(snap) ==
                {"network", "captured_utc", "source_radio", "online", "layout",
                 "security", "nwk_tx_counter"},
                "INVALID_SNAPSHOT_SCHEMA")
        require(identity(snap["network"]) == base, "CROSS_NETWORK_CONFLICT")
        require(isinstance(snap["captured_utc"], str)
                and bool(re.fullmatch(r"20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                                      snap["captured_utc"])), "INVALID_SNAPSHOT_TIME")
        try:
            datetime.fromisoformat(snap["captured_utc"].replace("Z", "+00:00"))
        except ValueError:
            raise EvidenceError("INVALID_SNAPSHOT_TIME") from None
        dates.append(snap["captured_utc"])
        nwk_tx = counter(snap["nwk_tx_counter"])
        highest_nwk_counter = max(highest_nwk_counter, nwk_tx)
        radio = sim(snap["source_radio"])
        require(type(snap["online"]) is bool, "INVALID_ONLINE_FLAG")
        require(isinstance(snap["layout"], str) and snap["layout"] in ALLOWED_LAYOUTS,
                "UNKNOWN_NV_LAYOUT")
        if snap["online"]:
            observed[radio] = True
        rows = snap["security"]
        require(isinstance(rows, list) and len(rows) <= 192, "INVALID_KEY_TABLE")
        entries = {}
        for row in rows:
            require(isinstance(row, dict) and set(row) ==
                    {"device", "key_ref", "tx_counter"}, "INVALID_KEY_RECORD")
            dev, key = sim(row["device"]), sim(row["key_ref"])
            tx = counter(row["tx_counter"])
            require(dev not in entries, "DUPLICATE_SECURITY_DEVICE")
            entries[dev] = (key, tx)
            if dev in floors:
                old_key, old_tx = floors[dev]
                if old_key != key:
                    findings.add("CHANGED_LINK_KEY")
                else:
                    floors[dev] = (key, max(old_tx, tx))
            else:
                floors[dev] = (key, tx)
        current = (snap, entries)
    require(dates == sorted(set(dates)), "SNAPSHOT_TIME_ORDER")
    latest, current_entries = current
    if latest["nwk_tx_counter"] < highest_nwk_counter:
        findings.add("NWK_TX_FLOOR_CONFLICT")
    if highest_nwk_counter == MAX_COUNTER:
        findings.add("NWK_COUNTER_OVERFLOW")
    if not current_entries or not roster:
        findings.add("EMPTY_SECURITY_TABLE")
    if floors.keys() - current_entries.keys():
        findings.add("DROPPED_HISTORICAL_SECURITY_RECORDS")
    require(latest["source_radio"] == config["active_radio"], "ACTIVE_RADIO_MISMATCH")
    missing = roster - current_entries.keys()
    extra = current_entries.keys() - roster
    if missing:
        findings.add("MISSING_SECURITY_RECORDS")
    if extra:
        findings.add("STALE_SECURITY_RECORDS")
    if len(observed) > 1:
        findings.add("SAME_IEEE_DOUBLE_ONLINE")
    for device, (key, tx) in current_entries.items():
        if device in floors:
            max_key, max_tx = floors[device]
            if max_key != key:
                findings.add("CHANGED_LINK_KEY")
            elif tx < max_tx:
                findings.add("COUNTER_FLOOR_CONFLICT")
            if max_tx == MAX_COUNTER:
                findings.add("COUNTER_OVERFLOW")
    layout = manifest.get("target_layout")
    require(isinstance(layout, str) and layout in ALLOWED_LAYOUTS,
            "UNKNOWN_TARGET_LAYOUT")
    if latest["layout"] != layout:
        findings.add("NV_LAYOUT_MISMATCH")
    # Digest binding cannot authenticate origin. This is merely an offline
    # synthetic rehearsal; even a completely matching fixture is NOT authority.
    findings = sorted(findings)
    return {"schema": "r4-b3-restore-decision-v1",
            "status": "NOT_RESTORE_READY" if findings else "OFFLINE_CONSISTENT_FOR_REVIEW",
            "reason_codes": findings,
            "counts": {"db_devices": len(roster), "latest_security_rows": len(current_entries),
                       "db_missing_security": len(missing), "security_not_in_db": len(extra),
                       "snapshots": len(snapshots)},
            "synthetic_only": True, "source_authentication": "NOT_ESTABLISHED",
            "restore_authorized": False, "flash_authorized": False,
            "network_mutation_authorized": False}


def judge(raw, expected_sha):
    try:
        manifest, data = validate_archive(raw, expected_sha)
        return evaluate(manifest, data)
    except (KeyError, TypeError, OverflowError, RecursionError):
        exc = EvidenceError("INVALID_INPUT_STRUCTURE")
    except EvidenceError as exc:
        pass
    # Every rejected structure MUST return a complete denial, never None.
    return {"schema": "r4-b3-restore-decision-v1", "status": "NOT_RESTORE_READY",
                "reason_codes": [exc.code], "synthetic_only": True,
                "source_authentication": "NOT_ESTABLISHED",
                "restore_authorized": False, "flash_authorized": False,
                "network_mutation_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="only synthetic four-file ZIP, no actual backups")
    parser.add_argument("--sha256", required=True,
                        help="SHA256 provided separately from the archive")
    args = parser.parse_args()
    try:
        with open(args.archive, "rb") as fd:
            data = fd.read(MAX_ARCHIVE + 1)
        decision = judge(data, args.sha256)
    except OSError:
        decision = judge(b"", args.sha256)
    print(json.dumps(decision, sort_keys=True, separators=(",", ":")))
    return 0 if decision["status"] == "OFFLINE_CONSISTENT_FOR_REVIEW" else 2


if __name__ == "__main__":
    sys.exit(main())
