"""Offline, measured feasibility gate for a 60-second P7U cutover.

The time budget is counted from entering maintenance (stop Z2M) until confirmed
production Z2M coordinator startup. Compilation, upstream CI, backup and full
security baseline preparation must complete BEFORE entering that window.

No serial I/O here. A 60-second promise is not made unless the measured
effective throughput and realistic startup/erase overhead permit it.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math

FLASH_BYTES=0xB0000
SECTOR_BYTES=0x2000
APP_LIMIT=0xA0000
BOOT=0xAC000
TARGET_SECONDS=60.0

def _digest(blob):
    return hashlib.sha256(blob).hexdigest()

def _require(ok, code):
    if not ok:
        raise ValueError("P7U_CUTOVER_" + code)

@dataclass(frozen=True)
class MeasuredLink:
    """Wire measurements from an actual nonmutating qualification.

    write_bytes_per_second must account for the ROM's per-packet ACK+status.
    read_bytes_per_second reflects verified counted MEMORY_READ frames.
    crc_seconds captures each native ROM CRC command and response; identity_seconds
    measures live chip/FCFG/CCFG identity checks. Use measured timings, not
    nominal UART bit rate.
    """
    read_bytes_per_second: float
    write_bytes_per_second: float
    erase_seconds: float
    crc_seconds: float
    stop_start_seconds: float
    bsl_entry_seconds: float
    security_seconds: float
    margin_seconds: float = 6.0
    identity_seconds: float = 0.1
    # Measured end-to-end costs; do not silently treat journaling and physical
    # serial/status fences as free just because they are not payload bytes.
    journal_seconds: float = 0.0
    serial_lifecycle_seconds: float = 0.0
    status_fence_seconds: float = 0.0

    def validate(self):
        values=vars(self)
        for name, value in values.items():
            _require(isinstance(value,(float,int)) and not isinstance(value,bool)
                     and math.isfinite(value) and value>=0, "INVALID_MEASUREMENT_"+name)
        _require(self.read_bytes_per_second>0 and self.write_bytes_per_second>0,
                 "MEASURED_THROUGHPUT_REQUIRED")
        _require(self.margin_seconds>=4, "MINIMUM_SAFETY_MARGIN")

@dataclass(frozen=True)
class CutoverEstimate:
    changed_sectors: tuple[int,...]
    write_bytes: int
    verify_bytes: int
    fresh_security_bytes: int
    rom_crc_calls: int
    identity_checks: int
    predicted_seconds: float
    fits_sixty_seconds: bool
    radio_budget_seconds: float
    immutable_hash: str
    # Includes the pre-vector 8-KiB boot-tail read, not just final readbacks.
    boot_tail_read_bytes: int = 0
    total_rom_read_bytes: int = 0


def inspect_delta(current: bytes, targets: dict[int, bytes], *,
                  protected_live_read_bytes: int, measurements: MeasuredLink):
    """Compute an honest budget; only APP + AC000 sectors can be programmed.

    Does NOT qualify a plan, keys, CCFG, restore counters or identity. It merely
    prevents deploying a physically impossible 60-second cutover.
    """
    _require(type(current) is bytes and len(current)==FLASH_BYTES, "BASELINE_SIZE")
    _require(type(targets) is dict and bool(targets), "SECTOR_TARGET_REQUIRED")
    _require(type(protected_live_read_bytes) is int and
             0<=protected_live_read_bytes<=0x10000 and
             protected_live_read_bytes%4==0, "SECURITY_CAPTURE_BOUNDS")
    measurements.validate()
    for address, image in targets.items():
        _require(type(address) is int and address%SECTOR_BYTES==0 and
                 (0<=address<APP_LIMIT or address==BOOT),
                 "WRITE_TO_PROTECTED_REGION")
        _require(type(image) is bytes and len(image)==SECTOR_BYTES,
                 "INVALID_SECTOR_BYTES")
    changed=tuple(address for address in sorted(targets)
                  if targets[address]!=current[address:address+SECTOR_BYTES])
    # Full per-written-sector byte readback is nonnegotiable. CRC of all 88
    # sectors is a cheap pre/post tripwire, but *not* an equivalent duplicate
    # full capture, nor sufficient for initial/unknown-state admission.
    write_bytes=len(changed)*SECTOR_BYTES
    verify_bytes=write_bytes
    fixed=(measurements.stop_start_seconds + measurements.bsl_entry_seconds +
           measurements.security_seconds + measurements.margin_seconds +
           measurements.journal_seconds + measurements.serial_lifecycle_seconds +
           measurements.status_fence_seconds)
    # Mirrors the exact transaction: sparse capture/admit, prewrite, and
    # final CRC parity; per-plan reserved-range guards; plus boot commit sweeps.
    # A naive two-full-CRC-sweep model massively undercounts commands.
    guard_size = lambda a: 8 + int(a < APP_LIMIT)
    guard_calls = sum(guard_size(a) for a in targets)
    guard_calls += sum(guard_size(a) for a in changed)
    boot_present = BOOT in targets
    boot_written = BOOT in changed
    full_sweeps = 4 + int(boot_present) + (3 if boot_written else 0)
    # _sector(rom,address) independently performs a CRC on every final 8-KiB
    # readback; the boot-tail pre-vector _sector additionally does a CRC.
    # Those calls were absent from the older model and surfaced in a real
    # instrumented transaction: 3 changed including boot -> 760; 25 -> 1178.
    crc_calls = full_sweeps*88 + guard_calls + len(changed) + int(boot_written)
    boot_tail_read_bytes = SECTOR_BYTES if boot_written else 0
    read_bytes = verify_bytes + protected_live_read_bytes + boot_tail_read_bytes
    identity_checks = 2 + full_sweeps - 1 + len(targets) + len(changed)
    radio=(write_bytes/measurements.write_bytes_per_second +
           read_bytes/measurements.read_bytes_per_second +
           len(changed)*measurements.erase_seconds +
           crc_calls*measurements.crc_seconds +
           identity_checks*measurements.identity_seconds)
    total=fixed+radio
    # Source binding of the *estimate only*: not flash authorization.
    hash_input=json.dumps({"schema":"p7u-budget-source-bound-v2",
        "current_sha256":_digest(current),
        "targets_sha256":{str(a):_digest(targets[a]) for a in sorted(targets)},
        "changed":changed,"protected_live_read_bytes":protected_live_read_bytes,
        "measurements":vars(measurements),"crc_calls":crc_calls,
        "identity_checks":identity_checks,"boot_tail_read_bytes":boot_tail_read_bytes},
        sort_keys=True,separators=(',',':')).encode()
    return CutoverEstimate(changed,write_bytes,verify_bytes,protected_live_read_bytes,
                           crc_calls,identity_checks,round(total,2),
                           total <= TARGET_SECONDS,round(radio,2),
                           _digest(hash_input),boot_tail_read_bytes,read_bytes)
