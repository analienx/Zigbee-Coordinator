"""Proposed R4 B4 v4 SYS F1 protocol, independently versioned from v3 SYS F0.

Pure bounded decoder: no serial, radio, files, secrets or false radio-epoch
continuity. Source-level diagnostic data are only valid if native firmware
proves their producers. Nonce correlation disambiguates late SRSPs, but does
NOT authenticate the peer or prove a radio reboot.
"""
from dataclasses import dataclass
import struct
from b4_protocol import frame, SOF, fcs, SRSP_SYS

V4_OPCODE = 0xF1
V4_REQUEST_BYTES = 8
V4_RESPONSE_BYTES = 160
V4_MAGIC = b"R4D4"
V4_BOOT_CAPABILITY = 1
V4_NONCE_CAPABILITY = 2
V4_VALID_SYNC = 0x3F
V4_VALID_ASYNC = 0x2C
HEADER = struct.Struct("<4sBBHIIQII")
COUNTERS = struct.Struct("<25I")
TAIL = struct.Struct("<8sIQHHI")
assert HEADER.size == 32 and COUNTERS.size == 100 and TAIL.size == 28
assert HEADER.size + COUNTERS.size + TAIL.size == V4_RESPONSE_BYTES

class InvalidV4(ValueError):
    """Malformed/uncorrelated v4 observations must not reach the oracle."""

@dataclass(frozen=True)
class V4Sample:
    abi: int
    validity_mask: int
    sequence: int
    radio_epoch: int | None
    boot_epoch_qualified: bool
    reset_reason: int
    source_fingerprint: int
    abi_minor: int
    counters: tuple[int | None, ...]
    # The echoed nonce is deliberately NOT persisted in any host telemetry.

def request_frame(nonce: bytes) -> bytes:
    if type(nonce) is not bytes or len(nonce) != 8 or nonce == bytes(8):
        raise InvalidV4("host must supply a nonzero cryptographic 64-bit request nonce")
    return frame(0x21, V4_OPCODE, nonce)

def decode_payload(body: bytes, *, expected_nonce: bytes) -> V4Sample:
    if type(body) is not bytes or len(body) != V4_RESPONSE_BYTES:
        raise InvalidV4("v4 response length is not exactly 160 bytes")
    if type(expected_nonce) is not bytes or len(expected_nonce) != 8 or expected_nonce == bytes(8):
        raise InvalidV4("caller did not supply a qualified nonce")
    magic, major, flags, length, caps, valid, boot, uptime, seq = HEADER.unpack_from(body)
    values = COUNTERS.unpack_from(body, HEADER.size)
    nonce, reset, fingerprint, minor, status, reserved = TAIL.unpack_from(body, 132)
    if magic != V4_MAGIC or major != 4 or length != V4_RESPONSE_BYTES or flags != 0:
        raise InvalidV4("v4 signature/flags/size mismatch")
    if caps not in (V4_NONCE_CAPABILITY, V4_NONCE_CAPABILITY | V4_BOOT_CAPABILITY):
        raise InvalidV4("v4 capability bitset invalid")
    if valid not in (V4_VALID_SYNC, V4_VALID_ASYNC):
        raise InvalidV4("unproven counter validity")
    if nonce != expected_nonce:
        raise InvalidV4("stale or misrouted diagnostic SRSP nonce")
    if minor != 0 or reserved != 0 or fingerprint == 0 or seq == 0:
        raise InvalidV4("invalid minor/fingerprint/sequence/reserved")
    if uptime != 0:
        # Source has not qualified a monotonic radio tick provider.
        raise InvalidV4("unqualified uptime field must be zero")
    if status not in (0, 1) or status != (1 if caps & V4_BOOT_CAPABILITY else 0):
        raise InvalidV4("boot provider status and capability disagree")
    if (status == 0 and boot != 0) or (status == 1 and boot == 0):
        raise InvalidV4("boot token absent or forged")
    if any(value != 0 for i, value in enumerate(values) if not (valid & (1 << i))):
        raise InvalidV4("unqualified counter contains nonzero value")
    if values[2] > values[3] or ((valid & 3) and values[0] > values[1]):
        raise InvalidV4("NPI queue depth exceeds historical high-water mark")
    return V4Sample(4, valid, seq, boot if status else None, status == 1,
                    reset, fingerprint, minor, tuple(v if valid & (1 << i) else None
                                                    for i, v in enumerate(values)))

def decode_frame(raw: bytes, *, expected_nonce: bytes) -> V4Sample:
    if type(raw) is not bytes or len(raw) != V4_RESPONSE_BYTES + 5:
        raise InvalidV4("v4 UNPI total frame length mismatch")
    if raw[0] != SOF or raw[1] != V4_RESPONSE_BYTES or raw[2:4] != bytes((SRSP_SYS, V4_OPCODE)):
        raise InvalidV4("v4 opcode/SRSP header mismatch")
    if fcs(raw[1:]) != 0:
        raise InvalidV4("UNPI FCS mismatch")
    return decode_payload(raw[4:-1], expected_nonce=expected_nonce)

def continuous_epoch(a: V4Sample, b: V4Sample, *, source_qualified=False) -> bool:
    """Refuse deltas unless separately proven native per-boot entropy exists.

    Status 1 alone is insufficient; native initialization ownership, one-shot
    entropy producer, and exact ELF must be independently audited.
    Even then, reject sequence rollover and source-image changes.
    """
    return (source_qualified is True and a.boot_epoch_qualified and b.boot_epoch_qualified
            and a.radio_epoch is not None and a.radio_epoch == b.radio_epoch
            and a.source_fingerprint == b.source_fingerprint
            and 0 < a.sequence < b.sequence <= 0xFFFFFFFF)
