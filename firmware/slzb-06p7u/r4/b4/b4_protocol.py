"""Offline, strict MT SYS F0 wire oracle for B4. NOT an active radio client.

Proposed R4 v3 and historical P10 v2 are separate ABIs. This module never
opens a serial port, emits a request, or asserts a radio epoch.
"""
from dataclasses import dataclass
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from r4_diag_reference import V2_SIZE, V3_SIZE, decode_v2, decode_v3

SOF = 0xFE
SREQ_SYS = 0x21
SRSP_SYS = 0x61
DIAG_ID = 0xF0
MAX_MT_PAYLOAD = 255
MAX_DIAGNOSTIC_PAYLOAD = max(V2_SIZE, V3_SIZE)
MAX_BUFFER = MAX_MT_PAYLOAD + 5
# Source-qualified boot identity is currently UNPROVEN, despite a wire cap.

def _payload(value):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError("MT input must be bytes")
    return bytes(value)

def fcs(data):
    checksum = 0
    for b in data:
        checksum ^= b
    return checksum

def frame(cmd0, cmd1, payload=b""):
    payload = _payload(payload)
    if len(payload) > MAX_MT_PAYLOAD:
        raise ValueError("MT payload exceeds one-byte length")
    if type(cmd0) is not int or type(cmd1) is not int or not 0 <= cmd0 <= 255 or not 0 <= cmd1 <= 255:
        raise ValueError("invalid MT command")
    body = bytes((len(payload), cmd0, cmd1)) + payload
    return bytes((SOF,)) + body + bytes((fcs(body),))

def decode_frame(raw, *, expected_cmd0=SRSP_SYS, expected_cmd1=DIAG_ID):
    """Strict *single frame* decode: exact size, correct FCS and command."""
    raw = _payload(raw)
    if len(raw) < 5 or raw[0] != SOF:
        raise ValueError("invalid MT header")
    size = raw[1]
    if size not in (V2_SIZE, V3_SIZE):
        raise ValueError("unsupported F0 payload length")
    if len(raw) != size + 5:
        raise ValueError("incomplete or overlong MT frame")
    if raw[2] != expected_cmd0 or raw[3] != expected_cmd1:
        raise ValueError("not a SYS F0 SRSP from the existing owner")
    if fcs(raw[1:]) != 0:
        raise ValueError("MT FCS mismatch")
    body = raw[4:-1]
    # No fallback from a malformed v3 to v2, or vice versa.
    if size == V2_SIZE:
        return decode_v2(body)
    return decode_v3(body)

@dataclass
class BoundedMtStream:
    """Offline bounded parser: cap memory, reject malformed frames, resync.

    Caller must inject already-captured, sanitized owner data. This is NOT a
    serial reader or an existing-owner callback implementation.
    """
    max_frames_per_feed: int = 64

    def __post_init__(self):
        if type(self.max_frames_per_feed) is not int or not 1 <= self.max_frames_per_feed <= 256:
            raise ValueError("invalid parsing budget")
        self._buf = bytearray()
        self.rejected = 0
        self.oversize_input = 0

    def feed(self, chunk):
        chunk = _payload(chunk)
        if len(chunk) > 4096:
            self.oversize_input += 1
            raise ValueError("input chunk exceeds reviewed bound")
        # All prior accumulation is at most MAX_BUFFER; incoming chunks have
        # fixed cap. No other memory grows across calls.
        self._buf.extend(chunk)
        samples = []
        examined = 0
        while self._buf and examined < self.max_frames_per_feed:
            pos = self._buf.find(SOF)
            if pos == -1:
                self.rejected += 1
                self._buf.clear()
                break
            if pos:
                self.rejected += 1
                del self._buf[:pos]
            if len(self._buf) < 2:
                break
            size = self._buf[1]
            if size not in (V2_SIZE, V3_SIZE):
                self.rejected += 1
                del self._buf[0]
                examined += 1
                continue
            if len(self._buf) < size + 5:
                break
            candidate = bytes(self._buf[:size + 5])
            try:
                value = decode_frame(candidate)
            except ValueError:
                self.rejected += 1
                del self._buf[0]  # overlapping SOF may begin a valid frame
            else:
                samples.append(value)
                del self._buf[:size + 5]
            examined += 1
        # Reject excessive trailing input rather than discarding a potentially
        # valid partial frame and falsely claiming it was decoded.
        if len(self._buf) > MAX_BUFFER:
            self.rejected += 1
            self._buf.clear()
        return samples

    @property
    def buffered_bytes(self):
        return len(self._buf)
