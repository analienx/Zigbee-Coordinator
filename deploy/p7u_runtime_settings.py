"""Read-only concentrator checks through an existing ZNP transport owner.

This module opens no serial port/socket and never writes NV or resets a radio.
The owner supplies an async ``exchange(complete_mt_frame)`` callback. Persisted
NV values and RAM observations are separate evidence: compiler defaults alone
do not establish either one after restoring a coordinator backup.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping

Exchange = Callable[[bytes], Awaitable[bytes]]
NV_IDS = {"enable": 0x0032, "discovery_seconds": 0x0033,
          "radius": 0x0034, "route_cache": 0x0036}
EXPECTED = {"enable": 1, "discovery_seconds": 60, "radius": 10,
            "route_cache": 1}


def _frame(cmd0: int, cmd1: int, payload: bytes) -> bytes:
    body = bytes((len(payload), cmd0, cmd1)) + payload
    checksum = 0
    for value in body:
        checksum ^= value
    return b"\xfe" + body + bytes((checksum,))


def _read_response(frame: bytes) -> int:
    if not isinstance(frame, bytes) or not 7 <= len(frame) <= 260:
        raise ValueError("INVALID_NV_READ_FRAME")
    if frame[0] != 0xFE or len(frame) != frame[1] + 5:
        raise ValueError("INVALID_NV_READ_FRAME_LENGTH")
    if frame[2:4] != b"\x61\x08":
        raise ValueError("UNEXPECTED_NV_READ_COMMAND")
    checksum = 0
    for value in frame[1:]:
        checksum ^= value
    if checksum:
        raise ValueError("INVALID_NV_READ_CHECKSUM")
    payload = frame[4:-1]
    if payload[0] != 0:
        raise ValueError("NV_READ_FAILED")
    if len(payload) != 3 or payload[1] != 1:
        raise ValueError("EXPECTED_ONE_BYTE_NV_ITEM")
    return payload[2]


async def read_persisted_concentrator(exchange: Exchange) -> dict[str, int]:
    """Read four public one-byte NV items, sequentially, via the current owner.

    Timeout/serialization belongs to that owner, as with its normal ZNP SRSP
    handling. An error aborts without retries or partial-success reporting.
    """
    result = {}
    for name, item in NV_IDS.items():
        request = _frame(0x21, 0x08, item.to_bytes(2, "little") + b"\x00")
        result[name] = _read_response(await exchange(request))
    return result


def assess_concentrator(persisted: Mapping[str, int],
                       runtime: Mapping[str, int] | None) -> dict:
    """Require both persisted and current RAM values before accepting R2 setup.

    RAM comes from a read-only diagnostic snapshot taken after network startup.
    A caller must not substitute compiler defaults or copy persisted values into
    this argument. No corrective write is suggested or performed on mismatch.
    """
    def checked(values: Mapping[str, int], label: str) -> dict[str, int]:
        if set(values) != set(EXPECTED):
            raise ValueError("INCOMPLETE_" + label + "_CONCENTRATOR_VALUES")
        if any(type(value) is not int or not 0 <= value <= 255
               for value in values.values()):
            raise ValueError("INVALID_" + label + "_CONCENTRATOR_VALUE")
        return dict(values)

    nv = checked(persisted, "PERSISTED")
    ram = None if runtime is None else checked(runtime, "RUNTIME")
    differences = {
        "persisted": {name: {"expected": expected, "observed": nv[name]}
                      for name, expected in EXPECTED.items() if nv[name] != expected},
        "runtime": None if ram is None else {
            name: {"expected": expected, "observed": ram[name]}
            for name, expected in EXPECTED.items() if ram[name] != expected},
    }
    return {"schema_version": 1, "expected": dict(EXPECTED),
            "persisted": nv, "runtime": ram, "differences": differences,
            "settings_verified": ram is not None and not differences["persisted"]
                                 and not differences["runtime"],
            "routing_behavior_verified": False,
            "limitation": "Matching settings require separate over-air many-to-one, "
                          "route-record and routed-delivery acceptance."}
