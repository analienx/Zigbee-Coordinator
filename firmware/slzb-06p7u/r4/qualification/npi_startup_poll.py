#!/usr/bin/env python3
"""Bounded, side-effect-free TI MT readiness polling after a P7U reset.

No reset is sent here. Never assume a management HTTP reset ACK means the
radio UART is ready. The TCP bridge may connect before genuine TI NPI/MT
frames are accepted. Retry both framed SYS_PING and ten-byte SYS_VERSION.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import json
import time

PING_REQUEST = bytes.fromhex("fe00210120")
VERSION_REQUEST = bytes.fromhex("fe00210223")


def mt_response(buffer: bytes, command: int) -> bytes | None:
    """Return data of one complete, FCS-valid SYS SRSP (no secrets logged)."""
    for start in range(len(buffer)):
        if buffer[start] != 0xFE or start + 5 > len(buffer):
            continue
        count = buffer[start + 1]
        end = start + count + 5
        if count > 250 or end > len(buffer) or buffer[start + 2:start + 4] != bytes((0x61, command)):
            continue
        fcs = 0
        for value in buffer[start + 1:end]:
            fcs ^= value
        if fcs == 0:
            return buffer[start + 4:end - 1]
    return None


async def request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                  *, command: int, timeout: float) -> bytes:
    writer.write(PING_REQUEST if command == 1 else VERSION_REQUEST)
    await asyncio.wait_for(writer.drain(), timeout=timeout)
    pending = bytearray()
    async with asyncio.timeout(timeout):
        while len(pending) <= 4096:
            part = await reader.read(256)
            if not part:
                raise ConnectionError("BRIDGE_CLOSED")
            pending.extend(part)
            payload = mt_response(pending, command)
            if payload is not None:
                return payload
    raise TimeoutError("MISSING_VALID_SRSP")


async def probe(host: str, port: int, *, timeout: float = 1.2) -> bool:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    try:
        ping = await request(reader, writer, command=1, timeout=timeout)
        version = await request(reader, writer, command=2, timeout=timeout)
        return (len(ping) == 2 and int.from_bytes(ping, "little") & 1 != 0
                and len(version) == 10 and version[0] >= 1)
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=.7)
        except (TimeoutError, ConnectionError, OSError, RuntimeError):
            pass


async def poll(host: str, port: int, *, reset_monotonic: float | None = None,
               max_seconds: float = 40.0, retry_seconds: float = .35,
               probe_timeout: float = 1.2) -> dict:
    """Readiness receipt; never changes firmware or shares NPI payload bytes."""
    if not (0 < max_seconds <= 120 and .05 <= retry_seconds <= 5 and
            .05 <= probe_timeout <= 10):
        raise ValueError("INVALID_STARTUP_POLL_LIMITS")
    started = time.monotonic() if reset_monotonic is None else reset_monotonic
    failures: Counter[str] = Counter()
    count = 0
    while time.monotonic() - started < max_seconds:
        count += 1
        try:
            if await probe(host, port, timeout=probe_timeout):
                return {"ready": True,
                        "seconds_since_reset": round(time.monotonic() - started, 3),
                        "attempts": count, "retry_reasons": dict(failures)}
            failures["unexpected_response_shape"] += 1
        except (TimeoutError, OSError, ConnectionError):
            failures["transport_or_response_not_ready"] += 1
        remaining = max_seconds - (time.monotonic() - started)
        if remaining > 0:
            await asyncio.sleep(min(retry_seconds, remaining))
    return {"ready": False, "seconds_since_reset": round(time.monotonic() - started, 3),
            "attempts": count, "retry_reasons": dict(failures)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="P7U TCP bridge IP/DNS name")
    parser.add_argument("--port", type=int, default=6638)
    parser.add_argument("--max-seconds", type=float, default=40.0)
    parser.add_argument("--retry-seconds", type=float, default=.35)
    parser.add_argument("--probe-timeout", type=float, default=1.2)
    args = parser.parse_args()
    if not 0 < args.port < 65536:
        parser.error("port must be 1..65535")
    result = asyncio.run(poll(args.host, args.port, max_seconds=args.max_seconds,
                              retry_seconds=args.retry_seconds,
                              probe_timeout=args.probe_timeout))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
