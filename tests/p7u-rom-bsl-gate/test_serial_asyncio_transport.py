#!/usr/bin/env python3
"""Actual pinned PySerial/asyncio on a Linux PTY; never opens a USB device."""
import asyncio
from contextlib import suppress
import importlib.metadata
import os
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'firmware/slzb-06p7u/qualification'))
from p7u_rom_lowlevel import RomSerial, RomWireError

ACK, NACK = b'\x00\xcc', b'\x00\x33'


def packet(data):
    return bytes((len(data) + 2, sum(data) & 255)) + data


async def main():
    import pty
    assert importlib.metadata.version('pyserial') == '3.5'
    assert importlib.metadata.version('pyserial-asyncio') == '0.6'
    master, slave = pty.openpty()
    device = os.ttyname(slave)
    assert device.startswith('/dev/pts/')  # Never use a hardware serial path.
    os.set_blocking(master, False)
    loop = asyncio.get_running_loop()

    async def read_exact(size):
        result = bytearray()
        while len(result) < size:
            try:
                result.extend(os.read(master, size - len(result)))
            except BlockingIOError:
                ready = loop.create_future()
                def readable():
                    if not ready.done(): ready.set_result(None)
                loop.add_reader(master, readable)
                try: await ready
                finally: loop.remove_reader(master)
        return bytes(result)

    async def expect(data):
        assert await read_exact(len(data)) == data

    async def respond(opcode, arguments, response):
        await expect(packet(bytes((opcode,)) + arguments))
        # Split the target ACK/response so the real transport must handle a
        # byte stream, rather than receive one preassembled fake-reader buffer.
        os.write(master, ACK[:1])
        await asyncio.sleep(0)
        os.write(master, ACK[1:] + packet(response))
        await expect(ACK)
        await expect(bytes.fromhex('032323'))  # GET_STATUS
        os.write(master, ACK + packet(b'\x40'))
        await expect(ACK)

    async def target():
        await expect(b'\x55\x55')
        os.write(master, ACK)
        await respond(0x28, b'', b'\x00\x00\x00\xb7')
        await respond(0x2A, struct.pack('>I', 0x50001318) + b'\x01\x01', b'\x00\x70\xb7\x0b')
        await respond(0x27, struct.pack('>II', 0x2000, 8192) + bytes(4), bytes.fromhex('12345678'))
        await expect(b'\x55\x55')
        os.write(master, NACK)

    rom = RomSerial()
    peer = None
    try:
        await rom.open(device, 115200)
        peer = asyncio.create_task(target())
        async with asyncio.timeout(10):
            assert await rom.synchronize() is True
            assert await rom.get_chip_id() == 0xB7
            assert await rom.read_word(0x50001318) == bytes.fromhex('0070b70b')
            assert await rom.crc32(0x2000, 8192) == 0x12345678
            try: await rom.synchronize()
            except RomWireError as error: assert str(error) == 'BSL_NACK'
            else: raise AssertionError('Actual transport ignored NACK')
            await peer
            await rom.close()
            assert rom.writer is None
    finally:
        if peer is not None:
            peer.cancel()
            with suppress(asyncio.CancelledError): await peer
        await rom.close()
        os.close(master)
        os.close(slave)
    print('PINNED_SERIAL_ASYNCIO_PTY_READ_CRC_NACK_CLOSE_PASS_NO_HARDWARE', sys.version.split()[0])


if __name__ == '__main__':
    asyncio.run(main())
