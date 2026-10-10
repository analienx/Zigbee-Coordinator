#!/usr/bin/env python3
"""MR4U CC2674P10 ROM BSL read-only transport, with NO bootloader activation.

DEFAULT prints an offline plan; it never touches the network unless --read
is specified AND operator gates are met. The tool does not know any BSL
activation/reset/update/erase APIs. It can only connect to an ALREADY-OPEN
BSL TCP serial bridge on the pinned P10 port.

Raw 30 KiB NVS contains PRIVATE Zigbee network and device keys. Its contents
must be written only to the restricted recovery directory, never console.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys

HOST = "192.168.50.200"
PORT = 7638                    # MR4U radio index1, CC2674P10
RADIO_INDEX = 1
NVS_BASE = 0x000F8800
NVS_SIZE = 15 * 2048
BSL_M33_FCFG_ICEPICK = 0x50000800 + 0x318
CC2674_WAFER_ID = 0xBB78
READ_STRIDE = 4
PRIVATE_HOME = Path(r"C:\Workspace\.analienx\sonoff-private\recovery")
# Strict allowlist. The ROM commands 0x21/0x24/0x25/0x26/0x2B/0x2C/0x2D/0x2F
# (program, send-data, reset, erase and CCFG) are unrepresentable.
CMD_SYNCH = 0x55
CMD_PING = 0x20
CMD_GET_STATUS = 0x23
CMD_GET_CHIP_ID = 0x28
CMD_MEMORY_READ = 0x2A
_ALLOWED = frozenset((CMD_SYNCH, CMD_PING, CMD_GET_STATUS,
                      CMD_GET_CHIP_ID, CMD_MEMORY_READ))
ACK = b"\x00\xcc"
NACK = b"\x00\x33"


class BslProtocolError(RuntimeError):
    pass


def command_packet(cmd: int, addr: int | None = None) -> bytes:
    if cmd not in _ALLOWED:
        raise BslProtocolError("BLOCKED_WRITE_OR_RESET_OPCODE")
    if cmd == CMD_SYNCH:
        if addr is not None:
            raise BslProtocolError("SYNCH_MUST_NOT_HAVE_ADDRESS")
        # SMLIGHT's TI ROM BSL sends 0x55,0x55 for SYNCH.
        return b"\x55\x55"
    if cmd == CMD_MEMORY_READ:
        if addr is None or addr & 3 or not (0 <= addr <= 0xFFFFFFFF):
            raise BslProtocolError("UNALIGNED_OR_INVALID_READ")
        allowed_fcfg = addr == BSL_M33_FCFG_ICEPICK
        allowed_nv = NVS_BASE <= addr <= NVS_BASE + NVS_SIZE - READ_STRIDE
        if not (allowed_fcfg or allowed_nv):
            raise BslProtocolError("READ_OUTSIDE_FCFG_ID_OR_NVS")
        payload = bytes((cmd,)) + struct.pack(">I",addr) + b"\x01\x01"
    else:
        if addr is not None:
            raise BslProtocolError("ADDRESS_NOT_ALLOWED")
        payload=bytes((cmd,))
    crc = sum(payload) & 255
    return bytes((len(payload)+2,crc)) + payload


def classify_cc2674_wafer(icepick_four: bytes) -> int:
    if len(icepick_four)!=4:raise BslProtocolError("INVALID_ICEPICK_SIZE")
    # Vendor CC26xx.async_init() wafer-id calculation: must be 0xBB78.
    return ((((icepick_four[3]&0x0F)<<16) +
             (icepick_four[2]<<8)+(icepick_four[1]&0xF0))>>4)


class GuardedBsl:
    """Transport must support .sendall and .recv. No GPIO/API reset methods."""
    def __init__(self,transport):
        self.sock=transport
        self.commands=[]
        self.reads=0

    def exact(self,n):
        out=bytearray()
        while len(out)<n:
            v=self.sock.recv(n-len(out))
            if not v:raise BslProtocolError("SHORT_OR_CLOSED_BSL_REPLY")
            out.extend(v)
        return bytes(out)

    def write_allowed(self,data:bytes,cmd:int):
        if cmd not in _ALLOWED:raise BslProtocolError("BLOCKED_OPCODE")
        self.sock.sendall(data)
        self.commands.append(cmd)

    def wait_ack(self):
        # Match SMLIGHT's upstream CommandInterface._wait_for_ack: the TCP
        # bridge can prepend stale UART bytes before ROM's 00 CC/00 33.
        # Bound scanning to 64 bytes (and the transport's short timeout).
        # Do not print, preserve or interpret any stray UART payload.
        window=bytearray()
        for _ in range(64):
            window.extend(self.exact(1))
            if len(window)>2:del window[:-2]
            if bytes(window)==ACK:return
            if bytes(window)==NACK:
                raise BslProtocolError("BSL_NACK")
        raise BslProtocolError("BSL_ACK_NOT_SEEN_WITHIN_64_BYTES")

    def read_packet(self):
        header=self.exact(2)
        n,checksum=header
        if not 2 <= n <= 255:raise BslProtocolError("BSL_RESPONSE_BAD_LENGTH")
        data=self.exact(n-2)
        if checksum!=(sum(data)&255):
            # Never ACK corrupted data, and never leak actual raw contents.
            raise BslProtocolError("BSL_RESPONSE_CHECKSUM_FAILED")
        self.sock.sendall(ACK)   # link-layer ACK, not a ROM command.
        return data

    def query(self,cmd:int,addr:int|None=None):
        packet=command_packet(cmd,addr)
        self.write_allowed(packet,cmd)
        self.wait_ack()
        if cmd==CMD_SYNCH:return b""
        payload=None
        if cmd in (CMD_GET_CHIP_ID,CMD_GET_STATUS,CMD_MEMORY_READ):
            payload=self.read_packet()
        if cmd!=CMD_GET_STATUS:
            status=self.query(CMD_GET_STATUS)
            if status!=b"\x40":
                raise BslProtocolError("BSL_RETURN_STATUS_NOT_SUCCESS")
        if cmd in (CMD_MEMORY_READ,CMD_GET_CHIP_ID):
            if not isinstance(payload,bytes) or len(payload)!=4:
                raise BslProtocolError("BSL_EXPECTED_FOUR_BYTES")
        if cmd==CMD_GET_STATUS and payload!=b"\x40":
            raise BslProtocolError("BSL_GET_STATUS_FAILED")
        return payload

    def begin(self):
        self.query(CMD_SYNCH)
        self.query(CMD_PING)
        # First read is chip-family ID from TI factory configuration.
        wafer=classify_cc2674_wafer(self.query(CMD_MEMORY_READ,
                                               BSL_M33_FCFG_ICEPICK))
        if wafer!=CC2674_WAFER_ID:
            raise BslProtocolError("WRONG_RADIO_CHIP_FAMILY")
        return {"wafer_id":hex(wafer),"correct_chip_family":True}

    def read_private_nvs(self):
        out=bytearray()
        for offset in range(0,NVS_SIZE,READ_STRIDE):
            out.extend(self.query(CMD_MEMORY_READ,NVS_BASE+offset))
            self.reads+=1
        if len(out)!=NVS_SIZE:raise BslProtocolError("NVS_SHORT_READ")
        return bytes(out)


def validate_live_authority(args):
    if not args.read:
        return
    if not (args.already_in_bsl and args.operator_approved and
            args.confirm_exact_p10 and args.backup_validated):
        raise BslProtocolError("LIVE_READ_REQUIRES_FOUR_EXPLICIT_GATES")
    if args.host!=HOST or args.port!=PORT:
        raise BslProtocolError("WRONG_HOST_OR_P10_PORT")
    if os.name!="nt":
        raise BslProtocolError("LIVE_REQUIRES_ORIGINAL_WINDOWS_ZEPHYRUS")
    if not args.output:raise BslProtocolError("RESTRICTED_OUTPUT_REQUIRED")
    target=Path(args.output).resolve()
    private=PRIVATE_HOME.resolve()
    if (not target.is_relative_to(private) or target.suffix.lower()!=".bin"
            or target.exists() or not target.parent.is_dir()):
        raise BslProtocolError("OUTPUT_NOT_PRIVATE_OR_ALREADY_EXISTS")


def plan()->dict:
    return {
        "mode":"OFFLINE_PLAN_NO_NETWORK_ACCESS",
        "hardware":"SLZB-MR4U / CC2674P10 / Zigbee radio index1",
        "target_host":HOST,"target_port":PORT,
        "entry_to_bsl_performed":False,
        "reset_performed":False,
        "bsl_entry_requirement":"Already active via separately authorized index1 BSL",
        "known_bsl_command_codes":sorted(hex(x) for x in _ALLOWED),
        "bsl_disallowed": ["DOWNLOAD","SEND_DATA","RESET",
                            "SECTOR_ERASE","BANK_ERASE",
                            "MEMORY_WRITE","SET_CCFG","DOWNLOAD_CRC"],
        "nvs_base":hex(NVS_BASE),"nvs_size":NVS_SIZE,
        "read_word_commands":NVS_SIZE//READ_STRIDE,
        "read_transport":"ROM memory read 4 bytes/command",
        "end_action":"close socket only; no cmdReset, no ESP reboot",
        "live_bsl_activation_authorized":False,
        "hardware_mutations":0,
        "secrets_ever_printed":False}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--read",action="store_true",
                   help="Read from an ALREADY-ACTIVE BSL; never enters BSL")
    p.add_argument("--already-in-bsl",action="store_true")
    p.add_argument("--operator-approved",action="store_true")
    p.add_argument("--confirm-exact-p10",action="store_true")
    p.add_argument("--backup-validated",action="store_true")
    p.add_argument("--host",default=HOST)
    p.add_argument("--port",type=int,default=PORT)
    p.add_argument("--output",type=str)
    args=p.parse_args(argv)
    if not args.read:
        print(json.dumps(plan(),indent=2,sort_keys=True))
        return
    validate_live_authority(args)
    target=Path(args.output).resolve()
    # NEVER send any management /api2 control request and NEVER enter BSL.
    with socket.create_connection((HOST,PORT),timeout=4) as connection:
        connection.settimeout(3)
        bsl=GuardedBsl(connection)
        chip=bsl.begin()
        content=bsl.read_private_nvs()
        # Fail closed: no partial dump is written on transport errors.
        # This file is sensitive; never commit or print bytes, restrict ACL
        # separately to the current user's private recovery directory.
        with target.open("xb") as output:
            output.write(content)
        print(json.dumps({"mode":"READONLY_BSL_SNAPSHOT_COMPLETED",
                          "wafer":chip["wafer_id"],
                          "nvs_sha256":hashlib.sha256(content).hexdigest(),
                          "bytes":len(content),"words_read":bsl.reads,
                          "reset_sent":False,"erase_sent":False,
                          "startup_sent":False,
                          "private_output":True},sort_keys=True))


if __name__=="__main__":
    try:
        main()
    except (OSError,BslProtocolError,ValueError) as e:
        # Do not echo system error strings containing security-sensitive paths
        # or fragments of incoming raw radio packets.
        print(json.dumps({"ok":False,"error_type":type(e).__name__,
                          "code": str(e) if isinstance(e,BslProtocolError)
                          else "TRANSPORT_OR_FILE_ERROR",
                          "no_retry":True,"reset_not_attempted":True}),file=sys.stderr)
        raise SystemExit(2)
