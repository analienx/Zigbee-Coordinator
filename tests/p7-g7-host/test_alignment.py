#!/usr/bin/env python3
"""Fail-closed ELF section alignment accounting regression: hosted/no device."""
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/g3"))
from nv5_verify_linked import verified_app_alignment_fill


def fixture():
    elf=bytearray(512)
    elf[:7]=b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HHIIIIIHHHHHH",elf,16,
        2,40,1,0x101,52,256,0x05000000,52,32,1,40,3,0)
    struct.pack_into("<IIIIIIII",elf,52,
        1,160,0x100,0x100,24,24,5,16)
    elf[160:172]=bytes([0xa5]*12)
    elf[176:184]=bytes([0x5a]*8)
    struct.pack_into("<IIIIIIIIII",elf,296,
        0,1,2,0x100,160,12,0,0,4,0)
    struct.pack_into("<IIIIIIIIII",elf,336,
        0,1,2,0x110,176,8,0,0,16,0)
    return elf


def must_fail(elf, programmed=24, map_used=20):
    try:
        verified_app_alignment_fill(bytes(elf),programmed,map_used)
    except ValueError:
        return
    raise AssertionError("UNVERIFIED_ELF_PADDING_ACCEPTED")


def main():
    good=fixture()
    gaps=verified_app_alignment_fill(bytes(good),24,20)
    assert gaps==[{"physical_start":"0x10c","length":4,
                   "fill":0,"following_alignment":16}],gaps
    assert verified_app_alignment_fill(bytes(good),24,24)==[]
    bad=fixture();bad[173]=1;must_fail(bad)
    bad=fixture();struct.pack_into("<I",bad,336+32,4);must_fail(bad)
    bad=fixture();struct.pack_into("<I",bad,336+12,0x10c);must_fail(bad)
    bad=fixture();struct.pack_into("<I",bad,52+12,0x104);must_fail(bad)
    bad=fixture();struct.pack_into("<I",bad,336+8,0);must_fail(bad)
    bad=fixture();struct.pack_into("<I",bad,336+16,180);must_fail(bad)
    must_fail(fixture(),24,23)
    must_fail(fixture(),24,25)
    must_fail(fixture(),24,0)
    print("PASS G7 ELF alignment fill: exact positive and 9 fail-closed mutations; no image writes")


if __name__=="__main__":
    main()
