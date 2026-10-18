"""Verify the public P7U 20240716 reference offline; never contact a radio."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import urllib.request
import zlib

URL = "https://updates.smlight.tech/firmware/slzb06x/zigbee/slzb06p7v2/znp-SLZB-06P7-EXT-20240716.bin"
SHA256 = "22f094b00459583fdcc56fb7ae0a1a84ff913d6810f9e729729a037de5a093c5"
LENGTH = 173580


def parse_container(raw):
    if not isinstance(raw, bytes) or raw[:4] != b"SLZB":
        raise ValueError("VENDOR_STOCK_CONTAINER_MAGIC")
    layouts = []
    for count in range(1, min(16, (len(raw) - 4) // 12) + 1):
        entries = [struct.unpack_from(">III", raw, 4 + index * 12) for index in range(count)]
        if 4 + 12 * count + sum(size for _, size, _ in entries) == len(raw):
            layouts.append(entries)
    if len(layouts) != 1:
        raise ValueError("VENDOR_STOCK_AMBIGUOUS_OR_TRUNCATED_LAYOUT")
    position, result = 4 + 12 * len(layouts[0]), {}
    for address, size, crc in layouts[0]:
        if not size or address in result or address + size > 0xB0000:
            raise ValueError("VENDOR_STOCK_SEGMENT_GEOMETRY")
        if any(address < prior + len(payload) and prior < address + size
               for prior, payload in result.items()):
            raise ValueError("VENDOR_STOCK_SEGMENT_OVERLAP")
        payload = raw[position:position + size]
        position += size
        if zlib.crc32(payload) & 0xFFFFFFFF != crc:
            raise ValueError("VENDOR_STOCK_SEGMENT_CRC")
        result[address] = payload
    return result


def verify(raw):
    if len(raw) != LENGTH or hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError("VENDOR_STOCK_EXACT_PUBLIC_ARTIFACT_PIN")
    chunks = parse_container(raw)
    if set(chunks) != {0, 0xAFFA8} or len(chunks[0]) != 173464 or len(chunks[0xAFFA8]) != 88:
        raise ValueError("VENDOR_STOCK_EXPECTED_APP_AND_CCFG")
    ccfg = chunks[0xAFFA8]
    expected = {4: 0xFFC00010, 12: 0xF1B9C1FF, 0x30: 0xC5FE0FC5, 0x44: 0}
    if any(struct.unpack_from("<I", ccfg, off)[0] != value for off, value in expected.items()):
        raise ValueError("VENDOR_STOCK_EXPECTED_PUBLIC_BOOT_POWER")
    return {"schema": "r4-p7u-public-stock-reference-v1", "url": URL,
            "sha256": SHA256, "bytes": LENGTH, "revision": "20240716",
            "segments": [{"address": address, "bytes": len(payload), "crc_verified": True}
                         for address, payload in chunks.items()],
            "ccfg_sha256": hashlib.sha256(ccfg).hexdigest(),
            "source_profile": {"mode_conf_1": "0xffc00010", "mode_conf": "0xf1b9c1ff",
                               "image_valid_conf": "0x00000000", "bl_config": "0xc5fe0fc5"},
            "initial_sp": hex(struct.unpack_from("<I", chunks[0], 0)[0]),
            "reset_vector": hex(struct.unpack_from("<I", chunks[0], 4)[0]),
            "current_physical_ccfg_verified": False, "flash_authorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", type=Path)
    group.add_argument("--download", action="store_true")
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if args.receipt.exists():
        parser.error("receipt must be new")
    if args.download:
        with urllib.request.urlopen(URL, timeout=30) as response:
            raw = response.read(LENGTH + 1)
    else:
        raw = args.file.read_bytes()
    report = verify(raw)
    with args.receipt.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"status": "PUBLIC_REFERENCE_CRC_AND_SHA_VERIFIED",
                      "current_physical_ccfg_verified": False}))


if __name__ == "__main__":
    main()
