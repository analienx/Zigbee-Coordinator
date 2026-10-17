#!/usr/bin/env python3
"""Fail-closed offline trust-chain verification for the isolated P7U R4 image.

Not a flasher. Never exports factory flash, network credentials, keys or TLV
contents. Public key is located *inside the matching factory flash* and is
verified against the factory KEYHASH and ECDSA signature before use.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

MAGIC = 0x96F3B83D
APP_LIMIT = 0xA0000
FACTORY_BYTES = 720896
FACTORY_SHA256 = "ba654310cef8f1543a96c9bb6d5ef4f17411829642bcbe8249e91de6ae5b38f3"
DER_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")


class Rejected(ValueError):
    """A signed-boot admission check did not pass."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Rejected("R4_SIGNED_IMAGE_REQUIRED_" + code)


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def parse_image(data: bytes) -> dict:
    require(len(data) >= 0x80, "TRUNCATED_HEADER")
    fields = struct.unpack_from("<IIHHIIBBHII", data, 0)
    magic, load, hdr, protected, size, flags, major, minor, revision, build, pad = fields
    require(magic == MAGIC and load == 0, "NOT_EXPECTED_MCUBOOT_XIP")
    require(hdr == 0x80 and protected == 0, "HEADER_GEOMETRY")
    require(flags == 0 and pad == 0, "UNSUPPORTED_FLAGS")
    require((major, minor, revision, build) >= (1, 0, 0, 0), "VERSION_ROLLBACK_RISK")
    require(size >= 0x1000 and size % 4 == 0, "IMAGE_SIZE")
    end = hdr + size
    require(end + 4 <= len(data) and end + 4 <= APP_LIMIT, "SLOT_BOUNDS")
    magic_tlv, total = struct.unpack_from("<HH", data, end)
    require(magic_tlv == 0x6907, "TLV_MISSING")
    require(total >= 4 and end + total <= len(data) and end + total <= APP_LIMIT, "TLV_BOUNDS")
    cursor, tlvs = end + 4, {}
    while cursor < end + total:
        require(cursor + 4 <= end + total, "TLV_ENTRY_TRUNCATED")
        kind, reserved, n = struct.unpack_from("<BBH", data, cursor)
        require(reserved == 0 and n > 0 and kind not in tlvs, "TLV_DUPLICATE_OR_FLAGS")
        require(cursor + 4 + n <= end + total, "TLV_ENTRY_BOUNDS")
        tlvs[kind] = data[cursor + 4:cursor + 4 + n]
        cursor += 4 + n
    require(cursor == end + total, "TLV_INCOMPLETE")
    require(set(tlvs) == {0x10, 0x01, 0x22}, "TLV_TYPES")
    require(len(tlvs[0x10]) == 32 and len(tlvs[0x01]) == 32, "HASH_LENGTH")
    require(64 <= len(tlvs[0x22]) <= 73, "ECDSA_LENGTH")
    require(tlvs[0x10] == digest(data[:end]), "IMAGE_SHA256")
    sp, pc = struct.unpack_from("<II", data, 0x80)
    require(0x20000000 <= sp <= 0x20024000 and sp % 8 == 0, "RESET_STACK")
    require(pc & 1 and 0x80 <= (pc & ~1) < end, "RESET_PC")
    return {"hash": tlvs[0x10], "keyhash": tlvs[0x01],
            "signature": tlvs[0x22], "image_end": end,
            "tlv_end": end + total, "version": (major, minor, revision, build)}


def public_key_from_factory(factory: bytes, stock: dict):
    """Match keyhash to a P-256 DER key in protected boot code, then verify stock."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.exceptions import InvalidSignature

    candidates = []
    position = 0xA4000
    while True:
        offset = factory.find(DER_P256_PREFIX, position, 0xB0000)
        if offset < 0:
            break
        position = offset + 1
        der = factory[offset:offset + 91]
        if len(der) != 91 or digest(der) != stock["keyhash"]:
            continue
        pub = serialization.load_der_public_key(der)
        require(isinstance(pub, ec.EllipticCurvePublicKey) and
                isinstance(pub.curve, ec.SECP256R1), "FACTORY_KEY_CURVE")
        try:
            pub.verify(stock["signature"], stock["hash"],
                       ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        except InvalidSignature as exc:
            raise Rejected("R4_SIGNED_IMAGE_REQUIRED_FACTORY_SIGNATURE") from exc
        candidates.append(pub)
    require(len(candidates) == 1, "FACTORY_TRUST_ANCHOR_UNRESOLVED")
    return candidates[0]


def validate_signed(candidate: bytes, factory: bytes) -> dict:
    """Require the same fitted trust anchor and *new* valid candidate signature."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.exceptions import InvalidSignature

    stock = parse_image(factory)
    key = public_key_from_factory(factory, stock)
    info = parse_image(candidate)
    require(info["keyhash"] == stock["keyhash"], "UNTRUSTED_SIGNER")
    require(info["version"] >= stock["version"], "VERSION_DOWNGRADE")
    require(info["hash"] != stock["hash"], "IDENTICAL_FACTORY_IMAGE_NOT_R4")
    try:
        key.verify(info["signature"], info["hash"],
                   ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature as exc:
        raise Rejected("R4_SIGNED_IMAGE_REQUIRED_ECDSA_VERIFY") from exc
    return {"schema": "r4-p7u-mcuboot-fitted-trust-v1",
            "signed_image_verified_against_fitted_public_key": True,
            "original_factory_signature_verified": True,
            "candidate_image_sha256": digest(candidate).hex(),
            "protected_bootloader_written": False,
            "ccfg_written": False,
            "hardware_boot_qualified": False,
            "flash_authorized": False}


def read_app_only_hex(path: Path) -> bytes:
    """Strict sparse Intel HEX decoding, *no* write to any device or protected flash."""
    addresses = {}
    high = 0
    ended = False
    for line in path.read_text("ascii").splitlines():
        require(not ended and line.startswith(":"), "HEX_LINE")
        try:
            raw = bytes.fromhex(line[1:])
        except ValueError as exc:
            raise Rejected("R4_SIGNED_IMAGE_REQUIRED_HEX_ENCODING") from exc
        require(len(raw) >= 5 and len(raw) == raw[0] + 5
                and sum(raw) % 256 == 0, "HEX_CHECKSUM")
        n, low, kind = raw[0], int.from_bytes(raw[1:3], "big"), raw[3]
        body = raw[4:-1]
        if kind == 0:
            require(low + n <= 0x10000, "HEX_RECORD_CROSSES_BANK")
            for i, b in enumerate(body):
                address = high + low + i
                require(0 <= address < APP_LIMIT, "PROTECTED_FLASH_ADDRESS")
                require(address not in addresses, "HEX_DUPLICATE_ADDRESS")
                addresses[address] = b
        elif kind == 4:
            require(n == 2 and low == 0, "HEX_EXTENDED_ADDRESS")
            high = int.from_bytes(body, "big") << 16
        elif kind == 1:
            require(n == 0 and low == 0, "HEX_EOF")
            ended = True
        else:
            raise Rejected("R4_SIGNED_IMAGE_REQUIRED_HEX_RECORD_TYPE")
    require(ended and addresses and all(k in addresses for k in range(0x80)),
            "HEX_HEADER_INCOMPLETE")
    length = max(addresses) + 1
    output = bytearray(b"\xff" * length)
    for address, value in addresses.items():
        output[address] = value
    info = parse_image(bytes(output))
    require(not any(k >= info["tlv_end"] for k in addresses), "HEX_POST_TRAILER_DATA")
    return bytes(output[:info["tlv_end"]])


def main() -> None:
    parser = argparse.ArgumentParser(description="OFFLINE ONLY. Never authorizes flash.")
    parser.add_argument("--candidate-hex", type=Path, required=True)
    parser.add_argument("--stock-a", type=Path, required=True)
    parser.add_argument("--stock-b", type=Path, required=True)
    parser.add_argument("--expected-candidate-hex-sha256", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    a, b = args.stock_a.read_bytes(), args.stock_b.read_bytes()
    require(len(a) == FACTORY_BYTES and a == b, "DUAL_STOCK_BACKUP")
    require(hashlib.sha256(a).hexdigest() == FACTORY_SHA256, "STOCK_SHA_PIN")
    raw = args.candidate_hex.read_bytes()
    require(hashlib.sha256(raw).hexdigest() ==
            args.expected_candidate_hex_sha256.lower(), "CANDIDATE_SHA_PIN")
    result = validate_signed(read_app_only_hex(args.candidate_hex), a)
    result["candidate_hex_sha256"] = hashlib.sha256(raw).hexdigest()
    require(not args.receipt.exists(), "RECEIPT_ALREADY_EXISTS")
    args.receipt.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
