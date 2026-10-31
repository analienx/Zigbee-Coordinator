"""Synthetic-only adversarial tests for fitted P7U MCUboot gate. No radio access."""
import hashlib
import importlib.util
import pathlib
import struct
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / "firmware/slzb-06p7u/r4/release/r4_verify_mcuboot_signed_image.py"
spec = importlib.util.spec_from_file_location("r4_mcuboot_verify", PATH)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def make_image(private, *, changed=b"A", signed=True, version=(1, 0, 0, 0)):
    payload = bytearray(b"\xA5" * 0x1000)
    payload[:8] = struct.pack("<II", 0x20023C00, 0x101)
    payload[32:33] = changed
    header = bytearray(b"\xFF" * 0x80)
    struct.pack_into("<IIHHIIBBHII", header, 0,
                     gate.MAGIC, 0, 0x80, 0, len(payload), 0, *version, 0)
    base = bytes(header + payload)
    if not signed:
        return base
    public_der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    sha = hashlib.sha256(base).digest()
    sig = private.sign(sha, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    entries = ((0x10, sha), (0x01, hashlib.sha256(public_der).digest()), (0x22, sig))
    items = b"".join(struct.pack("<BBH", t, 0, len(v)) + v for t, v in entries)
    return base + struct.pack("<HH", 0x6907, len(items) + 4) + items


def make_factory(private):
    image = make_image(private, changed=b"S")
    full = bytearray(b"\xFF" * gate.FACTORY_BYTES)
    full[:len(image)] = image
    der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert len(der) == 91
    full[0xAEA40:0xAEA40 + 91] = der
    return bytes(full)


def to_hex(image):
    # Known-valid contiguous test HEX records.
    lines = []
    high = -1
    for i in range(0, len(image), 16):
        if i >> 16 != high:
            high = i >> 16
            rec = bytes([2, 0, 0, 4]) + high.to_bytes(2, "big")
            lines.append(":" + (rec + bytes([-sum(rec) % 256])).hex().upper())
        body = image[i:i+16]
        rec = bytes([len(body), (i >> 8) & 0xff, i & 0xff, 0]) + body
        lines.append(":" + (rec + bytes([-sum(rec) % 256])).hex().upper())
    lines.append(":00000001FF")
    return "\n".join(lines) + "\n"


class SignedBootAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.other = ec.generate_private_key(ec.SECP256R1())
        cls.factory = make_factory(cls.key)
        cls.candidate = make_image(cls.key, changed=b"R")

    def test_valid_candidate_matches_realistic_fitted_trust_chain(self):
        result = gate.validate_signed(self.candidate, self.factory)
        self.assertTrue(result["signed_image_verified_against_fitted_public_key"])
        self.assertTrue(result["original_factory_signature_verified"])
        self.assertFalse(result["flash_authorized"])
        self.assertFalse(result["hardware_boot_qualified"])

    def test_unsigned_image_must_be_rejected(self):
        with self.assertRaisesRegex(gate.Rejected, "TLV_MISSING"):
            gate.validate_signed(make_image(self.key, changed=b"R", signed=False), self.factory)

    def test_wrong_key_cannot_create_compatible_signature(self):
        with self.assertRaisesRegex(gate.Rejected, "UNTRUSTED_SIGNER"):
            gate.validate_signed(make_image(self.other, changed=b"R"), self.factory)

    def test_tampered_signature_is_rejected(self):
        bad = bytearray(self.candidate)
        bad[-1] ^= 1
        with self.assertRaisesRegex(gate.Rejected, "ECDSA_VERIFY"):
            gate.validate_signed(bytes(bad), self.factory)

    def test_tampered_body_is_rejected(self):
        bad = bytearray(self.candidate)
        bad[0x200] ^= 1
        with self.assertRaisesRegex(gate.Rejected, "IMAGE_SHA256"):
            gate.validate_signed(bytes(bad), self.factory)

    def test_fake_factory_public_key_cannot_approve_candidate(self):
        bad = bytearray(self.factory)
        bad[0xAEA40] ^= 1
        with self.assertRaisesRegex(gate.Rejected, "FACTORY_TRUST_ANCHOR_UNRESOLVED"):
            gate.validate_signed(self.candidate, bytes(bad))

    def test_factory_original_signature_must_verify(self):
        bad = bytearray(self.factory)
        info = gate.parse_image(bytes(bad))
        bad[info["tlv_end"] - 1] ^= 1
        with self.assertRaisesRegex(gate.Rejected, "FACTORY_SIGNATURE"):
            gate.validate_signed(self.candidate, bytes(bad))

    def test_no_legacy_stock_image_as_new_r4(self):
        stock = make_image(self.key, changed=b"S")
        with self.assertRaisesRegex(gate.Rejected, "IDENTICAL_FACTORY_IMAGE_NOT_R4"):
            gate.validate_signed(stock, self.factory)

    def test_downgrade_denied(self):
        with self.assertRaisesRegex(gate.Rejected, "VERSION_ROLLBACK_RISK"):
            gate.validate_signed(make_image(self.key, changed=b"R", version=(0, 9, 0, 0)), self.factory)

    def test_hex_roundtrip_and_protected_address_denial(self):
        with tempfile.TemporaryDirectory() as td:
            f = pathlib.Path(td)/"test.hex"
            f.write_text(to_hex(self.candidate), encoding="ascii")
            self.assertEqual(gate.read_app_only_hex(f), self.candidate)
            text = f.read_text()
            # Put an additional record in the protected 0xA0000 NVS page.
            extension = bytes([2,0,0,4,0,10])
            rec = bytes([1,0,0,0,42])
            f.write_text(text.replace(":00000001FF", ":"+(extension+bytes([-sum(extension)%256])).hex().upper()+
                           "\n:"+(rec+bytes([-sum(rec)%256])).hex().upper()+"\n:00000001FF"))
            with self.assertRaisesRegex(gate.Rejected, "PROTECTED_FLASH_ADDRESS"):
                gate.read_app_only_hex(f)

    def test_hex_checksum_and_no_tlv(self):
        with tempfile.TemporaryDirectory() as td:
            f = pathlib.Path(td)/"test.hex"
            f.write_text(to_hex(make_image(self.key, signed=False)))
            with self.assertRaisesRegex(gate.Rejected, "TLV_MISSING"):
                gate.read_app_only_hex(f)
            f.write_text(to_hex(self.candidate).replace(":00000001FF", ":00000001FE"))
            with self.assertRaisesRegex(gate.Rejected, "HEX_CHECKSUM"):
                gate.read_app_only_hex(f)


if __name__ == "__main__":
    unittest.main()
