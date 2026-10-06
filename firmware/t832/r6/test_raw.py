import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from types import SimpleNamespace
from decode_raw import Parser, binding, decode, diagnostic


def frame(payload):
    data = bytes((len(payload), 0x48, 0x80)) + payload
    fcs = 0
    for value in data:
        fcs ^= value
    return b'\xfe' + data + bytes((fcs,))


class RawTests(unittest.TestCase):
    def test_actual_decoder_private_outputs_and_mismatched_build(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            variant = 'T832-R6-DIAG-production-demand'
            src = Path(__file__).resolve().parent.parent
            for name in ('t832_incident.py', 'diag_schema.json'):
                shutil.copy2(src / name, root / name)
            (root / (variant + '.hex')).write_bytes(b'fixture')
            artifacts = {p.name: {'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                         for p in root.iterdir()}
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps({'variant': variant, 'repository_commit': '12345678' + '0' * 32,
                                           'debug_build_id': 0x12345678, 'artifacts': artifacts}))
            raw = root / 'raw'
            def packet(build):
                header = struct.pack('<4sBBHHQIIHHH', b'T8D1', 2, 1, 1, 1, 12345, build, 0x3fffffff, 0, 0, 0)
                record = struct.pack('<IIHBBHHHH', 100, 101, 1, 49, 0, 8, 1, 0, 1)
                text = ('T832D2:' + (header + b'\x01' + record).hex()).encode()
                return frame(bytes((len(text),)) + text)
            raw.write_bytes(packet(0x12345678))
            good = decode(raw, manifest, root / 'matching')
            self.assertTrue(good['observed_matching_build'])
            self.assertEqual(good['raw_sha256'], hashlib.sha256(raw.read_bytes()).hexdigest())
            if os.name == 'posix':
                self.assertEqual((root / 'matching').stat().st_mode & 0o777, 0o700)
                self.assertEqual((root / 'matching/decoded.jsonl').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                decode(raw, manifest, root / 'matching')
            raw.write_bytes(packet(0xabcdef12))
            wrong = decode(raw, manifest, root / 'wrong')
            self.assertFalse(wrong['observed_matching_build'])
            self.assertEqual(wrong['build_mismatches'], 1)
            self.assertIn('2882400018', (root / 'wrong/decoded.jsonl').read_text())
            raw.write_bytes(b'no diagnostics')
            self.assertFalse(decode(raw, manifest, root / 'missing')['observed_matching_build'])

    def test_fragmented_noise_bad_fcs_and_incomplete_frame(self):
        good = frame(b'\x03abc')
        bad = good[:-1] + bytes((good[-1] ^ 1,))
        parser = Parser()
        rows = []
        for value in b'noise' + bad + good + good[:3]:
            rows.extend(parser.feed(bytes((value,))))
        self.assertEqual(rows, [good])
        self.assertEqual(parser.bad_fcs, 1)
        self.assertEqual(bytes(parser.buffer), good[:3])
        self.assertGreaterEqual(parser.discarded, 5)

    def test_wire_identity_mismatch_is_retained(self):
        codec = SimpleNamespace(decode_frame_payload=lambda _: ({'firmware_build_id': 12}, []))
        payload = b'T832D2:fixture'
        result = diagnostic(frame(bytes((len(payload),)) + payload), codec, 13)
        self.assertFalse(result['expected_build'])
        self.assertEqual(result['header']['firmware_build_id'], 12)
        with self.assertRaises(ValueError):
            diagnostic(frame(b'\xff' + payload), codec, 13)

    def test_manifest_rejects_tampered_artifact_and_non_diag_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            variant = 'T832-R6-DIAG-production-demand'
            artifacts = {}
            for name in ('t832_incident.py', 'diag_schema.json', variant + '.hex'):
                (root / name).write_bytes(b'fixture')
                artifacts[name] = {'bytes': 7, 'sha256': hashlib.sha256(b'fixture').hexdigest()}
            doc = {'variant': variant, 'repository_commit': '12345678' + '0' * 32,
                   'debug_build_id': 0x12345678, 'artifacts': artifacts}
            path = root / 'manifest.json'
            path.write_text(json.dumps(doc))
            self.assertEqual(binding(path), doc)
            (root / 't832_incident.py').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                binding(path)
            doc['debug_build_id'] = None
            path.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                binding(path)
