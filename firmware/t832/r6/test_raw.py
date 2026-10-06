import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from decode_raw import Parser, binding, diagnostic


def frame(payload):
    data = bytes((len(payload), 0x48, 0x80)) + payload
    fcs = 0
    for value in data:
        fcs ^= value
    return b'\xfe' + data + bytes((fcs,))


class RawTests(unittest.TestCase):
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
