"""Offline, manifest-bound raw ZNP evidence decoder. Never opens a radio.

Raw bytes can contain private network data. Output is a new private directory;
publish neither raw bytes nor decoded frames to the public repository.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

LIMIT = 16 * 1024 * 1024


class Parser:
    def __init__(self):
        self.buffer = bytearray()
        self.bad_fcs = self.discarded = 0

    def feed(self, data):
        self.buffer.extend(data)
        while self.buffer:
            start = self.buffer.find(0xfe)
            if start < 0:
                self.discarded += len(self.buffer)
                self.buffer.clear()
                return
            self.discarded += start
            del self.buffer[:start]
            if len(self.buffer) < 5:
                return
            size = self.buffer[1] + 5
            if len(self.buffer) < size:
                return
            frame = bytes(self.buffer[:size])
            checksum = 0
            for value in frame[1:-1]:
                checksum ^= value
            if checksum != frame[-1]:
                self.bad_fcs += 1
                del self.buffer[0]
                continue
            del self.buffer[:size]
            yield frame


def binding(manifest):
    doc = json.loads(manifest.read_text())
    commit = doc.get('repository_commit', '')
    build = doc.get('debug_build_id')
    if not re.fullmatch(r'[0-9a-f]{40}', commit) or type(build) is not int or build != int(commit[:8], 16):
        raise ValueError('DIAG manifest SHA/build identity required')
    if doc.get('variant') not in ('T832-R6-DIAG-production-demand', 'T832-R6-DIAG-capacity-400'):
        raise ValueError('R6 DIAG manifest variant required')
    root = manifest.parent
    for name in ('t832_incident.py', 'diag_schema.json', doc['variant'] + '.hex'):
        meta = doc['artifacts'][name]
        data = (root / name).read_bytes()
        if len(data) != meta['bytes'] or hashlib.sha256(data).hexdigest() != meta['sha256']:
            raise ValueError('manifest artifact mismatch: ' + name)
    return doc


def diagnostic(frame, codec, build):
    if frame[2:4] != b'\x48\x80':
        return None
    payload = frame[4:-1]
    if not payload or payload[0] != len(payload) - 1:
        raise ValueError('DEBUG length mismatch')
    text = payload[1:].decode('ascii')
    if not text.startswith(('T832D1:', 'T832D2:')):
        return None
    header, records = codec.decode_frame_payload(text)
    return {'header': header, 'records': records,
            'expected_build': header.get('firmware_build_id') == build}


def decode(raw, manifest, output):
    doc = binding(manifest)
    if raw.stat().st_size > LIMIT:
        raise ValueError('raw evidence exceeds 16 MiB')
    spec = importlib.util.spec_from_file_location('exact_t832_raw', manifest.parent / 't832_incident.py')
    codec = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = codec
    spec.loader.exec_module(codec)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    parser = Parser()
    digest = hashlib.sha256()
    frames = diags = mismatches = errors = count = 0
    with raw.open('rb') as source, os.fdopen(os.open(output / 'decoded.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as sink:
        while chunk := source.read(4096):
            count += len(chunk)
            if count > LIMIT:
                raise ValueError('raw evidence exceeds 16 MiB')
            digest.update(chunk)
            for frame in parser.feed(chunk):
                frames += 1
                row = {'frame_index': frames, 'frame_hex': frame.hex()}
                try:
                    value = diagnostic(frame, codec, doc['debug_build_id'])
                    if value:
                        diags += 1
                        mismatches += not value['expected_build']
                        row.update(value)
                except (ValueError, UnicodeError) as exc:
                    errors += 1
                    row['decode_error'] = str(exc)
                sink.write(json.dumps(row) + '\n')
        sink.flush()
        os.fsync(sink.fileno())
    result = {'repository_commit': doc['repository_commit'], 'expected_build_id': doc['debug_build_id'],
              'raw_sha256': digest.hexdigest(), 'raw_bytes': count, 'znp_frames': frames,
              'diagnostic_frames': diags, 'build_mismatches': mismatches, 'decode_errors': errors,
              'bad_fcs': parser.bad_fcs, 'discarded_bytes': parser.discarded, 'pending_bytes': len(parser.buffer),
              'observed_matching_build': diags > 0 and not mismatches and not errors,
              'first_boot_guaranteed': False, 'hardware_validated': False, 'flash_authorized': False}
    with os.fdopen(os.open(output / 'summary.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as sink:
        sink.write(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--raw', type=Path, required=True)
    p.add_argument('--manifest', type=Path, default=Path(__file__).with_name('T832-BUILD-MANIFEST.json'))
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = decode(a.raw, a.manifest, a.output)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['observed_matching_build'] else 2)
