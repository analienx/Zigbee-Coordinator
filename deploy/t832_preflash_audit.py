"""Hosted-only static audit; never contacts a device or writes firmware."""
import hashlib
import binascii
import json
from pathlib import Path
import re
import struct
import sys
import urllib.request
import zipfile

CANDIDATE = '1f08f3c1e5da067a1db144e07dc71fd7e155a217'
HEX_HASH = '773dcbb100353005ea8f86faf261d4e25c350ffac715c3dcb08aeeca8b69e15c'
ROLLBACK_HASH = '633f79058c39e2fc9335bb11f816ad6a045438515da11c36b30a46b7c8d1b7d9'
ROLLBACK_URL = 'https://updates.smlight.tech/firmware/slzb06x/zigbee/slzb06p10/znp-SLZB-06P10-20240716.bin'
SDK = '6499c3f53fc5fb5806213be695450a7b43fbaf3d'
HEADER_URL = f'https://raw.githubusercontent.com/TexasInstruments/simplelink-lowpower-f2-sdk/{SDK}/source/ti/devices/cc13x4_cc26x4/inc/hw_ccfg.h'


def ihex(raw):
    memory, upper, ended = {}, 0, False
    for line in raw.decode('ascii').splitlines():
        if not line.strip():
            continue
        if ended or not line.startswith(':'):
            raise ValueError('invalid HEX framing')
        row = bytes.fromhex(line[1:])
        if len(row) < 5 or len(row) != row[0] + 5 or sum(row) & 255:
            raise ValueError('invalid HEX checksum/length')
        n, addr, kind = row[0], int.from_bytes(row[1:3], 'big'), row[3]
        data = row[4:-1]
        if kind == 0:
            for i, value in enumerate(data):
                target = upper + addr + i
                if target in memory:
                    raise ValueError('overlapping HEX records')
                memory[target] = value
        elif kind == 1 and n == 0 and addr == 0:
            ended = True
        elif kind == 4 and n == 2 and addr == 0:
            upper = int.from_bytes(data, 'big') << 16
        elif kind == 2 and n == 2 and addr == 0:
            upper = int.from_bytes(data, 'big') << 4
        elif kind in (3, 5) and n == 4 and addr == 0:
            pass
        else:
            raise ValueError('unsupported HEX record')
    if not ended or not memory:
        raise ValueError('incomplete HEX')
    return memory


def decode(memory, offsets):
    def word(addr):
        return struct.unpack('<I', bytes(memory[addr+i] for i in range(4)))[0]
    values = {name: f'0x{word(0x50000000 + off):08x}' for name, off in offsets.items()
              if all(0x50000000 + off + i in memory for i in range(4))}
    bl = int(values['BL_CONFIG'], 16)
    vector = int(values['IMAGE_VALID_CONF'], 16)
    sp, reset = word(vector), word(vector+4)
    return {'fields': values, 'bootloader_enabled': bl >> 24 == 0xc5,
            'backdoor_enabled': bl & 255 == 0xc5, 'backdoor_dio': (bl >> 8) & 255,
            'backdoor_level': (bl >> 16) & 1, 'vector_base': vector,
            'initial_sp': f'0x{sp:08x}', 'reset_vector': f'0x{reset:08x}',
            'vector_valid': 0x20000000 < sp <= 0x20040000 and sp % 8 == 0
                and bool(reset & 1) and (reset & ~1) in memory,
            'nv_hex_records': sum(0xfd800 <= addr < 0x100000 for addr in memory)}


def slzb(raw):
    # Exact vendor 20240716 container: magic + two BE address/length/CRC
    # descriptors, followed by application and CCFG. CRC and complete extent
    # establish the mapping; never guess that a binary tail is CCFG.
    if raw[:4] != b'SLZB' or len(raw) < 28:
        raise ValueError('unsupported vendor container')
    memory, cursor, descriptors = {}, 28, []
    for offset in (4,16):
        address, size, crc = struct.unpack('>III',raw[offset:offset+12])
        segment = raw[cursor:cursor+size]
        if len(segment) != size or binascii.crc32(segment) & 0xffffffff != crc:
            raise ValueError('vendor segment CRC/extent mismatch')
        for index,value in enumerate(segment):
            if address+index in memory:
                raise ValueError('vendor segment overlap')
            memory[address+index] = value
        descriptors.append({'address':f'0x{address:08x}','size':size,'crc32':f'0x{crc:08x}'})
        cursor += size
    if cursor != len(raw) or [x['address'] for x in descriptors] != ['0x00000000','0x50000000']:
        raise ValueError('unexpected vendor container geometry')
    return memory, descriptors


def download(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(4_000_001)
    if len(data) > 4_000_000:
        raise ValueError('download oversized')
    return data


def main():
    root = Path(sys.argv[1])
    with zipfile.ZipFile(root/'candidate.zip') as archive:
        raw = archive.read('T832-DIAG-R0.hex')
        manifest = json.loads(archive.read('T832-BUILD-MANIFEST.json'))
    if hashlib.sha256(raw).hexdigest() != HEX_HASH or CANDIDATE not in json.dumps(manifest):
        raise ValueError('candidate provenance/hash mismatch')
    rollback = download(ROLLBACK_URL)
    if hashlib.sha256(rollback).hexdigest() != ROLLBACK_HASH:
        raise ValueError('rollback hash mismatch')
    (root/'rollback-20240716.bin').write_bytes(rollback)
    header = download(HEADER_URL)
    (root/'hw_ccfg.h').write_bytes(header)
    offsets = {name: int(value,16) for name,value in re.findall(
        r'^#define CCFG_O_(\w+)\s+(0x[0-9A-Fa-f]+)', header.decode(), re.M)
        if not name.startswith('CKEY')}
    result = {'candidate_commit': CANDIDATE, 'candidate_hex_sha256': HEX_HASH,
              'rollback_sha256': ROLLBACK_HASH, 'rollback_source': ROLLBACK_URL,
              'sdk_commit': SDK, 'header_sha256': hashlib.sha256(header).hexdigest(),
              'candidate': decode(ihex(raw), offsets), 'verdict': 'unresolved',
              'flash_authorized': False}
    if rollback.lstrip().startswith(b':') or rollback.startswith(b'SLZB'):
        if rollback.startswith(b'SLZB'):
            reference, result['vendor_segments'] = slzb(rollback)
        else:
            reference = ihex(rollback)
        result['reference'] = decode(reference, offsets)
        a,b = result['candidate'],result['reference']
        critical = ('BL_CONFIG','IMAGE_VALID_CONF','ERASE_CONF','ERASE_CONF_1',
                    'CCFG_TAP_DAP_0','CCFG_TAP_DAP_1','TRUSTZONE_FLASH_CFG',
                    'TRUSTZONE_SRAM_CFG','SRAM_CFG','CPU_LOCK_CFG','DEB_AUTH_CFG')
        result['critical_differences'] = {key:[a['fields'].get(key),b['fields'].get(key)]
            for key in critical if a['fields'].get(key) != b['fields'].get(key)}
        result['other_differences'] = {key:[a['fields'].get(key),b['fields'].get(key)]
            for key in offsets if a['fields'].get(key) != b['fields'].get(key) and key not in critical}
        compatible = all(x['bootloader_enabled'] and x['backdoor_enabled'] and x['vector_valid']
                         for x in (a,b)) and a['nv_hex_records'] == 0 and not result['critical_differences']
        result['verdict'] = 'compatible' if compatible and not result['other_differences'] else 'unresolved'
    else:
        result['reference_format'] = 'binary; address mapping not established'
        result['reference_prefix_hex'] = rollback[:32].hex()
        result['reference_suffix_hex'] = rollback[-128:].hex()
    (root/'ccfg-bsl.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
