"""Bounded passive P10 capture. No TX, flush, reset, erase, restore or modem ioctl.

Stage before upload; start on the earliest management-uploader release point.
Opening a CDC endpoint may itself change kernel-controlled line state. This
tool cannot promise a lossless first BOOT if the uploader holds UART through
boot; it reports only bytes actually observed. Production must stay stopped.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import sys
import termios
import time

PORT = '/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-MR4U_SLZB-MR4U115162-if02'
IMAGE_HASH = '773dcbb100353005ea8f86faf261d4e25c350ffac715c3dcb08aeeca8b69e15c'
BUILD_ID = 0x1f08f3c1


class Parser:
    def __init__(self):
        self.buffer = bytearray()
        self.bad_fcs = 0
        self.discarded = 0
    def feed(self, chunk):
        self.buffer += chunk
        while self.buffer:
            start = self.buffer.find(0xfe)
            if start < 0:
                self.discarded += len(self.buffer)
                self.buffer.clear()
                return
            self.discarded += start
            del self.buffer[:start]
            if len(self.buffer)<5: return
            size = self.buffer[1]+5
            if len(self.buffer)<size: return
            frame = bytes(self.buffer[:size])
            checksum = 0
            for value in frame[1:-1]: checksum ^= value
            if checksum != frame[-1]:
                self.bad_fcs += 1
                del self.buffer[0]
                continue
            del self.buffer[:size]
            yield frame


def diagnostic(frame, codec):
    if frame[2:4] != b'\x4f\x80': return None
    payload = frame[4:-1]
    if not payload or payload[0] != len(payload)-1:
        raise ValueError('DEBUG length mismatch')
    text = payload[1:].decode('ascii')
    if not text.startswith(('T832D1:','T832D2:')): return None
    header,records = codec.decode_frame_payload(text)
    return {'header':header,'records':records,
            'expected_build':header.get('firmware_build_id') == BUILD_ID}


def private_file(root,name):
    return os.fdopen(os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb')


def capture(args):
    if not args.after_management_release:
        raise ValueError('explicit management release confirmation required')
    if not 30 <= args.seconds <= 900: raise ValueError('capture duration out of bounds')
    root = args.bundle.resolve(strict=True)
    if not str(root).startswith('/homeassistant/p10-flash-ready/') or root.stat().st_mode & 0o077:
        raise ValueError('private staged bundle required')
    raw_image = (root/'T832-DIAG-R0.hex').read_bytes()
    if hashlib.sha256(raw_image).hexdigest()!=IMAGE_HASH: raise ValueError('staged image hash mismatch')
    plan = json.loads((root/('capture-plan-v2.json' if (root/'capture-plan-v2.json').exists() else 'capture-plan.json')).read_text())
    if plan.get('image_sha256') != IMAGE_HASH or plan.get('serial_path') != PORT:
        raise ValueError('capture plan target binding mismatch')
    decoder = root/'t832_incident.py'
    if hashlib.sha256(decoder.read_bytes()).hexdigest()!=plan['decoder_sha256']:
        raise ValueError('staged decoder hash mismatch')
    spec=importlib.util.spec_from_file_location('exact_t832',decoder)
    codec=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=codec
    spec.loader.exec_module(codec)
    spec=importlib.util.spec_from_file_location('existing_gate','/homeassistant/scripts/mr4u_p10_management_recovery.py')
    gate=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    info = gate.supervisor_info()
    if info['state'] != 'stopped' or info.get('watchdog'): raise ValueError('Z2M must be stopped without watchdog')
    gate.configuration_gate(info)
    identity = gate.endpoint_identity()
    device = Path(PORT).resolve(strict=True)
    owners=[]
    for pid in Path('/proc').iterdir():
        if not pid.name.isdigit() or pid.name==str(os.getpid()): continue
        try:
            for fd in (pid/'fd').iterdir():
                try:
                    if fd.resolve()==device: owners.append(pid.name)
                except (OSError,RuntimeError): pass
        except FileNotFoundError: pass
        except PermissionError: raise ValueError('owner scan incomplete')
    if owners: raise ValueError('P10 endpoint has another owner')
    parser,byte_count,frames,diags,seen = Parser(),0,0,0,set()
    with private_file(root,'first-boot.raw') as raw, private_file(root,'raw-chunks.jsonl') as chunks, private_file(root,'first-boot.decoded.jsonl') as decoded:
        fd = os.open(PORT,os.O_RDWR|os.O_NOCTTY|os.O_NONBLOCK)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.ioctl(fd,termios.TIOCEXCL)
            if gate.endpoint_identity()!=identity: raise ValueError('endpoint changed during acquisition')
            attrs=termios.tcgetattr(fd)
            attrs[0]=attrs[1]=attrs[3]=0
            attrs[2]=termios.CS8|termios.CLOCAL|termios.CREAD
            attrs[4]=attrs[5]=termios.B115200
            termios.tcsetattr(fd,termios.TCSANOW,attrs)
            # Never tcflush: already-buffered early boot bytes are evidence.
            start=time.monotonic()
            while time.monotonic()-start<args.seconds:
                if not select.select([fd],[],[],max(0,min(0.25,args.seconds-(time.monotonic()-start))))[0]: continue
                data=os.read(fd,4096)
                if not data: raise EOFError('P10 disconnected; no automatic reopen')
                stamp=dt.datetime.now(dt.timezone.utc).isoformat()
                raw.write(data)
                chunks.write((json.dumps({'utc':stamp,'monotonic':time.monotonic(),'offset':byte_count,'bytes':len(data)})+'\n').encode())
                byte_count+=len(data)
                if byte_count>16*1024*1024: raise ValueError('raw evidence byte cap')
                for frame in parser.feed(data):
                    frames+=1
                    event={'utc':stamp,'frame_hex':frame.hex()}
                    try:
                        value=diagnostic(frame,codec)
                        if value:
                            diags+=1
                            event.update(value)
                            seen.update(str(row.get('kind_name')) for row in value['records'])
                    except (ValueError,UnicodeDecodeError) as error:
                        event['decode_error']=str(error)
                    decoded.write((json.dumps(event)+'\n').encode())
                for stream in (raw,chunks,decoded): stream.flush()
        finally:
            # Do not clear TIOCEXCL before close; avoid a second-owner window.
            os.close(fd)
            for stream in (raw,chunks,decoded): stream.flush(); os.fsync(stream.fileno())
    result={'bytes':byte_count,'znp_frames':frames,'diagnostic_frames':diags,'record_kinds_seen':sorted(seen),
            'bad_fcs':parser.bad_fcs,'discarded_bytes':parser.discarded,'pending_bytes':len(parser.buffer),
            'first_boot_guaranteed':False,'note':'Earliest observed data after operator-confirmed uploader release; absence of BOOT is not proof of boot failure.',
            'flash_authorized':False,'opened_port':PORT,'files':{}}
    for name in ('first-boot.raw','raw-chunks.jsonl','first-boot.decoded.jsonl'):
        result['files'][name]=hashlib.sha256((root/name).read_bytes()).hexdigest()
    with private_file(root,'first-boot.capture-result.json') as output: output.write(json.dumps(result,indent=2).encode())
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--seconds',type=float,default=600)
    parser.add_argument('--after-management-release',action='store_true')
    try:
        print(json.dumps(capture(parser.parse_args()),indent=2))
    except Exception as error:
        print(json.dumps({'ok':False,'error_type':type(error).__name__,'flash_authorized':False}))
        sys.exit(1)
