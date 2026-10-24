"""Single-owner HA CDC transport for the existing FramedZnp parser.

A narrow socket interface; NO second ZNP implementation, auto-reset, service
restart, UART probe or firmware mutation. Open only after exclusive owner
release was proven by the HA operator. BSL and ZNP serial opens never overlap.
"""
from __future__ import annotations
import socket
import re
from pathlib import Path

USB_BY_ID = "/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00"


class UsbStartupTransport:
    def __init__(self, serial_port):
        self._port = serial_port
        self._closed = False

    @classmethod
    def open(cls, by_id=USB_BY_ID, baud=115200):
        if by_id != USB_BY_ID or baud != 115200:
            raise ValueError("P7U_USB_STARTUP_UNQUALIFIED_PORT_OR_BAUD")
        p = Path(by_id)
        if not p.is_symlink() or not re.fullmatch(r"/dev/ttyACM[0-9]+",
                                                     str(p.resolve())):
            raise ValueError("P7U_USB_STARTUP_DEVICE_ID_MISMATCH")
        try:
            import serial
        except ImportError as ex:
            raise RuntimeError("P7U_USB_STARTUP_PYSERIAL_NOT_INSTALLED") from ex
        # No toggling RTS/DTR after open; use externally proven board behaviour.
        port = serial.Serial(port=None, baudrate=baud, timeout=.75,
                             write_timeout=2, rtscts=False, dsrdtr=False)
        port.dtr = False
        port.rts = False
        try:
            port.port = by_id
            port.open()
        except BaseException:
            port.close()
            raise
        return cls(port)

    def settimeout(self, seconds):
        if self._closed or not isinstance(seconds,(int,float)) or seconds<=0:
            raise ValueError("P7U_USB_STARTUP_TIMEOUT_OR_CLOSED")
        self._port.timeout=seconds
        self._port.write_timeout=seconds

    def sendall(self, wire):
        if self._closed:
            raise OSError("P7U_USB_STARTUP_CLOSED")
        if type(wire) is not bytes or not wire or len(wire)>256:
            raise ValueError("P7U_USB_STARTUP_FRAME_INVALID")
        sent = self._port.write(wire)
        if sent != len(wire):
            raise OSError("P7U_USB_STARTUP_AMBIGUOUS_PARTIAL_WRITE")
        self._port.flush()

    def recv(self, length):
        if self._closed:
            raise OSError("P7U_USB_STARTUP_CLOSED")
        if not isinstance(length,int) or not 1<=length<=512:
            raise ValueError("P7U_USB_STARTUP_READ_BOUNDS")
        data=self._port.read(length)
        if not data:
            raise socket.timeout("P7U_USB_STARTUP_READ_TIMEOUT")
        return data

    def close(self):
        if not self._closed:
            self._closed=True
            self._port.close()

    def __enter__(self):
        return self

    def __exit__(self,*exc):
        self.close()
