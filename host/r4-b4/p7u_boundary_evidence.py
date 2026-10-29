"""Fail-closed independent P7U ESP/USB/host boundary evidence adapter.

Takes EXTERNALLY supplied, sanitized observations from the real existing
ZNP owner and management. It does not open USB/serial, query SMLIGHT, poll
web, reset, or install an ESP firmware image. USB_DIRECT != ESP UART bridge.
"""
from __future__ import annotations
from dataclasses import dataclass

class BoundaryEvidenceError(ValueError):pass

@dataclass(frozen=True)
class Observation:
    mode:str
    mode_verified:bool
    radio_epoch_continuous:bool
    radio_tx_finished_delta:int|None
    host_unpi_rx_raw_delta:int|None
    host_unpi_valid_frames_delta:int|None
    host_usb_attached:bool|None
    host_usb_reenumerations:int|None
    esp_status_authenticated:bool
    esp_uart_data_path_source_verified:bool
    esp_uart_rx_delta:int|None
    esp_uptime_ms:int|None
    # Cross-device deltas must originate in the same audited host-clock window.
    radio_window:tuple[int,int]|None=None
    host_window:tuple[int,int]|None=None
    esp_window:tuple[int,int]|None=None
    common_clock_source_verified:bool=False
    host_counter_epoch_continuous:bool=False
    esp_counter_epoch_continuous:bool=False

def _valid_window(v):
    return type(v) is tuple and len(v)==2 and all(
        type(x) is int and x>=0 for x in v) and v[0]<v[1]

def classify(o:Observation)->dict:
    if not isinstance(o,Observation) or o.mode not in ("USB_DIRECT","ETHERNET","UNKNOWN"):
        raise BoundaryEvidenceError("INVALID_SOURCE")
    for v in (o.radio_tx_finished_delta,o.host_unpi_rx_raw_delta,
              o.host_unpi_valid_frames_delta,o.host_usb_reenumerations,
              o.esp_uart_rx_delta,o.esp_uptime_ms):
        if v is not None and (type(v) is not int or v<0):
            raise BoundaryEvidenceError("BAD_NONNEGATIVE_DELTA")
    for window in (o.radio_window,o.host_window,o.esp_window):
        if window is not None and not _valid_window(window):
            raise BoundaryEvidenceError("INVALID_MONOTONIC_WINDOW")
    if o.esp_uart_rx_delta is not None and (
         not o.esp_status_authenticated or
         not o.esp_uart_data_path_source_verified or
         o.mode!="ETHERNET" or not o.mode_verified):
        raise BoundaryEvidenceError("ESP_UART_COUNTER_UNQUALIFIED")
    if (o.mode=="USB_DIRECT" and o.esp_uart_data_path_source_verified):
        raise BoundaryEvidenceError("FALSE_USB_ESP_UART_VISIBILITY")
    if o.host_usb_attached is False and o.mode=="ETHERNET":
        # Host USB attachment is not an Ethernet TCP link signal.
        raise BoundaryEvidenceError("MODE_HOST_TRANSPORT_CONFLICT")
    paired_host=(o.common_clock_source_verified is True and
        o.host_counter_epoch_continuous is True and
        o.radio_window is not None and o.radio_window==o.host_window)
    paired_esp=(o.common_clock_source_verified is True and
        o.esp_counter_epoch_continuous is True and
        o.radio_window is not None and o.radio_window==o.esp_window)
    if o.mode_verified is not True:
        result="MODE_NOT_VERIFIED"
    elif o.mode=="USB_DIRECT" and o.host_usb_attached is False:
        result="HOST_USB_DETACHED_OBSERVED"
    elif not o.radio_epoch_continuous:
        result="RADIO_EPOCH_UNCERTAIN"
    elif o.mode=="USB_DIRECT" and o.host_usb_attached is not True:
        result="HOST_USB_PRESENCE_UNMEASURED"
    elif (o.mode=="ETHERNET" and paired_esp and o.esp_uart_rx_delta is not None and
          o.radio_tx_finished_delta is not None and o.radio_tx_finished_delta>0 and
          o.esp_uart_rx_delta==0):
        # Most upstream missing boundary wins; only with authenticated
        # source-qualified ESP UART data path and a comparable sample window.
        result="ESP_BRIDGE_RX_GAP_CORRELATED"
    elif paired_host and o.radio_tx_finished_delta is not None and o.radio_tx_finished_delta>0 and (
         o.host_unpi_rx_raw_delta==0):
        result="RADIO_TX_COMPLETION_WITHOUT_HOST_RAW_RX_CORRELATED"
    elif (paired_host and o.host_unpi_rx_raw_delta is not None and o.host_unpi_rx_raw_delta>0 and
          o.host_unpi_valid_frames_delta==0):
        result="HOST_RAW_RX_WITHOUT_VALID_UNPI_CORRELATED"
    else:
        result="INSUFFICIENT_TO_LOCATE_SILENT_HANG"
    return {
        "schema":"p7u-independent-boundary-sanitized-v1",
        "localization":result,
        "mode":o.mode if o.mode_verified else "UNKNOWN",
        "espUartObservable":bool(o.mode=="ETHERNET" and
             o.mode_verified and o.esp_uart_data_path_source_verified and
             o.esp_status_authenticated),
        "radioSilenceProven":False,
        "terminalHangProven":False,
        "automaticRecoveryAuthorized":False,
        "additionalSerialOwner":False,
        "hardwareInstrumentationInstalled":False,
        "radioHostWindowsComparable":paired_host,
        "radioEspWindowsComparable":paired_esp,
    }
