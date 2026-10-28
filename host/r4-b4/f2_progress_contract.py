"""Strict scalar-only F2 minor3/4 extensions shared by offline evidence readers."""
CONGESTION_FIELDS = ("srspQueuedBytes", "asyncQueuedBytes", "srspBytesHighWater",
                     "asyncBytesHighWater", "maxSrspQueueAgeTicks", "maxAsyncQueueAgeTicks",
                     "maxReadyServiceGapTicks")


def valid_congestion(value):
    return (type(value) is dict and set(value) == set(CONGESTION_FIELDS) and
            all(type(value[k]) is int and 0 <= value[k] <= 0xffffffff for k in CONGESTION_FIELDS) and
            value["srspQueuedBytes"] <= value["srspBytesHighWater"] and
            value["asyncQueuedBytes"] <= value["asyncBytesHighWater"])
FIELDS = ("npiRequests", "mtEntered", "mtReturned", "uartWriteAccepted",
          "uartWriteRejected", "uartCallbackOk", "uartCallbackError",
          "uartLengthMismatch", "stateFlags", "uartRxBytes", "firstFaultKind",
          "firstFaultStatusBits", "firstFaultExpected", "firstFaultActual",
          "firstFaultFlags", "firstFaultTick", "firstFaultCommand", "npiWakes",
          "b1FirstFailure", "tickPeriodUs")


def valid_progress(value):
    return (type(value) is dict and set(value) == set(FIELDS) and
            all(type(value[k]) is int and 0 <= value[k] <= 0xffffffff for k in FIELDS) and
            value["firstFaultKind"] <= 5 and value["b1FirstFailure"] <= 255 and
            0 < value["tickPeriodUs"] <= 100000 and value["firstFaultCommand"] <= 65535 and
            not (value["stateFlags"] & 0xfff0) and not (value["firstFaultFlags"] & 0xfff0) and
            (value["firstFaultKind"] != 0 or all(value[k] == 0 for k in FIELDS[11:17])))
