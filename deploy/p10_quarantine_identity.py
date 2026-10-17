"""Pure read-only identity checks for P10 quarantine preflight.

No ZNP, HTTP, Zigbee, HA or credentials; all comparisons are exact.
A management radio cannot be accepted without a known mapping to the
connected socket and operator-pinned hardware label.
"""


def check(revision, actual_revision, management_revision, hw,
          expected_hw, radio_socket_port, connected_port):
    try:
        expected = int(revision)
        actual = int(actual_revision)
        management = int(management_revision)
    except (ValueError, TypeError):
        return {"znp_revision_match": False,
                "slzb_revision_match": False,
                "radio_hardware_match": False,
                "management_socket_binding_match": False}
    return {
        "znp_revision_match": actual == expected,
        "slzb_revision_match": management == expected,
        "radio_hardware_match": bool(expected_hw) and (
            str(hw or "").casefold() == str(expected_hw).casefold()),
        "management_socket_binding_match": (
            radio_socket_port is not None and
            str(radio_socket_port) == str(connected_port)),
    }


def refusal_reasons(gates):
    labels = {
        "znp_revision_match":
            "Direct ZNP SYS_VERSION CodeRevision differs from expected revision",
        "slzb_revision_match":
            "SLZB-OS does not report the expected radio revision",
        "radio_hardware_match":
            "Selected management radio hardware is not independently pinned",
        "management_socket_binding_match":
            "Management radio cannot be bound to the connected ZNP socket",
    }
    return [reason for key, reason in labels.items() if not gates.get(key)]
