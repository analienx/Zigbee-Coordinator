"""Exact, no-surprises V6 -> startup-capture host configuration transformation.

Pure offline/source-qualified policy. Does NOT touch Home Assistant, serial,
Docker, supervisor or Zigbee. The cutover operator must call this before writes.
"""
import hashlib

OLD_VERSION = "0.2.1-66ed700c2818"
NEW_VERSION = "0.2.1-2c2d96d6334b"
OLD_SHA256 = "60b15e95d57b8f9bb5e8f6bd0669bddb30b0c248f32f83a1976ced5f24cdc705"
SOURCE_SHA256 = "82af547373ee1297199fd8781c08f0755effbea95ce90e6fc0129bceac53b3c7"
OLD_FLAGS = b"  P7U_B4_FLIGHT_V5: '1'\n  P7U_B4_STAGE_V6: '1'\n"
SOURCE_STARTUP = b"  P7U_B4_STARTUP_CAPTURE: '0'\n"
NEW_FLAGS = b"  P7U_B4_STARTUP_CAPTURE: '1'\n" + OLD_FLAGS


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def render(installed: bytes, released: bytes) -> bytes:
    if not isinstance(installed, bytes) or not isinstance(released, bytes):
        raise ValueError("CONFIG_BINARY_INPUT_REQUIRED")
    if sha256(installed) != OLD_SHA256:
        raise ValueError("INSTALLED_CONFIG_DRIFT")
    if sha256(released) != SOURCE_SHA256:
        raise ValueError("QUALIFIED_SOURCE_CONFIG_DRIFT")
    old_version = ("version: " + OLD_VERSION + "\n").encode()
    new_version = ("version: " + NEW_VERSION + "\n").encode()
    if (installed.count(old_version) != 1 or
        released.count(new_version) != 1 or
        released.count(SOURCE_STARTUP) != 1 or
        installed.count(OLD_FLAGS) != 1 or
        b"P7U_B4_STARTUP_CAPTURE" in installed or
        b"P7U_B4_STAGE_V6" in released or
        b"P7U_B4_FLIGHT_V5" in released):
        raise ValueError("CONFIG_EXPECTED_SHAPE")
    # Enforce that *every other byte* is identical, not just a subset
    # of env keys. This detects an unrelated add-on source/config change.
    reconstructed = released.replace(new_version, old_version, 1).replace(
        SOURCE_STARTUP, OLD_FLAGS, 1)
    if reconstructed != installed:
        raise ValueError("CONFIG_UNEXPECTED_DIFFERENCE")
    result = released.replace(SOURCE_STARTUP, NEW_FLAGS, 1)
    if result.count(b"P7U_B4_STARTUP_CAPTURE: '1'") != 1:
        raise ValueError("CONFIG_STARTUP_NOT_ENABLED")
    return result
