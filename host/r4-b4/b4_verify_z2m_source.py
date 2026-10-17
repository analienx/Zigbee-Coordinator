"""B4 live-release *source* compatibility gate, never an installed-HA probe.

Zigbee2MQTT 2.14.0 pins herdsman 10.9.1; public Extension base has a
Zigbee controller but NO supported raw MT/SYS diagnostic request method.
Even matching upstream source does not prove the user's installed runtime.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

Z2M_SHA = "62b02e2aa1997c574223b80c196677b63a25f4a7"
Z2M_VERSION = "2.14.0"
HERDSMAN_VERSION = "10.9.1"
EXTENSION_PATH = "lib/extension/extension.ts"
PACKAGE_PATH = "package.json"

def validate(root):
    root = Path(root)
    if not root.is_dir():
        raise ValueError("Z2M 2.14.0 source directory missing")
    try:
        sha = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        raise ValueError("cannot source-verify Z2M tag") from None
    if sha != Z2M_SHA:
        raise ValueError("wrong upstream Z2M 2.14.0 commit SHA")
    path = root / PACKAGE_PATH
    extension = root / EXTENSION_PATH
    if not path.is_file() or path.is_symlink() or not extension.is_file() or extension.is_symlink():
        raise ValueError("Z2M manifest/extension source absent or symlinked")
    metadata = json.loads(path.read_text(encoding="utf-8"))
    source = extension.read_text(encoding="utf-8")
    if metadata.get("version") != Z2M_VERSION:
        raise ValueError("Z2M package version drift")
    if metadata.get("dependencies", {}).get("zigbee-herdsman") != HERDSMAN_VERSION:
        raise ValueError("pinned herdsman dependency drift")
    if not all(x in source for x in (
        "abstract class Extension",
        "protected zigbee: Zigbee;",
        "protected eventBus: EventBus;",
        "constructor(",
    )):
        raise ValueError("Z2M public extension class source drift")
    forbidden = (
        "public znp:", "public requestRaw", "public requestMT",
        "public getSerialPort", "public mtRequest", "public zigbeeHerdsmanZnp",
    )
    if any(x in source for x in forbidden):
        raise ValueError("extension raw-port/MT API changed; manual audit required")
    return {
        "schema": "b4-z2m-public-extension-source-v1",
        "z2m_sha": sha,
        "z2m_version": Z2M_VERSION,
        "herdsman_package_dependency": HERDSMAN_VERSION,
        "extension_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "external_extension_raw_mt_api": "NOT_SOURCE_VERIFIED",
        "required_strategy": "PATCH_INTERNAL_EXISTING_OWNER_ONLY",
        "installed_z2m_version": "UNKNOWN",
        "installed_herdsman_version": "UNKNOWN",
        "source_evidence": "SOURCE_PROVEN",
        "host_installed": False,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--z2m", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.z2m), sort_keys=True))

if __name__ == "__main__":
    main()
