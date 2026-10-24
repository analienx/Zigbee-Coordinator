#!/usr/bin/env python3
"""Immutable prepared TI dependency validation for two clean APP builds.

Only SHA-verified, pinned SDK libraries may be reused. Application objects,
final ELF, APP binary, APP HEX and boot handoff are always regenerated.
A digest-named image is insufficient on its own: verify exact provenance,
tool versions, pinned file digests, build flags and worker isolation.
"""
from pathlib import Path
import hashlib
import json
import re


class DependencyHold(ValueError):
    pass


REQUIRED_PINS = {
    "ccs":"12.8.0.00012",
    "sysconfig":"1.21.1.3772",
    "ti_arm_clang":"3.2.2.LTS",
    "examples":"87ff5b638b632050228a7504f35cf3b95581c278",
    "simplelink_sdk":"3615ad5d3f4f271258d18a2f5ce1785064ff9a58",
}
CONTROL_FIELDS = ("sdk_scope_sha256","build_flags_sha256","linker_sha256",
                  "sysconfig_inputs_sha256","abi_sha256",
                  "ccs_project_sha256","generator_recipe_sha256",
                  "runtime_image_sha256")


def require(ok, reason):
    if not ok:
        raise DependencyHold("P7U_PREPARED_DEPS_HOLD_"+reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),
                      allow_nan=False).encode()


def verify_manifest(path: Path):
    path=Path(path).resolve(strict=True)
    data=json.loads(path.read_bytes())
    require(type(data) is dict and data.get("schema")=="p7u-prepared-ti-deps-v1",
            "SCHEMA")
    identity=data.get("identity_sha256")
    require(type(identity) is str and re.fullmatch(r"[0-9a-f]{64}",identity),
            "MISSING_IMMUTABLE_IDENTITY")
    payload={k:v for k,v in data.items() if k!="identity_sha256"}
    require(digest(canonical(payload))==identity,"DEPENDENCY_RECEIPT_MODIFIED")
    pins=data.get("pins",{})
    require(all(pins.get(k)==v for k,v in REQUIRED_PINS.items()),
            "SDK_TOOLCHAIN_PINS_CHANGED")
    require(all(type(data.get(k)) is str and re.fullmatch("[0-9a-f]{64}",data[k])
                for k in CONTROL_FIELDS),"CACHE_KEY_INPUTS_INCOMPLETE")
    require(data.get("qualified_sdk_library_sets",0)>=1 and
            data.get("clean_app_objects_required") is True and
            data.get("reuse_app_objects") is False and
            data.get("provisioned") is True,
            "SDK_LIBRARIES_NOT_PREPARED")
    root=Path(data["immutable_root"]).resolve(strict=True)
    require(root.is_dir(),"IMMUTABLE_DIRECTORY_MISSING")
    paths=data.get("verified_files",{})
    require(type(paths) is dict and len(paths)>=1,"NO_VERIFIED_SDK_LIBRARIES")
    for rel,expected in paths.items():
        require(type(rel) is str and type(expected) is str and
                re.fullmatch("[0-9a-f]{64}",expected) and
                ".." not in Path(rel).parts and not Path(rel).is_absolute(),
                "UNSAFE_VERIFIED_LIBRARY_PATH")
        candidate=(root/rel).resolve()
        require(candidate.is_relative_to(root) and candidate.is_file(),
                "VERIFIED_LIBRARY_MISSING")
        require(digest(candidate.read_bytes())==expected,
                "VERIFIED_LIBRARY_SHA_MISMATCH")
    # The container must run with this root mounted read-only, enforced again
    # in each worker's own receipt. Mutable host folders are not trusted.
    require(data.get("immutable_mount") is True and
            data.get("container_digest_pinned") is True,
            "ROOT_NOT_PROVEN_IMMUTABLE")
    return data


def manifest_from_qualified_sources(*, pins, roots, controls, runtime_image_sha):
    """Pure builder for independently established provenance, never asserts
    qualification itself and never installs anything.
    """
    require(pins==REQUIRED_PINS,"PINNED_INPUT_REQUIRED")
    require(len(roots)>=1,"SDK_LIBRARY_OUTPUT_REQUIRED")
    require(all(re.fullmatch("[0-9a-f]{64}",controls.get(k,""))
                for k in CONTROL_FIELDS),"INPUT_FINGERPRINTS_MISSING")
    return {"pins":pins,"controls":controls,
            "sdk_library_roots":roots,"runtime_image_sha256":runtime_image_sha}
