"""Offline OCI image review for exact P7U aarch64 host patch.

This never executes an image, opens a UART, or reads HA credentials. It proves
that the compiled files built from the same reviewed source are actually
present in the exported OCI filesystem layers.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import PurePosixPath, Path

TARGETS = {
    "app/dist/p7u_diagnostic_worker.cjs": "p7u_diagnostic_worker.cjs",
    "app/dist/p7u_host_timeout_sink.cjs": "p7u_host_timeout_sink.cjs",
    "app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/controller/database.js": "herdsman-dist/controller/database.js",
    # H1 startup admission and save-first shutdown MUST be audited too.
    "app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/controller/controller.js":
        "herdsman-dist/controller/controller.js",
    "app/dist/controller.js": "z2m-controller.js",
    "app/dist/extension/otaUpdate.js": "z2m-otaUpdate.js",
    "app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/adapter/z-stack/adapter/zStackAdapter.js":
        "herdsman-dist/adapter/z-stack/adapter/zStackAdapter.js",
    "app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/adapter/z-stack/znp/znp.js":
        "herdsman-dist/adapter/z-stack/znp/znp.js",
    "app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/adapter/z-stack/adapter/manager.js":
        "herdsman-dist/adapter/z-stack/adapter/manager.js",
    "app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/adapter/z-stack/znp/definition.js":
        "herdsman-dist/adapter/z-stack/znp/definition.js",
    "app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/adapter/z-stack/znp/parameterType.js":
        "herdsman-dist/adapter/z-stack/znp/parameterType.js",
    "app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/adapter/z-stack/znp/buffaloZnp.js":
        "herdsman-dist/adapter/z-stack/znp/buffaloZnp.js",
}


def digest_blob(oci: tarfile.TarFile, value: str) -> bytes:
    algorithm, hexdigest = value.split(":", 1)
    if algorithm != "sha256" or len(hexdigest) != 64:
        raise ValueError("INVALID_OCI_DIGEST")
    f = oci.extractfile("blobs/sha256/" + hexdigest)
    if f is None:
        raise ValueError("MISSING_OCI_BLOB")
    data = f.read()
    if hashlib.sha256(data).hexdigest() != hexdigest:
        raise ValueError("OCI_DIGEST_MISMATCH")
    return data


def image_manifest(oci: tarfile.TarFile) -> dict:
    index = json.loads(oci.extractfile("index.json").read())
    descriptors = index.get("manifests") or []
    for entry in descriptors:
        data = json.loads(digest_blob(oci, entry["digest"]))
        if "layers" in data and "config" in data:
            return data
        for child in data.get("manifests", []):
            if child.get("platform", {}).get("architecture") == "arm64":
                result = json.loads(digest_blob(oci, child["digest"]))
                if "layers" in result:
                    return result
    raise ValueError("NO_ARM64_IMAGE_MANIFEST")


def audit(oci_path: Path, source_receipt: Path) -> dict:
    receipt = json.loads(source_receipt.read_text())
    if receipt.get("default_enabled") is not False or receipt.get("installed") is not False:
        raise ValueError("MUST_BE_UNDEPLOYED_IMAGE")
    if receipt["image_base_digest"] != (
        "sha256:97246758dab5099113c5a46fcbc1b9a36968a0eb9fd95ce8df6e2868cc7f533f"
    ):
        raise ValueError("UNEXPECTED_PRODUCTION_BASE")
    expected = {path: receipt["files"][source]
                for path, source in TARGETS.items()}
    seen: dict[str, str] = {}
    with tarfile.open(oci_path, "r:*") as archive:
        manifest = image_manifest(archive)
        if len(manifest["layers"]) < 4:
            raise ValueError("OCI_IMAGE_MISSING_LAYERS")
        # The audited Dockerfile contains exactly four COPY statements,
        # each adding one final patch layer. Vendor base layers are already
        # digest pinned and may retain a distinct compression format (zstd);
        # re-decoding them is both unnecessary and expensive.
        for item in manifest["layers"][-4:]:
            media = item.get("mediaType", "")
            blob = digest_blob(archive, item["digest"])
            if media.endswith("+gzip"):
                blob = gzip.decompress(blob)
            elif not media.endswith(".tar"):
                raise ValueError("UNSUPPORTED_OCI_LAYER_FORMAT")
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as layer:
                for member in layer:
                    path = str(PurePosixPath(member.name.lstrip("./")))
                    if path in expected and member.isfile():
                        contents = layer.extractfile(member).read()
                        seen[path] = hashlib.sha256(contents).hexdigest()
    if seen != expected:
        raise ValueError("BUILT_IMAGE_FILES_DO_NOT_MATCH_SOURCE " +
                         repr({"missing": sorted(set(expected) - set(seen)),
                               "different": sorted(p for p, h in seen.items()
                                                   if h != expected.get(p))}))
    return {"schema": "p7u-r4-oci-fs-audit-v1",
            "source_sha": receipt["source_sha"],
            "verified_files":len(seen),
            "oci_sha256":hashlib.sha256(oci_path.read_bytes()).hexdigest(),
            "hardware_exercised":False, "installed":False}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--oci",type=Path,required=True)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--receipt",type=Path,required=True)
    args=parser.parse_args()
    result=audit(args.oci,args.source)
    args.receipt.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("PASS: source-bound ARM64 OCI filesystem attestation",result["verified_files"])


if __name__ == "__main__":
    main()
