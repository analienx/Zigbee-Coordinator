#!/usr/bin/env python3
"""Hosted TLS catalog acquisition, exact selection; no firmware redistribution."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--inputs", type=Path, required=True)
p.add_argument("--private-downloads", type=Path, required=True)
p.add_argument("--evidence", type=Path, required=True)
a = p.parse_args()
config = json.loads(a.inputs.read_text())
assert config["model"] == "SLZB-06P7U" and config["catalog_device_id"] == 17
assert config["catalog_url"] == "https://updates.smlight.tech/services/api/slzb-06x-ota.php?type=ZB&format=slzb&device=17&idx=0"
a.private_downloads.mkdir(parents=True, exist_ok=True)
a.evidence.mkdir(parents=True, exist_ok=True)
with urlopen(config["catalog_url"], timeout=30) as r:
    catalog_bytes = r.read(1024 * 1024 + 1)
assert len(catalog_bytes) <= 1024 * 1024
catalog = json.loads(catalog_bytes)
observations = []
for wanted in config["images"]:
    matches = [x for x in catalog if str(x.get("rev")) == wanted["rev"] and
               int(x.get("baud", -1)) == wanted["baud"] and str(x.get("type")) == wanted["type"] and
               x.get("link") == wanted["url"]]
    assert len(matches) == 1, "EXACT_P7U_CATALOG_ENTRY_NOT_UNIQUE"
    assert wanted["url"].startswith("https://updates.smlight.tech/firmware/slzb06x/zigbee/slzb06p7v2/")
    assert wanted["url"].rsplit("/", 1)[-1] == wanted["filename"] and "P10" not in wanted["filename"]
    with urlopen(wanted["url"], timeout=45) as r:
        blob = r.read(0xb0000 + 1)
    assert len(blob) == 0xb0000, "VENDOR_FLAT_IMAGE_SIZE_UNEXPECTED"
    sha = hashlib.sha256(blob).hexdigest()
    if wanted["sha256"] is not None:
        assert sha == wanted["sha256"], "PINNED_VENDOR_DIGEST_CHANGED"
    (a.private_downloads / wanted["filename"]).write_bytes(blob)
    observations.append({"id": wanted["id"], "url": wanted["url"], "rev": wanted["rev"],
                         "baud": wanted["baud"], "type": wanted["type"], "sha256": sha,
                         "bytes": len(blob), "expected_digest_was_pinned": wanted["sha256"] is not None,
                         "license_url": wanted["license_url"], "installed_content_verified": False})
(a.evidence / "vendor-acquisition.json").write_text(json.dumps({
    "catalog_url": config["catalog_url"], "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(),
    "images": observations, "raw_binaries_published": False, "flash_authorized": False}, indent=2) + "\n")
print(json.dumps({"acquired_images": len(observations), "raw_binaries_published": False}))
