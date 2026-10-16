"""Fetch exact pinned TI distributions with mandatory externally supplied SHA-256.

Download is separate from installation. Never execute downloaded installers
without a reviewed installation procedure and correct vendor-authenticated pins.
"""
import argparse
import hashlib
import json
import os
import pathlib
import urllib.parse
import urllib.request

ARTIFACTS = {
    "ccs": ("12.8.0.00012", "CCS12.8.0.00012_linux-x64.tar.gz",
            "https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-J1VdearkvK/12.8.0/CCS12.8.0.00012_linux-x64.tar.gz"),
    "sysconfig": ("1.21.1.3772", "sysconfig-1.21.1_3772-setup.run",
                  "https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-nsUM6f7Vvb/1.21.1.3772/sysconfig-1.21.1_3772-setup.run"),
    "clang": ("3.2.2.LTS", "ti_cgt_armllvm_3.2.2.LTS_linux-x64_installer.bin",
              "https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-ayxs93eZNN/3.2.2.LTS/ti_cgt_armllvm_3.2.2.LTS_linux-x64_installer.bin"),
}


# Vendor-published SHA-256, extracted from each TI version-specific download
# page's adjacent Linux artifact <ti-text-copy value="..."> element on
# 2026-10-16. Exact filename/link/digest pairing verified per artifact.
# This is *publisher* metadata, not a digest computed after download.
VENDOR_SHA256 = {
    "ccs": "fa807c9ea3bc8a558c4c9bef64c37261c1146d0b9da96ae7867e1b5e3046e06d",
    "sysconfig": "0c1674f82a53b187f60e376de3da2b719f003187c7437998c2ce3f975504d1d5",
    "clang": "2864bb1013ec60b1290f92ff723a4fc222653db1278c08ad81af6063f698dec9",
}
PUBLISHER_PAGES = {
    "ccs": "https://www.ti.com/tool/download/CCSTUDIO/12.8.0",
    "sysconfig": "https://www.ti.com/tool/download/SYSCONFIG/1.21.1.3772",
    "clang": "https://www.ti.com/tool/download/ARM-CGT-CLANG/3.2.2.LTS",
}


def valid_digest(value):
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def acquire(kind, digest, destination):
    if kind not in ARTIFACTS:
        raise ValueError("unknown TI component")
    if not valid_digest(digest):
        raise ValueError("publisher SHA-256 must be a 64-character lowercase hexadecimal pin")
    version, filename, url = ARTIFACTS[kind]
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "dr-download.ti.com":
        raise RuntimeError("untrusted TI distribution origin")
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / filename
    if path.is_file():
        digest_cached = hashlib.sha256()
        with path.open("rb") as existing:
            for chunk in iter(lambda: existing.read(1024 * 1024), b""):
                digest_cached.update(chunk)
        if digest_cached.hexdigest() == digest:
            return {"component": kind, "version": version, "sha256": digest,
                    "bytes": path.stat().st_size, "file": str(path), "source": url,
                    "status": "AUTHENTICATED_CACHED_DOWNLOAD"}
        path.unlink()
    temporary = destination / (filename + ".incomplete")
    temporary.unlink(missing_ok=True)
    h = hashlib.sha256()
    size = 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "R4-B0-pinned-fetch/1"})
        with urllib.request.urlopen(req, timeout=45) as response, temporary.open("wb") as target:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in ("dr-download.ti.com", "dr-download-cdn.ti.com", "downloads.ti.com"):
                raise RuntimeError("TI download redirected to untrusted origin: %s (%s)" % (final.hostname, final.scheme))
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > 2 * 1024 * 1024 * 1024:
                    raise RuntimeError("TI distribution exceeds 2 GiB download cap")
                target.write(chunk)
                h.update(chunk)
        actual = h.hexdigest()
        if actual != digest:
            raise RuntimeError("TI distribution SHA-256 mismatch")
        os.replace(temporary, path)
        return {"component": kind, "version": version, "sha256": actual,
                "bytes": size, "file": str(path), "source": url,
                "status": "AUTHENTICATED_DOWNLOAD_ONLY"}
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("component", choices=sorted(ARTIFACTS))
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = acquire(args.component, args.sha256, args.out)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
