#!/usr/bin/env python3
"""Revalidate every byte in private v0.1.0-rc1 software kit; NO device I/O."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from p7u_rc1_package import verify_directory

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--directory",required=True,type=Path)
    a=p.parse_args()
    try:
        report=verify_directory(a.directory)
        # A file list and its SHA are only trustworthy when cross-checked
        # against the native CCS build's published RC1 manifest.
    except (OSError,ValueError,KeyError) as exc:
        message=str(exc) if isinstance(exc,ValueError) else "RC1_MANIFEST_OR_FILE_UNREADABLE"
        print(json.dumps({"status":"FAIL_CLOSED","reason":message,"flash_authorized":False}))
        raise SystemExit(2) from None
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
