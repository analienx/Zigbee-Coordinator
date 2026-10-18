"""Compare actual firmware bytes from two separate native CI replicas."""
import argparse
import hashlib
import json
from pathlib import Path
import board_profile


def compare(first, second, *, source_sha, reference):
    power = board_profile.settings(reference=reference)
    receipts = []
    for root in (first, second):
        build = json.loads((root / "qualification-build.json").read_text())
        native = json.loads((root / "transport-profile-native.json").read_text())
        board = json.loads((root / "board-native.json").read_text())
        if (build.get("schema") != "r4-p7u-qualification-build-v1" or
                build.get("source_sha") != source_sha or
                build.get("profile") != "transport-only" or build.get("reference_power") != reference or
                native.get("schema") != "r4-p7u-transport-profile-native-v1" or
                native.get("profile") != "transport-only" or
                native.get("source_sha") != source_sha or native.get("native_compilation_verified") is not True or
                board.get("schema") != "r4-p7u-qualification-board-v1" or board.get("power") != power or
                board.get("transport_only") is not True or
                board.get("native_verified") is not True or
                any(x.get("flash_authorized") is not False for x in (build, native, board))):
            raise ValueError("QUALIFICATION_REPLICA_RECEIPT_MISMATCH")
        files = native["image_binding"]["files"]
        for ext, key in ((".hex", "hex"), (".bin", "bin")):
            name = files[key]["file"]
            if Path(name).name != name:
                raise ValueError("QUALIFICATION_REPLICA_PATH")
            digest = hashlib.sha256((root / name).read_bytes()).hexdigest()
            if digest != files[key]["sha256"] or digest != build["firmware"][ext]:
                raise ValueError("QUALIFICATION_REPLICA_CONTENT_MISMATCH")
            if key == "bin" and digest != board.get("native_binary_sha256"):
                raise ValueError("QUALIFICATION_BOARD_NATIVE_CONTENT_MISMATCH")
        receipts.append(build)
    if (receipts[0].get("replica") != "1" or receipts[1].get("replica") != "2" or
            not receipts[0].get("run_id") or receipts[0]["run_id"] != receipts[1].get("run_id") or
            receipts[0]["firmware"] != receipts[1]["firmware"]):
        raise ValueError("QUALIFICATION_INDEPENDENT_REPLICAS_DIVERGE")
    return {"schema": "r4-p7u-qualification-reproducibility-v1", "source_sha": source_sha,
            "reference_power": reference, "firmware": receipts[0]["firmware"],
            "two_native_replicas_byte_identical": True, "current_board_qualified": False,
            "physical_uart_verified": False, "flash_authorized": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--first", required=True, type=Path)
    parser.add_argument("--second", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = compare(args.first, args.second, source_sha=args.source_sha, reference=args.reference)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
