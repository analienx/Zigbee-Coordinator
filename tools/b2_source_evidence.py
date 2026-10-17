#!/usr/bin/env python3
"""Generate verifiable SOURCE-LEVEL B2 evidence from the exact pinned TI trees.

This indexes source definitions and declarations. It deliberately does NOT
invent active preprocessor values, ELF sections, linked sizeof or real memory.
Native linked evidence must be collected by a separate attested build stage.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SDK_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
EXAMPLES_SHA = "87ff5b638b632050228a7504f35cf3b95581c278"
GITLINK = "cc13xx_cc26xx_sdk"
DEFINITIONS = (
    "MAX_RTG_SRC_ENTRIES", "MAX_NEIGHBOR_ENTRIES",
    "MAX_RTG_ENTRIES", "NWK_MAX_DEVICE_LIST", "NWK_MAX_DEVICES",
    "MAX_RREQ_ENTRIES", "MAX_SOURCE_ROUTE", "SRC_RTG_EXPIRY_TIME",
    "MTO_RREQ_LIMIT_TIME", "MTO_ROUTE_EXPIRY_TIME",
    "NWK_MAX_DATABUFS_WAITING", "NWK_MAX_DATABUFS_SCHEDULED",
    "NWK_MAX_DATABUFS_CONFIRMED", "NWK_MAX_DATABUFS_TOTAL",
    "NWK_INDIRECT_MSG_MAX_ALL", "NWK_INDIRECT_MSG_MAX_PER",
    "NWK_MAX_DATA_RETRIES", "APSC_MAX_FRAME_RETRIES",
    "ROUTE_EXPIRY_TIME", "CONCENTRATOR_ENABLE",
    "CONCENTRATOR_DISCOVERY_TIME", "CONCENTRATOR_ROUTE_CACHE",
)
TABLES = {
    "source_routes": ("rtgSrcTable", "MAX_RTG_SRC_ENTRIES"),
    "neighbors": ("neighborTable", "MAX_NEIGHBOR_ENTRIES"),
    "nwk_routes": ("rtgTable", "MAX_RTG_ENTRIES"),
    "children": ("AssociatedDevList", "NWK_MAX_DEVICES"),
    "route_requests": ("rtDiscTable", "MAX_RREQ_ENTRIES"),
    "source_relay_path": ("rtgSrcRelayList", "MAX_SOURCE_ROUTE"),
}
SEEDS = (
    "source/ti/zstack/stack/nwk/nwk_globals.h",
    "source/ti/zstack/stack/nwk/nwk_globals.c",
    "source/ti/zstack/sysconfig/ti_zstack_config.h",
    "source/ti/zstack/stack/nwk/nwk_util.h",
    "source/ti/zstack/stack/sys/zglobals.h",
    "source/ti/zstack/stack/sys/zglobals.c",
)
SCAN_DIRS = (
    "source/ti/zstack/stack/nwk", "source/ti/zstack/stack/aps",
    "source/ti/zstack/stack/mac", "source/ti/zstack/mt",
    "source/ti/zstack/npi", "source/ti/zstack/sysconfig",
)
INTERESTING = re.compile(
    r"NWKSTAT_SOURCE_ROUTE_FAILURE|NWKSTAT_NO_ROUTE_AVAIL|"
    r"RTG_(?:\w+)|srcRtg\w*|rtgSrc\w*|nwkNeighbor\w*|"
    r"nwkHandleBrokenRoute|MAX_RTG_\w+|MAX_RREQ_ENTRIES|"
    r"nwkConcentrator\w*|zgConcentrator\w*|"
    r"NWK_MAX_DATABUFS_\w+|MAC.*[Cc]onfirm|"
    r"AF_DataRequest|MT_AF_DATA_REQUEST|MT_SYS_PING|"
    r"NWK_INDIRECT_MSG_\w+"
)
DEF_PATTERN = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+(.+?)\s*(?://.*)?$")
ARRAY_PATTERN = re.compile(
    r"^\s*(?:[A-Za-z_]\w*\s+)+(?P<symbol>"
    + "|".join(map(re.escape, (v[0] for v in TABLES.values())))
    + r")\s*\[(?P<capacity>[^\]]+)\]\s*;"
)

def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

def validate_pin(root, expected):
    observed = git(root, "rev-parse", "HEAD")
    if observed != expected or git(root, "status", "--porcelain"):
        raise ValueError("unpinned or modified TI source tree: " + str(root))
    return observed

def extract(sdk, examples, output, repo_sha, run_id):
    validate_pin(sdk, SDK_SHA)
    validate_pin(examples, EXAMPLES_SHA)
    gitlink = git(examples, "ls-tree", "HEAD", GITLINK)
    if not re.search(r"\b160000 commit " + SDK_SHA + r"\b", gitlink):
        raise ValueError("TI examples SDK gitlink SHA mismatch")
    files = []
    for path in SEEDS:
        if not (sdk / path).is_file():
            raise ValueError("missing pinned required source " + path)
        files.append(sdk / path)
    for folder in SCAN_DIRS:
        d = sdk / folder
        if d.is_dir():
            files.extend(p for p in d.rglob("*") if p.is_file() and p.suffix in (".c", ".h", ".xdt"))
    files = sorted(set(files))
    definitions = {name: [] for name in DEFINITIONS}
    refs = []
    declarations = {key: [] for key in TABLES}
    inventory = []
    for file in files:
        path = file.relative_to(sdk).as_posix()
        raw = file.read_bytes()
        # UTF-8 only, with replacement for TI legacy comments.
        lines = raw.decode("utf-8", errors="replace").splitlines()
        if path in SEEDS or any(INTERESTING.search(line) for line in lines):
            inventory.append({"path": path, "sha256": hashlib.sha256(raw).hexdigest(),
                              "lines": len(lines)})
        for line_no, line in enumerate(lines, 1):
            m = DEF_PATTERN.match(line)
            if m and m.group(1) in definitions:
                definitions[m.group(1)].append({
                    "path": path, "line": line_no, "source_expression": m.group(2).strip(),
                    "status": "SOURCE_ONLY_PREPROCESSOR_BRANCH_UNRESOLVED"
                })
            a = ARRAY_PATTERN.match(line)
            if a:
                for key, (sym, macro) in TABLES.items():
                    if a.group("symbol") == sym:
                        declarations[key].append({
                            "path":path, "line":line_no,
                            "symbol":sym,"declared_capacity_expression":a.group("capacity").strip(),
                            "expected_macro":macro,
                            "linked_section":None,"entry_sizeof":None,"linked_bytes":None
                        })
            if INTERESTING.search(line) and not line.lstrip().startswith("*"):
                refs.append({"path":path, "line":line_no, "text":line.strip()[:240]})
    if not inventory or not declarations["source_routes"] or not declarations["neighbors"]:
        raise ValueError("required real NWK table declarations absent")
    provenance = {
        "status":"SOURCE_CONFIRMED_NOT_NATIVE_LINKED",
        "sdk_git_sha":SDK_SHA,"examples_git_sha":EXAMPLES_SHA,
        "examples_sdk_gitlink":gitlink,"b2_repository_sha":repo_sha or "UNKNOWN",
        "github_actions_run_id":run_id or "UNKNOWN",
        "source_files":inventory,
    }
    limits = {
        "measurement_kind":"SOURCE_ONLY_NOT_LINKED",
        "native_elf_sha256":None,"native_map_sha256":None,
        "runtime_heap_high_water":None,
        "effective_profiles":{"P0":None,"P1":None,"P2":None,"P3":None},
        "tables":{name:{
            "source_declarations":declarations[name],
            "source_definitions":definitions[macro] if macro in definitions else [],
            "effective_linked_count":None,"entry_sizeof":None,
            "linked_bytes":None,"elf_symbol_verified":False
        } for name,(_,macro) in TABLES.items()},
        "macro_definitions":definitions,
    }
    output.mkdir(parents=True, exist_ok=True)
    def write(name,data):
        (output/name).write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    write("B2_SOURCE_INVENTORY.json",provenance)
    write("B2_EFFECTIVE_LIMITS.json",limits)
    write("B2_SOURCE_REFERENCES.json",{"status":"INDEX_NOT_CALL_GRAPH","references":refs})
    source_md = [
        "# B2 source entry-point index — actual pinned TI source",
        "",
        "**SOURCE_CONFIRMED / NOT NATIVE LINKED / NOT EXECUTION TRACE.**",
        "This indexes exact source lines, without claiming edges of an actual call graph.",
        f"SDK \`{SDK_SHA}\`; examples \`{EXAMPLES_SHA}\`; B2 \`{repo_sha}\`.",
        "",
        "## NWK storage declarations (linkage unresolved)",
    ]
    for key,items in declarations.items():
        source_md.append(f"### {key}")
        source_md.extend(
            f"- \`{item['path']}:{item['line']}\`: "
            f"\`{item['symbol']}[{item['declared_capacity_expression']}]\`"
            for item in items
        )
        if not items:
            source_md.append("- Not found in scanned files; requires investigation.")
    source_md += ["","## How to reconstruct the runtime call graph",
        "1. Inspect real functions around source references and their callers.",
        "2. Trace NLDE/AF request -> NWK routing -> MAC confirms/status -> invalidation.",
        "3. Cross-reference each reached symbol with native ELF/map; do not infer from grep.",
        "4. Establish ownership/lifetime before changing arrays, relay lists or queues.",
        "", f"Full exact path:line index in \`B2_SOURCE_REFERENCES.json\` ({len(refs)} lines).",
        "Call graph edges and real failure reproduction: **OPEN**.",
    ]
    (output/"SOURCE_CALL_GRAPH.md").write_text("\n".join(source_md)+"\n",encoding="utf-8")
    (output/"B2_BASELINE_MEMORY.md").write_text(
        "# B2 baseline memory ledger — data acquisition\n\n"
        "**SOURCE_CONFIRMED; NATIVE MEMORY UNKNOWN.**\n\n"
        "The pinned TI source exposes storage declarations, but no honest SRAM"
        " headroom can be calculated without the authentic exact-SHA linked ELF,"
        " linker XML/map, compiler defines and generated SysConfig.\n\n"
        "Pending: .data/.bss, IRQ/C stack, RTOS task stacks, heap arena,"
        " dynamic route/fragment high-water (UNKNOWN until measured),"
        " effective entry sizeof, fragmentation, protected CCFG/NV, UART pins.\n",
        encoding="utf-8")
    (output/"DATA_STATUS.md").write_text(
        "# B2 source-evidence artifact receipt\n\n"
        f"SDK: \`{SDK_SHA}\`\n\nExamples: \`{EXAMPLES_SHA}\`\n\n"
        f"B2 source commit: \`{repo_sha}\`\n\nGitHub Actions run: \`{run_id}\`\n\n"
        f"Indexed files: {len(inventory)}; matched source references: {len(refs)}.\n\n"
        "Native ELF/map, real compile flags, effective limits and physical RF: **NOT VERIFIED**.\n",
        encoding="utf-8")
    return provenance,limits

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--examples",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--repo-sha",default="")
    p.add_argument("--run-id",default="")
    a=p.parse_args()
    provenance,limits=extract(a.sdk,a.examples,a.out,a.repo_sha,a.run_id)
    print(json.dumps({"result":provenance["status"],"files":len(provenance["source_files"]),
                      "tables_with_declarations":sum(bool(t["source_declarations"]) for t in limits["tables"].values()),
                      "native_linked":False},sort_keys=True))

if __name__ == "__main__":
    main()
