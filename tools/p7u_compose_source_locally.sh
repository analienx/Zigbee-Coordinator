#!/usr/bin/env bash
# Reproduce the P7U R4 composed TI source locally, without a TI toolchain.
#
# Mirrors the source-composition steps of
# .github/workflows/test-r4-stock20260311-native.yml (B1 overlay, B1+B3 fusion,
# #128 NVOCMP/seed fusions, B2/B4 donors, composite stage with every stage's
# compile-and-mutate harness, NV4 bridge, T6 guard, security ABI stage) and
# finishes with tools/r4_final_source_snapshot.py, which writes the reviewable
# patch of every changed TI file to <out>/b0out/r4-final-ti-source.patch and
# leaves the composed SDK at <out>/b0src/examples/cc13xx_cc26xx_sdk.
#
# No CCS/SysConfig/TI Clang build, no artifacts, no hardware, no flashing.
# Needs: git, curl, python3, a C compiler (cc/gcc) for the harnesses.
#
# Usage: tools/p7u_compose_source_locally.sh <source-sha> <out-dir-under-/tmp> [cache-dir]
#   <source-sha>  40-hex commit whose first 4 bytes become the evidence digest
#                 (use the commit you are reviewing; 8ec1439... reproduces V53).
#   <out-dir>     must be under /tmp (the composite stage refuses other paths).
#   [cache-dir]   pinned downloads are kept here (default /tmp/p7u-compose-cache).
set -Eeuo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ $# -ge 2 ] || { sed -n 2,22p "${BASH_SOURCE[0]}"; exit 2; }
export B1_SOURCE_SHA="$1"; OUT="$2"; CACHE="${3:-/tmp/p7u-compose-cache}"
[[ "$B1_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "source-sha must be 40 lowercase hex"; exit 2; }
case "$OUT" in /tmp/*) ;; *) echo "out-dir must be under /tmp"; exit 2;; esac

TI_SDK_SHA=3615ad5d3f4f271258d18a2f5ce1785064ff9a58
TI_EXAMPLES_SHA=87ff5b638b632050228a7504f35cf3b95581c278
HERDSMAN_SHA=0968f979d558874b17396c96b66382d4236bbdcd
B3_SHA=b481e0beabf1966900644f69d7f5d024708ebf73
NVSEC_SHA=d9f6ea1f463b7be4f72f8ecd22fd0eb4d64fc193
B2_SHA=d13a48f5226d42e247a17d9198d84c94a4415030
B2_FAILURE_SHA=530a52631fbde274a2ae356c490bad71b47168a6
B4_SHA=3231abb1f13210eb88afe13ff7b7f9f29709cd6b

pinned_repo() {  # <dir> <url> <sha>: shallow fetch once, keep a ref so clones work
  local dir="$1" url="$2" sha="$3"
  if [ ! -d "$dir/.git" ]; then git init -q "$dir"; git -C "$dir" remote add origin "$url"; fi
  if ! git -C "$dir" cat-file -e "$sha^{commit}" 2>/dev/null; then
    git -C "$dir" fetch -q --depth 1 origin "$sha"
  fi
  git -C "$dir" update-ref "refs/heads/pin-$sha" "$sha"
}
mkdir -p "$CACHE"
pinned_repo "$CACHE/sdk" https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk.git "$TI_SDK_SHA"
pinned_repo "$CACHE/examples" https://github.com/TexasInstruments/simplelink-zstack-examples.git "$TI_EXAMPLES_SHA"
for sha in "$B3_SHA" "$NVSEC_SHA" "$B2_SHA" "$B2_FAILURE_SHA" "$B4_SHA"; do
  pinned_repo "$CACHE/donors" https://github.com/analienx/Zigbee-Coordinator.git "$sha"
done
[ -f "$CACHE/herdsman-definition.ts" ] || curl -fsSL --proto '=https' --tlsv1.2 \
  "https://raw.githubusercontent.com/Koenkk/zigbee-herdsman/$HERDSMAN_SHA/src/adapter/z-stack/znp/definition.ts" \
  -o "$CACHE/herdsman-definition.ts"

rm -rf "$OUT" && mkdir -p "$OUT/b0out" "$OUT/b0src"
b0out="$OUT/b0out"
git clone -q --no-checkout -b "pin-$TI_EXAMPLES_SHA" "$CACHE/examples" "$OUT/b0src/examples"
git -C "$OUT/b0src/examples" checkout -q "$TI_EXAMPLES_SHA"
rm -rf "$OUT/b0src/examples/cc13xx_cc26xx_sdk"
git clone -q -b "pin-$TI_SDK_SHA" "$CACHE/sdk" "$OUT/b0src/examples/cc13xx_cc26xx_sdk"
sdk="$OUT/b0src/examples/cc13xx_cc26xx_sdk"
[ "$(git -C "$sdk" rev-parse HEAD)" = "$TI_SDK_SHA" ]
donor="$OUT/b0src/examples/examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7"
profile="$WS/firmware/slzb-06p7u/r4/profiles/p7u-r4-stock20260311-nv4.json"

python3 "$WS/firmware/slzb-06p7u/r4/qualification/full_nv4_profile.py" \
  --stage pinned-sources --profile "$profile" --syscfg "$donor/znp.syscfg" \
  --linker "$sdk/source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd" \
  --projectspec "$donor/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec" \
  --receipt "$b0out/r4-full-nv4-pinned-source.json"
mkdir -p "$sdk/.b1-prerequisites"
cp "$CACHE/herdsman-definition.ts" "$sdk/.b1-prerequisites/herdsman-definition.ts"
python3 "$WS/firmware/slzb-06p7u/r4/b1/tools/apply_b1.py" --sdk "$sdk" --receipt "$b0out/b1-overlay.json"

show() { git -C "$CACHE/donors" show "$1"; }
show "$B3_SHA:firmware/slzb-06p7u/r4/b3/tools/b3_source_overlay.py" > "$OUT/r4_b3_pinned_security_overlay.py"
python3 "$WS/tools/r4_b1_b3_security_fuse.py" --sdk "$sdk" --b3-script "$OUT/r4_b3_pinned_security_overlay.py" \
  --b3-git-sha "$B3_SHA" --b1-overlay-receipt "$b0out/b1-overlay.json" --receipt "$b0out/b1-b3-source-fusion.json"
mkdir -p "$OUT/nvsec"
show "$NVSEC_SHA:tools/r4_b3_nvocmp_compaction_fuse.py" > "$OUT/nvsec/r4_b3_nvocmp_compaction_fuse.py"
show "$NVSEC_SHA:tools/r4_b3_seed_status_fuse.py" > "$OUT/nvsec/r4_b3_seed_status_fuse.py"
for fuse in r4_b3_nvocmp_compaction_fuse r4_b3_seed_status_fuse; do
  python3 "$OUT/nvsec/$fuse.py" --sdk "$sdk" --b3-script "$OUT/r4_b3_pinned_security_overlay.py" \
    --b3-git-sha "$B3_SHA" --b1-overlay-receipt "$b0out/b1-overlay.json" --receipt "$b0out/$fuse.json"
done
C="$OUT/composite-sources"; mkdir -p "$C"
show "$B2_SHA:tools/b2_mto_fail_closed_overlay.py" > "$C/b2_mto_fail_closed_overlay.py"
show "$B2_FAILURE_SHA:firmware/slzb-06p7u/r4/b2/tools/b2_mto_nv_guard.py" > "$C/b2_mto_failure_guard_overlay.py"
show "$B2_SHA:tools/b2_compile_actual_mto_nv_timer.py" > "$C/b2_compile_actual_mto_nv_timer.py"
show "$B4_SHA:firmware/slzb-06p7u/r4/b4/b4_native_patch.py" > "$C/b4_native_patch.py"
show "$B4_SHA:firmware/slzb-06p7u/r4/b4/b4_v4_native_patch.py" > "$C/b4_v4_native_patch.py"
python3 "$WS/tools/r4_b0_b4_composite_stage.py" --sdk "$sdk" --baseline "$C" \
  --b1-receipt "$b0out/b1-overlay.json" --fusion-receipt "$b0out/b1-b3-source-fusion.json" \
  --b2-script "$C/b2_mto_fail_closed_overlay.py" --b2-failure-script "$C/b2_mto_failure_guard_overlay.py" \
  --b4-v3-script "$C/b4_native_patch.py" --b4-v4-script "$C/b4_v4_native_patch.py" \
  --b2-sha "$B2_SHA" --b2-failure-sha "$B2_FAILURE_SHA" --b4-sha "$B4_SHA" \
  --receipt "$b0out/r4-composite-source.json"
python3 "$WS/firmware/slzb-06p7u/r4/qualification/nv4_b1_bridge.py" --sdk "$sdk" \
  --b1-overlay-receipt "$b0out/b1-overlay.json" --nv-base 0xA4000 --receipt "$b0out/r4-nv4-b1-source.json"
python3 "$WS/tools/r4_t6_migration_guard.py" --sdk "$sdk" --profile "$profile" \
  --b1-overlay-receipt "$b0out/b1-overlay.json" --receipt "$b0out/t6-legacy-migration-prohibition.json"
python3 "$WS/firmware/slzb-06p7u/r4/qualification/stock20260311_security_abi.py" stage --sdk "$sdk" \
  --b1-overlay-receipt "$b0out/b1-overlay.json" --source-sha "$B1_SOURCE_SHA" --profile "$profile" \
  --receipt "$b0out/security-native-abi-stage.json"
python3 "$WS/tools/r4_final_source_snapshot.py" --sdk "$sdk" --out-dir "$b0out" --source-sha "$B1_SOURCE_SHA"
echo "COMPOSED: $b0out/r4-final-ti-source.patch  (SDK tree: $sdk)"
