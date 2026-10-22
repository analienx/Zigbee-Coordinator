# R4 operator: reviewed private provisioning and fast ROM guards

Applies to **one SLZB-06P7U / CC2652P7**, not a spare, MR4U or different board.
The operator is the ONLY entry point for a NEW deployment. All builds come from
the exact seven-job native/reproducibility GitHub Actions workflow. Operations
run locally on the authorized Windows host, not WSL. No broad erase, formation
fallback, NV replay, counter rewriting or automatic reset is supported.

## Latest physical completion and speed finding (2026-10-22)

- Verified deployed `323949a`: **capture, prepare, flash, startup all PASS**. Three sectors were written, 88-sector parity passed, and genuine coordinator state 9 with marker `0x60=0x55` was confirmed on the first startup. Network traffic via USB Zigbee2MQTT is pending. Board should return to HA USB mode rather than changing Z2M to TCP.
- Flash stage consumed **494.27s** for just three changed 8-KiB APP sectors because of duplicate 704-KiB admissions and final full-image readback over 240-byte serial ROM packets. The initial duplicate 704-KiB snapshot took **234.91s**. This is **not** optimized for fastest flashing.
- Read-only inspection of actual device SLZB-OS JavaScript exposed its staged custom Zigbee-upload path; it could bypass the host/network ROM-packet loop, but sparse APP+AC000 and NV/CCFG guarantees remain unverified. See [the technical investigation, fast-lane proposal and source caveats](R4_FLASH_PERFORMANCE_2026-10-22.md). **Do not flash a generic contiguous BIN or use automatic NVM erase.**

## Historical 36aa811 physical incident (2026-10-22)

- Source `36aa8117df8508f6236baa633c1f7907e0626fd7`, GitHub run
  [39764140206](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39764140206)
  produced matching native APP and AC000 outputs.
- One initial duplicate ROM-BSL capture matched. Retained-security preflight
  passed against latest persisted data and original coordinator keys/identities.
- The orchestrated writer completed in **1511.33 seconds** (25m 11s):
  25/25 target sectors readback-verified, all-88 parity, NV/CCFG preserved,
  no reset, rollback or sector outside allowlist.
- The one allowed application boot was acknowledged. The retained-startup SRSP
  succeeded in 0.047s. Subsequent independent B1P1/B1E1 polling received
  **zero valid snapshots** within its 80-second deadline. A distinct later
  B1P1-only read-only probe also timed out.
- Final state is **OBSERVER_TIMEOUT_STATE_UNKNOWN**, *not* a demonstrated
  firmware-FAILED state or a working state9 coordinator. The startup request
  and its operation lock are **consumed**. Never rerun startup, restart Zigbee2MQTT,
  clear the lock or reset the radio based only on a host timeout.
  Preserve private receipts and the flashed network/counter state.

## Why the 25-sector flash required ~25 minutes

TI ROM-BSL has a maximum 240-byte read chunk through the pinned adapter.
Every response is checksum/ACK/status-validated, over one TCP connection.
The original writer reread every protected NV/CCFG/boot-range sector and
the target sector **twice per erase**, including across an async journal
boundary. It also performed full-88 SHA parity before boot-vector commit and
at the end, and each written sector received a full bytewise readback.

This is much more expensive than the SMLIGHT UI's ordinary firmware upload;
the UI need not honor our APP+matching-AC000, 88-sector invariant and
postfailure-NV-preservation requirements. We have **not benchmarked** its
actual programming algorithm and must not assume its guarantees are equal.

### Optimized future writer (requires a NEW GitHub-native candidate)

`r4_stock20260311_transition.py` now uses the existing TI ROM CRC32
read-only command for interim protected-sector checks **after the complete
SHA-based 88-sector admission**. Before the first erase, it compares ROM CRC
against the source-bound capture on APP, NV, AC000 and top/CCFG sectors.
Mismatch stops without an erase. CRC tripwires run both before and after
the journal; if any region changes, the operation holds.

It **does not replace** bytewise sector readback, all-88 pre-boot SHA parity,
all-88 final SHA parity, frozen ordered erase/write scope, AC000 vectors-last,
NV/CCFG prohibition or one-shot failure lock. CRC has weaker collision
resistance than SHA256, so it is deliberately an interim change detector,
not a proof of installed firmware correctness. Performance benefit on real
hardware remains unmeasured until a separately justified next operation.
Do not rerun the installed 36aa811 flash to benchmark the optimization.

## Single entry point: sealed private adapter provisioning

A new `provision` command prepares all four audited, one-shot adapters
(`capture_current_once.py`, `prepare_upgrade_once.py`,
`flash_upgrade_once.py`, `startup_once.py`) in a fresh private directory.
The templates remain private and must be reviewed once, rather than
committed or copied into public artifacts. The exact candidate, workflow run,
template SHA256, replacements and each **rendered script SHA256** are all
recorded in a privately reviewed JSON recipe.

Schema sketch (illustrative values, not authorization):

```json
{
  "schema": "p7u-r4-one-use-adapters-v1",
  "source_sha": "<exact 40-character native source SHA>",
  "github_run_id": "<exact GitHub Actions run ID>",
  "candidate_sha256": "<SHA256 of canonical candidate.json>",
  "stages": {
    "capture": {
      "template_sha256": "<SHA256 of private capture template>",
      "output_sha256": "<SHA256 of fully rendered capture script>",
      "replacements": [
        {"old": "<reviewed single anchor>", "new": "<approved replacement>", "count": 1}
      ]
    }
  }
}
```

The actual recipe must include `capture`, `prepare`, `flash` and
`startup` entries. The reviewed recipe's SHA is supplied independently
to reject substitutions. Provisioning validates **all outputs before
creating any file**, writes exclusively (no overwrite), and seals the output
hashes in `operator-adapters.json`. An interrupted provision leaves a
partial workspace that cannot be reused; select a fresh private directory.
Any subsequent edit to a sealed script blocks `run`.

```text
python firmware/slzb-06p7u/r4/release/p7u_r4_operator.py \
  --candidate <exact-built-candidate-directory> \
  --private <NEW-empty-private-operation-directory> \
  --source <exact-source-SHA> \
  provision --template-dir <reviewed-private-template-directory> \
  --recipe <private-reviewed-recipe.json> \
  --recipe-sha256 <independently-reviewed-recipe-SHA256>
```

Then the **same operator** performs bounded stages:

```text
... p7u_r4_operator.py --candidate <same> --private <same> --source <same> status
... p7u_r4_operator.py --candidate <same> --private <same> --source <same> run --through capture --allow-bsl
... p7u_r4_operator.py --candidate <same> --private <same> --source <same> run --through prepare
... p7u_r4_operator.py --candidate <same> --private <same> --source <same> run --through flash --allow-flash
... p7u_r4_operator.py --candidate <same> --private <same> --source <same> run --through startup --allow-boot
```

Or use one `run --through startup` with all required flags, only after
the reviewed operation and permission gates are satisfied. The operator
skips verified prior stages, but never retries an initiated, incomplete
or failed stage. A failure leaves its lock for independent investigation.

The `status` operation remains strictly read-only and displays a
receipt-based stage summary, lock presence and progress of the **existing**
flash journal. Journal progress alone is never a successful flash receipt.

## Safety and acceptance still required

Only one existing physical board is available. Source tests and reproducible
native compilation do not establish a working radio. The required physical
gate remains successful native network-start confirmation, real state9,
correct 0x55 configured marker, source-bound management frames, and
ordinary Zigbee2MQTT round trips/natural reporting. This incident has **not**
passed that gate; leave Z2M stopped and avoid repeat startup/restore.
