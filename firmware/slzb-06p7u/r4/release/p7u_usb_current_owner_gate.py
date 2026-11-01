"""Current-stock owner admission, DISTINCT from historical-107 forensic audit.

Read-only. An older owner snapshot may contain one no-key non-child entry no
longer in the stock coordinator. That absent HISTORICAL inventory is not
automatically rewritten to NVM or fabricated for firmware-only flashing.
Only all identities present in the current owner snapshot, their live APS keys
and counter floors, NWK PAN/epoch/channel/seed and genuine TI native reader
are checked. No artifact generated here is permission to write flash.
"""
from __future__ import annotations
import json
from p7u_usb_security_model import (
    Backup, SecurityHold, _silicon_owner_fields, parse_backup,
)

SCHEMA = "p7u-usb-current-owner-preservation-v1"


def reconcile_current(*, historical: dict, fresh: dict, records: dict, abi: dict,
                      native_preflight_pass: bool = False,
                      candidate_semantics_pass: bool = False,
                      baseline_counter_floor: int | None = None,
                      runtime_inventory_peers=frozenset(),
                      acknowledged_new_peers=frozenset()) -> dict:
    report = {"schema": SCHEMA, "status": "HOLD",
              "flash_authorized": False, "nv_write_authorized": False,
              "replay_old_nv_authorized": False,
              "native_preflight_pass": native_preflight_pass is True,
              "candidate_semantics_pass": candidate_semantics_pass is True,
              "reason_codes": []}
    reasons: set[str] = set()
    def check(ok: bool, code: str) -> None:
        if not ok:
            reasons.add(code)
    try:
        old, now = parse_backup(historical), parse_backup(fresh)
        live = _silicon_owner_fields(records, abi)
        old_ids, now_ids, chip_ids = set(old.peers), set(now.peers), set(live["addresses"])
        missing = old_ids - now_ids
        extra = now_ids - old_ids
        report.update(historical_devices=len(old_ids),
                      current_devices=len(now_ids),
                      silicon_devices=len(chip_ids),
                      historical_only=len(missing),
                      historically_new=len(extra),
                      live_aps_associations=len(live["aps"]))
        # Do not normalize unknown or keyed historical devices away.
        check(len(old_ids) == 107, "HISTORICAL_REFERENCE_INVALID")
        check(len(missing) <= 1, "HISTORICAL_MISSING_PEER_LIMIT_EXCEEDED")
        # A device new since the historical reference is admitted only when the
        # owner acknowledged that exact IEEE (pinned in the operator package).
        ack_valid = (type(acknowledged_new_peers) is frozenset and
                     all(type(p) is bytes and len(p) == 8 for p in acknowledged_new_peers))
        check(ack_valid, "ACKNOWLEDGED_NEW_PEERS_INVALID")
        check(not extra or (ack_valid and extra <= acknowledged_new_peers), "CURRENT_UNEXPECTED_PEER")
        report["acknowledged_new_peers"] = len(extra & acknowledged_new_peers) if ack_valid else 0
        # A stale host backup can omit the one historically keyless,
        # non-child router whose address record has reappeared at runtime.
        # Admit only that exact bounded difference, independently bound to
        # original backup + protected DB by the sealed caller. Never synthesize
        # backup entries, keys, children, new devices, or any NV write.
        known_valid = (type(runtime_inventory_peers) is frozenset and
                       all(type(peer) is bytes and len(peer) == 8
                           for peer in runtime_inventory_peers))
        known = {peer[::-1] for peer in runtime_inventory_peers} if known_valid else set()
        extra_chip = chip_ids - now_ids
        runtime_reappearance = (known_valid and len(extra_chip) == 1 and
            extra_chip == missing and extra_chip <= known and
            now_ids <= chip_ids and not (extra_chip & set(live["aps"])) and
            all(old.peers[peer] == (None, None, None, False) for peer in extra_chip))
        check(now_ids == chip_ids or runtime_reappearance,
              "CURRENT_SILICON_PEER_INVENTORY_MISMATCH")
        report["runtime_inventory_bound_reappearances"] = len(extra_chip) if runtime_reappearance else 0
        for ieee in missing:
            key, tx, rx, is_child = old.peers[ieee]
            check(key is None and tx is None and rx is None and is_child is False,
                  "HISTORICAL_MISSING_KEYED_OR_CHILD_PEER")
        # Historical backups can be stale as to peer key/counters, but may
        # never mask a different Zigbee network or coordinator identity.
        for name in ("coordinator", "pan", "extended_pan", "channel", "update",
                     "level", "network_key", "sequence", "seed"):
            check(getattr(old, name) == getattr(now, name),
                  "NETWORK_HISTORY_IDENTITY_DIFFERENCE")
            check(getattr(now, name) == live[name],
                  "CURRENT_SILICON_NETWORK_IDENTITY_DIFFERENCE")
        check(live["trust_center_raw"] in (bytes(8), live["coordinator"][::-1]),
              "CURRENT_SILICON_TC_FOREIGN")
        check(old.frame_counter <= now.frame_counter,
              "CURRENT_OWNER_NWK_COUNTER_REGRESSION")
        check(type(baseline_counter_floor) is int and
              baseline_counter_floor > 0 and baseline_counter_floor >= now.frame_counter,
              "CURRENT_SILICON_NWK_COUNTER_FLOOR_NOT_PROVEN")
        check(native_preflight_pass is True, "CURRENT_NATIVE_PREFLIGHT_NOT_PASS")
        check(candidate_semantics_pass is True, "CURRENT_CANDIDATE_SOURCE_NOT_VERIFIED")
        # Every present key must map to the exact peer IEEE in the native APS
        # table. Historical keys may have been legitimately rotated: only the
        # live snapshot is authoritative at flash-time.
        check(set(live["aps"]) <= now_ids, "CURRENT_APS_UNKNOWN_PEER")
        for ieee, (key, tx, rx) in live["aps"].items():
            if ieee not in now.peers:
                continue
            nowkey, nowtx, nowrx, _ = now.peers[ieee]
            check(nowkey is not None and nowkey == key, "CURRENT_APS_KEY_MISMATCH")
            check(nowtx is not None and nowrx is not None and
                  tx >= nowtx and rx >= nowrx,
                  "CURRENT_APS_COUNTER_FLOOR_UNPROVEN")
        for ieee, (key, tx, rx, _) in now.peers.items():
            if key is not None:
                # An explicit owner key must not be silently re-associated.
                if ieee in live["aps"]:
                    check(live["aps"][ieee][0] == key,
                          "CURRENT_APS_OWNER_ASSOCIATION_CHANGED")
                check(tx is not None and rx is not None,
                      "CURRENT_PEER_KEY_COUNTER_ABSENT")
    except (SecurityHold, KeyError, TypeError, ValueError, IndexError) as err:
        reasons.add(str(err) if isinstance(err, SecurityHold) else
                    "CURRENT_RECORD_SCHEMA_INVALID")
    report["reason_codes"] = sorted(reasons)
    report["status"] = ("PASS_CURRENT_OWNER_OFFLINE_ONLY" if not reasons else "HOLD")
    return report
