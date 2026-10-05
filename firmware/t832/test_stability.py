"""B09/R4-F03 slow leg: real ten-minute stability windows through the
actual YAML scheduler and CLI.

Five independent incidents run concurrently (separate state roots, one
worker each) because each close decision needs ~600 real seconds of
tool-visible window: a healthy close, an outage mid-window, missed ticks,
a close tick a full cadence late (within the one-period grace), and a
close tick past the grace. Tick spacing mirrors the YAML minutes:/5 timer
(300 real seconds); the interpreter fires the real stability automation
per tick with no invented radio traffic (no ZDO publishes ever leave the
stability phase). Wired into the firmware/control jobs only: ~17 minutes
wall time, past the fast-lane budget by design.
"""
from __future__ import annotations

import importlib.util
import json
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "t832_automation", HERE / "test_automation.py"
)
assert SPEC and SPEC.loader
automod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(automod)

LEG_TIMEOUT_S = 20 * 60


def fresh_case():
    """A standalone barrier fixture (not a collected test)."""
    case = automod.BarrierAutomationTests("runTest")
    case.setUp()
    return case


def tick(case, outage="off", bridge="on"):
    stab = automod.Ha(case.root, automation_id="zigbee2mqtt_t832_stability_close")
    stab.set_state(automod.OUTAGE, outage)
    stab.set_state(automod.BRIDGE, bridge)
    result = stab.fire_time_pattern()
    assert result == "ran", result
    return stab


def incident_closed_events(case) -> list:
    latch = case.latch()
    path = case.ha.state / "host-events.log"
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("kind") == "incident_closed" and row.get("incident_id") == latch.get(
            "incident_id"
        ):
            events.append(row)
    return events


def recover(case) -> None:
    case.hold_outage()
    case.run_to_recovery(lambda: case.ha.fire_state("mesh_outage"))


def leg_happy_close(case) -> str:
    recover(case)
    tick(case)
    time.sleep(300)
    tick(case)
    time.sleep(300)
    tick(case)
    latch = case.latch()
    assert latch.get("status") == "closed", latch
    assert latch.get("zdo_proof", {}).get("transaction") == latch.get(
        "zdo_transaction"
    ), latch.get("zdo_proof")
    # Exactly once: a further tick observes, finds non-stabilizing status,
    # and halts without a second close event.
    tick(case)
    assert case.latch().get("status") == "closed", case.latch()
    assert len(incident_closed_events(case)) == 1, incident_closed_events(case)
    # No recurring radio probes: the only ZDO request is the barrier's.
    assert len(case.publishes(automod.ZDO_REQ)) == 1, case.publishes(automod.ZDO_REQ)
    return "ok"


def leg_outage_fails(case) -> str:
    recover(case)
    tick(case)
    time.sleep(300)
    tick(case, outage="on", bridge="off")
    time.sleep(290)
    tick(case)
    time.sleep(12)
    tick(case)
    latch = case.latch()
    assert latch.get("status") == "failed", latch
    assert latch.get("failure_reason") == "stability-window-failed", latch
    return "ok"


def leg_gap_fails(case) -> str:
    recover(case)
    tick(case)
    time.sleep(590)
    tick(case)
    time.sleep(12)
    tick(case)
    latch = case.latch()
    assert latch.get("status") == "failed", latch
    assert latch.get("failure_reason") == "stability-coverage-gap", latch
    return "ok"


def leg_late_tick_closes(case) -> str:
    # R4-F03: the first close attempt comes a full cadence late (phase
    # offset), inside the one-period grace: a healthy window still closes
    # exactly once instead of failing on phase alone.
    recover(case)
    tick(case)
    time.sleep(300)
    tick(case)
    time.sleep(450)
    tick(case)
    latch = case.latch()
    assert latch.get("status") == "closed", latch
    assert len(incident_closed_events(case)) == 1, incident_closed_events(case)
    return "ok"


def leg_beyond_grace_fails(case) -> str:
    # Past one full grace period the closing observation is out-of-window
    # evidence and fails closed even though every flag is healthy.
    recover(case)
    tick(case)
    time.sleep(300)
    tick(case)
    time.sleep(650)
    tick(case)
    latch = case.latch()
    assert latch.get("status") == "failed", latch
    assert latch.get("failure_reason") == "stability-out-of-window", latch
    return "ok"


LEGS = {
    "happy-close": leg_happy_close,
    "outage-fails": leg_outage_fails,
    "gap-fails": leg_gap_fails,
    "late-tick-closes": leg_late_tick_closes,
    "beyond-grace-fails": leg_beyond_grace_fails,
}


class StabilityWindowTests(unittest.TestCase):
    def test_stability_windows(self) -> None:
        results: dict[str, str] = {}

        def worker(name: str, leg) -> None:
            case = fresh_case()
            try:
                results[name] = leg(case)
            except Exception as exc:  # noqa: BLE001 - per-leg attribution
                results[name] = f"{type(exc).__name__}: {exc}"
            finally:
                case.tearDown()

        threads = [
            threading.Thread(target=worker, args=(name, leg), name=f"t832-{name}")
            for name, leg in LEGS.items()
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=LEG_TIMEOUT_S)
        for thread in threads:
            self.assertFalse(thread.is_alive(), f"leg hung: {thread.name}")
        for name in LEGS:
            self.assertEqual(results.get(name), "ok", f"leg {name}: {results.get(name)}")


if __name__ == "__main__":
    unittest.main()
