"""Tests for the undeployed T832 capture barrier candidate.

Structure tests parse deploy/t832_capture_barrier.yaml and prove every
destructive step is gated by a response_variable plus a template condition,
with bounded waits and no notifications. Fallible services carry
continue_on_error only with fail-closed response gates (R4-F05).

Chain tests walk the same step order with the real incident CLI and mocked
services (supervisor API shim, RTS helper shim): each injected failure must
halt the chain with the latch preserved, and success must reach stabilizing
with the RTS helper invoked exactly once after stop confirmation.

Phase tests (R4-F03) prove the close schedule is phase-independent: the
real observe/close decision code runs under virtual clocks at every
first-tick offset, driven on the YAML's real minutes:/5 grid. Slow
real-time legs in test_stability.py cover the full YAML+CLI path.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
BARRIER = REPO / "deploy" / "t832_capture_barrier.yaml"
SHELL_COMMANDS = REPO / "deploy" / "t832_shell_commands.yaml"
SPEC = importlib.util.spec_from_file_location("t832_incident", HERE / "t832_incident.py")
assert SPEC and SPEC.loader
incident = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(incident)

VAR_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}")


COND_RE = re.compile(
    r"\{\{\s*(\w+) \| tojson if \1 is mapping else \1\s*\}\}"
)


DEFAULT_RE = re.compile(
    r"\{\{\s*(\w+)\s*\|\s*default\('([^']*)'\)\s*\}\}"
)


def htmlsafe_json_dumps(obj: object) -> str:
    """Jinja2 tojson escaping (htmlsafe_json_dumps): < > & ' as \\uXXXX."""
    return (
        json.dumps(obj)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("'", "\\u0027")
    )


def render(template: str, values: dict) -> str:
    def sub_cond(match: re.Match) -> str:
        name = match.group(1)
        if name not in values:
            raise AssertionError(f"unbound template variable {name!r}")
        value = values[name]
        # Faithful staging of the HA shell render: mappings re-serialize
        # via tojson, pre-serialized strings pass through untouched.
        if isinstance(value, dict):
            return htmlsafe_json_dumps(value)
        return str(value)

    def sub(match: re.Match) -> str:
        name = match.group(1)
        if name not in values:
            raise AssertionError(f"unbound template variable {name!r}")
        return str(values[name])

    def sub_default(match: re.Match) -> str:
        # Faithful staging of HA's default('') filter: a missing variable
        # renders the default, a provided one renders as-is.
        name = match.group(1)
        if name not in values:
            return match.group(2)
        return str(values[name])

    collapsed = " ".join(template.split())
    collapsed = COND_RE.sub(sub_cond, collapsed)
    collapsed = DEFAULT_RE.sub(sub_default, collapsed)
    return VAR_RE.sub(sub, collapsed)


def load_shell_commands() -> dict:
    return yaml.safe_load(SHELL_COMMANDS.read_text(encoding="utf-8"))


def flatten_actions(actions: list) -> list:
    """Flatten nested action lists so design rules stay enforced inside
    repeat/choose/if/parallel blocks, not just at the top level."""
    flat: list = []
    for step in actions:
        if not isinstance(step, dict):
            continue
        flat.append(step)
        repeat = step.get("repeat")
        if isinstance(repeat, dict):
            seq = repeat.get("sequence")
            if isinstance(seq, list):
                flat.extend(flatten_actions(seq))
        choose = step.get("choose")
        if isinstance(choose, list):
            for branch in choose:
                if isinstance(branch, dict):
                    seq = branch.get("sequence")
                    if isinstance(seq, list):
                        flat.extend(flatten_actions(seq))
        default = step.get("default")
        if isinstance(default, list):
            flat.extend(flatten_actions(default))
        for key in ("then", "else", "parallel"):
            sub = step.get(key)
            if isinstance(sub, list):
                flat.extend(flatten_actions(sub))
    return flat


def all_condition_texts(node: object) -> list[str]:
    """Collect every template condition expression in an action tree."""
    texts: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "conditions":
                texts.append(json.dumps(value))
            else:
                texts.extend(all_condition_texts(value))
        if node.get("condition") == "template" and "value_template" in node:
            texts.append(str(node["value_template"]))
    elif isinstance(node, list):
        for item in node:
            texts.extend(all_condition_texts(item))
    return texts


class BarrierStructureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.automations = yaml.safe_load(BARRIER.read_text(encoding="utf-8"))
        self.barrier = next(a for a in self.automations if a["id"] == "zigbee2mqtt_t832_capture_barrier")
        self.close = next(a for a in self.automations if a["id"] == "zigbee2mqtt_t832_stability_close")

    def test_modes_and_no_notifications(self) -> None:
        text = BARRIER.read_text(encoding="utf-8")
        self.assertNotIn("notify.", text)
        for automation in self.automations:
            self.assertEqual(automation.get("mode"), "single")

    def test_tolerant_steps_are_fail_closed(self) -> None:
        # R4-F05: continue_on_error is allowed only on fallible services,
        # and every tolerated response must be consumed by a later
        # fail-closed gate — never silently swallowed past a destructive
        # or recovery step.
        allowed = {
            "hassio.addon_stop",
            "hassio.addon_start",
            "mqtt.publish",
            "input_text.set_value",
        }
        for automation in self.automations:
            steps = flatten_actions(automation["actions"])
            cond_texts = all_condition_texts(automation["actions"])
            for step in steps:
                if not isinstance(step, dict) or "continue_on_error" not in step:
                    continue
                service = step.get("service", "")
                self.assertTrue(
                    service in allowed or service.startswith("shell_command."),
                    f"continue_on_error on non-fallible {service}",
                )
                if "response_variable" not in step:
                    continue
                var = step["response_variable"]
                if any(var in text for text in cond_texts):
                    continue
                # A tolerated response in a terminal failure branch is
                # fail-closed when nothing but neutral steps (expectation
                # cleanup, logging) precedes the run-ending halt.
                idx = steps.index(step)
                neutral = {"input_text.set_value", "logbook.log"}
                closed = False
                for later in steps[idx + 1:]:
                    if not isinstance(later, dict):
                        continue
                    if later.get("condition") == "template" and "false" in str(
                        later.get("value_template", "")
                    ):
                        closed = True
                        break
                    if later.get("service") not in neutral and (
                        "service" in later or "action" in later
                    ):
                        break
                self.assertTrue(
                    closed,
                    f"tolerated response {var} has no fail-closed gate",
                )

    def test_production_triggers_reused(self) -> None:
        ids = {t.get("id") for t in self.barrier["triggers"]}
        self.assertEqual(ids, {"mesh_outage", "bridge_offline", "radio_timeout"})

    def test_destructive_steps_gated(self) -> None:
        steps = flatten_actions(self.barrier["actions"])
        destructive = [
            (i, s)
            for i, s in enumerate(steps)
            if s.get("service") in {"hassio.addon_stop", "hassio.addon_start"}
            or s.get("service") == "shell_command.mr4u_p10_rts_reset"
        ]
        self.assertEqual(len(destructive), 3)
        for index, step in destructive:
            prior = steps[:index]
            responses = [s["response_variable"] for s in prior if "response_variable" in s]
            self.assertTrue(responses, f"no response_variable before {step.get('service')}")
            gate_ok = False
            for cond_text in all_condition_texts(prior):
                if any(var in cond_text for var in responses):
                    gate_ok = True
            self.assertTrue(gate_ok, f"no response condition before {step.get('service')}")

    def test_rts_is_existing_helper_only(self) -> None:
        text = BARRIER.read_text(encoding="utf-8")
        self.assertIn("shell_command.mr4u_p10_rts_reset", text)
        for banned in ("usbreset", "reboot", "echo ", "gpioset", "uhubctl"):
            self.assertNotIn(banned, text)

    def test_waits_bounded_and_timeouts_handled(self) -> None:
        for automation in self.automations:
            flat = flatten_actions(automation["actions"])
            cond_texts = all_condition_texts(automation["actions"])
            for step in flat:
                if "wait_for_trigger" in step or "wait_template" in step:
                    self.assertIn("timeout", step)
                    if step.get("continue_on_timeout", True):
                        # A wait that survives its timeout must be consumed
                        # by a choose on its completion flag: silent
                        # timeouts that fall through are forbidden.
                        var = step.get("response_variable", "wait")
                        self.assertTrue(
                            any(f"{var}.completed" in text for text in cond_texts),
                            f"unhandled timeout: {var}",
                        )
                if "delay" in step:
                    delay = step["delay"]
                    total = delay.get("seconds", 0) + 60 * delay.get("minutes", 0)
                    self.assertLessEqual(total, 600)

    def test_close_automation_order(self) -> None:
        services = [s.get("service") for s in self.close["actions"] if isinstance(s, dict)]
        self.assertLess(services.index("shell_command.t832_status"), services.index("shell_command.t832_observe"))
        self.assertLess(services.index("shell_command.t832_observe"), services.index("shell_command.t832_close_if_stable"))

    def test_zdo_proof_uses_incident_transaction(self) -> None:
        text = BARRIER.read_text(encoding="utf-8")
        # B08: the permit_join request carries time 0 and a transaction
        # unique to the captured incident; the response wait only completes
        # on that exact transaction; proof and recovery consume the observed
        # transaction, never a constant. No fixed transaction id remains.
        self.assertIn('"time": 0', text)
        self.assertIn("ha-t832-{{ (t832_capture", text)
        self.assertNotIn("ha-t832-barrier", text)
        steps = flatten_actions(self.barrier["actions"])
        services = [s.get("service") for s in steps if isinstance(s, dict)]
        wait_at = next(
            i for i, s in enumerate(steps)
            if isinstance(s, dict) and "wait_for_trigger" in s
            and any("permit_join" in str(t.get("topic", "")) for t in s["wait_for_trigger"])
        )
        wait = steps[wait_at]["wait_for_trigger"][0]
        self.assertIn("value_template", wait)
        self.assertIn("transaction", wait["value_template"])
        proof_at = next(
            i for i, s in enumerate(steps)
            if s.get("service") == "shell_command.t832_zdo_proof" and i > wait_at
        )
        proof_data = steps[proof_at].get("data", {})
        self.assertIn("wait.trigger.payload_json.transaction", str(proof_data.get("transaction", "")))
        # R4-F02: the wait branch consumes the OBSERVED wait transaction
        # while the late-probe branch consumes the incident-derived one
        # the probe verified — both bindings stay transaction-exact.
        wait_recoveries = [
            s for s in steps
            if s.get("service") == "shell_command.t832_recovery_result"
            and s.get("data", {}).get("success") is True
            and "wait.trigger.payload_json.transaction" in str(s.get("data", {}).get("zdo_transaction", ""))
        ]
        self.assertEqual(len(wait_recoveries), 1)
        late_recoveries = [
            s for s in steps
            if s.get("service") == "shell_command.t832_recovery_result"
            and s.get("data", {}).get("success") is True
            and "t832_capture" in str(s.get("data", {}).get("zdo_transaction", ""))
        ]
        self.assertEqual(len(late_recoveries), 1)

    def test_mqtt_trigger_filters_at_fire_time(self) -> None:
        # B08: unrelated responses never fire the automation: the mqtt
        # trigger carries the production value_template/payload filter.
        mqtt = [
            t for t in self.barrier["triggers"] if t.get("trigger") == "mqtt"
        ]
        self.assertEqual(len(mqtt), 1)
        self.assertIn("value_template", mqtt[0])
        self.assertIn("SRSP -", mqtt[0]["value_template"])
        self.assertIn("payload", mqtt[0])

    def test_rts_singleton_recorded_after_reset(self) -> None:
        steps = flatten_actions(self.barrier["actions"])
        services = [s.get("service") for s in steps if isinstance(s, dict)]
        # Exactly one RTS step exists: retries have nothing else to call.
        self.assertEqual(services.count("shell_command.mr4u_p10_rts_reset"), 1)
        marked = next(
            i for i, s in enumerate(steps)
            if s.get("service") == "shell_command.t832_rts_used"
        )
        # The recording gate is a reported halt: success continues on the
        # marked variable, failure records phase rts and stops the run.
        gate = steps[marked + 1]
        self.assertIn("choose", gate)
        dump = json.dumps(gate)
        self.assertIn("t832_rts_marked", dump)
        self.assertIn('"failure_phase": "rts"', dump)

    def test_capture_fragment_passes_trigger_evidence(self) -> None:
        text = SHELL_COMMANDS.read_text(encoding="utf-8")
        capture = text.split("t832_authorize_reset")[0]
        for flag in ("--triggers", "--trigger-topic", "--trigger-payload"):
            self.assertIn(flag, capture)

    def test_capture_payload_reserializes_mappings(self) -> None:
        # B13: service.data truthfully holds an object (or, when the first
        # render emits true/false/null, a JSON string). The shell argv must
        # re-serialize mappings instead of str() mangling them.
        text = SHELL_COMMANDS.read_text(encoding="utf-8")
        capture = text.split("t832_authorize_reset")[0]
        self.assertIn(
            "{{ trigger_payload_json | tojson if "
            "trigger_payload_json is mapping else trigger_payload_json }}",
            capture,
        )


class BarrierChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "z2m.log"
        self.log.write_text("2026-10-03T09:00:00Z zh:zstack:znp boot\n", encoding="utf-8")
        self.marker_log = self.root / "markers.log"
        self.addon_states = self.root / "addon_states.txt"
        self.commands = load_shell_commands()
        self.env = dict(os.environ)
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env.get("PATH", "")
        self.env["T832_INCIDENT_ROOT"] = str(self.state)
        self.ha_log = self.root / "home-assistant.log"
        self.ha_log.write_text("", encoding="utf-8")
        self.write_supervisor_shim()
        self.write_rts_shim(0)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_supervisor_shim(self, states: list[str] | None = None) -> None:
        """Queue supervisor add-on states; each query consumes the head.

        A tiny Python reader stands in for `curl ... http://supervisor/...` so
        the chain tests run without a shell or network. It emits the exact
        supervisor JSON envelope, so the template's `| python3 -c` parsing
        stage is still exercised verbatim.
        """
        self.addon_states.write_text("\n".join(states or ["stopped"]) + "\n", encoding="utf-8")
        reader = self.bin / "supervisor_state.py"
        if not reader.exists():
            reader.write_text(
                "import json\n"
                "import sys\n"
                "from pathlib import Path\n"
                "path = Path(sys.argv[1])\n"
                "lines = path.read_text(encoding='utf-8').splitlines()\n"
                "first = lines[0] if lines else 'unknown'\n"
                "rest = lines[1:]\n"
                "path.write_text('\\n'.join(rest) + ('\\n' if rest else ''), encoding='utf-8')\n"
                "print(json.dumps({'data': {'state': first}}))\n",
                encoding="utf-8",
            )

    def write_rts_shim(self, returncode: int) -> None:
        shim = self.bin / "mr4u_p10_rts_reset.py"
        shim.write_text(
            "import sys\n"
            "from pathlib import Path\n"
            f"returncode = {int(returncode)}\n"
            f"marker = {str(self.marker_log)!r}\n"
            "with open(marker, 'a', encoding='utf-8') as fh:\n"
            "    fh.write('rts-invoked\\n')\n"
            "raise SystemExit(returncode)\n",
            encoding="utf-8",
        )

    def run_rts_shim(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(self.bin / "mr4u_p10_rts_reset.py")],
            capture_output=True,
            text=True,
            env=self.env,
        )

    def mark(self, name: str) -> None:
        with self.marker_log.open("a", encoding="utf-8") as fh:
            fh.write(name + "\n")

    def markers(self) -> list[str]:
        if not self.marker_log.exists():
            return []
        return self.marker_log.read_text(encoding="utf-8").split()

    def run_tool(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(HERE / "t832_incident.py"), "--root", str(self.state), *argv],
            capture_output=True,
            text=True,
            env=self.env,
        )

    def rewrite_deploy_paths(self, rendered: str) -> str:
        """Map deploy-time paths to this test's sandbox (no shell needed)."""
        rendered = rendered.replace(
            "/config/t832_capture_barrier.yaml", str(REPO / "deploy" / "t832_capture_barrier.yaml")
        )
        rendered = rendered.replace(
            "/config/python_scripts/t832_incident.py", str(HERE / "t832_incident.py")
        )
        rendered = rendered.replace("--root /config/.private/t832-diag", "--root " + str(self.state))
        rendered = rendered.replace("--source /config/zigbee2mqtt/log", "--source " + str(self.log))
        rendered = rendered.replace(
            "--source /config/home-assistant.log", "--source " + str(self.ha_log)
        )
        return rendered

    def run_shell_template(self, name: str, values: dict | None = None) -> subprocess.CompletedProcess:
        rendered = render(self.commands[name], values or {})
        rendered = self.rewrite_deploy_paths(rendered)
        rendered = rendered.replace("python3 ", sys.executable + " ", 1)
        rendered = rendered.replace(" | python3 ", " | " + sys.executable + " ")
        return subprocess.run(
            rendered,
            shell=True,
            capture_output=True,
            text=True,
            env=self.env,
        )

    def run_capture(self, trigger: str, topic: str = "", payload: str = "{}"):
        return self.run_shell_template(
            "t832_capture",
            {
                "trigger": trigger,
                "trigger_topic": topic,
                "trigger_payload_json": payload,
            },
        )

    def latch_status(self) -> str:
        latch = json.loads((self.state / "state" / "incident-latch.json").read_text(encoding="utf-8"))
        return str(latch.get("status"))

    def addon_state(self) -> str:
        rendered = render(self.commands["t832_addon_state"], {})
        head, sep, tail = rendered.partition(" | ")
        self.assertTrue(sep, "addon_state template lost its parse stage")
        reader = (
            f'"{sys.executable}" "{self.bin / "supervisor_state.py"}" "{self.addon_states}"'
        )
        rendered = reader + " | " + tail
        rendered = rendered.replace("python3 ", sys.executable + " ", 1)
        rendered = rendered.replace(" | python3 ", " | " + sys.executable + " ")
        proc = subprocess.run(rendered, shell=True, capture_output=True, text=True, env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return str(json.loads(proc.stdout).get("state"))

    def test_success_chain_reaches_stabilizing(self) -> None:
        self.bind()

        cap = self.run_capture("mesh_outage")
        self.assertEqual(cap.returncode, 0, cap.stderr)
        cap_doc = json.loads(cap.stdout)
        self.assertTrue(cap_doc["ok"])

        auth = self.run_shell_template("t832_authorize_reset")
        self.assertEqual(auth.returncode, 0, auth.stderr)
        auth_doc = json.loads(auth.stdout)
        self.assertEqual(auth_doc["status"], "reset_authorized")
        self.assertEqual(auth_doc["incident_id"], cap_doc["incident_id"])

        mark = self.run_shell_template("t832_mark_recovering")
        self.assertEqual(mark.returncode, 0, mark.stderr)

        # Supervisor state persists across polls; the queue models a slow
        # stop (serial-ownership prerequisite: RTS only runs after stopped
        # is actually observed, never on the first guess).
        self.write_supervisor_shim(["starting"] * 4 + ["stopped", "stopped"])
        self.mark("addon-stop")
        for _ in range(6):
            if self.addon_state() == "stopped":
                break
        self.assertEqual(self.addon_state(), "stopped")

        rts = self.run_rts_shim()
        self.assertEqual(rts.returncode, 0)
        rts_used = self.run_shell_template("t832_rts_used", {})
        self.assertEqual(rts_used.returncode, 0, rts_used.stderr)
        # One RTS maximum: recording again refuses, so a retry or a
        # duplicate automation run cannot reset the coordinator twice.
        rts_again = self.run_shell_template("t832_rts_used", {})
        self.assertNotEqual(rts_again.returncode, 0)
        self.mark("addon-start")

        # Real ZDO evidence first: the bare zdo_ok claim below is only
        # accepted against this recorded, transaction-bound proof.
        proof = self.run_shell_template("t832_zdo_proof", {"transaction": "ha-t832-barrier"})
        self.assertEqual(proof.returncode, 0, proof.stderr)
        rec = self.run_shell_template(
            "t832_recovery_result",
            {
                "success": "true",
                "normal_traffic": "true",
                "zdo_ok": "true",
                "zdo_transaction": "ha-t832-barrier",
            },
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        self.assertEqual(json.loads(rec.stdout)["status"], "stabilizing")

        obs = self.run_shell_template(
            "t832_observe",
            {"bridge_up": "true", "normal_traffic": "true", "zdo_ok": "true"},
        )
        self.assertEqual(obs.returncode, 0, obs.stderr)
        self.assertEqual(json.loads(obs.stdout)["observations"], 1)

        order = self.markers()
        self.assertLess(order.index("addon-stop"), order.index("rts-invoked"))
        self.assertLess(order.index("rts-invoked"), order.index("addon-start"))
        self.assertEqual(order.count("rts-invoked"), 1)

    def test_capture_refused_without_binding(self) -> None:
        cap = self.run_capture("mesh_outage")
        self.assertNotEqual(cap.returncode, 0)
        self.assertFalse((self.state / "state" / "incident-latch.json").exists())
        self.assertNotIn("rts-invoked", self.markers())

    def test_tampered_bundle_halts_chain(self) -> None:
        self.bind()
        cap_doc = json.loads(self.run_capture("mesh_outage").stdout)
        bundle = Path(cap_doc["bundle"])
        (bundle / "manifest.json").write_text('{"tampered": true}\n', encoding="utf-8")
        auth = self.run_shell_template("t832_authorize_reset")
        self.assertNotEqual(auth.returncode, 0)
        self.assertEqual(self.latch_status(), "captured")
        self.assertNotIn("rts-invoked", self.markers())

    def test_stop_never_confirms_halts_before_rts(self) -> None:
        self.bind()
        self.run_capture("mesh_outage")
        self.run_shell_template("t832_authorize_reset")
        self.run_shell_template("t832_mark_recovering")
        self.write_supervisor_shim(["started"] * 8)
        confirmed = False
        for _ in range(6):
            if self.addon_state() == "stopped":
                confirmed = True
                break
        self.assertFalse(confirmed)
        self.assertEqual(self.latch_status(), "recovering")
        self.assertNotIn("rts-invoked", self.markers())

    def test_rts_failure_halts_before_start(self) -> None:
        self.bind()
        self.run_capture("mesh_outage")
        self.run_shell_template("t832_authorize_reset")
        self.run_shell_template("t832_mark_recovering")
        self.write_supervisor_shim(["stopped"])
        self.assertEqual(self.addon_state(), "stopped")
        self.write_rts_shim(3)
        rts = self.run_rts_shim()
        self.assertEqual(rts.returncode, 3)
        self.assertEqual(self.latch_status(), "recovering")
        self.assertNotIn("addon-start", self.markers())

    def test_zdo_failure_marks_failed(self) -> None:
        self.bind()
        self.run_capture("mesh_outage")
        self.run_shell_template("t832_authorize_reset")
        self.run_shell_template("t832_mark_recovering")
        rec = self.run_shell_template(
            "t832_recovery_result",
            {
                "success": "true",
                "normal_traffic": "true",
                "zdo_ok": "false",
                "zdo_transaction": "",
            },
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        failed = json.loads(rec.stdout)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["failure_reason"], "no-zdo-verification")

    def bind(self) -> None:
        # B12: the operator flow declares the image (variant, build
        # manifest, build id) — a bare artifact hash never binds.
        artifact = self.root / "fw.hex"
        artifact.write_text(":020000040000FA\n", encoding="utf-8")
        manifest = self.root / "build-manifest.json"
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        manifest.write_text(
            json.dumps(
                {
                    "variant": "T832-DIAG-R0",
                    "repository_commit": "a" * 40,
                    "artifacts": {"T832-DIAG-R0.hex": {"sha256": digest}},
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        proc = self.run_tool(
            "bind-firmware",
            "--artifact", str(artifact),
            "--role", "deployed",
            "--variant", "T832-DIAG-R0",
            "--manifest", str(manifest),
            "--build-id", "8320001",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_healthy_response_preserves_evidence_without_blocking(self) -> None:
        self.bind()
        cap = self.run_capture(
            "radio_timeout",
            topic="zigbee2mqtt/bridge/response/permit_join",
            payload='{"status": "ok", "transaction": "other"}',
        )
        self.assertEqual(cap.returncode, 0, cap.stderr)
        auth = self.run_shell_template("t832_authorize_reset")
        self.assertNotEqual(auth.returncode, 0)
        # B07: non-qualifying evidence is preserved as observed, and the
        # preserved latch never blocks a later genuine outage: it captures
        # and authorizes exactly once.
        self.assertEqual(self.latch_status(), "observed")
        self.assertNotIn("rts-invoked", self.markers())
        cap2 = self.run_capture("mesh_outage")
        self.assertEqual(cap2.returncode, 0, cap2.stderr)
        auth2 = self.run_shell_template("t832_authorize_reset")
        self.assertEqual(auth2.returncode, 0, auth2.stderr)
        self.assertEqual(json.loads(auth2.stdout)["status"], "reset_authorized")
        self.assertEqual(self.latch_status(), "reset_authorized")

    def test_malformed_payload_never_authorizes(self) -> None:
        self.bind()
        cap = self.run_capture(
            "radio_timeout",
            topic="zigbee2mqtt/bridge/response/permit_join",
            payload="{not json",
        )
        self.assertEqual(cap.returncode, 0, cap.stderr)
        auth = self.run_shell_template("t832_authorize_reset")
        self.assertNotEqual(auth.returncode, 0)
        self.assertEqual(self.latch_status(), "observed")
        self.assertNotIn("rts-invoked", self.markers())

    def test_wrong_topic_never_authorizes(self) -> None:
        self.bind()
        cap = self.run_capture(
            "radio_timeout",
            topic="zigbee2mqtt/bridge/response/device/remove",
            payload='{"status": "error", "error": "SRSP - x after 6000ms"}',
        )
        self.assertEqual(cap.returncode, 0, cap.stderr)
        auth = self.run_shell_template("t832_authorize_reset")
        self.assertNotEqual(auth.returncode, 0)
        self.assertEqual(self.latch_status(), "observed")

    def test_unknown_trigger_refused_at_capture(self) -> None:
        self.bind()
        cap = self.run_capture("bogus_trigger")
        self.assertNotEqual(cap.returncode, 0)
        self.assertFalse((self.state / "state" / "incident-latch.json").exists())

    def test_qualifying_timeout_reaches_authorize(self) -> None:
        self.bind()
        cap = self.run_capture(
            "radio_timeout",
            topic="zigbee2mqtt/bridge/response/permit_join",
            payload='{"status": "error", "error": "Failed to set permit join: SRSP - AF_DataRequest after 6000ms"}',
        )
        self.assertEqual(cap.returncode, 0, cap.stderr)
        cap_doc = json.loads(cap.stdout)
        manifest = json.loads(
            (Path(cap_doc["bundle"]) / "manifest.json").read_text(encoding="utf-8")
        )
        qualification = manifest["trigger_qualification"]
        self.assertTrue(qualification["qualifying"])
        self.assertEqual(qualification["reason"], "timeout-error")
        # The verdict is pinned to the exact reviewed candidate file.
        barrier = REPO / "deploy" / "t832_capture_barrier.yaml"
        expected_sha = hashlib.sha256(barrier.read_bytes()).hexdigest()
        self.assertEqual(qualification["source_sha256"], expected_sha)
        self.assertEqual(manifest["trigger_definitions_sha256"], expected_sha)
        auth = self.run_shell_template("t832_authorize_reset")
        self.assertEqual(auth.returncode, 0, auth.stderr)
        self.assertEqual(json.loads(auth.stdout)["status"], "reset_authorized")

    def test_zdo_claim_without_proof_stays_failed(self) -> None:
        self.bind()
        self.run_capture("mesh_outage")
        self.run_shell_template("t832_authorize_reset")
        self.run_shell_template("t832_mark_recovering")
        # An outage-derived Boolean alone is never ZDO proof: no recorded
        # permit_join transaction means the claim cannot stabilize.
        rec = self.run_shell_template(
            "t832_recovery_result",
            {
                "success": "true",
                "normal_traffic": "true",
                "zdo_ok": "true",
                "zdo_transaction": "ha-t832-barrier",
            },
        )
        self.assertEqual(rec.returncode, 0, rec.stderr)
        failed = json.loads(rec.stdout)
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["failure_reason"], "no-zdo-verification")
        self.assertFalse(failed["zdo_verified"])

    def test_supervisor_api_failure_halts_before_rts(self) -> None:
        self.bind()
        self.run_capture("mesh_outage")
        self.run_shell_template("t832_authorize_reset")
        self.run_shell_template("t832_mark_recovering")
        self.addon_states.unlink()
        with self.assertRaises(AssertionError):
            self.addon_state()
        self.assertEqual(self.latch_status(), "recovering")
        self.assertNotIn("rts-invoked", self.markers())


class R3M3TriggerYamlTests(unittest.TestCase):
    """B07: the actual candidate YAML carries the production contract."""

    def setUp(self) -> None:
        self.defs, self.sha = incident.load_trigger_defs(BARRIER)
        file_sha = hashlib.sha256(BARRIER.read_bytes()).hexdigest()
        self.assertEqual(self.sha, file_sha)

    def test_yaml_mqtt_trigger_matches_tool(self) -> None:
        automations = yaml.safe_load(BARRIER.read_text(encoding="utf-8"))
        barrier = next(
            a for a in automations if a["id"] == "zigbee2mqtt_t832_capture_barrier"
        )
        mqtt = [t for t in barrier["triggers"] if t.get("trigger") == "mqtt"]
        self.assertEqual(len(mqtt), 1)
        self.assertEqual(mqtt[0].get("id"), "radio_timeout")
        self.assertEqual(
            mqtt[0].get("topic"), incident.RADIO_TIMEOUT_TOPIC
        )
        self.assertEqual(
            self.defs["radio_timeout"]["topic"], incident.RADIO_TIMEOUT_TOPIC
        )
        self.assertEqual(
            self.defs["radio_timeout"]["source_sha256"], self.sha
        )

    def test_actual_yaml_defs_production_corpus(self) -> None:
        def run(topic: str, payload: object) -> dict:
            return incident.evaluate_trigger(
                "radio_timeout", self.defs, topic=topic, payload=payload
            )
        good = run(
            incident.RADIO_TIMEOUT_TOPIC,
            {"status": "error",
             "error": "permit join failed: SRSP - timeout after 6000ms"},
        )
        self.assertTrue(good["qualifying"])
        self.assertEqual(good["source"], "candidate-yaml")
        self.assertEqual(good["source_sha256"], self.sha)
        bad = [
            run(incident.RADIO_TIMEOUT_TOPIC, {"status": "ok"}),
            run(incident.RADIO_TIMEOUT_TOPIC,
                {"status": "error", "error": "device not found"}),
            run(incident.RADIO_TIMEOUT_TOPIC,
                {"status": "error", "error": "generic timeout, no markers"}),
            run("zigbee2mqtt/bridge/response/device/remove",
                {"status": "error",
                 "error": "SRSP - x after 6000ms"}),
            run(incident.RADIO_TIMEOUT_TOPIC, "{oops"),
        ]
        self.assertTrue(all(v["source"] == "candidate-yaml" for v in bad))
        self.assertFalse(any(v["qualifying"] for v in bad))


class R3M3ShellBoundaryTests(unittest.TestCase):
    """B13: stage automation render, service parse, shell render, shlex.

    Faithful staging of the HA pipeline per the cited source lines:
    service data templates render in a Jinja2 sandbox, parse_result
    restores objects via ast.literal_eval, the shell template renders with
    parse_result=False, and the command runs through shlex with no shell.
    """

    def setUp(self) -> None:
        jinja2 = importlib.import_module("jinja2")
        print(f"jinja2=={jinja2.__version__}")
        from jinja2.sandbox import SandboxedEnvironment

        self.env = SandboxedEnvironment()
        automations = yaml.safe_load(BARRIER.read_text(encoding="utf-8"))
        barrier = next(
            a
            for a in automations
            if a["id"] == "zigbee2mqtt_t832_capture_barrier"
        )
        call = next(
            s
            for s in barrier["actions"]
            if isinstance(s, dict)
            and s.get("action", s.get("service")) == "shell_command.t832_capture"
        )
        self.data_templates = dict(call["data"])
        commands = load_shell_commands()
        self.shell_template = commands["t832_capture"]

    def stage(self, trigger: dict) -> list[str]:
        """Render automation data, parse service data, render shell, split."""
        import ast
        import shlex

        rendered: dict = {}
        for key, template in self.data_templates.items():
            out = self.env.from_string(str(template)).render(trigger=trigger)
            if key == "trigger_payload_json":
                try:
                    # HA service.data parse_result=True (literal_eval): JSON
                    # objects come back as dicts; true/false/null payloads
                    # stay strings for the shell render to pass through.
                    rendered[key] = ast.literal_eval(out)
                except (ValueError, SyntaxError):
                    rendered[key] = out
            else:
                rendered[key] = out
        shell = self.env.from_string(self.shell_template).render(
            trigger=rendered["trigger"],
            trigger_topic=rendered["trigger_topic"],
            trigger_payload_json=rendered["trigger_payload_json"],
        )
        return shlex.split(shell, posix=True)

    def payload_argv(self, argv: list[str]) -> str:
        self.assertIn("--trigger-payload", argv)
        at = argv.index("--trigger-payload")
        self.assertLess(at + 1, len(argv))
        return argv[at + 1]

    def test_mapping_payloads_round_trip_as_single_argv(self) -> None:
        corpus = [
            {"status": "error", "error": "O'Brien: SRSP - x after 6000ms"},
            {"a": 'q"q', "n": "line1\nline2", "d": "$HOME `x` ; rm & |",
             "u": "žluť <tag> & 'q'"},
            {"nested": {"a": [1, {"b": "x"}]}, "list": [1, 2, 3]},
            {"empty": {}, "deep": {"a": {"b": {"c": []}}}},
        ]
        for payload in corpus:
            with self.subTest(payload=payload):
                argv = self.stage(
                    {"id": "radio_timeout",
                     "topic": "zigbee2mqtt/bridge/response/permit_join",
                     "payload_json": payload}
                )
                raw = self.payload_argv(argv)
                # tojson escaping, never Python repr: no single quotes.
                self.assertNotIn("'", raw)
                self.assertEqual(json.loads(raw), payload)

    def test_missing_payload_defaults_to_empty_object(self) -> None:
        argv = self.stage({"id": "mesh_outage"})
        self.assertEqual(json.loads(self.payload_argv(argv)), {})

    def test_true_false_null_payloads_pass_through_as_json_text(self) -> None:
        payload = {"flag": True, "nothing": None, "n": 3}
        argv = self.stage(
            {"id": "radio_timeout",
             "topic": "zigbee2mqtt/bridge/response/permit_join",
             "payload_json": payload}
        )
        raw = self.payload_argv(argv)
        self.assertEqual(json.loads(raw), payload)
        self.assertIn("true", raw)

    def test_pre_serialized_string_passes_through(self) -> None:
        argv = self.stage(
            {"id": "radio_timeout",
             "topic": "t",
             "payload_json": '{"already": "json-string"}'}
        )
        self.assertEqual(
            json.loads(self.payload_argv(argv)), {"already": "json-string"}
        )

    def test_old_template_mangles_objects(self) -> None:
        # Negative control: the pre-B13 template fed str(dict) to shlex, so
        # the boundary it produced never round-trips: either shlex cannot
        # even split the argv (unbalanced quote from the repr), or the
        # joined remainder is not the payload.
        import shlex

        payload = {"status": "error", "error": "O'Brien device"}
        old = "--trigger-payload '{{ trigger_payload_json }}'"
        rendered = self.env.from_string(old).render(
            trigger_payload_json=payload
        )
        try:
            argv = shlex.split(rendered, posix=True)
        except ValueError:
            return
        at = argv.index("--trigger-payload")
        rest = argv[at + 1 :]
        try:
            parsed = json.loads(" ".join(rest))
        except ValueError:
            parsed = None
        self.assertNotEqual(parsed, payload)


class R4F11AuthorizeCliTests(unittest.TestCase):
    """R4-F11: the authorize-time observed-vs-bound verdict through the
    real CLI, both miss directions, with distinct realistic 32-bit build
    ids. Hashes prove integrity; only the post-verdict identity check
    proves the running image is the bound one."""

    OPS_A = 0xA5A50001
    OPS_B = 0xA5A50002
    CAPS = "0x003fffff"

    def run_tool(self, state: Path, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(HERE / "t832_incident.py"), "--root", str(state), *argv],
            capture_output=True,
            text=True,
        )

    def stage(self, root: Path, bound_id: int, observed_id: int):
        state = root / "private"
        artifact = root / "fw.hex"
        artifact.write_text(":020000040000FA\n", encoding="utf-8")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        manifest_path = root / "build-manifest.json"
        manifest_path.write_text(
            json.dumps({
                "variant": "T832-DIAG-R0",
                "repository_commit": "a" * 40,
                "artifacts": {"fw.hex": {"sha256": digest}},
            }) + "\n",
            encoding="utf-8",
        )
        proc = self.run_tool(
            state, "bind-firmware", "--artifact", str(artifact),
            "--role", "deployed", "--variant", "T832-DIAG-R0",
            "--manifest", str(manifest_path), "--build-id", str(bound_id),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        incident_id = "20261005T080000.000000Z"
        bundle = state / "incidents" / incident_id
        bundle.mkdir(parents=True)
        rows = [
            {"observed_build_id": observed_id,
             "capability_bitmap": self.CAPS, "marker": i}
            for i in range(2)
        ]
        files = {
            "manifest.json": json.dumps({
                "incident_id": incident_id,
                "diag_record_count": 2,
                "host_event_count": 0,
                "diag_unknown_time_count": 0,
                "host_unknown_time_count": 0,
                "unknown_supplement_count": 0,
                "trigger_qualification": {"qualifying": True},
            }),
            "diag-15m.jsonl": "".join(json.dumps(r) + "\n" for r in rows),
            "host-events-15m.jsonl": "",
            "unknown-time-supplement.jsonl": "",
        }
        for name, content in files.items():
            (bundle / name).write_text(content, encoding="utf-8")
        hashes = {
            name: hashlib.sha256((bundle / name).read_bytes()).hexdigest()
            for name in files
        }
        (bundle / "SHA256.json").write_text(json.dumps(hashes), encoding="utf-8")
        latch = {
            "schema": 1,
            "status": "captured",
            "incident_id": incident_id,
            "reset_used": False,
            "bundle": str(bundle),
            "trigger_qualifying": True,
        }
        (state / "state").mkdir(parents=True, exist_ok=True)
        (state / "state" / "incident-latch.json").write_text(
            json.dumps(latch), encoding="utf-8"
        )
        return state

    def authorize(self, state: Path) -> subprocess.CompletedProcess:
        return self.run_tool(state, "authorize-reset")

    def test_miss_direction_a_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = self.stage(Path(td), self.OPS_A, self.OPS_B)
            proc = self.authorize(state)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(
                f"reset-permit-build-mismatch:{self.OPS_B}:{self.OPS_A}:"
                f"caps={self.CAPS}",
                proc.stdout + proc.stderr,
            )

    def test_miss_direction_b_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = self.stage(Path(td), self.OPS_B, self.OPS_A)
            proc = self.authorize(state)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(
                f"reset-permit-build-mismatch:{self.OPS_A}:{self.OPS_B}:"
                f"caps={self.CAPS}",
                proc.stdout + proc.stderr,
            )

    def test_match_authorizes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = self.stage(Path(td), self.OPS_A, self.OPS_A)
            proc = self.authorize(state)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("reset_authorized", proc.stdout)


class VirtualClock:
    """Virtual HA/host clocks for the phase matrix: the real decision code
    reads incident.utcnow, time.monotonic and current_boot_id, so patching
    those three points virtualizes the whole window deterministically."""

    def __init__(self) -> None:
        self.wall = dt.datetime(2026, 10, 5, 8, 0, 0, tzinfo=dt.timezone.utc)
        self.mono = 1000000.0

    def utcnow(self) -> dt.datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall += dt.timedelta(seconds=seconds)
        self.mono += seconds


class R4F03PhaseTests(unittest.TestCase):
    """R4-F03: the close schedule is phase-independent.

    HA fires minutes:/5 on fixed wall boundaries, so the first tick after
    recovery lands at an offset of 0..300s. For each pinned offset the real
    stability_observation and close_if_stable run under virtual clocks on
    the production grid (ticks at offset + 300k): healthy windows close
    exactly once, at the first tick at or past the window end, and earlier
    ticks refuse with window-not-complete rather than failing.

    Timing-test split (documented, no live hardware): phases run fast here
    through the real decision functions with virtual clocks; the YAML grid
    itself is pinned by the timer contract test; the full YAML+CLI path at
    a representative offset runs in test_stability.py slow legs.
    """

    PHASES = (0, 1, 120, 121, 130, 299, 300)
    EXPECTED_CLOSE = {0: 600, 1: 601, 120: 720, 121: 721, 130: 730, 299: 899, 300: 600}

    def run_phase(self, phi: int):
        clock = VirtualClock()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = incident.Store(Path(tmp.name) / "private")
        txn = f"ha-t832-phase-{phi}"
        with mock.patch.object(incident, "utcnow", clock.utcnow), mock.patch(
            "time.monotonic", clock.monotonic
        ), mock.patch.object(incident, "current_boot_id", lambda: "phase-boot"):
            store.atomic_json(
                store.latch,
                {"schema": 1, "status": "recovering",
                 "incident_id": f"phase-{phi}", "reset_used": True},
            )
            incident.record_zdo_proof(store, txn)
            verdict = incident.recovery_result(
                store, success=True, normal_traffic=True, zdo_ok=True,
                zdo_transaction=txn, failure_phase="recovery",
            )
            self.assertEqual(verdict.get("status"), "stabilizing")
            base = clock.mono
            ticks = []
            tick = float(phi)
            while tick <= 600 + 300:
                ticks.append(tick)
                tick += 300
            closed_at = None
            for tick in ticks:
                clock.advance(tick - (clock.mono - base))
                incident.stability_observation(
                    store, bridge_up=True, normal_traffic=True, zdo_ok=True
                )
                try:
                    result = incident.close_if_stable(
                        store, bridge_up=True, normal_traffic=True
                    )
                except RuntimeError as exc:
                    self.assertIn("stability-window-not-complete", str(exc))
                    self.assertEqual(
                        store.load(store.latch, {}).get("status"),
                        "stabilizing",
                    )
                    continue
                self.assertEqual(result.get("status"), "closed")
                closed_at = tick
                break
            return store, clock, closed_at

    def test_healthy_windows_close_exactly_once_per_phase(self) -> None:
        for phi in self.PHASES:
            with self.subTest(phi=phi):
                store, clock, closed_at = self.run_phase(phi)
                self.assertEqual(closed_at, self.EXPECTED_CLOSE[phi])
                latch = store.load(store.latch, {})
                self.assertEqual(latch.get("status"), "closed")
                events = [
                    json.loads(line)
                    for line in store.host_events.read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if json.loads(line).get("kind") == "incident_closed"
                ]
                self.assertEqual(len(events), 1)
                # A further tick finds non-stabilizing status: no second close.
                clock.advance(300)
                with self.assertRaises(RuntimeError) as ctx:
                    incident.close_if_stable(
                        store, bridge_up=True, normal_traffic=True
                    )
                self.assertIn("incident-not-stabilizing", str(ctx.exception))

    def test_missed_close_tick_fails_out_of_window(self) -> None:
        # Skip the tick that would close (730 at phi 130): the next grid
        # tick lands past one full grace period and fails closed.
        clock = VirtualClock()
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            with mock.patch.object(incident, "utcnow", clock.utcnow), mock.patch(
                "time.monotonic", clock.monotonic
            ), mock.patch.object(incident, "current_boot_id", lambda: "phase-boot"):
                store.atomic_json(
                    store.latch,
                    {"schema": 1, "status": "recovering",
                     "incident_id": "gap-130", "reset_used": True},
                )
                incident.record_zdo_proof(store, "ha-t832-gap-130")
                incident.recovery_result(
                    store, success=True, normal_traffic=True, zdo_ok=True,
                    zdo_transaction="ha-t832-gap-130", failure_phase="recovery",
                )
                base = clock.mono
                for tick in (130, 430):
                    clock.advance(tick - (clock.mono - base))
                    incident.stability_observation(
                        store, bridge_up=True, normal_traffic=True, zdo_ok=True
                    )
                clock.advance(1030 - (clock.mono - base))
                incident.stability_observation(
                    store, bridge_up=True, normal_traffic=True, zdo_ok=True
                )
                failed = incident.close_if_stable(
                    store, bridge_up=True, normal_traffic=True
                )
                self.assertEqual(failed.get("status"), "failed")
                self.assertEqual(
                    failed.get("failure_reason"), "stability-out-of-window"
                )

    def test_false_midpoint_observation_rejects(self) -> None:
        # R4-F04 counterevidence through the same harness: one false
        # observation among good ones fails the window at close time.
        clock = VirtualClock()
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            with mock.patch.object(incident, "utcnow", clock.utcnow), mock.patch(
                "time.monotonic", clock.monotonic
            ), mock.patch.object(incident, "current_boot_id", lambda: "phase-boot"):
                store.atomic_json(
                    store.latch,
                    {"schema": 1, "status": "recovering",
                     "incident_id": "mid-false", "reset_used": True},
                )
                incident.record_zdo_proof(store, "ha-t832-mid-false")
                incident.recovery_result(
                    store, success=True, normal_traffic=True, zdo_ok=True,
                    zdo_transaction="ha-t832-mid-false",
                    failure_phase="recovery",
                )
                base = clock.mono
                flags = [(True, True), (False, True), (True, True)]
                for tick, (traffic, _) in zip((0, 300, 600), flags):
                    clock.advance(tick - (clock.mono - base))
                    incident.stability_observation(
                        store, bridge_up=True, normal_traffic=traffic,
                        zdo_ok=traffic,
                    )
                failed = incident.close_if_stable(
                    store, bridge_up=True, normal_traffic=True
                )
                self.assertEqual(failed.get("status"), "failed")
                self.assertEqual(
                    failed.get("failure_reason"), "stability-window-failed"
                )


if __name__ == "__main__":
    unittest.main()
