"""Tests for the undeployed T832 capture barrier candidate.

Structure tests parse deploy/t832_capture_barrier.yaml and prove every
destructive step is gated by a response_variable plus a template condition,
with bounded waits and no continue_on_error or notifications.

Chain tests walk the same step order with the real incident CLI and mocked
services (supervisor API shim, RTS helper shim): each injected failure must
halt the chain with the latch preserved, and success must reach stabilizing
with the RTS helper invoked exactly once after stop confirmation.
"""
from __future__ import annotations

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

    collapsed = " ".join(template.split())
    collapsed = COND_RE.sub(sub_cond, collapsed)
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
            # Prose may discuss the pattern; only real action keys matter.
            for step in flatten_actions(automation["actions"]):
                self.assertNotIn("continue_on_error", step)

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
        recover_at = next(
            i for i, s in enumerate(steps)
            if s.get("service") == "shell_command.t832_recovery_result"
            and i > proof_at
            and s.get("data", {}).get("success") is True
        )
        proof_data = steps[proof_at].get("data", {})
        self.assertIn("wait.trigger.payload_json.transaction", str(proof_data.get("transaction", "")))
        recover_data = steps[recover_at].get("data", {})
        self.assertIn("wait.trigger.payload_json.transaction", str(recover_data.get("zdo_transaction", "")))

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
            and s.get("action") == "shell_command.t832_capture"
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
        # the boundary it produced never round-trips.
        import shlex

        payload = {"status": "error", "error": "O'Brien device"}
        old = "--trigger-payload '{{ trigger_payload_json }}'"
        rendered = self.env.from_string(old).render(
            trigger_payload_json=payload
        )
        argv = shlex.split(rendered, posix=True)
        at = argv.index("--trigger-payload")
        rest = argv[at + 1 :]
        try:
            parsed = json.loads(" ".join(rest))
        except ValueError:
            parsed = None
        self.assertNotEqual(parsed, payload)


if __name__ == "__main__":
    unittest.main()
