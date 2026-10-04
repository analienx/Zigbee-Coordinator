"""B08: execute the actual candidate barrier automation in a faithful
bounded interpreter over the real YAML, shell fragments, and CLI.

Contract (pinned against HA core master, read-only):
- shell_command with templates renders args with parse_result=False and
  runs shlex-split with shell=False; template-free fragments run in a
  shell (homeassistant/components/shell_command/__init__.py,
  create_subprocess_shell vs create_subprocess_exec). Responses carry
  stdout (stripped), stderr, returncode.
- mqtt triggers fire only when the rendered value_template equals the
  rendered payload filter
  (homeassistant/components/mqtt/trigger.py, mqtt_automation_listener).
- wait_for_trigger/wait_template expose wait.completed / wait.trigger;
  a wait that survives its timeout continues only via continue_on_timeout.

The interpreter advances a virtual clock (delays, timeouts, polls);
scenario scripts model ONLY externals (supervisor addon/RTS shims, Z2M
responses, sensor states). Unknown action kinds, unknown template
functions, and unparseable durations fail loudly. No live HA, no radio.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml
from jinja2 import ChainableUndefined
from jinja2.sandbox import SandboxedEnvironment

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
BARRIER = REPO / "deploy" / "t832_capture_barrier.yaml"
SHELL_COMMANDS = REPO / "deploy" / "t832_shell_commands.yaml"


class Halt(Exception):
    """A false bare condition stopped the run (HA semantics)."""


class HaViolation(AssertionError):
    """The automation used a construct the interpreter does not implement."""


def parse_duration(value: object) -> float:
    """Parse HA duration shapes (dict, HH:MM:SS, bare seconds)."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        total = 0.0
        total += float(value.get("seconds", 0))
        total += 60.0 * float(value.get("minutes", 0))
        total += 3600.0 * float(value.get("hours", 0))
        total += 86400.0 * float(value.get("days", 0))
        return total
    if isinstance(value, str):
        parts = value.strip().split(":")
        if len(parts) == 3:
            hours, minutes, seconds = parts
            return int(hours) * 3600 + int(minutes) * 60 + float(seconds)
    raise HaViolation(f"unparseable duration: {value!r}")


class Ha:
    """Bounded executor for one barrier-automation run over real YAML."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.state = root / "state"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.state.mkdir(parents=True, exist_ok=True)
        # ChainableUndefined mirrors HA runtime leniency: missing trigger
        # fields and wait attributes degrade to empty/False in conditions
        # instead of raising, while unknown functions, unknown filters,
        # and failed parses still raise loudly via render()'s guard.
        self.env = SandboxedEnvironment(undefined=ChainableUndefined)
        self.env.filters["tojson"] = lambda value: json.dumps(value)
        self.env.filters["from_json"] = lambda value: json.loads(value)
        raw = BARRIER.read_text(encoding="utf-8")
        automations = yaml.safe_load(raw.split("```")[0])
        if not isinstance(automations, list) or len(automations) != 2:
            raise HaViolation("barrier file must hold exactly the 2 pinned automations")
        self.automation = next(
            a for a in automations if a.get("id") == "zigbee2mqtt_t832_capture_barrier"
        )
        self.commands = {
            name: frag if isinstance(frag, str) else frag["command"]
            for name, frag in yaml.safe_load(
                SHELL_COMMANDS.read_text(encoding="utf-8")
            ).items()
            if isinstance(frag, str) or (isinstance(frag, dict) and "command" in frag)
        }
        self.clock = 0.0
        self.bus_mark = 0
        self.vars: dict = {}
        self.states: dict[str, tuple[str, float]] = {}
        self.state_history: dict[str, list[tuple[float, str]]] = {}
        self.bus: list[tuple[float, str, str]] = []
        self.events: list[tuple[float, object]] = []
        self.records: list[tuple[str, dict]] = []
        self.running = False
        self.suppressions: list[str] = []
        self.on_publish = None
        self.state_file = root / "addon_state.txt"
        self.stop_plan: list[dict] = []
        self.start_plan: list[dict] = []
        self.rts_rc = 0
        self.env_dict = dict(os.environ)
        self.env_dict["SUPERVISOR_TOKEN"] = "fixture-token"
        self.env_dict["PATH"] = str(self.bin) + os.pathsep + self.env_dict.get("PATH", "")

    # -- template rendering ------------------------------------------------
    def render(self, text: object, extra: dict | None = None) -> object:
        if not isinstance(text, str) or "{{" not in text:
            return text
        scope = dict(self.vars)
        if extra:
            scope.update(extra)
        if "states" not in scope:
            scope["states"] = lambda entity: self.states.get(entity, ("unknown", 0.0))[0]
        if "is_state" not in scope:
            scope["is_state"] = (
                lambda entity, want: self.states.get(entity, ("unknown", 0.0))[0] == want
            )
        try:
            return self.env.from_string(text).render(scope)
        except Exception as exc:  # noqa: BLE001 - templates must be total here
            raise HaViolation(f"template failed: {text!r}: {exc}") from exc

    def eval_condition(self, text: str) -> bool:
        """Evaluate a bare Jinja condition string to a boolean."""
        text = str(text).strip()
        if text.startswith("{{") and text.endswith("}}"):
            rendered = self.render(text)
        else:
            rendered = self.render("{{ (" + text + ") }}")
        value = str(rendered).strip().lower()
        if value in ("true", "1"):
            return True
        if value in ("false", "0", "", "none"):
            return False
        raise HaViolation(f"non-boolean condition result: {text!r} -> {rendered!r}")

    # -- entities, clock, bus ----------------------------------------------
    def set_state(self, entity: str, value: str) -> None:
        self.states[entity] = (value, self.clock)
        self.state_history.setdefault(entity, []).append((self.clock, value))

    def held_for(self, entity: str, value: str, seconds: float) -> bool:
        """True when entity held value continuously for the last seconds."""
        cutoff = self.clock - seconds
        history = self.state_history.get(entity, [])
        if not history:
            return False
        if history[-1][1] != value:
            return False
        start = history[-1][0]
        for moment, val in reversed(history[:-1]):
            if val != value:
                break
            start = moment
        return start <= cutoff

    def schedule(self, delay: float, func: object) -> None:
        moment = self.clock + delay
        self.events.append((moment, func))
        self.events.sort(key=lambda item: item[0])

    def mqtt_publish(self, topic: str, payload: str) -> None:
        self.bus.append((self.clock, topic, str(payload)))
        if self.on_publish is not None:
            self.on_publish(self, topic, str(payload))
        self.deliver_triggers()

    def mqtt_deliver(self, topic: str, payload: str) -> None:
        self.bus.append((self.clock, topic, str(payload)))

    def advance_to(self, target: float) -> None:
        while self.events and min(moment for moment, _ in self.events) <= target:
            moment = min(m for m, _ in self.events)
            due = [fn for m, fn in self.events if m == moment]
            self.events = [(m, fn) for m, fn in self.events if m != moment]
            self.clock = moment
            for func in due:
                func()
            self.deliver_triggers()
        self.clock = target

    def deliver_triggers(self) -> None:
        """Mid-run matches against the entry mqtt filters are suppressed
        under mode: single instead of forking a second run."""
        if not self.running:
            self.bus_mark = len(self.bus)
            return
        for _, topic, payload in self.bus[self.bus_mark:]:
            for trigger in self.automation.get("triggers", []) or []:
                if (trigger.get("trigger") or trigger.get("platform")) != "mqtt":
                    continue
                if self.match_mqtt(trigger, topic, payload) is not None:
                    self.suppressions.append(str(trigger.get("id", "?")))
        self.bus_mark = len(self.bus)

    # -- fixture shims -------------------------------------------------------
    def write_shims(self) -> None:
        (self.bin / "supervisor_state.py").write_text(
            "import json\n"
            "import sys\n"
            "from pathlib import Path\n"
            "current = Path(sys.argv[1]).read_text(encoding='utf-8').strip()\n"
            "print(json.dumps({'data': {'state': current or 'unknown'}}))\n",
            encoding="utf-8",
        )
        marker = self.root / "rts.marker"
        (self.bin / "mr4u_p10_rts_reset.py").write_text(
            "import sys\n"
            f"marker = {str(marker)!r}\n"
            f"returncode = {int(self.rts_rc)}\n"
            "with open(marker, 'a', encoding='utf-8') as handle:\n"
            "    handle.write('rts-invoked\\n')\n"
            "raise SystemExit(returncode)\n",
            encoding="utf-8",
        )

    # -- subprocesses ----------------------------------------------------------
    def rewrite_paths(self, rendered: str) -> str:
        rendered = rendered.replace(
            "/config/t832_capture_barrier.yaml", str(BARRIER)
        )
        rendered = rendered.replace(
            "/config/python_scripts/t832_incident.py", str(HERE / "t832_incident.py")
        )
        rendered = rendered.replace("--root /config/.private/t832-diag", "--root " + str(self.state))
        rendered = rendered.replace("--source /config/zigbee2mqtt/log", "--source " + str(self.root / "z2m.log"))
        rendered = rendered.replace(
            "--source /config/home-assistant.log", "--source " + str(self.root / "home-assistant.log")
        )
        return rendered

    def rewrite_arg(self, arg: str) -> str:
        """Rewrite one post-shlex argv element. The --root value travels as
        its own element after splitting, so it needs an exact match: the
        combined '--root <path>' pattern never spans elements."""
        arg = self.rewrite_paths(arg)
        if arg == "/config/.private/t832-diag":
            return str(self.state)
        return arg

    def run_template_free(self, rendered: str) -> subprocess.CompletedProcess:
        """Run a template-free fragment in a shell (HA create_subprocess_shell).

        The supervisor curl head is answered by the fixture reader so the
        real `| python3 -c` JSON parse stage runs verbatim.
        """
        rendered = self.rewrite_paths(rendered)
        if "supervisor/addons" in rendered:
            head, sep, tail = rendered.partition(" | ")
            if not sep:
                raise HaViolation(f"addon_state lost its parse stage: {rendered!r}")
            reader = (
                f'"{sys.executable}" "{self.bin / "supervisor_state.py"}" '
                f'"{self.state_file}"'
            )
            rendered = reader + " | " + tail
        rendered = rendered.replace("python3 ", sys.executable + " ", 1)
        rendered = rendered.replace(" | python3 ", " | " + sys.executable + " ")
        return subprocess.run(
            rendered, shell=True, capture_output=True, text=True, env=self.env_dict
        )

    def call_shell_command(self, name: str, data: dict) -> dict:
        """Mirror HA shell_command staging: Jinja, then shlex when templated."""
        raw_args = self.commands[name]
        staged = {}
        for key, value in data.items():
            staged[key] = self.render(value)
        if "{{" not in raw_args:
            proc = self.run_template_free(raw_args)
        else:
            shell_rendered = self.env.from_string(raw_args).render(staged)
            if shell_rendered == raw_args:
                proc = self.run_template_free(shell_rendered)
            else:
                argv = shlex.split(shell_rendered)
                argv = [self.rewrite_arg(arg) for arg in argv]
                argv = [sys.executable if arg == "python3" else arg for arg in argv]
                proc = subprocess.run(
                    argv, shell=False, capture_output=True, text=True, env=self.env_dict
                )
        return {
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "returncode": proc.returncode,
        }

    # -- services --------------------------------------------------------------
    def call_service(self, action: dict) -> None:
        service = self.render(action.get("action", action.get("service")))
        data = {}
        for key, value in (action.get("data") or {}).items():
            data[key] = self.render(value)
        response_key = action.get("response_variable")
        if service == "shell_command.mr4u_p10_rts_reset":
            # Pre-existing production helper (not part of the candidate
            # file): the fixture RTS shim stands in for the validated R2
            # script behind the production shell_command binding. Pinned:
            # HA records the response (including a nonzero returncode)
            # and CONTINUES; the YAML's choose on returncode routes the
            # halt explicitly instead of the service aborting the run.
            proc = subprocess.run(
                [sys.executable, str(self.bin / "mr4u_p10_rts_reset.py")],
                capture_output=True,
                text=True,
                env=self.env_dict,
            )
            if response_key:
                self.vars[response_key] = {
                    "stdout": proc.stdout.strip(),
                    "stderr": proc.stderr.strip(),
                    "returncode": proc.returncode,
                }
        elif service.startswith("shell_command."):
            response = self.call_shell_command(service.split(".", 1)[1], data)
            if response_key:
                self.vars[response_key] = response
        elif service == "hassio.addon_stop":
            step = self.stop_plan.pop(0) if self.stop_plan else {"rc": 0, "state": "stopped"}
            self.state_file.write_text(str(step.get("state", "stopped")), encoding="utf-8")
            if int(step.get("rc", 0)) != 0:
                raise Halt(f"addon_stop rc={step.get('rc')}")
        elif service == "hassio.addon_start":
            step = self.start_plan.pop(0) if self.start_plan else {"rc": 0, "state": "started"}
            self.state_file.write_text(str(step.get("state", "started")), encoding="utf-8")
            if int(step.get("rc", 0)) != 0:
                raise Halt(f"addon_start rc={step.get('rc')}")
        elif service == "mqtt.publish":
            self.mqtt_publish(str(data.get("topic", "")), str(data.get("payload", "")))
        elif service in ("logbook.log", "system_log.write", "notify.persistent_notification"):
            message = data.get("message", data.get("name", ""))
            self.records.append((service, {"message": str(message)}))
        else:
            raise HaViolation(f"unsupported service: {service!r}")

    # -- waits -----------------------------------------------------------------
    def match_mqtt(self, spec: dict, topic: str, payload: str) -> dict | None:
        """Mirror mqtt_automation_listener: the rendered value_template must
        equal the rendered payload filter (both may carry run variables)."""
        if self.render(spec.get("topic")) != topic:
            return None
        payload_json = None
        if isinstance(payload, str):
            try:
                payload_json = json.loads(payload)
            except json.JSONDecodeError:
                payload_json = None
        scope = dict(self.vars)
        scope["trigger"] = {"topic": topic, "payload": payload, "payload_json": payload_json}
        scope["value_json"] = payload_json
        scope["payload"] = payload
        filt = spec.get("payload")
        if filt is None:
            return {"topic": topic, "payload": payload, "payload_json": payload_json}
        want = str(self.render(str(filt), scope))
        template = spec.get("value_template")
        if template is None:
            if payload != want:
                return None
        # Pinned: Template.async_render_with_possible_json_value strips the
        # rendered value (helpers/template/__init__.py) before the exact
        # mqtt_automation_listener comparison, so folded multi-line
        # templates match their payload filter.
        elif str(self.render(str(template), scope)).strip() != want:
            return None
        return {"topic": topic, "payload": payload, "payload_json": payload_json}

    def wait_for_trigger(self, spec: dict, var: str) -> bool:
        timeout = parse_duration(spec.get("timeout", 30))
        deadline = self.clock + timeout
        mark = len(self.bus)
        while True:
            for moment, topic, payload in self.bus[mark:]:
                for sub in spec.get("wait_for_trigger", spec.get("triggers", [])):
                    kind = sub.get("trigger") or sub.get("platform")
                    if kind != "mqtt":
                        raise HaViolation(f"wait trigger kind not implemented: {kind!r}")
                    matched = self.match_mqtt(sub, topic, payload)
                    if matched is not None:
                        self.clock = max(self.clock, moment)
                        self.vars[var] = {"trigger": matched}
                        return True
            mark = len(self.bus)
            upcoming = [moment for moment, _ in self.events if moment <= deadline]
            if upcoming:
                self.advance_to(min(upcoming))
                continue
            self.clock = deadline
            self.vars[var] = {}
            return False

    def wait_template(self, template: str, timeout: float, var: str) -> bool:
        deadline = self.clock + timeout
        step = 0.25
        while self.clock < deadline:
            if self.eval_condition(str(template)):
                self.vars[var] = {"completed": True}
                return True
            self.advance_to(min(self.clock + step, deadline))
        if self.eval_condition(str(template)):
            self.vars[var] = {"completed": True}
            return True
        self.vars[var] = {"completed": False}
        return False

    # -- actions -----------------------------------------------------------------
    def run_variables(self, spec: dict) -> None:
        for key, value in spec.items():
            self.vars[key] = self.render(value)

    def run_condition_step(self, spec: dict) -> None:
        kind = spec.get("condition")
        if kind == "template":
            if not self.eval_condition(str(spec.get("value_template", ""))):
                raise Halt(f"condition false: {spec.get('value_template', '')!r}")
        else:
            raise HaViolation(f"condition kind not implemented: {kind!r}")

    def run_choose(self, spec: dict) -> None:
        for branch in spec.get("choose", []):
            conditions = branch.get("conditions", [])
            if isinstance(conditions, (dict, str)):
                conditions = [conditions]
            holds = True
            for cond in conditions:
                if isinstance(cond, str):
                    holds = holds and self.eval_condition(cond)
                elif isinstance(cond, dict) and cond.get("condition") == "template":
                    holds = holds and self.eval_condition(str(cond.get("value_template", "")))
                else:
                    raise HaViolation(f"choose condition not implemented: {cond!r}")
            if holds:
                self.run_actions(branch.get("sequence", []))
                break
        else:
            self.run_actions(spec.get("default", []))

    def run_repeat(self, spec: dict) -> None:
        body = spec.get("repeat", {})
        count = body.get("count")
        until = body.get("until")
        if isinstance(until, (dict, str)):
            until = [until]
        if count is None and until is None:
            raise HaViolation("repeat needs count or until")
        index = 0
        while True:
            if count is not None and index >= int(self.render(count)):
                break
            index += 1
            self.vars["repeat"] = {"index": index}
            self.run_actions(body.get("sequence", []))
            if until:
                done = True
                for cond in until:
                    if isinstance(cond, str):
                        done = done and self.eval_condition(cond)
                    elif isinstance(cond, dict) and cond.get("condition") == "template":
                        done = done and self.eval_condition(str(cond.get("value_template", "")))
                    else:
                        raise HaViolation(f"repeat until not implemented: {cond!r}")
                if done:
                    break
            elif count is None:
                raise HaViolation("repeat needs count or until")

    def run_actions(self, actions: list) -> None:
        for action in actions or []:
            if "variables" in action:
                self.run_variables(action["variables"])
            elif "choose" in action or "default" in action:
                self.run_choose(action)
            elif "repeat" in action:
                self.run_repeat(action)
            elif "condition" in action:
                self.run_condition_step(action)
            elif "delay" in action:
                self.advance_to(self.clock + parse_duration(self.render(action["delay"])))
            elif "wait_for_trigger" in action:
                done = self.wait_for_trigger(action, "wait")
                if not done and not action.get("continue_on_timeout", False):
                    raise Halt("wait_for_trigger timed out without continue_on_timeout")
            elif "wait_template" in action:
                done = self.wait_template(
                    action["wait_template"], parse_duration(action.get("timeout", 30)), "wait"
                )
                if not done and not action.get("continue_on_timeout", False):
                    raise Halt("wait_template timed out without continue_on_timeout")
            elif "action" in action or "service" in action:
                self.call_service(action)
            else:
                raise HaViolation(f"action kind not implemented: {sorted(action)!r}")

    # -- entry ---------------------------------------------------------------------
    def run_body(self, trigger_obj: dict) -> None:
        self.running = True
        self.bus_mark = len(self.bus)
        try:
            self.vars["trigger"] = trigger_obj
            self.vars["this"] = {"entity_id": self.automation.get("alias", "automation")}
            self.run_actions(self.automation.get("actions", []))
        except Halt:
            pass
        finally:
            self.running = False

    def fire_state(self, trigger_id: str) -> str:
        """Fire a state trigger after enforcing its to-state and for-hold."""
        spec = next(
            (t for t in self.automation.get("triggers", []) or [] if t.get("id") == trigger_id),
            None,
        )
        if spec is None or (spec.get("trigger") or spec.get("platform")) != "state":
            return "no-match"
        entity = spec["entity_id"]
        want = spec.get("to")
        hold = parse_duration(spec.get("for", 0))
        current = self.states.get(entity, ("unknown", 0.0))[0]
        if want is not None and current != want:
            return "no-match"
        if not self.held_for(entity, current, hold):
            return "no-match"
        if self.running:
            self.suppressions.append(trigger_id)
            return "suppressed"
        self.run_body({"id": trigger_id, "platform": "state", "entity_id": entity})
        return "ran"

    def fire_mqtt(self, trigger_id: str, topic: str, payload: str) -> str:
        """Fire an mqtt trigger only when the bus message matches its filter."""
        spec = next(
            (t for t in self.automation.get("triggers", []) or [] if t.get("id") == trigger_id),
            None,
        )
        if spec is None or (spec.get("trigger") or spec.get("platform")) != "mqtt":
            return "no-match"
        matched = self.match_mqtt(spec, topic, payload)
        if matched is None:
            return "no-match"
        self.mqtt_deliver(topic, payload)
        if self.running:
            self.suppressions.append(trigger_id)
            return "suppressed"
        matched["id"] = trigger_id
        self.run_body(matched)
        return "ran"


OUTAGE = "binary_sensor.zigbee2mqtt_mesh_communication_outage"
BRIDGE = "binary_sensor.zigbee2mqtt_bridge_online"
ZDO_REQ = "zigbee2mqtt/bridge/request/permit_join"
ZDO_RESP = "zigbee2mqtt/bridge/response/permit_join"
PRODUCTION_ERROR = "SRSP - AF - dataRequest after 6000ms"


def zdo_hook(mode: str):
    """Scenario Z2M: answer the permit_join request per mode, and always
    emit one entry-shaped timeout error mid-run (must be suppressed).

    Answers are deferred to the next virtual-clock step, not delivered
    synchronously inside the publish: on real HA the response round trip
    always lands after the wait subscribes, and a synchronous fixture
    would hide the wait from its own answers.
    """

    def hook(ha: Ha, topic: str, payload: str) -> None:
        if topic != ZDO_REQ:
            return
        request = json.loads(payload)
        assert request.get("time") == 0, request
        assert str(request.get("transaction", "")).startswith("ha-t832-"), request
        answers = [
            json.dumps(
                {"status": "error", "error": PRODUCTION_ERROR, "transaction": "stale"}
            )
        ]
        if mode == "match":
            answers.append(
                json.dumps({"status": "ok", "transaction": request["transaction"]})
            )
        elif mode == "mismatch":
            answers.append(
                json.dumps({"status": "ok", "transaction": "ha-t832-someone-else"})
            )
        elif mode == "silent":
            pass
        else:
            raise AssertionError(f"unknown zdo mode: {mode}")
        for answer in answers:
            ha.schedule(0.0, lambda answer=answer: ha.mqtt_deliver(ZDO_RESP, answer))

    return hook


class BarrierAutomationTests(unittest.TestCase):
    """B08: run the real barrier automation end to end per phase scenario."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ha = Ha(self.root)
        (self.root / "z2m.log").write_text(
            "2026-10-03T09:00:00Z zh:zstack:znp boot\n", encoding="utf-8"
        )
        (self.root / "home-assistant.log").write_text("", encoding="utf-8")
        self.bind()
        self.ha.write_shims()
        self.ha.state_file.write_text("started", encoding="utf-8")
        self.ha.set_state(OUTAGE, "off")
        self.ha.set_state(BRIDGE, "on")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def bind(self) -> None:
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
        proc = subprocess.run(
            [
                sys.executable,
                str(HERE / "t832_incident.py"),
                "--root",
                str(self.ha.state),
                "bind-firmware",
                "--artifact",
                str(artifact),
                "--role",
                "deployed",
                "--variant",
                "T832-DIAG-R0",
                "--manifest",
                str(manifest),
                "--build-id",
                "8320001",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    # -- readers ---------------------------------------------------------------
    def latch(self) -> dict:
        path = self.ha.state / "state" / "incident-latch.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def rts_invocations(self) -> int:
        marker = self.root / "rts.marker"
        if not marker.exists():
            return 0
        return len(marker.read_text(encoding="utf-8").splitlines())

    def publishes(self, topic: str) -> list[str]:
        return [payload for _, entry, payload in self.ha.bus if entry == topic]

    def hold_outage(self, seconds: float = 300.0) -> None:
        self.ha.set_state(OUTAGE, "on")
        self.ha.advance_to(self.ha.clock + seconds)

    def require_capture(self) -> dict:
        """The run must have captured (rc 0, JSON verdict) to reach any phase."""
        cap = self.ha.vars["t832_capture"]
        self.assertEqual(cap["returncode"], 0, cap["stderr"])
        return json.loads(cap["stdout"])

    def run_to_recovery(self, fire) -> dict:
        """Drive one run through RTS/start/bridge/ZDO; return the latch.

        The responder and traffic schedule are installed BEFORE firing:
        argument expressions evaluate before the call, so passing the
        fire result would run the automation with no responder attached.
        """
        self.ha.on_publish = zdo_hook("match")
        self.ha.schedule(5.0, lambda: self.ha.set_state(OUTAGE, "off"))
        self.assertEqual(fire(), "ran")
        cap = self.ha.vars["t832_capture"]
        self.assertEqual(cap["returncode"], 0, cap["stderr"])
        capture = json.loads(cap["stdout"])
        self.assertTrue(capture.get("ok"))
        self.assertTrue(capture.get("incident_id"))
        latch = self.latch()
        zdo_resp = self.ha.vars.get("t832_zdo") or {}
        self.assertEqual(
            latch.get("status"),
            "stabilizing",
            {
                "failure_reason": latch.get("failure_reason"),
                "failure_phase": latch.get("failure_phase"),
                "zdo_proof": latch.get("zdo_proof"),
                "recovered": self.ha.vars.get("t832_recovered"),
                "wait_timed_out": self.ha.vars.get("wait") == {},
                "zdo_rc": zdo_resp.get("returncode"),
                "zdo_stderr": str(zdo_resp.get("stderr"))[:300],
            },
        )
        return latch

    # -- success paths -----------------------------------------------------------
    def test_mesh_outage_runs_to_stabilizing(self) -> None:
        # S1: state entry -> capture -> authorize -> stop -> RTS (once) ->
        # start -> bridge -> incident-unique ZDO -> stabilizing. A mid-run
        # timeout-shaped error is suppressed, never a second run. The
        # bridge is down at entry and returns mid-wait, so the
        # wait_template transition path (not just already-online) is taken.
        self.hold_outage()
        self.ha.set_state(BRIDGE, "off")
        self.ha.schedule(30.0, lambda: self.ha.set_state(BRIDGE, "on"))
        latch = self.run_to_recovery(lambda: self.ha.fire_state("mesh_outage"))
        self.assertEqual(self.rts_invocations(), 1)
        requests = self.publishes(ZDO_REQ)
        self.assertEqual(len(requests), 1)
        request = json.loads(requests[0])
        self.assertEqual(request.get("time"), 0)
        self.assertEqual(request.get("transaction"), "ha-t832-" + str(latch.get("incident_id")))
        self.assertEqual(latch.get("zdo_transaction"), request.get("transaction"))
        self.assertIn("radio_timeout", self.ha.suppressions)
        self.assertTrue(
            any(service == "logbook.log" for service, _ in self.ha.records),
            self.ha.records,
        )

    def test_genuine_timeout_entry_runs_to_stabilizing(self) -> None:
        # S10/B07/B13: the production error string crosses the real service
        # boundary (entry filter -> tojson argv -> tool verdict) and the run
        # reaches stabilizing with the mapping payload intact: a mangled
        # argv would fail capture and halt before any RTS. Success carries
        # no failure keys.
        payload = json.dumps(
            {"status": "error", "error": PRODUCTION_ERROR, "transaction": "prod-1"}
        )
        latch = self.run_to_recovery(
            lambda: self.ha.fire_mqtt("radio_timeout", ZDO_RESP, payload)
        )
        self.assertEqual(self.rts_invocations(), 1)
        self.assertNotIn("failure_reason", latch)
        self.assertNotIn("failure_phase", latch)

    # -- entry qualification -------------------------------------------------------
    def test_wrong_topic_never_runs(self) -> None:
        # S7: a timeout-shaped payload on another response topic is no-match;
        # no incident exists and nothing is published.
        payload = json.dumps({"status": "error", "error": PRODUCTION_ERROR})
        self.assertEqual(
            self.ha.fire_mqtt(
                "radio_timeout", "zigbee2mqtt/bridge/response/device/remove", payload
            ),
            "no-match",
        )
        self.assertEqual(self.ha.bus, [])
        self.assertFalse((self.ha.state / "state" / "incident-latch.json").exists())

    def test_malformed_payload_never_runs(self) -> None:
        # S8: non-JSON renders the entry filter to ignore: no-match.
        self.assertEqual(
            self.ha.fire_mqtt("radio_timeout", ZDO_RESP, "{not json"), "no-match"
        )
        self.assertEqual(self.rts_invocations(), 0)

    def test_healthy_response_never_runs(self) -> None:
        # S9: status ok on another transaction renders ignore: no-match.
        payload = json.dumps({"status": "ok", "transaction": "other"})
        self.assertEqual(self.ha.fire_mqtt("radio_timeout", ZDO_RESP, payload), "no-match")
        self.assertEqual(self.rts_invocations(), 0)

    def test_unheld_outage_never_runs(self) -> None:
        # The state trigger's for-duration is enforced before the run.
        self.ha.set_state(OUTAGE, "on")
        self.assertEqual(self.ha.fire_state("mesh_outage"), "no-match")
        self.assertEqual(self.rts_invocations(), 0)

    # -- terminal phase halts -------------------------------------------------------
    def test_stop_unconfirmed_halts_in_stop_phase(self) -> None:
        # S3: the add-on never reports stopped: 6 bounded polls, then the
        # run reports addon-stop-unconfirmed/stop with no RTS attempt.
        self.hold_outage()
        self.ha.on_publish = zdo_hook("match")
        self.ha.stop_plan = [{"rc": 0, "state": "started"}] * 6
        self.assertEqual(self.ha.fire_state("mesh_outage"), "ran")
        self.require_capture()
        latch = self.latch()
        self.assertEqual(latch.get("failure_reason"), "addon-stop-unconfirmed")
        self.assertEqual(latch.get("failure_phase"), "stop")
        self.assertEqual(self.rts_invocations(), 0)

    def test_rts_failure_halts_in_rts_phase(self) -> None:
        # S6: the validated helper fails once: reported, never retried.
        self.hold_outage()
        self.ha.on_publish = zdo_hook("match")
        self.ha.rts_rc = 1
        self.ha.write_shims()
        self.assertEqual(self.ha.fire_state("mesh_outage"), "ran")
        self.require_capture()
        latch = self.latch()
        self.assertEqual(latch.get("failure_reason"), "rts-unconfirmed")
        self.assertEqual(latch.get("failure_phase"), "rts")
        self.assertEqual(self.rts_invocations(), 1)

    def test_start_unconfirmed_halts_in_start_phase(self) -> None:
        # S4: RTS consumed, the add-on never reports started: halt/start.
        self.hold_outage()
        self.ha.on_publish = zdo_hook("match")
        self.ha.start_plan = [{"rc": 0, "state": "stopped"}] * 6
        self.assertEqual(self.ha.fire_state("mesh_outage"), "ran")
        self.require_capture()
        latch = self.latch()
        self.assertEqual(latch.get("failure_reason"), "addon-start-unconfirmed")
        self.assertEqual(latch.get("failure_phase"), "start")
        self.assertEqual(self.rts_invocations(), 1)

    def test_bridge_offline_halts_in_bridge_phase(self) -> None:
        # S5: the bridge state itself never comes on within 2 virtual
        # minutes: halt/bridge without sending the ZDO request.
        self.hold_outage()
        self.ha.on_publish = zdo_hook("match")
        self.ha.set_state(BRIDGE, "off")
        self.assertEqual(self.ha.fire_state("mesh_outage"), "ran")
        self.require_capture()
        latch = self.latch()
        self.assertEqual(latch.get("failure_reason"), "bridge-offline")
        self.assertEqual(latch.get("failure_phase"), "bridge")
        self.assertEqual(self.publishes(ZDO_REQ), [])

    def test_stale_zdo_halts_in_zdo_phase(self) -> None:
        # S2/S12: only stale and foreign-transaction responses arrive. The
        # 15s wait times out (wait var stays empty) into a reported zdo halt.
        self.hold_outage()
        self.ha.on_publish = zdo_hook("mismatch")
        self.ha.schedule(5.0, lambda: self.ha.set_state(OUTAGE, "off"))
        self.assertEqual(self.ha.fire_state("mesh_outage"), "ran")
        self.require_capture()
        self.assertEqual(self.ha.vars.get("wait"), {})
        latch = self.latch()
        self.assertEqual(latch.get("failure_reason"), "zdo-unconfirmed")
        self.assertEqual(latch.get("failure_phase"), "zdo")
        self.assertEqual(self.rts_invocations(), 1)


if __name__ == "__main__":
    unittest.main()
