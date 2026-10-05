"""B08: execute the actual candidate barrier automation in a faithful
bounded interpreter over the real YAML, shell fragments, and CLI.

Contract (pinned against HA core master, read-only):
- automation service data renders with parse_result=True (a template
  that renders to a JSON container comes back native for the shell
  fragment's is-mapping test; helpers/service.py render_complex);
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

import ast
import hashlib
import importlib.util
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
from jinja2.utils import htmlsafe_json_dumps

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
BARRIER = REPO / "deploy" / "t832_capture_barrier.yaml"
SHELL_COMMANDS = REPO / "deploy" / "t832_shell_commands.yaml"
SPEC = importlib.util.spec_from_file_location("t832_incident", HERE / "t832_incident.py")
assert SPEC and SPEC.loader
incident = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(incident)


class Halt(Exception):
    """A false bare condition stopped the run (HA semantics)."""


class HaViolation(AssertionError):
    """The automation used a construct the interpreter does not implement."""


def parse_service_value(value: object) -> object:
    """Mirror HA service-data parse_result for the shell_command handoff.

    Automation service data renders through render_complex with
    parse_result=True, so a template that renders to a JSON container
    comes back native and the shell fragment's `is mapping` branch
    re-serializes it with tojson; anything else passes through as
    rendered. Scoped to the shell_command staging path: the
    mqtt.publish path below must keep its JSON-string payload (the ZDO
    hook and Z2M both json.loads it), matching observed production
    behavior.
    """
    if isinstance(value, str):
        try:
            return ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return value
    return value


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
    """Bounded executor for one automation run over real YAML."""

    def __init__(
        self, root: Path, automation_id: str = "zigbee2mqtt_t832_capture_barrier"
    ) -> None:
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
        # Pinned: the Jinja2 builtin tojson is htmlsafe_json_dumps (no HA
        # override); plain json.dumps would pass ' through raw and break
        # the single-quoted shell argv below on adversarial payloads.
        self.env.filters["tojson"] = lambda value: htmlsafe_json_dumps(value)
        self.env.filters["from_json"] = lambda value: json.loads(value)
        raw = BARRIER.read_text(encoding="utf-8")
        automations = yaml.safe_load(raw.split("```")[0])
        if not isinstance(automations, list) or len(automations) != 3:
            raise HaViolation("barrier file must hold exactly the 3 pinned automations")
        self.automations = automations
        self.automation = next(
            a for a in automations if a.get("id") == automation_id
        )
        self.running_ids: set = set()
        self.catcher_marks: dict = {}
        self.shell_plan: dict = {}
        self.publish_exc: str | None = None
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

    def eval_any_condition(self, cond: object) -> bool:
        """Evaluate an automation-level condition in str or dict form.

        HA automations spell conditions as dicts
        ({condition: template, value_template: ...}); the harness must
        accept the same shapes at automation level that run_choose and
        run_repeat already accept inside branches. Unknown shapes raise
        instead of passing silently.
        """
        if isinstance(cond, str):
            return self.eval_condition(cond)
        if isinstance(cond, dict) and cond.get("condition") == "template":
            return self.eval_condition(str(cond.get("value_template", "")))
        raise HaViolation(f"condition not implemented: {cond!r}")

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
        if self.publish_exc is not None:
            raise RuntimeError(self.publish_exc)
        self.bus.append((self.clock, topic, str(payload)))
        if self.on_publish is not None:
            self.on_publish(self, topic, str(payload))
        self.deliver_triggers()
        self.deliver_catchers()

    def mqtt_deliver(self, topic: str, payload: str) -> None:
        self.bus.append((self.clock, topic, str(payload)))
        self.deliver_catchers()

    def deliver_catchers(self) -> None:
        """R4-F02: every non-running automation's mqtt triggers evaluate on
        bus ingress — the pre-armed catcher records proof even when the
        running automation's own wait has not armed yet. Faithful to HA:
        subscriptions live from automation load; mode single suppresses
        reentry while the catcher itself runs."""
        for auto in self.automations:
            auto_id = auto.get("id")
            if auto_id == self.automation.get("id"):
                continue
            if auto_id in self.running_ids:
                continue
            mark = self.catcher_marks.get(auto_id, 0)
            fired = False
            for trig in auto.get("triggers", []) or []:
                if (trig.get("trigger") or trig.get("platform")) != "mqtt":
                    continue
                for _, topic, payload in self.bus[mark:]:
                    matched = self.match_mqtt(trig, topic, payload)
                    if matched is not None:
                        matched["platform"] = "mqtt"
                        # HA runs automations in isolated scopes: save and
                        # restore the suspended run's variables and flag.
                        saved_vars = self.vars
                        saved_running = self.running
                        self.running_ids.add(auto_id)
                        try:
                            self.run_body(matched, auto)
                        finally:
                            self.vars = saved_vars
                            self.running = saved_running
                            self.running_ids.discard(auto_id)
                        fired = True
                        break
                if fired:
                    break
            self.catcher_marks[auto_id] = len(self.bus)

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
            staged[key] = parse_service_value(self.render(value))
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
            name = service.split(".", 1)[1]
            # R4-F05: injected tool failures (empty/malformed/absent
            # responses, transport errors) raise before the real CLI runs;
            # continue_on_error consumes them with the response unset.
            plan = self.shell_plan.get(name)
            if plan:
                step = plan.pop(0)
                if "exc" in step:
                    raise RuntimeError(f"shell_command.{name}:{step['exc']}")
                response = {
                    "stdout": str(step.get("stdout", "")),
                    "stderr": str(step.get("stderr", "")),
                    "returncode": int(step.get("rc", 0)),
                }
            else:
                response = self.call_shell_command(name, data)
            if response_key:
                self.vars[response_key] = response
        elif service == "hassio.addon_stop":
            step = self.stop_plan.pop(0) if self.stop_plan else {"rc": 0, "state": "stopped"}
            # R4-F05: API timeout/401 and transport failures raise instead
            # of returning a plan: continue_on_error consumes them.
            if "exc" in step:
                raise RuntimeError(f"hassio.addon_stop:{step['exc']}")
            self.state_file.write_text(str(step.get("state", "stopped")), encoding="utf-8")
            if int(step.get("rc", 0)) != 0:
                raise Halt(f"addon_stop rc={step.get('rc')}")
        elif service == "hassio.addon_start":
            step = self.start_plan.pop(0) if self.start_plan else {"rc": 0, "state": "started"}
            if "exc" in step:
                raise RuntimeError(f"hassio.addon_start:{step['exc']}")
            self.state_file.write_text(str(step.get("state", "started")), encoding="utf-8")
            if int(step.get("rc", 0)) != 0:
                raise Halt(f"addon_start rc={step.get('rc')}")
        elif service == "input_text.set_value":
            self.set_state(str(data.get("entity_id", "")), str(data.get("value", "")))
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
                # R4-F05: continue_on_error consumes service exceptions
                # (the response stays unset) but never control-flow Halt.
                if action.get("continue_on_error"):
                    try:
                        self.call_service(action)
                    except Halt:
                        raise
                    except Exception:
                        pass
                else:
                    self.call_service(action)
            else:
                raise HaViolation(f"action kind not implemented: {sorted(action)!r}")

    # -- entry ---------------------------------------------------------------------
    def run_body(self, trigger_obj: dict, automation: dict | None = None) -> None:
        # HA runs do not share script variables: each firing starts clean.
        auto = automation if automation is not None else self.automation
        self.vars = {}
        self.running = True
        self.bus_mark = len(self.bus)
        try:
            self.vars["trigger"] = trigger_obj
            self.vars["this"] = {"entity_id": auto.get("alias", "automation")}
            # HA evaluates the automation's own conditions before actions.
            for cond in auto.get("conditions", []) or []:
                if not self.eval_any_condition(cond):
                    raise Halt("automation conditions not met")
            self.run_actions(auto.get("actions", []))
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

    def fire_automation_state(self, entity: str, new_value: str) -> str:
        """Fire this automation on a state trigger (R4-F04 passive
        counterevidence): apply the state, then run the body when a state
        trigger matches from/to. Returns ran|no-match|suppressed."""
        old = self.states.get(entity, ("unknown", 0.0))[0]
        self.set_state(entity, new_value)
        for trig in self.automation.get("triggers", []) or []:
            if (trig.get("trigger") or trig.get("platform")) != "state":
                continue
            if trig.get("entity_id") != entity:
                continue
            want_from = trig.get("from")
            want_to = trig.get("to")
            if want_from is not None and old != want_from:
                continue
            if want_to is not None and new_value != want_to:
                continue
            if self.running:
                self.suppressions.append(str(trig.get("id", entity)))
                return "suppressed"
            self.run_body({"platform": "state", "entity_id": entity,
                           "from_state": {"state": old},
                           "to_state": {"state": new_value}})
            return "ran"
        return "no-match"

    def fire_time_pattern(self) -> str:
        """Fire the stability scheduler tick.

        HA enforces the minutes:/5 cadence; the scenarios space ticks to
        match it. Returns ran|suppressed.
        """
        spec = next(
            (
                t
                for t in self.automation.get("triggers", []) or []
                if (t.get("trigger") or t.get("platform")) == "time_pattern"
            ),
            None,
        )
        if spec is None:
            return "no-match"
        if self.running:
            self.suppressions.append(str(spec.get("id", "tick")))
            return "suppressed"
        self.run_body({"platform": "time_pattern", "id": spec.get("id", "tick")})
        return "ran"


OUTAGE = "binary_sensor.zigbee2mqtt_mesh_communication_outage"
BRIDGE = "binary_sensor.zigbee2mqtt_bridge_online"
ZDO_REQ = "zigbee2mqtt/bridge/request/permit_join"
ZDO_RESP = "zigbee2mqtt/bridge/response/permit_join"
EXPECT = "input_text.t832_zdo_expect"
PRODUCTION_ERROR = "SRSP - AF - dataRequest after 6000ms"


def zdo_hook(mode: str):
    """Scenario Z2M: answer the permit_join request per mode, and always
    emit one entry-shaped timeout error mid-run (must be suppressed).

    Deferred modes deliver at the next virtual-clock step. R4-F02 gap
    modes deliver synchronously inside the publish call — before the
    barrier's own wait arms — which is exactly the production race the
    pre-armed catcher must win.
    """

    def hook(ha: Ha, topic: str, payload: str) -> None:
        if topic != ZDO_REQ:
            return
        request = json.loads(payload)
        assert request.get("time") == 0, request
        assert str(request.get("transaction", "")).startswith("ha-t832-"), request
        match = json.dumps({"status": "ok", "transaction": request["transaction"]})
        stale = json.dumps(
            {"status": "error", "error": PRODUCTION_ERROR, "transaction": "stale"}
        )
        if mode == "match":
            for answer in (stale, match):
                ha.schedule(0.0, lambda answer=answer: ha.mqtt_deliver(ZDO_RESP, answer))
            return
        if mode == "mismatch":
            for answer in (
                stale,
                json.dumps({"status": "ok", "transaction": "ha-t832-someone-else"}),
            ):
                ha.schedule(0.0, lambda answer=answer: ha.mqtt_deliver(ZDO_RESP, answer))
            return
        if mode == "silent":
            ha.schedule(0.0, lambda: ha.mqtt_deliver(ZDO_RESP, stale))
            return
        # Gap modes: synchronous bus ingress during the publish, before the
        # barrier's wait_for_trigger arms (mark set at wait entry).
        if mode == "gap-match":
            ha.mqtt_deliver(ZDO_RESP, match)
            return
        if mode == "gap-unrelated-first":
            ha.mqtt_deliver(
                ZDO_RESP,
                json.dumps({"status": "ok", "transaction": "ha-t832-someone-else"}),
            )
            ha.mqtt_deliver(ZDO_RESP, match)
            return
        if mode == "gap-malformed":
            ha.mqtt_deliver(ZDO_RESP, "{not json")
            return
        if mode == "gap-duplicate":
            ha.mqtt_deliver(ZDO_RESP, match)
            ha.mqtt_deliver(ZDO_RESP, match)
            return
        raise AssertionError(f"unknown zdo mode: {mode}")

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

    def test_adversarial_payload_round_trips_shell_boundary(self) -> None:
        # S10b/B13 (M4 review): a quote-carrying production error must
        # cross the real service boundary intact. Service-data
        # parse_result restores the mapping so the shell fragment's
        # `is mapping` branch re-serializes it, and htmlsafe tojson keeps
        # the apostrophe out of the raw argv: without both, shlex splits
        # at the quote and capture fails before any RTS.
        payload = json.dumps(
            {
                "status": "error",
                "error": "O'Brien: SRSP - AF - dataRequest after 6000ms",
                "transaction": "prod-2",
            }
        )
        latch = self.run_to_recovery(
            lambda: self.ha.fire_mqtt("radio_timeout", ZDO_RESP, payload)
        )
        self.assertEqual(self.rts_invocations(), 1)
        capture = self.require_capture()
        self.assertTrue(
            capture.get("trigger_qualifying"),
            capture.get("trigger_qualification_reason"),
        )
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


class R4F02CatcherTests(BarrierAutomationTests):
    """R4-F02: the pre-armed catcher wins the publish/wait race; anything
    that is not the armed incident transaction can never create proof."""

    def gap_run(self, mode: str):
        self.hold_outage()
        self.ha.on_publish = zdo_hook(mode)
        self.ha.schedule(5.0, lambda: self.ha.set_state(OUTAGE, "off"))
        self.assertEqual(self.ha.fire_state("mesh_outage"), "ran")
        return self.latch()

    def test_gap_match_recovers_single_request(self) -> None:
        # The matching response arrives inside the publish call, before
        # the barrier's own wait arms (its wait var stays empty): proof
        # still records and the run reaches stabilizing with one request.
        latch = self.gap_run("gap-match")
        self.assertEqual(self.ha.vars.get("wait"), {})
        self.assertEqual(latch.get("status"), "stabilizing")
        requests = self.publishes(ZDO_REQ)
        self.assertEqual(len(requests), 1)
        request = json.loads(requests[0])
        self.assertEqual(latch.get("zdo_transaction"), request.get("transaction"))
        self.assertEqual(
            latch.get("zdo_proof", {}).get("transaction"), request.get("transaction")
        )
        # Consumed: the expectation no longer names the transaction.
        self.assertEqual(self.ha.states.get(EXPECT, ("", 0.0))[0], "")
        self.assertEqual(self.rts_invocations(), 1)

    def test_gap_unrelated_first_recovers(self) -> None:
        # A foreign transaction lands first in the same gap: ignored, and
        # the matching reply still proves the incident exactly once.
        latch = self.gap_run("gap-unrelated-first")
        self.assertEqual(latch.get("status"), "stabilizing")
        self.assertEqual(len(self.publishes(ZDO_REQ)), 1)
        proof = latch.get("zdo_proof", {})
        self.assertTrue(str(proof.get("transaction", "")).startswith("ha-t832-"))
        self.assertNotEqual(proof.get("transaction"), "ha-t832-someone-else")

    def test_gap_duplicate_proves_once(self) -> None:
        # Two identical replies in the gap: the first proves and consumes
        # the expectation, the second matches nothing.
        latch = self.gap_run("gap-duplicate")
        self.assertEqual(latch.get("status"), "stabilizing")
        self.assertEqual(len(self.publishes(ZDO_REQ)), 1)
        self.assertEqual(self.ha.states.get(EXPECT, ("", 0.0))[0], "")

    def test_gap_malformed_halts_unconfirmed(self) -> None:
        # Only garbage arrives: no proof exists and the run halts with the
        # legacy terminal reason — the consumed permit stays consumed.
        # The failed latch carries the proof CHECK detail ("missing"),
        # never a verified proof.
        latch = self.gap_run("gap-malformed")
        self.assertEqual(latch.get("status"), "failed")
        self.assertEqual(latch.get("failure_reason"), "zdo-unconfirmed")
        self.assertEqual(latch.get("failure_phase"), "zdo")
        self.assertTrue(latch.get("reset_used"))
        self.assertEqual(self.rts_invocations(), 1)
        self.assertFalse(latch.get("zdo_verified"))
        self.assertEqual(latch.get("zdo_proof"), "missing")

    def test_retained_reply_before_arm_creates_no_proof(self) -> None:
        # A matching reply already on the bus before the run (retained or
        # redelivered) predates both the armed expectation and the wait's
        # mark: it proves nothing and the run halts unconfirmed.
        self.hold_outage()
        self.ha.schedule(5.0, lambda: self.ha.set_state(OUTAGE, "off"))
        stale = json.dumps({"status": "ok", "transaction": "ha-t832-stale-1"})
        self.ha.mqtt_deliver(ZDO_RESP, stale)
        self.ha.on_publish = zdo_hook("silent")
        self.assertEqual(self.ha.fire_state("mesh_outage"), "ran")
        latch = self.latch()
        self.assertEqual(latch.get("status"), "failed")
        self.assertEqual(latch.get("failure_reason"), "zdo-unconfirmed")
        self.assertFalse(latch.get("zdo_verified"))
        self.assertEqual(latch.get("zdo_proof"), "missing")


class R4F05TerminalTests(BarrierAutomationTests):
    """R4-F05: service exceptions, malformed or absent responses still reach
    a terminal persisted recovery-result — never a stranded incident, never
    a destructive step past an unconfirmed gate."""

    def terminal(self, setup) -> dict:
        self.hold_outage()
        setup()
        self.ha.schedule(5.0, lambda: self.ha.set_state(OUTAGE, "off"))
        self.assertEqual(self.ha.fire_state("mesh_outage"), "ran")
        return self.latch()

    def assert_permit_retained(self, latch: dict) -> None:
        self.assertEqual(latch.get("status"), "failed")
        self.assertTrue(latch.get("reset_used"))
        self.assertEqual(self.rts_invocations(), 1)

    def test_stop_exception_halts_terminal(self) -> None:
        # The stop API itself blows up and the add-on never reports
        # stopped: bounded polls, then addon-stop-unconfirmed/stop.
        def setup() -> None:
            self.ha.on_publish = zdo_hook("match")
            self.ha.stop_plan = [{"exc": "supervisor-timeout"}]

        latch = self.terminal(setup)
        self.assertEqual(latch.get("failure_reason"), "addon-stop-unconfirmed")
        self.assertEqual(latch.get("failure_phase"), "stop")
        self.assert_permit_retained(latch)
        self.assertEqual(self.ha.start_plan, [])

    def test_start_exception_halts_terminal(self) -> None:
        def setup() -> None:
            self.ha.on_publish = zdo_hook("match")
            self.ha.start_plan = [{"exc": "supervisor-401"}]

        latch = self.terminal(setup)
        self.assertEqual(latch.get("failure_reason"), "addon-start-unconfirmed")
        self.assertEqual(latch.get("failure_phase"), "start")
        self.assert_permit_retained(latch)

    def test_malformed_state_poll_halts_terminal(self) -> None:
        # The supervisor pipe tears mid-stream: rc!=0 with garbage stdout
        # never parses, and the bounded poll still reports unconfirmed.
        def setup() -> None:
            self.ha.on_publish = zdo_hook("match")
            self.ha.shell_plan["t832_addon_state"] = [
                {"rc": 1, "stdout": '{"state":', "stderr": "curl: (28) timeout"}
            ] * 12

        latch = self.terminal(setup)
        self.assertEqual(latch.get("failure_reason"), "addon-stop-unconfirmed")
        self.assertEqual(latch.get("failure_phase"), "stop")
        self.assert_permit_retained(latch)

    def test_publish_error_halts_unconfirmed(self) -> None:
        # The single ZDO request never leaves: timeout, no proof, the
        # legacy terminal reason with the permit retained.
        def setup() -> None:
            self.ha.on_publish = zdo_hook("match")
            self.ha.publish_exc = "broker-down"

        latch = self.terminal(setup)
        self.assertEqual(self.publishes(ZDO_REQ), [])
        self.assertEqual(latch.get("failure_reason"), "zdo-unconfirmed")
        self.assertEqual(latch.get("failure_phase"), "zdo")
        self.assert_permit_retained(latch)

    def test_terminal_tool_error_leaves_no_phantom_state(self) -> None:
        # The terminal failed persist itself fails: nothing is recorded,
        # nothing is invented, and the run ends without raising past the
        # barrier (the store error surfaces in the host log instead).
        def setup() -> None:
            self.ha.on_publish = zdo_hook("match")
            self.ha.stop_plan = [{"rc": 0, "state": "started"}] * 6
            self.ha.shell_plan["t832_recovery_result"] = [{"exc": "disk-full"}]

        latch = self.terminal(setup)
        self.assertEqual(latch.get("status"), "recovering")
        self.assertNotIn("failure_reason", latch)

    def test_success_envelopes_parse(self) -> None:
        # CLI contract the YAML relies on: every response the barrier
        # parses with from_json arrives as valid JSON when rc==0, so
        # returncode-first gates never meet a torn stdout with rc==0.
        self.hold_outage()
        self.ha.on_publish = zdo_hook("match")
        self.ha.schedule(5.0, lambda: self.ha.set_state(OUTAGE, "off"))
        self.assertEqual(self.ha.fire_state("mesh_outage"), "ran")
        for key in (
            "t832_capture",
            "t832_addon_state",
            "t832_addon_start_state",
            "t832_zdo",
            "t832_recovered",
        ):
            response = self.ha.vars.get(key)
            self.assertIsInstance(response, dict, key)
            self.assertEqual(response.get("returncode"), 0, key)
            json.loads(response.get("stdout", ""))
        recovered = json.loads(self.ha.vars["t832_recovered"]["stdout"])
        self.assertEqual(recovered.get("status"), "stabilizing")


class StabilitySchedulerTests(BarrierAutomationTests):
    """B09 fast leg: the actual stability automation runs per tick over the
    real CLI. Window-close decisions need real elapsed time and live in
    test_stability.py; these pin the timer contract and per-tick honesty."""

    def setUp(self) -> None:
        super().setUp()
        self.stab = Ha(self.root, automation_id="zigbee2mqtt_t832_stability_close")
        for entity, value in ((OUTAGE, "off"), (BRIDGE, "on")):
            self.stab.states[entity] = (value, 0.0)
            self.stab.state_history.setdefault(entity, []).append((0.0, value))

    def test_timer_contract_pins_five_minute_cadence(self) -> None:
        # The /5 timer the oracles mirror is a static contract of the YAML.
        auto = self.stab.automation
        triggers = auto.get("triggers", []) or []
        kinds = [(t.get("trigger") or t.get("platform")) for t in triggers]
        self.assertIn("time_pattern", kinds)
        tick = next(t for t in triggers if (t.get("trigger") or t.get("platform")) == "time_pattern")
        self.assertEqual(str(tick.get("minutes")), "/5")
        self.assertEqual(auto.get("mode"), "single")
        services = [
            step.get("action", step.get("service"))
            for step in auto.get("actions", [])
            if isinstance(step, dict) and ("action" in step or "service" in step)
        ]
        self.assertEqual(
            services,
            [
                "shell_command.t832_status",
                "shell_command.t832_observe",
                "shell_command.t832_close_if_stable",
                "system_log.write",
            ],
        )
        self.assertFalse(any(str(s).startswith("notify") for s in services))
        observe = next(s for s in auto["actions"] if s.get("data", {}).get("zdo_ok"))
        # B09: per-tick zdo_ok needs both a quiet mesh and an online
        # bridge; outage quiet alone never attests radio health.
        self.assertIn("zigbee2mqtt_bridge_online", observe["data"]["zdo_ok"])

    def test_state_triggers_pin_passive_counterevidence(self) -> None:
        # R4-F04: bridge/mesh transitions are observed passively between
        # ticks — exactly the off/on edges, event-driven, no probes.
        auto = self.stab.automation
        state_trigs = [
            t for t in auto.get("triggers", []) or []
            if (t.get("trigger") or t.get("platform")) == "state"
        ]
        self.assertEqual(len(state_trigs), 2)
        by_entity = {t.get("entity_id"): t for t in state_trigs}
        self.assertEqual(
            (by_entity["binary_sensor.zigbee2mqtt_bridge_online"].get("from"),
             by_entity["binary_sensor.zigbee2mqtt_bridge_online"].get("to")),
            ("on", "off"),
        )
        self.assertEqual(
            (by_entity["binary_sensor.zigbee2mqtt_mesh_communication_outage"].get("from"),
             by_entity["binary_sensor.zigbee2mqtt_mesh_communication_outage"].get("to")),
            ("off", "on"),
        )

    def test_outage_tick_records_counterevidence_without_closing(self) -> None:
        # A tick mid-outage records false flags bound to the live boot and
        # the incident proof, and the latch stays stabilizing: close raises
        # window-not-complete this early, so the tick halts on its gate.
        self.hold_outage()
        self.run_to_recovery(lambda: self.ha.fire_state("mesh_outage"))
        latch = self.latch()
        self.stab.set_state(OUTAGE, "on")
        self.stab.set_state(BRIDGE, "off")
        self.assertEqual(self.stab.fire_time_pattern(), "ran")
        self.assertEqual(self.latch().get("status"), "stabilizing")
        obs = self.latch().get("observations", [])
        self.assertTrue(obs)
        last = obs[-1]
        self.assertFalse(last.get("bridge_up"))
        self.assertFalse(last.get("normal_traffic"))
        self.assertFalse(last.get("zdo_ok"))
        self.assertEqual(last.get("zdo_transaction"), latch.get("zdo_transaction"))
        self.assertEqual(last.get("boot_id"), incident.current_boot_id())
        self.assertTrue(last.get("boot_id"))

    def test_idle_tick_without_incident_is_noop(self) -> None:
        # No latch exists: the status gate halts the tick before any write.
        # The response pin is structural: t832_status (read-only) is the
        # only command that may run, so deleting the gate fails here when
        # observe records its response before halting on rc.
        self.assertEqual(self.stab.fire_time_pattern(), "ran")
        self.assertEqual(
            sorted(k for k in self.stab.vars if k.startswith("t832_")),
            ["t832_status"],
        )
        self.assertFalse((self.ha.state / "state" / "incident-latch.json").exists())

    def test_boot_comparator_rejects_foreign_boot(self) -> None:
        # B09: a rebooted host with greater uptime keeps monotonic
        # continuity, so only the boot id fails it closed. Pure-function
        # leg: different boot rejects, missing identity fails closed, the
        # live boot accepts.
        live = incident.current_boot_id()
        self.assertTrue(live)
        self.assertEqual(incident.check_boot_continuity([live, live], live), (True, "ok"))
        self.assertEqual(
            incident.check_boot_continuity([live, "other-boot"], live),
            (False, "boot-mismatch"),
        )
        self.assertEqual(
            incident.check_boot_continuity([live], None), (False, "boot-unknown")
        )
        self.assertEqual(
            incident.check_boot_continuity([live], ""), (False, "boot-unknown")
        )

    def test_wall_skew_comparator_rejects_jumps(self) -> None:
        # Wall and monotonic overshoot past the window end agree on a
        # healthy close and diverge on a wall jump or suspend/resume.
        self.assertEqual(incident.check_wall_skew(12.0, 9.0), (True, "ok"))
        self.assertEqual(
            incident.check_wall_skew(3700.0, 9.0), (False, "wall-skew")
        )


if __name__ == "__main__":
    unittest.main()
