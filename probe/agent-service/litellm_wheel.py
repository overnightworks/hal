"""Probe of the wheel cell (HAL-2.8w): `GatewayBackend` from hal's own pin of the agent-runtime
client runs one tool turn from a throwaway on hopin's network, with hopin's key as a file, through
the real front and LiteLLM to the fake Anthropic; 2.8's census (litellm_retention.py) then
searches the route for the turn's canaries. Before the turn, the same throwaway runner
calls the wheel's `list_gateway_models` through the front (HAL-2.6m's W models).

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        uv run --frozen python3 probe/agent-service/litellm_wheel.py --scratch DIR

Measured: a run took 81 s, teardown included; the teardown is litellm_retention.py's, a few
seconds (K 30 s, CAP 1800 s).

The throwaway runs on the pinned base in probe/agent-service/Dockerfile (its first `FROM`)
with this interpreter's site-packages mounted read-only, so the wheel is exactly the one hal's lock
pins, and as the host's own user and group, which own the venv's files; the probe refuses root.
Its program builds the turn from the wheel's own types; the tool's handler answers with the result
canary. The fake calls the steered tool only while no tool result came back, so the turn ends with
the answer canary.

After the turn, one more per mode that cuts the fake's stream (`stream_cut`, `stream_cut_chunked`)
records the events the wheel gets or the stop, without judging them; a client that does not
stream gets the whole answer. Measured: the cut turns take about 3 s.

Evidence: W the throwaway's model list and turn events, F the fake's request log, C the census with
its planted row, Q an SQL count. Exit 0: K0, W models, W turn, W cut, W census and W tags held.
"""

from __future__ import annotations

import json
import os
import re
import sys
import sysconfig
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_runtime_client.turn import Principal, person_fingerprint
from litellm import (
    DEFAULT_MODEL,
    FRONT,
    FRONT_PORT,
    LABEL,
    PROJECT,
    REPO,
    ProbeFailed,
    expect,
    run_scratch_probe,
)
from litellm_key_files import APP_KEYS_FOLDER
from litellm_retention import (
    FINGERPRINT_TABLES,
    TOOL_TABLE,
    TOOL_TABLES,
    RetentionProbe,
    canary,
    front_user_agent,
)

DOCKERFILE = REPO / "probe" / "agent-service" / "Dockerfile"
BASE_IMAGE = re.compile(r"^FROM\s+(\S+)", re.M)
WHEEL = "/wheel"
CUT_MODES = ("stream_cut", "stream_cut_chunked")
KEY_FILE = "/run/secrets/hopin-key"
ISSUER = "https://probe.invalid/issuer"
API_GROUP = "probe-api"
TURN_SECONDS = 120
ORIGIN = f"http://{FRONT}:{FRONT_PORT}"  # NOSONAR(S5332) plain HTTP front, as apps reach it
# Each program runs as `python -I -B -`: isolated, so the path holds the mounted site-packages
# alone. Its standard input starts with `SCENARIO = {...}` and `HIDDEN = [...]`; it prints JSON
# lines with every value of HIDDEN shown as `<hidden>`.
WHEEL_PREAMBLE = f"""\
import asyncio, json, sys
sys.path.insert(0, {WHEEL!r})
def show(record):
    shown = json.dumps(record)
    for value in HIDDEN:
        shown = shown.replace(value, "<hidden>")
    print(shown, flush=True)
"""
# One line: the names by kind, or the closed label of the list's failure.
LIST_PROGRAM = (
    WHEEL_PREAMBLE
    + """\
from agent_runtime_client.backend.gateway import ModelListUnavailable, list_gateway_models
from agent_runtime_client.config import ChatGateway
async def main():
    gateway = ChatGateway(origin=SCENARIO["origin"], key_file=SCENARIO["key_file"])
    try:
        models = await list_gateway_models(gateway)
    except ModelListUnavailable as unavailable:
        show({"unavailable": unavailable.detail.value})
        return
    show({"text": list(models.text), "image": list(models.image)})
asyncio.run(main())
"""
)
# One line per turn event, or the stop.
TURN_PROGRAM = (
    WHEEL_PREAMBLE
    + """\
from agent_runtime_client.agents import TurnRequest
from agent_runtime_client.backend import TurnPerson, TurnStopped
from agent_runtime_client.backend.gateway import GatewayBackend
from agent_runtime_client.config import AgentConfig, ChatGateway
from agent_runtime_client.tools import HandTool, ToolDeclaration, ToolEffect, ToolOutcome
from agent_runtime_client.turn import Principal, Turn, TurnMessage
async def answer(principal, arguments):
    return ToolOutcome(content=SCENARIO["result"], is_error=False)
async def groups():
    return frozenset({SCENARIO["api_group"]})
async def main():
    declaration = ToolDeclaration(
        name=SCENARIO["tool"], description=SCENARIO["description"], effect=ToolEffect.READ_ONLY,
        parameters={"type": "object", "properties": {"q": {"type": "string"}}},
    )
    config = AgentConfig(
        backend="litellm", api_group=SCENARIO["api_group"],
        gateway=ChatGateway(origin=SCENARIO["origin"], key_file=SCENARIO["key_file"]),
    )
    request = TurnRequest(
        agent="probe", roles=["admin", "user"], tools=(declaration,), model=SCENARIO["model"],
        max_duration_seconds=SCENARIO["seconds"], max_tool_calls=1,
        turn=Turn(system="probe", messages=[TurnMessage(role="user", text=SCENARIO["message"])]),
    )
    person = TurnPerson(principal=Principal(**SCENARIO["principal"]), role="user", groups=groups)
    backend = GatewayBackend(config, tools=[HandTool(declaration, answer)])
    try:
        async for event in backend.run(request, person):
            show(event.model_dump(mode="json"))
    except TurnStopped as stopped:
        stop = {"kind": stopped.kind, "code": stopped.code, "detail": stopped.detail}
        show({"type": "stopped", **stop})
asyncio.run(main())
"""
)


def base_image() -> str:
    """The probe's pinned base: the reference of probe/agent-service/Dockerfile's first `FROM`."""
    matched = BASE_IMAGE.search(DOCKERFILE.read_text(encoding="utf-8"))
    if matched is None or "@sha256:" not in matched[1]:
        raise ProbeFailed(f"{DOCKERFILE}: no pinned FROM")
    return matched[1]


class WheelProbe(RetentionProbe):
    """2.8's stack and census with one turn of hal's own client wheel through it."""

    def drive(self) -> None:
        self.wait_until_listening()
        self.cell_k0()
        self.cell_w_models()
        self.steer()
        self.cell_w()

    def wheel_command(self) -> list[str]:
        """The throwaway's argv: hopin's network only, the venv and the key file read-only, as the
        host's own user, which owns the venv's files."""
        expect(os.getuid() != 0, "the wheel's throwaway would run as root")
        self.throwaways += 1
        site_packages = sysconfig.get_path("purelib")
        hopin_key = Path(self.environment["HOME"]) / APP_KEYS_FOLDER / "hopin"
        return [
            "docker", "run", "--rm", "-i", "--name", f"{PROJECT}-wheel-{self.throwaways}",
            "--label", LABEL, f"--network={PROJECT}_{self.caller_network}", "--read-only",
            "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--volume", f"{site_packages}:{WHEEL}:ro", "--volume", f"{hopin_key}:{KEY_FILE}:ro",
            base_image(), "python", "-I", "-B", "-",
        ]  # fmt: skip

    def in_throwaway(self, program: str, scenario: dict) -> list[dict]:
        """W: the lines one of the wheel's programs printed in the throwaway."""
        preamble = f"SCENARIO = {scenario!r}\nHIDDEN = {self.hidden_keys()!r}\n"
        result = self.run(self.wheel_command(), stdin=preamble + program, timeout=240)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def cell_w_models(self) -> None:
        (listed,) = self.in_throwaway(LIST_PROGRAM, {"origin": ORIGIN, "key_file": KEY_FILE})
        names = sorted([*listed.get("text", ()), *listed.get("image", ())])
        own = sorted(self.key_info(self.key)["models"])
        expect(names == own, f"W models: the wheel listed {listed}, hopin's key holds {own}")
        self.hold("W models", f"list_gateway_models through the front with hopin's key file: "
                  f"{listed}, exactly the key's models")  # fmt: skip

    @staticmethod
    def turn_canaries(prefix: str) -> dict[str, str]:
        labels = ("message", "description", "arguments", "result", "answer", "subject")
        return {label: canary(f"{prefix}-{label}") for label in labels}

    @staticmethod
    def turn_scenario(tool: str, canaries: dict[str, str], principal: dict) -> dict:
        return {
            "tool": tool, "description": canaries["description"], "message": canaries["message"],
            "result": canaries["result"], "principal": principal, "api_group": API_GROUP,
            "origin": ORIGIN, "key_file": KEY_FILE, "model": DEFAULT_MODEL,
            "seconds": TURN_SECONDS,
        }  # fmt: skip

    def cell_w_cuts(self) -> None:
        """W cut: one more turn per mode that cuts the fake's stream. The events the client gets
        are recorded and not judged; a client that does not stream gets the whole answer."""
        started, outcomes = time.monotonic(), []
        for mode in CUT_MODES:
            canaries = self.turn_canaries(f"w-{mode}")
            tool = canary("w-tool").replace("-", "_")
            principal = {"iss": ISSUER, "sub": canaries["subject"]}
            self.steer(mode=mode, marker=canaries["answer"], request_canary=canaries["result"],
                       tool_use={"name": tool, "input": {"q": canaries["arguments"]}},
                       tool_use_once=True)  # fmt: skip
            try:
                events = self.in_throwaway(
                    TURN_PROGRAM, self.turn_scenario(tool, canaries, principal)
                )
            except ProbeFailed as failure:
                outcomes.append(f"{mode}: the program failed: {failure}")
                continue
            kinds = [event["type"] for event in events]
            spoken = "".join(event.get("text", "") for event in events if event["type"] != "final")
            stopped = [
                {key: event[key] for key in ("kind", "code")} for event in events
                if event["type"] == "stopped"
            ]  # fmt: skip
            said = canaries["answer"] in spoken
            outcomes.append(
                f"{mode}: events {kinds}, stops {stopped}, answer canary in text {said}"
            )
        self.steer()
        self.hold("W cut", f"{'; '.join(outcomes)} ({time.monotonic() - started:.0f} s, recorded "
                  "and not judged)")  # fmt: skip

    def cell_w(self) -> None:
        canaries = self.turn_canaries("w")
        tool = canary("w-tool").replace("-", "_")
        principal = {"iss": ISSUER, "sub": canaries["subject"]}
        person = person_fingerprint(Principal(**principal))
        steering = dict(
            marker=canaries["answer"], request_canary=canaries["result"],
            tool_use={"name": tool, "input": {"q": canaries["arguments"]}},
            tool_use_once=True, declares=tool,
            arrivals={k: canaries[k] for k in ("message", "description")},
        )  # fmt: skip
        self.steer(**steering)
        before = len(self.provider_requests())
        events = self.in_throwaway(TURN_PROGRAM, self.turn_scenario(tool, canaries, principal))
        self.steer()
        before_the_call = self.expect_the_turn(events, tool, canaries, steering["marker"])
        rounds = self.provider_requests()[before:]
        seen = [(r["tool_result"], r["request_canary_hits"], r["user_id"]) for r in rounds]
        expect(seen == [(False, 0, person), (True, 1, person)], f"W: F saw {seen}")
        first = rounds[0]
        arrived = (first["declared_tool"], first["arrivals"])
        expect(arrived == (True, {"message": 1, "description": 1}), f"W: round 1 showed {arrived}")
        self.hold("W turn", f"{len(events)} events: {before_the_call} text pieces before the call, "
                  "the call of the one declared tool with the fake's arguments, the handler's "
                  "result, the answer; F saw two rounds for the wheel's "
                  "fingerprint, the first declaring the tool and carrying the message and "
                  "description canaries once, the second with a tool_result block holding the "
                  "result")  # fmt: skip
        self.cell_w_cuts()
        self.expect_the_census(tool, person, canaries)

    @staticmethod
    def expect_the_turn(
        events: list[dict], tool: str, canaries: dict[str, str], tool_round_text: str
    ) -> int:
        """The text pieces before the call join to the tool round's steered text, those after the
        result to the answer canary. Returns how many pieces came before the call."""
        kinds = [event["type"] for event in events]
        before_the_call = kinds.index("tool_call") if "tool_call" in kinds else len(kinds)
        after = kinds[before_the_call + 2 : -1]
        wanted = ["assistant_text"] * before_the_call + ["tool_call", "tool_result"]
        wanted += ["assistant_text"] * len(after) + ["final"]
        expect(kinds == wanted and after, f"W: the turn's events {kinds}: {events[-1:]}")
        spoken_before = "".join(event["text"] for event in events[:before_the_call])
        expect(not before_the_call or spoken_before == tool_round_text, "W: the tool round's text")
        call, result, *texts, final = events[before_the_call:]
        spoken = "".join(event["text"] for event in texts)
        expect(spoken == canaries["answer"], "W: the answer's text pieces")
        expect(call["name"] == tool, "W: the call names another tool")
        expect(call["input"] == {"q": canaries["arguments"]}, "W: the call's arguments")
        expect(result["content"] == canaries["result"], "W: the tool's result")
        expect(final["text"] == canaries["answer"], "W: the answer")
        return before_the_call

    def expect_the_census(self, tool: str, person: str, canaries: dict[str, str]) -> None:
        """C after the batch writes: no canary anywhere, the dump included; the tool name in the
        tool table and at most the spend tables that carry tool names, the fingerprint in the
        end-user tables alone; Q: no tag row of hopin's key once the tag job has run past the
        turn."""
        self.wait_for_tool(tool)
        self.wait_for_row("LiteLLM_DailyEndUserSpend", "end_user_id", person)
        found = self.planted_sweep({**canaries, "tool": tool, "fingerprint": person})
        held = sorted(set(canaries) & set(found))
        expect(not held, f"W: canaries retained: {held}: {[found[label] for label in held]}")
        for label, holds in (
            ("tool", lambda landed: TOOL_TABLE in landed <= TOOL_TABLES),
            ("fingerprint", lambda landed: landed == FINGERPRINT_TABLES),
        ):
            sinks = found.get(label, ())
            landed, outside = self.dump_tables(sinks), self.outside_the_database(sinks)
            expect(holds(landed) and not outside, f"W: the {label} in {landed} and {outside}")
        agents = self.tool_user_agents(tool)
        expect(agents == {front_user_agent()}, f"W: the tool row's user agents {agents}")
        self.hold("W census", f"none of {len(canaries)} canaries in any sink, the dump included; "
                  f"the planted row found; the tool name in {TOOL_TABLE}, at most also the spend "
                  f"tables that carry tool names, with the front's user agent; "
                  f"the fingerprint in {sorted(FINGERPRINT_TABLES)} alone")  # fmt: skip
        self.tag_barrier("W")
        hopin = self.count(self.tag_rows_of(self.key))
        control = self.count(self.tag_rows_of(self.file_keys["presentator"]))
        expect(hopin == 0, f"W: {hopin} daily tag rows of hopin's key")
        expect(control >= 1, "W: the control finds no tag row of presentator's barrier")
        self.hold("W tags", "no daily tag row of hopin's key after the barrier's own tag row; "
                  f"the same query finds {control} of presentator's")  # fmt: skip


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], WheelProbe)


if __name__ == "__main__":
    sys.exit(main())
