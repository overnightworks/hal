"""Probe of the wheel cell (HAL-2.8w): `GatewayBackend` from hal's own pin of the agent-runtime
client runs one tool turn from a throwaway on hopin's network, with hopin's key as a file, through
the real front and LiteLLM to the fake Anthropic; 2.8's census (litellm_retention.py) then
searches the route for the turn's canaries.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        uv run --frozen python3 probe/agent-service/litellm_wheel.py --scratch DIR

Measured: a run took 81 s, teardown included; the teardown is litellm_retention.py's, a few
seconds (K 30 s, CAP 1800 s).

The throwaway runs on the agent-service image's pinned base (the first `FROM` of its Dockerfile)
with this interpreter's site-packages mounted read-only, so the wheel is exactly the one hal's lock
pins, and as the service's user, which can read them. Its program builds the turn from the wheel's
own types; the tool's handler answers with the result canary. The fake calls the steered tool only
while no tool result came back, so the turn ends with the answer canary.

Evidence: W the throwaway's turn events, F the fake's request log, C the census with its planted
row, Q an SQL count. Exit 0: K0 and W held.
"""

from __future__ import annotations

import json
import re
import sys
import sysconfig
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_runtime_client.turn import Principal, person_fingerprint
from issuer import SERVICE
from litellm import (
    DEFAULT_MODEL,
    FRONT,
    FRONT_PORT,
    LABEL,
    PROJECT,
    REPO,
    expect,
    run_scratch_probe,
)
from litellm_key_files import APP_KEYS_FOLDER
from litellm_retention import (
    FINGERPRINT_TABLES,
    TOOL_TABLE,
    RetentionProbe,
    canary,
    front_user_agent,
)

DOCKERFILE = REPO / "agent-service" / "image" / "Dockerfile"
BASE_IMAGE = re.compile(r"^FROM\s+(\S+)", re.M)
WHEEL = "/wheel"
KEY_FILE = "/run/secrets/hopin-key"
ISSUER = "https://probe.invalid/issuer"
API_GROUP = "probe-api"
TURN_SECONDS = 120
# Run as `python -I -B -`: isolated, so the path holds the mounted site-packages alone. Its
# standard input starts with `SCENARIO = {...}` and `HIDDEN = [...]`; it prints one JSON line per
# turn event, or the stop, with every value of HIDDEN shown as `<hidden>`.
TURN_PROGRAM = f"""\
import asyncio, json, sys
sys.path.insert(0, {WHEEL!r})
from agent_runtime_client.agents import TurnRequest
from agent_runtime_client.backend import TurnPerson, TurnStopped
from agent_runtime_client.backend.gateway import GatewayBackend
from agent_runtime_client.config import AgentConfig, ChatGateway
from agent_runtime_client.tools import HandTool, ToolDeclaration, ToolEffect, ToolOutcome
from agent_runtime_client.turn import Principal, Turn, TurnMessage
def show(record):
    shown = json.dumps(record)
    for value in HIDDEN:
        shown = shown.replace(value, "<hidden>")
    print(shown, flush=True)
async def answer(principal, arguments):
    return ToolOutcome(content=SCENARIO["result"], is_error=False)
async def groups():
    return frozenset({{SCENARIO["api_group"]}})
async def main():
    declaration = ToolDeclaration(
        name=SCENARIO["tool"], description=SCENARIO["description"], effect=ToolEffect.READ_ONLY,
        parameters={{"type": "object", "properties": {{"q": {{"type": "string"}}}}}},
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
        stop = {{"kind": stopped.kind, "code": stopped.code, "detail": stopped.detail}}
        show({{"type": "stopped", **stop}})
asyncio.run(main())
"""


def base_image() -> str:
    """The agent-service image's pinned base: the reference of its Dockerfile's first `FROM`."""
    matched = BASE_IMAGE.search(DOCKERFILE.read_text(encoding="utf-8"))
    expect(matched is not None and "@sha256:" in matched[1], f"{DOCKERFILE}: no pinned FROM")
    return matched[1]


class WheelProbe(RetentionProbe):
    """2.8's stack and census with one turn of hal's own client wheel through it."""

    def drive(self) -> None:
        self.wait_until_listening()
        self.cell_k0()
        self.steer()
        self.cell_w()

    def wheel_command(self) -> list[str]:
        """The throwaway's argv: hopin's network only, the venv and the key file read-only, as
        the service's user, who owns the venv's files."""
        self.throwaways += 1
        site_packages = sysconfig.get_path("purelib")
        hopin_key = Path(self.environment["HOME"]) / APP_KEYS_FOLDER / "hopin"
        return [
            "docker", "run", "--rm", "-i", "--name", f"{PROJECT}-wheel-{self.throwaways}",
            "--label", LABEL, f"--network={PROJECT}_{self.caller_network}", "--read-only",
            "--user", self.resolved_services()[SERVICE]["user"], "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--volume", f"{site_packages}:{WHEEL}:ro", "--volume", f"{hopin_key}:{KEY_FILE}:ro",
            base_image(), "python", "-I", "-B", "-",
        ]  # fmt: skip

    def turn(self, scenario: dict) -> list[dict]:
        """W: the turn's events, as the throwaway printed them."""
        program = f"SCENARIO = {scenario!r}\nHIDDEN = {self.hidden_keys()!r}\n"
        result = self.run(self.wheel_command(), stdin=program + TURN_PROGRAM, timeout=240)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def cell_w(self) -> None:
        canaries = {
            label: canary(f"w-{label}")
            for label in ("message", "description", "arguments", "result", "answer", "subject")
        }  # fmt: skip
        tool = canary("w-tool").replace("-", "_")
        principal = {"iss": ISSUER, "sub": canaries["subject"]}
        person = person_fingerprint(Principal(**principal))
        self.steer(marker=canaries["answer"], request_canary=canaries["result"],
                   tool_use={"name": tool, "input": {"q": canaries["arguments"]}},
                   tool_use_once=True)  # fmt: skip
        before = len(self.provider_requests())
        events = self.turn({
            "tool": tool, "description": canaries["description"], "message": canaries["message"],
            "result": canaries["result"], "principal": principal, "api_group": API_GROUP,
            "origin": f"http://{FRONT}:{FRONT_PORT}", "key_file": KEY_FILE,
            "model": DEFAULT_MODEL, "seconds": TURN_SECONDS,
        })  # fmt: skip
        self.steer()
        self.expect_the_turn(events, tool, canaries)
        rounds = self.provider_requests()[before:]
        seen = [(r["tool_result"], r["request_canary_hits"], r["user_id"]) for r in rounds]
        expect(seen == [(False, 0, person), (True, 1, person)], f"W: F saw {seen}")
        self.hold("W turn", f"{len(events)} events: the call of the one declared tool with the "
                  "fake's arguments, the handler's result, the answer; F saw two rounds for the "
                  "wheel's fingerprint, the second with a tool_result block holding the "
                  "result")  # fmt: skip
        self.expect_the_census(tool, person, canaries)

    @staticmethod
    def expect_the_turn(events: list[dict], tool: str, canaries: dict[str, str]) -> None:
        kinds = [event["type"] for event in events]
        wanted = ["tool_call", "tool_result", "assistant_text", "final"]
        expect(kinds == wanted, f"W: the turn's events {kinds}: {events[-1:]}")
        call, result, _, final = events
        expect(call["name"] == tool, "W: the call names another tool")
        expect(call["input"] == {"q": canaries["arguments"]}, "W: the call's arguments")
        expect(result["content"] == canaries["result"], "W: the tool's result")
        expect(final["text"] == canaries["answer"], "W: the answer")

    def expect_the_census(self, tool: str, person: str, canaries: dict[str, str]) -> None:
        """C after the batch writes: no canary anywhere, the dump included; the tool name in the
        tool table alone, the fingerprint in the end-user tables alone; Q: no tag row of hopin's
        key once the tag job has run past the turn."""
        self.wait_for_tool(tool)
        self.wait_for_row("LiteLLM_DailyEndUserSpend", "end_user_id", person)
        found = self.planted_sweep({**canaries, "tool": tool, "fingerprint": person})
        held = sorted(set(canaries) & set(found))
        expect(not held, f"W: canaries retained: {held}: {[found[label] for label in held]}")
        for label, tables in (("tool", {TOOL_TABLE}), ("fingerprint", FINGERPRINT_TABLES)):
            sinks = found.get(label, ())
            landed, outside = self.dump_tables(sinks), self.outside_the_database(sinks)
            expect(landed == tables and not outside, f"W: the {label} in {landed} and {outside}")
        agents = self.tool_user_agents(tool)
        expect(agents == {front_user_agent()}, f"W: the tool row's user agents {agents}")
        self.hold("W census", f"none of {len(canaries)} canaries in any sink, the dump included; "
                  f"the planted row found; the tool name in {TOOL_TABLE} alone with the front's "
                  f"user agent; the fingerprint in {sorted(FINGERPRINT_TABLES)} alone")  # fmt: skip
        self.tag_barrier("W")
        hopin = self.count(self.tag_rows_of(self.key))
        expect(hopin == 0, f"W: {hopin} daily tag rows of hopin's key")
        self.hold("W tags", "no daily tag row of hopin's key after the barrier's own tag row")


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], WheelProbe)


if __name__ == "__main__":
    sys.exit(main())
