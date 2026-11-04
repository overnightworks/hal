"""Probe of the direct route's retention (#814 S1c cells B1-B7, B9-B11, D9 and P7; HAL-2.8 cells
K0, T1-T4, STR-c and STR): the stack of litellm.py without the agent service and the issuer (the
one-route front, LiteLLM, its database and the gateway's second entrypoint, against a fake
Anthropic) and its caller with hopin's key, made by `hal apply`'s key step from a scratch key file,
with a unique canary in each request and answer, searched afterwards in every writable mount and
every log of the front, the gateway, LiteLLM and its database, and in a `pg_dump` of the database,
by `agent-service/retention_census.py`.
Nothing live and nothing paid: the probe refuses to start unless `internet` is internal and holds
only the fakes.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_retention.py --scratch DIR

Measured: a run takes about three minutes and its
teardown a few seconds (K 30 s, CAP 1800 s).

Evidence: F is the fake provider's request log, A the caller's status, C the census's verdict
(canaries found per sink, the dump's tables among them, and every sink it could not examine), Q
an SQL count in the database. B2, B3a, B3b and D9's planted row are the controls: each plants a
canary where the search must find it (a file by exec into a tmpfs, a LiteLLM debug log, the front's
access log, a row), and B2 and B3 run first on a stack the probe then recreates, so no clean
cell sees their tmpfs. The probe differs from production as the controls say, for B3a and B3b
only: `LITELLM_LOG=DEBUG`, and the front's access log. The fake's control file and the caller's
program are harness inputs that hold the canaries by design and are no sinks of the route. Unlike
litellm.py, the probe runs the shipped config.yaml unchanged, which B11 reads.
Every clean cell sends fresh canaries. B11 prints the configuration of the running
containers; the reviewer judges it against the pinned image's source writers.

Exit 0: every cell held.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "agent-service"))

from litellm import (  # noqa: E402
    DATABASE,
    DEFAULT_MODEL,
    FAKE_PROVIDER,
    FRONT,
    FRONT_STATIC,
    GATEWAY,
    LITELLM,
    PROJECT,
    ROUTE,
    ProbeFailed,
    answer_text,
    expect,
    hashed,
    mounted_file,
    run_scratch_probe,
    wire_body,
)
from litellm_caller import CALL_PROGRAM, STREAM_PROGRAM, caller_input  # noqa: E402
from litellm_failures import FailureProbe  # noqa: E402
from litellm_key_files import APPS, KeyFiles  # noqa: E402
from live_canary import LITELLM_LONGEST_WRITE_INTERVAL_SECONDS  # noqa: E402
from retention_census import (  # noqa: E402
    DUMP,
    ROUTE_SERVICES,
    Census,
    Sweep,
    Target,
    route_target,
    run_docker,
)

from hal.output import write_line  # noqa: E402

HOLD_SECONDS = 45  # B4's hold: over a scan of the route
STREAM_HOLD_SECONDS = 60  # STR's hold: past it the fake logs `held timed out` and the cell fails
SCAN_DEADLINE_SECONDS = 60
UPSTREAM_ERROR = 400
ROUTE_FILE = REPO / "agent-service" / "litellm" / "front" / "dynamic" / "route.yml"


class NonEmptyId:
    """Equal to any non-empty string: B11 judges the person budget's id, not today's value."""

    def __eq__(self, other: object) -> bool:
        return isinstance(other, str) and other != ""

    def __repr__(self) -> str:
        return "a non-empty id"


SETTINGS_SECTIONS = {
    "litellm_settings": {
        "turn_off_message_logging": True,
        "redact_messages_in_exceptions": True,
        "max_end_user_budget_id": NonEmptyId(),
        "disable_add_user_agent_to_request_tags": True,
    },
    "general_settings": {
        "enforce_user_param": True,
        "disable_spend_logs": True,
        "disable_error_logs": True,
        "store_prompts_in_spend_logs": False,
    },
    "router_settings": {"num_retries": 0},
}
DEPLOYMENT_KEYS = {"model_name", "litellm_params"}
DEPLOYMENT_PARAMS = {"model", "api_key", "max_retries", "max_tokens"}
# The one table of LiteLLM's database that may name a tool (D9), those that may name a fingerprint
# (P7), and those a body tag may land in (T3).
TOOL_TABLE = "LiteLLM_ToolTable"
FINGERPRINT_TABLES = {"LiteLLM_EndUserTable", "LiteLLM_DailyEndUserSpend"}
TAG_TABLE, DAILY_TAG_TABLE = "LiteLLM_TagTable", "LiteLLM_DailyTagSpend"
USER_AGENT = "user agent"  # the label of the user-agent canary in T1 and D9
TOOL_WRITE_SECONDS = 120
TAG_BARRIER_SECONDS = 2 * LITELLM_LONGEST_WRITE_INTERVAL_SECONDS  # two runs of the tag job
STORE_NAMES = re.compile(
    r"DATABASE|REDIS|CALLBACK|LANGFUSE|VERBOSE|SPEND|S3_|LITELLM_PRINT_STANDARD_LOGGING_PAYLOAD",
    re.I,
)
# The four body tag forms of decision 10, each a body extra holding the tag `canary`.
TAG_FORMS = {
    "T3a root tags": lambda canary: {"tags": [canary]},
    "T3b metadata.tags": lambda canary: {"metadata": {"tags": [canary]}},
    "T3c metadata as a JSON string": lambda canary: {"metadata": json.dumps({"tags": [canary]})},
    "T3d litellm_metadata.tags": lambda canary: {"litellm_metadata": {"tags": [canary]}},
}


def canary(label: str) -> str:
    return f"{label}-{secrets.token_hex(10)}"


def settings_of(text: str, section: str) -> object:
    """The whole top-level `section` of a YAML file, so a nested list or block compares as one."""
    return yaml.safe_load(text).get(section)


def deployment_strays(text: str) -> set[str]:
    """The keys of model_list[] outside the allowlists; a per-model callback lives there."""
    strays: set[str] = set()
    for deployment in yaml.safe_load(text)["model_list"]:
        strays |= set(deployment) - DEPLOYMENT_KEYS
        strays |= set(deployment.get("litellm_params", {})) - DEPLOYMENT_PARAMS
    return strays


def front_user_agent() -> str:
    """The constant the front writes as every request's User-Agent, read from its route file."""
    middlewares = yaml.safe_load(ROUTE_FILE.read_text(encoding="utf-8"))["http"]["middlewares"]
    return middlewares["request-headers"]["headers"]["customRequestHeaders"]["User-Agent"]


def tool_body(tool: str, user: str, messages: list[dict], description: str = "probe") -> dict:
    function = {"name": tool, "description": description,
                "parameters": {"type": "object", "properties": {}}}  # fmt: skip
    return wire_body(
        user=user, messages=messages, tools=[{"type": "function", "function": function}]
    )


def sinks_outside_the_database(
    sinks: Sequence[str], database: str, mounts: Sequence[Mapping[str, str]]
) -> list[str]:
    """The sinks of a canary that are neither the database's dump nor one of its volumes: its log,
    its tmpfs, its binds and its other mounts count as outside. `mounts` are the resolved Compose
    entries of the database service."""
    volumes = [mount["target"] for mount in mounts if mount["type"] == "volume"]
    permitted = {f"{database} {volume}" for volume in volumes} | {f"{database} {DUMP}"}
    return [
        sink for sink in sinks
        if sink not in permitted and not sink.startswith(f"{database} {DUMP} ")
    ]  # fmt: skip


class RetentionProbe(FailureProbe, KeyFiles):
    """litellm.py's stack with the census run over the route's containers, at the log level
    compose.yaml ships, and hopin's key made by the key step."""

    LITELLM_LOG_LEVEL = None

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.census = Census(run_docker, secrets.token_bytes(16))
        self.clean: dict[str, str] = {}
        self.controls = self.write_controls(scratch)
        self.t1_tag = ""

    def write_controls(self, scratch: Path) -> Path:
        """The overlay of B3a and B3b alone: LiteLLM's debug log and the front's access log."""
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        shipped = mounted_file(resolved[FRONT], FRONT_STATIC).read_text(encoding="utf-8")
        static = scratch / "front-with-access-log.yml"
        static.write_text(shipped + "\naccessLog: {}\n", encoding="utf-8")
        static.chmod(0o644)
        overlay = scratch / "compose.controls.yaml"
        overlay.write_text(
            json.dumps({
                "services": {
                    LITELLM: {"environment": {"LITELLM_LOG": "DEBUG"}},
                    FRONT: {"volumes": [{
                        "type": "bind", "source": str(static), "target": FRONT_STATIC,
                        "read_only": True,
                    }]},
                },
            }),
            encoding="utf-8",
        )  # fmt: skip
        return overlay

    def write_litellm_config(self, config: dict) -> None:
        self.litellm_config.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        self.litellm_config.chmod(0o644)

    # --- the census ---------------------------------------------------------------------------

    def resolved_services(self) -> dict:
        return json.loads(self.compose("config", "--format", "json").stdout)["services"]

    def targets(self) -> list[Target]:
        resolved = self.resolved_services()
        return [route_target(s, self.container_name(s), resolved) for s in ROUTE_SERVICES]

    def sweep(self, tokens: Mapping[str, str]) -> Sweep:
        """C: the census over the route's containers for the canaries `tokens` (label -> value)."""
        result = self.census.sweep(self.targets(), tokens)
        expect(not result.problems, f"C: sinks not examined: {list(result.problems)}")
        return result

    def dump_tables(self, sinks: tuple[str, ...]) -> set[str]:
        """The tables of the database's dump among a canary's sinks; `` for a line outside one."""
        dump = f"{self.container_name(DATABASE)} {DUMP}"
        return {s.removeprefix(dump).strip() for s in sinks if s.startswith(dump)}

    def outside_the_database(self, sinks: tuple[str, ...]) -> list[str]:
        """The sinks of a canary that are neither the database's dump nor its volume."""
        mounts = self.resolved_services()[DATABASE]["volumes"]
        return sinks_outside_the_database(sinks, self.container_name(DATABASE), mounts)

    def landing(self, sinks: tuple[str, ...]) -> list[str]:
        """Where a canary sits, the database's container shown as its service."""
        return sorted(s.replace(self.container_name(DATABASE), DATABASE) for s in sinks)

    def expect_nothing_retained(self, cell: str, tokens: Mapping[str, str]) -> None:
        found = self.sweep(tokens).found
        expect(not found, f"{cell}: canaries retained: {found}{self.excerpts(tokens, found)}")
        self.clean.update({f"{cell} {label}": value for label, value in tokens.items()})

    def excerpts(self, tokens: Mapping[str, str], found: Mapping[str, tuple[str, ...]]) -> str:
        """The first 200 characters of each log line that holds a canary found in a log, the
        canary shown as its label: what a reviewer needs to see where the content was written."""
        shown = []
        for label, sinks in found.items():
            for sink in (s for s in sinks if s.endswith(" log")):
                log = self.run(["docker", "logs", sink.removesuffix(" log")], check=False)
                lines = (log.stdout + log.stderr).splitlines()
                shown += [
                    f"[{label}] {line.replace(tokens[label], '<canary>')[:200]}"
                    for line in lines if tokens[label] in line
                ]  # fmt: skip
        return "".join(f"\n  {line}" for line in shown)

    def failed_with(self, cell: str, request: str, model: str = DEFAULT_MODEL) -> int:
        """The status of a request holding the canary `request` that does not succeed."""
        asked = [{"role": "user", "content": request}]
        answer = self.complete(self.key, model, self.fingerprint(), messages=asked)
        expect(answer["status"] != 200, f"{cell}: the request was answered 200")
        return answer["status"]

    def request_canary_hits(self, since: int) -> int:
        return sum(request["request_canary_hits"] for request in self.provider_requests()[since:])

    # --- the caller with headers or a stream --------------------------------------------------

    def caller(self, program: str, key: str, body: dict, *, front: bool, headers=None):
        """The argv of one throwaway's request and its own standard input."""
        self.throwaways += 1
        name = f"{PROJECT}-caller-{self.throwaways}"
        argv, _ = self.call_command(name, key, "POST", ROUTE, body, front=front)
        return argv, caller_input(program, key, body, self.hidden_keys(), headers)

    def call_with_headers(self, key: str, body: dict, headers: dict, *, front: bool) -> dict:
        argv, program = self.caller(CALL_PROGRAM, key, body, front=front, headers=headers)
        return json.loads(self.run(argv, stdin=program, timeout=240).stdout.splitlines()[-1])

    # --- life cycle ---------------------------------------------------------------------------

    def recreate_route(self) -> None:
        """Every container of the route recreated, so that no tmpfs and no log of an earlier cell
        remains."""
        for service in (GATEWAY, LITELLM, FRONT):
            self.compose("up", "--detach", "--wait", "--force-recreate", "--no-deps", service)
        self.wait_until_listening()
        self.wait_for_front()

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        """K0, the controls, then a recreated route for the clean cells, in the order of the
        matrix."""
        self.wait_until_listening()
        self.cell_k0()
        self.steer()
        failed = []
        for step in (
            self.cell_b2, self.cells_b3, self.recreate_route, self.cell_b1, self.cell_t1,
            self.cell_b4, self.cell_b5, self.cell_b6, self.cell_b7, self.cell_b9, self.cell_d9,
            self.cell_str_c, self.cell_str, self.cell_t4, self.cells_t3, self.cell_b10,
            self.cell_b11,
        ):  # fmt: skip
            try:
                step()
            except ProbeFailed as problem:
                failed.append(step.__name__)
                write_line(f"{step.__name__} FAILED: {problem}", flush=True)
        expect(not failed, f"cells failed: {', '.join(failed)}")

    def cell_k0(self) -> None:
        plan = self.read_plan("K0")
        planned = {(change.subject, change.new) for change in plan.changes}
        expect(planned == {(self.budget_id, True), *((app, True) for app in APPS)}, f"K0: {plan}")
        self.run_step(plan)
        self.key = self.file_keys["hopin"]
        rows = self.admin("POST", "/v2/key/info", {"keys": [hashed(self.key)]})["info"]
        expect([row["key_alias"] for row in rows] == ["hopin"], "K0: hopin's key row")
        self.hold("K0", "the plan named the person budget and the three keys as new; after the "
                  "run one key has hopin's file hash and alias hopin")  # fmt: skip

    def cell_b2(self) -> None:
        tokens = {"file in litellm": canary("b2-litellm"), "file in front": canary("b2-front")}
        litellm, front = self.container_name(LITELLM), self.container_name(FRONT)
        self.run([
            "docker", "exec", litellm, "python", "-c",
            f"open('/tmp/planted', 'w').write({tokens['file in litellm']!r})",
        ])  # fmt: skip
        self.run([
            "docker", "exec", front, "sh", "-c",
            f"echo {tokens['file in front']} > /dev/shm/planted",
        ])  # fmt: skip
        found = self.sweep(tokens).found
        expect(set(found) == set(tokens), f"B2: found {found}")
        expect(f"{litellm} /tmp" in found["file in litellm"], f"B2: litellm {found}")
        expect(f"{front} /dev/shm" in found["file in front"], f"B2: front {found}")
        self.hold("B2", "a canary planted by exec in LiteLLM's /tmp and in the front's /dev/shm "
                  "is found, each by the search of its own kind of container")  # fmt: skip

    def cells_b3(self) -> None:
        self.overlays.append(self.controls)
        try:
            for service in (LITELLM, FRONT):
                self.compose("up", "--detach", "--wait", "--force-recreate", "--no-deps", service)
            self.wait_until_listening()
            self.wait_for_front()
            litellm_canary, front_canary = canary("b3a-request"), canary("b3b-path")
            asked = [{"role": "user", "content": litellm_canary}]
            status = self.complete(self.key, user=self.fingerprint(), messages=asked)["status"]
            expect(status == 200, f"B3a: the request got {status}")
            status = self.call(None, "GET", f"/{front_canary}")["status"]
            expect(status == 404, f"B3b: the front answered {status}")
            found = self.sweep({"request in LiteLLM debug log": litellm_canary,
                                "path in front access log": front_canary}).found  # fmt: skip
            expect(
                f"{self.container_name(LITELLM)} log"
                in found.get("request in LiteLLM debug log", ()),
                f"B3a: found {found}",
            )
            self.hold("B3a", "with LITELLM_LOG=DEBUG the request canary is found in LiteLLM's log")
            expect(
                f"{self.container_name(FRONT)} log" in found.get("path in front access log", ()),
                f"B3b: found {found}",
            )
            self.hold(
                "B3b", "with the access log on, a canary in the path is found in the front's log"
            )
        finally:
            self.overlays.remove(self.controls)

    def cell_b1(self) -> None:
        result = self.sweep({"probe": canary("b1")})
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        lines = []
        for service in ROUTE_SERVICES:
            inspected = json.loads(self.run(["docker", "inspect", self.container(service)]).stdout)[
                0
            ]
            wanted = self.declared_writable(resolved[service])
            seen = {mount["Destination"] for mount in inspected["Mounts"] if mount["RW"]} | set(
                inspected["HostConfig"].get("Tmpfs") or {}
            )
            expect(
                wanted == seen, f"B1: {service} declares {sorted(wanted)}, inspect {sorted(seen)}"
            )
            lines.append(f"{service}: {', '.join(result.inventory[self.container_name(service)])}")
        self.hold("B1", "; ".join(lines))

    @staticmethod
    def declared_writable(service: dict) -> set[str]:
        """The destinations the resolved Compose service declares writable: read-write binds and
        tmpfs."""
        binds = {
            volume["target"]
            for volume in service.get("volumes", [])
            if volume["type"] in {"bind", "volume"} and not volume.get("read_only")
        }
        tmpfs = {entry.split(":")[0] for entry in service.get("tmpfs", [])}
        return (
            binds
            | tmpfs
            | {
                volume["target"]
                for volume in service.get("volumes", [])
                if volume["type"] == "tmpfs"
            }
        )

    def cell_t1(self) -> None:
        """Around the front with presentator's key: both header canaries reach their tables."""
        tool, agent, tag = canary("t1-tool").replace("-", "_"), canary("t1-agent"), canary("t1-tag")
        self.t1_tag = tag
        body = tool_body(tool, self.fingerprint(), [{"role": "user", "content": "probe"}])
        headers = {"User-Agent": agent, "x-litellm-tags": tag}
        presentator = self.file_keys["presentator"]
        status = self.call_with_headers(presentator, body, headers, front=False)["status"]
        expect(status == 200, f"T1: LiteLLM answered {status}")
        self.wait_for_tool(tool)
        self.wait_for_row(DAILY_TAG_TABLE, "tag", tag)
        found = self.sweep({USER_AGENT: agent, "tag": tag}).found
        agent_tables = self.dump_tables(found.get(USER_AGENT, ()))
        expect(TOOL_TABLE in agent_tables, f"T1: the user agent is in {sorted(agent_tables)}")
        expect(DAILY_TAG_TABLE not in agent_tables, "T1: a tag row holds the user agent")
        tag_tables = self.dump_tables(found.get("tag", ()))
        expect(DAILY_TAG_TABLE in tag_tables, f"T1: the tag is in {sorted(tag_tables)}")
        self.hold("T1", f"around the front, the user agent in {TOOL_TABLE} and no tag row, the "
                  f"tag header in {DAILY_TAG_TABLE}")  # fmt: skip

    def cell_b4(self) -> None:
        request, answer = canary("b4-request"), canary("b4-answer")
        tokens = {"request": request, "answer": answer}
        self.steer(mode="hold", hold_seconds=HOLD_SECONDS, marker=answer, request_canary=request)
        before, already = len(self.provider_requests()), len(self.hold_ends())
        asked = [{"role": "user", "content": request}]
        body = wire_body(user=self.fingerprint(), messages=asked)
        argv, program = self.call_command(
            f"{PROJECT}-b4-caller", self.key, "POST", ROUTE, body, front=True
        )
        process = subprocess.Popen(  # noqa: S603 - argv is built by the program itself
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=self.environment, cwd=REPO,
        )  # fmt: skip
        process.stdin.write(program)
        process.stdin.close()
        deadline = time.monotonic() + SCAN_DEADLINE_SECONDS
        while len(self.provider_requests()) == before:
            expect(time.monotonic() < deadline, "B4: the run never reached the provider")
            time.sleep(1)
        during = self.sweep(tokens).found
        expect(len(self.hold_ends()) == already, "B4: the hold ended before the scan did")
        out, _ = process.communicate(timeout=HOLD_SECONDS + SCAN_DEADLINE_SECONDS)
        reply = json.loads(out.strip().splitlines()[-1])
        expect(answer_text(reply) == answer, f"B4: {reply['status']}, the answer canary missing")
        expect(self.request_canary_hits(before) >= 1, "B4: the request canary never reached F")
        self.steer()
        after = self.sweep(tokens).found
        expect(not during and not after, f"B4: retained during {during}, after {after}")
        self.clean.update({f"B4 {label}": value for label, value in tokens.items()})
        self.hold("B4", "both canaries in no file and no log while F held the request and after; "
                  "the answer canary reached the client and the request canary F")  # fmt: skip

    def cell_b5(self) -> None:
        request = canary("b5-request")
        self.steer(mode="status", status=500, request_canary=request)
        before = len(self.provider_requests())
        status = self.failed_with("B5", request)
        expect(self.request_canary_hits(before) == 1, "B5: the request canary never reached F")
        self.expect_nothing_retained("B5", {"request": request})
        self.hold("B5", f"upstream 500: the caller got {status}, the canary reached F, retained "
                  "nowhere")  # fmt: skip

    def cell_b6(self) -> None:
        request = canary("b6-request")
        self.steer(mode="echo", status=UPSTREAM_ERROR, request_canary=request)
        before = len(self.provider_requests())
        status = self.failed_with("B6", request)
        expect(self.request_canary_hits(before) == 1, "B6: the request canary never reached F")
        self.expect_nothing_retained("B6", {"request": request})
        self.hold("B6", f"an upstream {UPSTREAM_ERROR} whose body echoes the request canary: "
                  f"the caller got {status}, retained nowhere")  # fmt: skip

    def cell_b7(self) -> None:
        request = canary("b7-request")
        self.steer(request_canary=request)
        before = len(self.provider_requests())
        self.failed_with("B7", request, "text/nonesuch")
        expect(len(self.provider_requests()) == before, "B7: the provider was reached")
        self.expect_nothing_retained("B7", {"request": request})
        self.hold("B7", "a model LiteLLM lacks: refused, F 0, the canary retained nowhere")

    def cell_b9(self) -> None:
        body = canary("b9-body")
        before = len(self.provider_requests())
        status = self.complete(self.key, user=self.fingerprint(), api_base=body)["status"]
        expect(400 <= status < 500, f"B9: LiteLLM answered {status}")
        expect(len(self.provider_requests()) == before, "B9: the provider was reached")
        self.expect_nothing_retained("B9", {"body": body})
        self.hold("B9", f"LiteLLM's guard refuses ({status}) `api_base` holding the canary: F 0, "
                  "retained nowhere")  # fmt: skip

    def cell_d9(self) -> None:
        """D9 with T2: no canary of a request, an answer or a header through the front at rest,
        the dump searched with a planted row as its control; a request and a response tool name
        in the tool table alone, with the front's user agent. P7 judges the same sweep."""
        canaries = {
            label: canary(f"d9-{label}")
            for label in ("message", "description", "arguments", "result", "answer", "call",
                          USER_AGENT, "tag")
        }  # fmt: skip
        tool = canary("d9-tool").replace("-", "_")
        answered = canary("d9-answered").replace("-", "_")
        self.steer(
            marker=canaries["answer"],
            tool_use={"name": answered, "input": {"q": canaries["call"]}},
        )
        arguments = json.dumps({"q": canaries["arguments"]})
        call = {"id": "call_d9", "type": "function",
                "function": {"name": tool, "arguments": arguments}}  # fmt: skip
        person = self.fingerprint()
        body = tool_body(tool, person, [
            {"role": "user", "content": canaries["message"]},
            {"role": "assistant", "content": None, "tool_calls": [call]},
            {"role": "tool", "tool_call_id": "call_d9", "content": canaries["result"]},
        ], description=canaries["description"])  # fmt: skip
        headers = {"User-Agent": canaries[USER_AGENT], "x-litellm-tags": canaries["tag"]}
        status = self.call_with_headers(self.key, body, headers, front=True)["status"]
        expect(status == 200, f"D9: the route answered {status}")
        self.steer()
        for name in (tool, answered):
            self.wait_for_tool(name)
        self.wait_for_row("LiteLLM_DailyEndUserSpend", "end_user_id", person)
        found = self.planted_sweep({
            **canaries, "request tool": tool, "response tool": answered, "fingerprint": person,
            "hopin's hash": hashed(self.key),
            **{f"app key {index}": key for index, key in enumerate(self.app_keys)},
        })  # fmt: skip
        held = sorted(set(canaries) & set(found))
        expect(not held, f"D9: canaries retained: {held}: {[found[label] for label in held]}")
        for kind in ("request tool", "response tool"):
            sinks = found.get(kind, ())
            tables, outside = self.dump_tables(sinks), self.outside_the_database(sinks)
            expect(tables == {TOOL_TABLE}, f"D9: the {kind} name is in {sorted(tables)}")
            expect(not outside, f"D9: the {kind} name is in {outside}")
        agents = self.tool_user_agents(tool, answered)
        expect(agents == {front_user_agent()}, f"D9: the tool rows' user agents {agents}")
        raw = [label for label in found if label.startswith("app key")]
        hash_tables = self.dump_tables(found.get("hopin's hash", ()))
        expect(not raw and hash_tables, f"D9: raw app keys {raw}, hash in {hash_tables}")
        self.clean.update({f"D9 {label}": value for label, value in canaries.items()})
        self.hold("D9", f"none of {len(canaries)} canaries in any sink, the dump included; the "
                  f"planted row found; the tool names in {TOOL_TABLE} alone with the front's user "
                  "agent; of the app keys only hashes")  # fmt: skip
        self.hold("T2", "the User-Agent and x-litellm-tags canaries through the front at rest "
                  "nowhere")  # fmt: skip
        self.cell_p7(found.get("fingerprint", ()))

    def planted_sweep(self, tokens: Mapping[str, str]) -> dict[str, tuple[str, ...]]:
        """C over `tokens`, with a row planted in the database as the dump's control."""
        planted = canary("d9-planted")
        self.sql(
            f"CREATE TABLE d9_control (value text); INSERT INTO d9_control VALUES ('{planted}')"  # noqa: S608 - the value is a token this probe generated
        )
        try:
            found = self.sweep({**tokens, "planted": planted}).found
        finally:
            self.sql("DROP TABLE d9_control")
        expect(
            "d9_control" in self.dump_tables(found.get("planted", ())), "the planted row missing"
        )
        return {label: sinks for label, sinks in found.items() if label != "planted"}

    def tool_user_agents(self, *tools: str) -> set[str]:
        names = ", ".join(f"'{tool}'" for tool in tools)
        query = f'SELECT DISTINCT user_agent FROM "{TOOL_TABLE}" WHERE tool_name IN ({names})'  # noqa: S608 - the names are tokens this probe generated
        return set(self.sql(query, "--tuples-only", "--no-align").stdout.split())

    def cell_p7(self, sinks: tuple[str, ...]) -> None:
        """The sweep D9 found its planted row in: the fingerprint in the end-user tables alone."""
        tables, outside = self.dump_tables(sinks), self.outside_the_database(sinks)
        expect(tables == FINGERPRINT_TABLES, f"P7: the fingerprint is in {sorted(tables)}")
        expect(not outside, f"P7: the fingerprint is in {outside}")
        self.hold("P7", f"the fingerprint only in {sorted(tables)}; the planted row found")

    def cell_str_c(self) -> None:
        self.held_stream("STR-c", front=False)
        self.hold("STR-c", "around the front, the first delta reached the caller while F held the "
                  "rest; released, the stream ended with the second")  # fmt: skip

    def cell_str(self) -> None:
        tokens, person = self.held_stream("STR", front=True)
        self.wait_for_row("LiteLLM_DailyEndUserSpend", "end_user_id", person)
        self.expect_nothing_retained("STR", tokens)
        self.hold("STR", "through the front, the first delta reached the caller while F held the "
                  "rest; released, the stream ended; the canaries retained nowhere")  # fmt: skip

    def held_stream(self, cell: str, *, front: bool) -> tuple[dict[str, str], str]:
        """One streamed request the fake holds after its first delta, released only once the
        caller printed that delta while the fake has logged no end of the hold."""
        tokens = {
            label: canary(f"{cell.lower()}-{label}") for label in ("request", "first", "rest")
        }
        texts = [tokens["first"], tokens["rest"]]
        self.steer(mode="stream_hold", hold_seconds=STREAM_HOLD_SECONDS, texts=texts,
                   request_canary=tokens["request"])  # fmt: skip
        person, before, held = self.fingerprint(), len(self.provider_requests()), self.held_lines()
        body = wire_body(user=person, messages=[{"role": "user", "content": tokens["request"]}])
        argv, program = self.caller(STREAM_PROGRAM, self.key, body, front=front)
        process = subprocess.Popen(  # noqa: S603 - argv is built by the program itself
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, env=self.environment, cwd=REPO,
        )  # fmt: skip
        try:
            process.stdin.write(program)
            process.stdin.close()
            texts = self.read_held_stream(cell, process, tokens["first"], held)
        finally:
            process.kill()
            process.wait()
        expect(self.held_lines()[len(held) :] == ["held released"], f"{cell}: the hold's end")
        expect(tokens["rest"] in "".join(texts), f"{cell}: the stream ended without the rest")
        expect(self.request_canary_hits(before) == 1, f"{cell}: F saw the request canary")
        self.steer()
        return tokens, person

    def read_held_stream(self, cell: str, process, first: str, held: list[str]) -> list[str]:
        """The caller's delta texts; on the first canary the fake must still hold, then it is
        released."""
        status = json.loads(process.stdout.readline() or "{}").get("status")
        expect(status == 200, f"{cell}: the stream's status {status}")
        texts: list[str] = []
        for line in process.stdout:
            texts.append(json.loads(line).get("text") or "")
            if first in texts[-1]:
                expect(self.held_lines() == held, f"{cell}: the first event came after the hold")
                self.steer(mode="answer")
        return texts

    def held_lines(self) -> list[str]:
        return [
            line for line in self.log_of(FAKE_PROVIDER).splitlines() if line.startswith("held ")
        ]

    def cell_t4(self) -> None:
        """Q after the conforming flows: no tag row of hopin's key, the tag table empty."""
        self.tag_barrier("T4")
        hopin = self.count(self.tag_rows_of(self.key))
        tags = self.count(f'SELECT count(*) FROM "{TAG_TABLE}"')  # noqa: S608 - the table name is this probe's literal
        control = self.count(
            f"{self.tag_rows_of(self.file_keys['presentator'])} AND tag = '{self.t1_tag}'"
        )
        expect(tags == 0 and hopin == 0, f"T4: {tags} tag table rows, {hopin} of hopin's key")
        expect(control >= 1, "T4: the control finds no tag row of T1")
        self.hold("T4", f"{TAG_TABLE} empty and no {DAILY_TAG_TABLE} row of hopin's key; "
                  f"{control} of presentator's from T1")  # fmt: skip

    @staticmethod
    def tag_rows_of(key: str) -> str:
        return f"SELECT count(*) FROM \"{DAILY_TAG_TABLE}\" WHERE api_key = '{hashed(key)}'"  # noqa: S608 - the hash of a key this probe generated

    def count(self, query: str) -> int:
        return int(self.sql(query, "--tuples-only", "--no-align").stdout.strip())

    def cells_t3(self) -> None:
        """Each body tag form on its own non-conforming request through the front."""
        tags = {form: canary("t3-tag") for form in TAG_FORMS}
        recorded = {form: self.tagged_request(form, tag) for form, tag in tags.items()}
        self.tag_barrier("T3")
        rows = self.tag_rows(list(tags.values()))
        found = self.sweep(tags).found
        expect(self.tag_rows(list(tags.values())) == rows, "T3: a tag row came after the dump")
        failed = []
        for form, tag in tags.items():
            sinks = found.get(form, ())
            tables, outside = self.dump_tables(sinks), self.outside_the_database(sinks)
            figures = f"{recorded[form]}, in {self.landing(sinks) or 'no sink'}"
            figures += f", tag row id {self.request_id_form(tag)}"
            if not tables <= {TAG_TABLE, DAILY_TAG_TABLE} or outside:
                failed.append(form)
                write_line(f"{form} FAILED: {figures}, outside the database {outside}", flush=True)
            else:
                self.hold(form, figures if sinks else f"{figures}: lands nowhere")
        expect(not failed, f"T3: {failed}")

    def tag_rows(self, tags: list[str]) -> int:
        named = ", ".join(f"'{tag}'" for tag in tags)
        return self.count(f'SELECT count(*) FROM "{DAILY_TAG_TABLE}" WHERE tag IN ({named})')  # noqa: S608 - the tags are tokens this probe generated

    def tag_barrier(self, cell: str) -> None:
        """LiteLLM writes tag rows in a job of its own that flushes its whole queue. A request
        straight to LiteLLM under presentator's key carries a fresh tag: once that tag's row is
        written, every tag row queued before it is too."""
        tag = canary("barrier-tag")
        body = wire_body(user=self.fingerprint(), messages=[{"role": "user", "content": "probe"}])
        headers = {"x-litellm-tags": tag}
        presentator = self.file_keys["presentator"]
        status = self.call_with_headers(presentator, body, headers, front=False)["status"]
        expect(status == 200, f"{cell}: the barrier request was answered {status}")
        waited = self.wait_for(
            cell, "the barrier's tag row", lambda: self.tag_rows([tag]) >= 1, TAG_BARRIER_SECONDS
        )
        write_line(f"{cell} barrier: the tag row came after {waited:.0f} s", flush=True)

    def tagged_request(self, form: str, tag: str) -> str:
        """A, whether the tag reached F, and the batch of the form's fingerprint written."""
        self.steer(request_canary=tag)
        person, before = self.fingerprint(), len(self.provider_requests())
        status = self.complete(self.key, user=person, **TAG_FORMS[form](tag))["status"]
        reached = self.request_canary_hits(before)
        if status == 200:
            self.wait_for_row("LiteLLM_DailyEndUserSpend", "end_user_id", person)
        self.steer()
        return f"A {status}, F {reached}"

    def request_id_form(self, tag: str) -> str:
        query = f"SELECT request_id FROM \"{DAILY_TAG_TABLE}\" WHERE tag = '{tag}'"  # noqa: S608 - a tag this probe generated
        ids = self.sql(query, "--tuples-only", "--no-align").stdout.split()
        if not ids:
            return "none"
        return "the fake's msg_probe" if "msg_probe" in ids else "LiteLLM's"

    def wait_for_tool(self, tool: str) -> None:
        self.wait_for_row(TOOL_TABLE, "tool_name", tool)

    def wait_for_row(self, table: str, column: str, value: str) -> None:
        """LiteLLM writes tool names, tags and daily spends with its batched database updates, not
        with the request."""
        query = f"SELECT count(*) FROM \"{table}\" WHERE {column} = '{value}'"  # noqa: S608 - the value is a token this probe generated
        deadline = time.monotonic() + TOOL_WRITE_SECONDS
        while self.count(query) < 1:
            expect(time.monotonic() < deadline, f"{value} is not in {table}")
            time.sleep(3)

    def cell_b10(self) -> None:
        """Every sink of the route over B4 to B9, D9 and STR."""
        found = self.sweep(self.clean).found
        expect(not found, f"B10: retained in {found}")
        self.hold("B10", f"the mounts, logs and dump of {', '.join(ROUTE_SERVICES)} hold none of "
                  f"{len(self.clean)} canaries of B4 to B7, B9, D9 and STR")  # fmt: skip

    def cell_b11(self) -> None:
        litellm, front = self.container_name(LITELLM), self.container_name(FRONT)
        config = self.run(["docker", "exec", litellm, "cat", "/etc/litellm/config.yaml"]).stdout
        for section, wanted in SETTINGS_SECTIONS.items():
            found = settings_of(config, section)
            expect(found == wanted, f"B11: {section} holds {found}, not {wanted}")
        top = set(yaml.safe_load(config))
        expect(top == {"model_list", *SETTINGS_SECTIONS}, f"B11: LiteLLM's sections {sorted(top)}")
        strays = deployment_strays(config)
        expect(not strays, f"B11: model_list[] holds the keys {sorted(strays)}")
        names = self.run(["docker", "exec", litellm, "env"]).stdout
        stores = sorted({n.split("=")[0] for n in names.splitlines() if STORE_NAMES.search(n)})
        expect(not stores, f"B11: LiteLLM's environment names {stores}")
        level = [n for n in names.splitlines() if n.startswith("LITELLM_LOG=")]
        expect(level == ["LITELLM_LOG=CRITICAL"], f"B11: LiteLLM's log level {level}")
        static = self.run(["docker", "exec", front, "cat", FRONT_STATIC]).stdout
        expect("accessLog" not in static and "level: INFO" in static, "B11: the front's log")
        self.hold("B11", "LiteLLM: message logging off, redaction on, no custom_auth, "
                  "enforce_user_param on, one person budget id, no user-agent tag, retries 0, "
                  "no callback, cache or spend and error log, no such environment name, "
                  "log level CRITICAL; the front: INFO and no access log")  # fmt: skip


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], RetentionProbe)


if __name__ == "__main__":
    sys.exit(main())
