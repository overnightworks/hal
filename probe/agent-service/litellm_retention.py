"""Probe of the API route's retention (#814 S1c cells B1-B7, B9-B11, D9, and P7): the stack of
litellm.py (the service, the one-route front, LiteLLM and the gateway's second entrypoint, against a
fake Anthropic) and its caller with an app key, with a unique canary in each request and answer,
searched afterwards in every writable mount and every log of the front, the gateway, LiteLLM and
the service by `agent-service/retention_census.py`.
Nothing live and nothing paid: the probe refuses to start unless `internet` is internal and holds
only the fakes.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_retention.py --scratch DIR

Measured: a run takes about three minutes and its
teardown a few seconds (K 30 s, CAP 1800 s).

Evidence: F is the fake provider's request log, A the caller's status, C the census's verdict
(canaries found per sink, and every sink it could not examine). B2, B3a and B3b are the controls:
each plants a canary where the search must find it (a file by exec into a tmpfs, a LiteLLM debug
log, the front's access log), and they run first on a stack the probe then recreates, so no clean
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
from collections.abc import Mapping
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "agent-service"))

from litellm import (  # noqa: E402
    DATABASE,
    DEFAULT_MODEL,
    FRONT,
    FRONT_STATIC,
    GATEWAY,
    LISTENING,
    LITELLM,
    PROJECT,
    ROUTE,
    SERVICE,
    ProbeFailed,
    answer_text,
    expect,
    hashed,
    mounted_file,
    person_budget,
    run_scratch_probe,
    wire_body,
)
from litellm_failures import FailureProbe  # noqa: E402
from retention_census import ROUTE_SERVICES, Census, Sweep, Target, run_docker  # noqa: E402

from hal.output import write_line  # noqa: E402

HOLD_SECONDS = 45  # B4's hold: over a scan of the route
SCAN_DEADLINE_SECONDS = 60
UPSTREAM_ERROR = 400


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
# The one table of LiteLLM's database that may name a tool (D9), and those that may name a
# fingerprint (P7).
TOOL_TABLE = "LiteLLM_ToolTable"
FINGERPRINT_TABLES = {"LiteLLM_EndUserTable", "LiteLLM_DailyEndUserSpend"}
TOOL_WRITE_SECONDS = 120
COPY_HEADER = re.compile(r'^COPY public\."?(\w+)"? ')
STORE_NAMES = re.compile(
    r"DATABASE|REDIS|CALLBACK|LANGFUSE|VERBOSE|SPEND|S3_|LITELLM_PRINT_STANDARD_LOGGING_PAYLOAD",
    re.I,
)


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


class RetentionProbe(FailureProbe):
    """litellm.py's stack with the census run over the route's containers, at the log level
    compose.yaml ships."""

    LITELLM_LOG_LEVEL = None

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.census = Census(run_docker, secrets.token_bytes(16))
        self.clean: dict[str, str] = {}
        self.controls = self.write_controls(scratch)

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

    def targets(self) -> list[Target]:
        return [
            Target(self.container_name(service), has_python)
            for service, has_python in ROUTE_SERVICES.items()
        ]

    def sweep(self, tokens: Mapping[str, str]) -> Sweep:
        """C: the census over the route's containers for the canaries `tokens` (label -> value)."""
        result = self.census.sweep(self.targets(), tokens)
        expect(not result.problems, f"C: sinks not examined: {list(result.problems)}")
        return result

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

    # --- life cycle ---------------------------------------------------------------------------

    def recreate_route(self) -> None:
        """Every container of the route recreated, so that no tmpfs and no log of an earlier cell
        remains."""
        for service in (GATEWAY, LITELLM, FRONT, SERVICE):
            self.compose("up", "--detach", "--wait", "--force-recreate", "--no-deps", service)
        self.wait_until_listening()
        self.wait_until(SERVICE, LISTENING)
        self.wait_until_the_gateway_answers()
        self.wait_for_front()

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        """The controls first, then a recreated route for the clean cells, in the order of the
        matrix."""
        self.wait_until(SERVICE, LISTENING)
        self.wait_until_listening()
        self.admin("POST", "/budget/new", person_budget())
        self.key = self.make_key()
        self.steer()
        failed = []
        for step in (
            self.cell_b2, self.cells_b3, self.recreate_route, self.cell_b1, self.cell_b4,
            self.cell_b5, self.cell_b6, self.cell_b7, self.cell_b9, self.cell_d9, self.cell_b10,
            self.cell_b11,
        ):  # fmt: skip
            try:
                step()
            except ProbeFailed as problem:
                failed.append(step.__name__)
                write_line(f"{step.__name__} FAILED: {problem}", flush=True)
        expect(not failed, f"cells failed: {', '.join(failed)}")

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
        for service in (FRONT, GATEWAY, LITELLM, SERVICE, DATABASE):
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
        """D9: no canary of a request or an answer in a `pg_dump`, with a planted row as the
        search's control; a request and a response tool name appear in the tool table alone. P7:
        the request's fingerprint only in the end-user tables, no identity string anywhere."""
        canaries = {
            label: canary(f"d9-{label}")
            for label in ("message", "description", "arguments", "result", "answer", "call")
        }
        tool = canary("d9-tool").replace("-", "_")
        answered = canary("d9-answered").replace("-", "_")
        planted = canary("d9-planted")
        self.steer(
            marker=canaries["answer"],
            tool_use={"name": answered, "input": {"q": canaries["call"]}},
        )
        function = {"name": tool, "description": canaries["description"],
                    "parameters": {"type": "object", "properties": {}}}  # fmt: skip
        arguments = json.dumps({"q": canaries["arguments"]})
        call = {"id": "call_d9", "type": "function",
                "function": {"name": tool, "arguments": arguments}}  # fmt: skip
        person = self.fingerprint()
        body = {
            "model": DEFAULT_MODEL,
            "user": person,
            "messages": [
                {"role": "user", "content": canaries["message"]},
                {"role": "assistant", "content": None, "tool_calls": [call]},
                {"role": "tool", "tool_call_id": "call_d9", "content": canaries["result"]},
            ],
            "tools": [{"type": "function", "function": function}],
        }  # fmt: skip
        status = self.call(self.key, "POST", ROUTE, body)["status"]
        expect(status == 200, f"D9: the route answered {status}")
        self.steer()
        for name in (tool, answered):
            self.wait_for_tool(name)
        self.wait_for_row("LiteLLM_DailyEndUserSpend", "end_user_id", person)
        self.sql(
            f"CREATE TABLE d9_control (value text); INSERT INTO d9_control VALUES ('{planted}')"  # noqa: S608 - the value is a token this probe generated
        )
        try:
            dump = self.dump()
        finally:
            self.sql("DROP TABLE d9_control")
        expect(planted in dump, "D9: the planted row is not in the dump")
        held = [label for label, value in canaries.items() if value in dump]
        expect(not held, f"D9: the dump holds the canaries of {held}")
        self.expect_key_hashes_alone(dump)
        for kind, name in (("request", tool), ("response", answered)):
            tables = self.tables_naming(dump, name)
            expect(tables == {TOOL_TABLE}, f"D9: the {kind} tool name is in {sorted(tables)}")
        self.expect_nothing_retained("D9", canaries)
        self.hold(
            "D9",
            f"the dump of {len(dump)} characters holds none of {len(canaries)} canaries and the"
            f" planted row; of {len(self.app_keys)} app keys only hashes; the request and the"
            f" response tool name are in {TOOL_TABLE} alone",
        )
        self.cell_p7(dump, person)

    def expect_key_hashes_alone(self, dump: str) -> None:
        """No app key in the dump, and the probe's key there as its hash: the control."""
        raw = sum(key in dump for key in self.app_keys)
        expect(raw == 0 and hashed(self.key) in dump, f"D9: {raw} raw app keys in the dump")

    def cell_p7(self, dump: str, person: str) -> None:
        """The dump D9 found its planted row in: the fingerprint in the end-user tables alone, no
        identity string anywhere."""
        tables = self.tables_naming(dump, person)
        expect(tables == FINGERPRINT_TABLES, f"P7: the fingerprint is in {sorted(tables)}")
        named = [label for label, value in self.identity.items() if value in dump]
        expect(not named, f"P7: the dump holds the scratch {named}")
        self.hold("P7", f"the fingerprint only in {sorted(tables)}; sub, name and mail nowhere; "
                  "the planted row found")  # fmt: skip

    def wait_for_tool(self, tool: str) -> None:
        self.wait_for_row(TOOL_TABLE, "tool_name", tool)

    def wait_for_row(self, table: str, column: str, value: str) -> None:
        """LiteLLM writes tool names and daily spends with its batched database updates, not with
        the request."""
        query = f"SELECT count(*) FROM \"{table}\" WHERE {column} = '{value}'"  # noqa: S608 - the value is a token this probe generated
        deadline = time.monotonic() + TOOL_WRITE_SECONDS
        while True:
            counted = self.sql(query, "--tuples-only", "--no-align").stdout.strip()
            if counted == "1":
                return
            expect(time.monotonic() < deadline, f"D9: {value} is not in {table}")
            time.sleep(3)

    def dump(self) -> str:
        return self.run(["docker", "exec", self.container(DATABASE), "pg_dump",
                         *self.database_options()]).stdout  # fmt: skip

    @staticmethod
    def tables_naming(dump: str, name: str) -> set[str]:
        """The tables of a plain-format dump whose rows hold `name`."""
        tables, current = set(), None
        for line in dump.splitlines():
            if header := COPY_HEADER.match(line):
                current = header[1]
            elif line == r"\.":
                current = None
            elif current and name in line:
                tables.add(current)
        return tables

    def cell_b10(self) -> None:
        """Every sink of the route over B4 to B9."""
        found = self.sweep(self.clean).found
        expect(not found, f"B10: retained in {found}")
        self.hold("B10", f"the mounts and logs of {', '.join(ROUTE_SERVICES)} hold none of "
                  f"{len(self.clean)} canaries of B4 to B7 and B9")  # fmt: skip

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
                  "enforce_user_param on, one person budget id, retries 0, "
                  "no callback, cache or spend and error log, no such environment name, "
                  "log level CRITICAL; the front: INFO and no access log")  # fmt: skip


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], RetentionProbe)


if __name__ == "__main__":
    sys.exit(main())
