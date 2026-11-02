#!/usr/bin/env python3
"""The live smoke of the agent service in one command (docs/agent-service.md, "Proofs").

    cd ~/srv/hal && python3 agent-service/live_smoke.py

You sign in as yourself (the `songmaker` client's device grant, `device_sign_in.py`): open the
printed link, sign in and confirm the code; the run then carries on by itself, nothing is pasted.
The person's and the workload's token live in this process only and reach `agent-smoke`
on its stdin; no token or secret is on a command line, in a file or in the report.
The run recreates the service, takes the idle
memory, runs the paid turn (L2; L3: `run_started` names a model of `service.toml` on the
subscription route), the memory peak (L7), the cancelled turn (L4, counts only), the searches for
a leaked secret (L6) and for a JWT-shaped string (L9), in the same places,
and the egress cells of the running container (L5: E6-E10, E12).
Exit 1 when a cell prints FAILED; L4 is an observation and never fails the run.
L7's figures are the idle `memory.current` of the recreated service and its `memory.peak`
right after the one turn (an upper bound of the answer phase, it includes the start).
A refusal `unauthorized` means expired tokens, `forbidden` a missing `/apps/songmaker` or tokens
that do not bind one app to one person, `not_enabled` no subscription group; the report names them.
`agent-smoke` is the service image running `smoke.py` on songmaker's agent network alone (profile
`apply`).

The compose project and the egress gateway's address are read from `docker compose config` of the
repository this file sits in. The in-container smoke is `smoke.py`, used as it is, and the egress
observations are `egress_observe.py`, shared with the probe. Only the standard library is used.
`live_signer.py` is the second command: it proves what the service signs for one tool (L4a, L4b).
"""

from __future__ import annotations

import argparse
import inspect
import ipaddress
import json
import re
import socket
import subprocess
import sys
import threading
import time
import tomllib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from typing import Final

import egress_observe
from device_sign_in import CLIENT, SignInFailed, sign_in
from egress_observe import PUBLIC_RESOLVER, UNREACHABLE, lan_address
from retention_census import AGENT_SERVICE as SERVICE
from retention_census import GATEWAY as EGRESS_SERVICE
from smoke import EVENT_PREFIX, HOLDING_MESSAGE, SERVED_AFTER_RUN_STARTED, SERVED_BY, Tokens

SECRETS_DIRECTORY = Path.home() / ".secrets"
CLIENT_SECRET_FILE = SECRETS_DIRECTORY / "keycloak/clients" / CLIENT
LOGIN_TOKEN_FILE = SECRETS_DIRECTORY / "agent-service/claude/token"
REPOSITORY = Path(__file__).resolve().parents[1]
SERVICE_TOML = REPOSITORY / "agent-service/service.toml"
LIVE_COMPOSE = (
    "docker", "compose", "--project-directory", str(REPOSITORY),
    "--file", str(REPOSITORY / "compose.yaml"), "--profile", "agent-service",
)  # fmt: skip
GATEWAY_ADDRESS_KEY = "x-egress-address"
# compose.yaml's anchors of the gateway's entrypoint addresses, one per network it serves.
ENTRYPOINT_ADDRESS_KEYS = (GATEWAY_ADDRESS_KEY, "x-litellm-egress-address")
SMOKE_SERVICE = "agent-smoke"
LISTENING = "Uvicorn running"
LISTEN_ATTEMPTS = 120
SETTLE_SECONDS = 5
PAID_TURN_SECONDS = 420  # above the 300 s of each socket of smoke.py
CANCELLED_TURN_SECONDS = 420
CHILD_END_SECONDS = 10
RECREATE_REASON_CHARACTERS = 200
SAMPLE_FAILED = "SAMPLE FAILED"
TIMED_OUT = 124
EMBEDDED_RESOLVER = "127.0.0.11"
PROVIDER_HOST = "api.anthropic.com"
CLI_PROCESS_COUNT = (
    'file=$(mktemp) && cat /proc/[0-9]*/cmdline > "$file" && tr "\\0" "\\n" < "$file" '
    '| grep -c "[c]laude"; status=$?; rm -f "$file"; test "$status" -le 1'
)
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class LiveSmokeFailed(Exception):
    """The run cannot go on; the message is the one line to print, free of any secret."""


class Verdict(StrEnum):
    HELD = "held"
    FAILED = "FAILED"
    OBSERVED = "observed"


@dataclass(frozen=True)
class Cell:
    name: str
    verdict: Verdict
    figure: str

    def line(self) -> str:
        return f"{self.name} {self.verdict}: {self.figure}"


def redacted(text: str, values: Sequence[str]) -> str:
    """`text` with every value removed, the longest first so that none leaves a part behind."""
    for value in sorted(values, key=len, reverse=True):
        text = text.replace(value, "[secret]")
    return text


@dataclass(frozen=True)
class Secrets:
    """Everything that must appear nowhere: the two tokens, the login token, the client secret."""

    tokens: Tokens
    login_token: str
    client_secret: str

    def values(self) -> list[str]:
        everything = (
            self.tokens.person, self.tokens.workload, self.login_token, self.client_secret
        )  # fmt: skip
        return [value for value in everything if value]

    def redact(self, text: str) -> str:
        return redacted(text, self.values())


@dataclass(frozen=True)
class Stack:
    """One compose project and how docker is asked for it.

    `compose_prefix` is everything before the compose subcommand: the repository's own files for
    the live stack, the probe's project and files for the probe. The project's name and the egress
    gateway's address are read from the configuration compose resolves for that prefix."""

    compose_prefix: tuple[str, ...] = LIVE_COMPOSE
    environment: Mapping[str, str] | None = None
    directory: Path | None = None

    def run(
        self, command: Sequence[str], stdin: str | None = None, timeout: int = 300
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command, input=stdin, capture_output=True, text=True, check=False, timeout=timeout,
            env=self.environment, cwd=self.directory,
        )  # fmt: skip

    def compose(
        self, *arguments: str, stdin: str | None = None, timeout: int = 300
    ) -> subprocess.CompletedProcess[str]:
        return self.run([*self.compose_prefix, *arguments], stdin, timeout)

    def start(self, command: Sequence[str]) -> subprocess.Popen[str]:
        return subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, env=self.environment, cwd=self.directory,
        )  # fmt: skip

    def start_compose(self, *arguments: str) -> subprocess.Popen[str]:
        return self.start([*self.compose_prefix, *arguments])

    @cached_property
    def configuration(self) -> dict:
        answer = self.compose("config", "--format", "json")
        try:
            configuration = json.loads(answer.stdout) if answer.returncode == 0 else None
        except ValueError:
            configuration = None
        if not isinstance(configuration, dict):
            raise LiveSmokeFailed(f"docker compose config failed: {last_line(answer.stderr)}")
        return configuration

    @property
    def project(self) -> str:
        return self.configuration["name"]

    @property
    def gateway(self) -> str:
        return self.configuration[GATEWAY_ADDRESS_KEY]

    @property
    def entrypoint_addresses(self) -> list[str]:
        return [self.configuration[key] for key in ENTRYPOINT_ADDRESS_KEYS]


@dataclass
class Report:
    """Prints each cell at once, with every known secret removed from the line."""

    secret_values: list[str]
    cells: list[Cell] = field(default_factory=list)
    out: Callable[[str], None] = print

    def add(self, *cells: Cell) -> None:
        for cell in cells:
            self.cells.append(cell)
            self.out(redacted(cell.line(), self.secret_values))

    def failed(self) -> bool:
        return any(cell.verdict is Verdict.FAILED for cell in self.cells)


# --- what a smoke prints ----------------------------------------------------------------------


def last_line(text: str) -> str:
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1].strip() if lines else "no output"


def lines_holding(text: str, values: Sequence[str]) -> int:
    return sum(any(value in line for value in values) for line in text.splitlines())


def event_names(output: str) -> list[str]:
    return [
        line.removeprefix(EVENT_PREFIX)
        for line in output.splitlines()
        if line.startswith(EVENT_PREFIX)
    ]


def other_lines(output: str) -> str:
    """The answer and any refusal (`unauthorized`, `forbidden`); the smoke prints no token."""
    kept = [
        line
        for line in output.splitlines()
        if line.strip() and not line.startswith((EVENT_PREFIX, SERVED_BY))
    ]
    return " | ".join(kept)[:300]


JWT_SHAPE: Final = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
SUBSCRIPTION_ROUTE: Final = "cli"


def jwt_lines(text: str) -> int:
    return sum(JWT_SHAPE.search(line) is not None for line in text.splitlines())


REFUSAL_LINE: Final = re.compile(r"^refused with \d+ (?P<code>[a-z_]+):", re.MULTILINE)


def configured_models() -> list[str]:
    service = tomllib.loads(SERVICE_TOML.read_text(encoding="utf-8"))
    return sorted(f"anthropic/{name}" for name in service["cli"]["anthropic"]["models"])


def subscription_groups() -> list[str]:
    service = tomllib.loads(SERVICE_TOML.read_text(encoding="utf-8"))
    return service["identity"]["subscription_groups"]


def missing_group_hint(output: str, events: list[str]) -> str:
    """The causes of a rights refusal, which comes before any event; an answer never earns one."""
    refusal = None if events else REFUSAL_LINE.search(output)
    code = refusal and refusal["code"]
    if code == "forbidden":
        return f"; forbidden: no member of /apps/{CLIENT}, another azp, or a bad workload token"
    if code == "not_enabled":
        return f"; not_enabled: the operator is in none of {' or '.join(subscription_groups())}"
    return ""


def empty_fields(output: str) -> str:
    """Which part of the line under `run_started` is missing."""
    following = output[output.index(f"{EVENT_PREFIX}run_started") :].splitlines()[1:2]
    loose = re.match(rf"{SERVED_BY} (?P<model>.*) on route (?P<route>.*)$", "".join(following))
    if loose is None:
        return "no served-by line"
    return (
        " and ".join(f"no {field}" for field in ("model", "route") if not loose[field].strip())
        or "an unreadable served-by line"
    )


def admission_cell(events: list[str], output: str) -> Cell:
    """`run_started` names a model of `service.toml` on the subscription route. The service's own
    choice of that model is not re-derived."""
    name = "L3 admission through the gateway"
    if "run_started" not in events:
        return Cell(name, Verdict.FAILED, "no run_started: the issuer's keys did not arrive")
    served = SERVED_AFTER_RUN_STARTED.match(output, output.index(f"{EVENT_PREFIX}run_started"))
    if served is None:
        return Cell(name, Verdict.FAILED, f"run_started names {empty_fields(output)}")
    shown = f"run_started names {served['model']} on route {served['route']}"
    listed = served["model"] in configured_models()
    held = listed and served["route"] == SUBSCRIPTION_ROUTE
    return Cell(name, Verdict.HELD if held else Verdict.FAILED, shown)


def turn_cells(returncode: int, output: str, known: Secrets) -> list[Cell]:
    """The secrets go out of the output before it is cut, so that none leaves its beginning."""
    output = known.redact(output)
    events = event_names(output)
    text = other_lines(output)
    said = f"exit {returncode}; events {events}; {text}{missing_group_hint(output, events)}"
    answered = bool(text)  # an answer needs text of its own, not only the event that carries it
    paid = returncode == 0 and events[-1:] == ["succeeded"] and answered
    return [
        Cell("L2 the paid turn", Verdict.HELD if paid else Verdict.FAILED, said),
        admission_cell(events, output),
    ]


# --- the service ------------------------------------------------------------------------------


def wait_until_listening(stack: Stack, pause: Callable[[float], None] = time.sleep) -> bool:
    for _ in range(LISTEN_ATTEMPTS):
        logs = stack.compose("logs", SERVICE)
        if logs.returncode == 0 and LISTENING in logs.stdout + logs.stderr:
            return True
        pause(1)
    return False


def recreate_service(
    stack: Stack, known: Secrets, pause: Callable[[float], None] = time.sleep
) -> Cell:
    started = stack.compose("up", "-d", "--force-recreate", SERVICE)
    if started.returncode != 0:
        reason = known.redact(last_line(started.stderr))[:RECREATE_REASON_CHARACTERS]
        return Cell(
            "recreate", Verdict.FAILED, f"docker compose up exited {started.returncode}: {reason}"
        )
    if wait_until_listening(stack, pause):
        return Cell("recreate", Verdict.HELD, "the service listens")
    return Cell(
        "recreate", Verdict.FAILED,
        f"not listening after {LISTEN_ATTEMPTS} s; read: docker compose logs {SERVICE}",
    )  # fmt: skip


def cgroup_figure(stack: Stack, name: str) -> str | None:
    answer = stack.compose("exec", "-T", SERVICE, "cat", f"/sys/fs/cgroup/{name}")
    return answer.stdout.strip() if answer.returncode == 0 and answer.stdout.strip() else None


def cli_processes(stack: Stack) -> str:
    answer = stack.compose("exec", "-T", SERVICE, "sh", "-c", CLI_PROCESS_COUNT)
    count = answer.stdout.strip()
    return count if answer.returncode == 0 and count.isdigit() else SAMPLE_FAILED


def memory_cell(idle: str | None, peak: str | None) -> Cell:
    sampled = idle is not None and peak is not None
    return Cell(
        "L7 memory", Verdict.HELD if sampled else Verdict.FAILED,
        f"idle memory.current {idle or SAMPLE_FAILED}; "
        f"memory.peak after the turn {peak or SAMPLE_FAILED}",
    )  # fmt: skip


def remove_smoke_containers(stack: Stack, service: str = SMOKE_SERVICE) -> str | None:
    """A run of `service` the host stopped waiting for leaves its `run --rm` container behind.
    Returns why the clean-up failed, in one line that may still hold a secret, or None."""
    listed = stack.run([
        "docker", "ps", "-aq",
        "--filter", f"label=com.docker.compose.project={stack.project}",
        "--filter", f"label=com.docker.compose.service={service}",
    ])  # fmt: skip
    if listed.returncode != 0:
        return f"docker ps exited {listed.returncode}: {last_line(listed.stderr)}"
    leftovers = listed.stdout.split()
    if not leftovers:
        return None
    removed = stack.run(["docker", "rm", "-f", *leftovers])
    if removed.returncode != 0:
        return f"docker rm exited {removed.returncode}: {last_line(removed.stderr)}"
    return None


def cleanup_cell(failure: str | None, known: Secrets) -> list[Cell]:
    reason = known.redact(failure or "")[:RECREATE_REASON_CHARACTERS]
    return [Cell("cleanup of the smoke containers", Verdict.FAILED, reason)] if failure else []


@dataclass(frozen=True)
class PaidTurn:
    process: subprocess.CompletedProcess[str]
    cleanup: str | None


def paid_turn(
    stack: Stack,
    tokens: Tokens,
    seconds: int = PAID_TURN_SECONDS,
    smoke_arguments: Sequence[str] = (),
    service: str = SMOKE_SERVICE,
) -> PaidTurn:
    try:
        process = stack.compose(
            "run", "--rm", "-T", service, *smoke_arguments,
            stdin=f"{tokens.person}\n{tokens.workload}\n", timeout=seconds,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        process = subprocess.CompletedProcess(
            [], TIMED_OUT, f"the host gave up after {seconds} s", ""
        )
    finally:
        cleanup = remove_smoke_containers(stack, service)
    return PaidTurn(process, cleanup)


@dataclass(frozen=True)
class CancelledTurn:
    returncode: int
    output: str
    during: str
    since: str
    cleanup: str | None = None


def end_child(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=CHILD_END_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def cancelled_turn(
    stack: Stack, tokens: Tokens, seconds: float = CANCELLED_TURN_SECONDS
) -> CancelledTurn:
    """Starts the cancelling smoke and counts the CLI processes while it holds its stream open.
    The host gives up after `seconds`, and the child and its container end however this leaves."""
    since = datetime.now(UTC).strftime(TIME_FORMAT)
    process = stack.start_compose("run", "--rm", "-T", SMOKE_SERVICE, "--cancel")
    gave_up = threading.Event()

    def give_up() -> None:
        gave_up.set()
        process.kill()

    watchdog = threading.Timer(seconds, give_up)
    watchdog.daemon = True
    watchdog.start()
    during = "no hold seen"
    lines = []
    cleanup = None
    try:
        try:
            process.stdin.write(f"{tokens.person}\n{tokens.workload}\n")
            process.stdin.close()
        except BrokenPipeError:
            pass  # the smoke ended first; its output and exit code say why
        for line in process.stdout:
            lines.append(line)
            if HOLDING_MESSAGE in line:
                during = cli_processes(stack)
        returncode = process.wait()
    finally:
        watchdog.cancel()
        end_child(process)
        cleanup = remove_smoke_containers(stack)
    if gave_up.is_set():
        lines.append(f"the host gave up after {seconds:g} s\n")
    return CancelledTurn(returncode, "".join(lines), during, since, cleanup)


def cancel_cells(
    stack: Stack,
    before: str,
    turn: CancelledTurn,
    known: Secrets,
    pause: Callable[[float], None] = time.sleep,
) -> list[Cell]:
    pause(SETTLE_SECONDS)
    after = cli_processes(stack)
    logs = stack.compose("logs", "--since", turn.since, SERVICE)
    errors = (
        lines_holding(logs.stdout + logs.stderr, ["ERROR"])
        if logs.returncode == 0
        else SAMPLE_FAILED
    )
    return [
        Cell(
            "L4 the cancelled turn", Verdict.OBSERVED,
            f"smoke exit {turn.returncode}; CLI processes before (0) {before}, while held "
            f"(1 or more) {turn.during}, left after the cancel (0) {after}; "
            f"ERROR lines since (0) {errors}; {other_lines(known.redact(turn.output))}",
        )
    ]  # fmt: skip


def leak_cells(stack: Stack, known: Secrets, smoke_outputs: str) -> list[Cell]:
    container = stack.compose("ps", "-q", SERVICE).stdout.strip()
    inspected = stack.run(["docker", "inspect", container]) if container else None
    logs = stack.compose("logs", SERVICE)
    searched = {
        "docker inspect": inspected.stdout if inspected and inspected.returncode == 0 else None,
        "the service log": logs.stdout + logs.stderr if logs.returncode == 0 else None,
        "the smoke output": smoke_outputs,
    }
    return [
        search_cell(
            "L6 no secret anywhere", searched, lambda text: lines_holding(text, known.values())
        ),
        search_cell("L9 no JWT-shaped string anywhere", searched, jwt_lines),
    ]


def search_cell(
    name: str, searched: Mapping[str, str | None], count_lines: Callable[[str], int]
) -> Cell:
    counts = {
        place: None if text is None else count_lines(text) for place, text in searched.items()
    }
    return Cell(
        name,
        Verdict.HELD if all(count == 0 for count in counts.values()) else Verdict.FAILED,
        "; ".join(
            f"{place} {SAMPLE_FAILED if count is None else count} (0)"
            for place, count in counts.items()
        ),
    )


# --- L5, the egress cells against the running container ---------------------------------------


@dataclass(frozen=True)
class EgressTargets:
    provider: str
    reach: dict[str, str]  # label -> an address the service must not reach on TCP 22
    agent_gateways: list[str]
    egress_gateways: list[str]


EGRESS_PROGRAM = (
    "import json, sys\n"
    + inspect.getsource(egress_observe)
    + """
targets = json.loads(sys.argv[1])
print(json.dumps({
    "public_tcp": {
        target: tcp_connect(target, 443)["result"]
        for target in (PUBLIC_RESOLVER, targets["provider"])
    },
    "defaults": default_routes()["default_routes"],
    "reach": {
        label: tcp_connect(address, 22)["result"] for label, address in targets["reach"].items()
    },
    "ipv6_interfaces": ipv6_interfaces()["interfaces"],
    "ipv6_tcp": tcp_connect(PUBLIC_RESOLVER_V6, 443)["result"],
    "udp": {str(port): udp_connect(PUBLIC_RESOLVER, port)["result"] for port in (443, 53)},
    "outside": resolve_name("example.com")["addresses"],
    "gateway": resolve_name("agent-egress")["addresses"],
}))
"""
)

LISTENERS_PROGRAM = (
    "import json\n"
    + inspect.getsource(egress_observe)
    + "\nprint(json.dumps(listening_sockets()))\n"
)


def network_ids(stack: Stack, name: str) -> list[str]:
    listed = stack.run([
        "docker", "network", "ls", "-q",
        "--filter", f"label=com.docker.compose.project={stack.project}",
        "--filter", f"label=com.docker.compose.network={name}",
    ])  # fmt: skip
    if listed.returncode != 0:
        raise LiveSmokeFailed(f"docker network ls for {name} failed")
    return listed.stdout.split()


def inspect_network(stack: Stack, reference: str) -> dict:
    answer = stack.run(["docker", "network", "inspect", reference])
    if answer.returncode != 0:
        raise LiveSmokeFailed(f"docker network inspect {reference} failed")
    try:
        return json.loads(answer.stdout)[0]
    except (ValueError, IndexError):
        raise LiveSmokeFailed(f"docker network inspect {reference} gave no network") from None


def project_network(stack: Stack, name: str) -> dict:
    found = network_ids(stack, name)
    if len(found) != 1:
        raise LiveSmokeFailed(f"the project {stack.project} has no single network {name}")
    return inspect_network(stack, found[0])


def gateways_of(network: dict) -> list[str]:
    configs = (network.get("IPAM") or {}).get("Config") or []
    return [config["Gateway"] for config in configs if config.get("Gateway")]


def unused_address(network: dict) -> str:
    """The last host address that no member holds. Docker hands out the low addresses, so a
    smoke container that has come and gone leaves no neighbour entry here, which would make the
    attempt time out instead of finding the host unreachable."""
    owned = {
        ipaddress.ip_interface(member["IPv4Address"]).ip
        for member in (network.get("Containers") or {}).values()
    }
    subnet = ipaddress.ip_network(network["IPAM"]["Config"][0]["Subnet"])
    return str(next(host for host in reversed(list(subnet.hosts())) if host not in owned))


def service_network_names(stack: Stack) -> list[str]:
    """The networks the service joins, from the configuration compose resolves."""
    return list(stack.configuration["services"][SERVICE]["networks"])


def egress_targets(
    stack: Stack,
    resolve_provider: Callable[[str], str] = socket.gethostbyname,
    discover_lan: Callable[[], str] = lan_address,
) -> EgressTargets:
    """The host looks up the addresses, because the container has no DNS and no Docker."""
    egress = project_network(stack, "egress")
    agent_networks = {
        name: project_network(stack, name)
        for name in service_network_names(stack)
        if name != "egress"
    }
    return EgressTargets(
        provider=resolve_provider(PROVIDER_HOST),
        reach={
            "docker0": gateways_of(inspect_network(stack, "bridge"))[0],
            "internet": gateways_of(project_network(stack, "internet"))[0],
            "lan": discover_lan(),
            **{f"{name}_free": unused_address(net) for name, net in agent_networks.items()},
            "egress_free": unused_address(egress),
        },
        agent_gateways=[
            address for network in agent_networks.values() for address in gateways_of(network)
        ],
        egress_gateways=gateways_of(egress),
    )


def verdict_of(held: bool) -> Verdict:
    return Verdict.HELD if held else Verdict.FAILED


def all_unreachable(codes: Mapping[str, str]) -> bool:
    return all(code in UNREACHABLE for code in codes.values())


def judge_egress(targets: EgressTargets, seen: dict, gateway: str) -> list[Cell]:
    tcp = ", ".join(f"{target}:443 {code}" for target, code in seen["public_tcp"].items())
    reached = ", ".join(
        f"{label} {targets.reach[label]}:22 {code}" for label, code in seen["reach"].items()
    )
    udp = ", ".join(f"{PUBLIC_RESOLVER}:{port} {code}" for port, code in seen["udp"].items())
    no_gateway = not targets.agent_gateways and not targets.egress_gateways
    no_route = not seen["defaults"] and no_gateway and all_unreachable(seen["reach"])
    no_ipv6 = seen["ipv6_interfaces"] == ["lo"] and seen["ipv6_tcp"] in UNREACHABLE
    names = seen["outside"] == [] and seen["gateway"] == [gateway]
    return [
        Cell("E6 no TCP to the internet", verdict_of(all_unreachable(seen["public_tcp"])), tcp),
        Cell(
            "E7 no route out", verdict_of(no_route),
            f"default routes {seen['defaults']}; gateways of agent {targets.agent_gateways} "
            f"and egress {targets.egress_gateways}; TCP to {reached}",
        ),
        Cell(
            "E8 no IPv6", verdict_of(no_ipv6),
            f"IPv6 interfaces {seen['ipv6_interfaces']}; TCP over IPv6 {seen['ipv6_tcp']}",
        ),
        Cell("E9 no UDP", verdict_of(all_unreachable(seen["udp"])), udp),
        Cell(
            "E10 names", verdict_of(names),
            f"example.com resolves to {seen['outside']}; agent-egress to {seen['gateway']}",
        ),
    ]  # fmt: skip


def judge_listeners(listening: Mapping[str, Sequence[str]], entrypoints: Sequence[str]) -> Cell:
    """Only TCP 443 on each of the gateway's `entrypoints` addresses and Docker's embedded resolver
    may listen."""
    others = [
        f"{protocol} {name}"
        for protocol, names in listening.items()
        for name in names
        if not name.startswith(f"{EMBEDDED_RESOLVER}:")
    ]
    expected = sorted(f"tcp {address}:443" for address in entrypoints)
    return Cell(
        "E12 the gateway's listeners", verdict_of(sorted(others) == expected),
        f"listening: {others}",
    )  # fmt: skip


def egress_cells(stack: Stack) -> list[Cell]:
    targets = egress_targets(stack)
    service = stack.compose("ps", "-q", SERVICE).stdout.strip()
    inside = stack.compose(
        "exec",
        "-T",
        SERVICE,
        "python",
        "-I",
        "-",
        json.dumps(asdict(targets)),
        stdin=EGRESS_PROGRAM,
    )
    if inside.returncode != 0:
        return [Cell("E6-E10", Verdict.FAILED, f"the egress program exited {inside.returncode}")]
    cells = judge_egress(targets, json.loads(inside.stdout), stack.gateway)
    return [*cells, listeners_cell(stack, service)]


def listeners_cell(stack: Stack, service: str) -> Cell:
    """Read from a throwaway container in the gateway's network namespace: nobody, no capability."""
    gateway = stack.compose("ps", "-q", EGRESS_SERVICE).stdout.strip()
    image = stack.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", service]
    ).stdout.strip()
    listing = stack.run([
        "docker", "run", "--rm", "--log-driver", "none", "--network", f"container:{gateway}",
        "--read-only",
        "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--entrypoint", "python", image, "-I", "-c", LISTENERS_PROGRAM,
    ])  # fmt: skip
    try:
        listening = json.loads(listing.stdout) if listing.returncode == 0 else None
    except ValueError:
        listening = None
    if not isinstance(listening, dict):
        return Cell("E12 the gateway's listeners", Verdict.FAILED, SAMPLE_FAILED)
    return judge_listeners(listening, stack.entrypoint_addresses)


# --- the run ----------------------------------------------------------------------------------


def smoke_cells(
    stack: Stack, known: Secrets, report: Report, pause: Callable[[float], None] = time.sleep
) -> None:
    """Recreate, idle memory, the paid turn, the peak, the cancelled turn, searches."""
    recreated = recreate_service(stack, known, pause)
    report.add(recreated)
    if recreated.verdict is Verdict.FAILED:
        return
    idle = cgroup_figure(stack, "memory.current")
    paid = paid_turn(stack, known.tokens)
    report.add(*turn_cells(paid.process.returncode, paid.process.stdout, known))
    report.add(*cleanup_cell(paid.cleanup, known))
    report.add(memory_cell(idle, cgroup_figure(stack, "memory.peak")))
    before = cli_processes(stack)
    cancelled = cancelled_turn(stack, known.tokens)
    report.add(*cancel_cells(stack, before, cancelled, known, pause))
    report.add(*cleanup_cell(cancelled.cleanup, known))
    smoke_outputs = paid.process.stdout + paid.process.stderr
    report.add(*leak_cells(stack, known, smoke_outputs + cancelled.output))


def live_smoke(stack: Stack, known: Secrets, report: Report) -> int:
    smoke_cells(stack, known, report)
    report.add(*egress_cells(stack))
    return 1 if report.failed() else 0


def read_secret(path: Path, what: str) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        raise LiveSmokeFailed(f"cannot read {what} at {path}") from None


def main(argv: Sequence[str]) -> int:
    argparse.ArgumentParser(description=__doc__.splitlines()[0]).parse_args(argv)
    try:
        client_secret = read_secret(CLIENT_SECRET_FILE, "the client secret")
        login_token = read_secret(LOGIN_TOKEN_FILE, "the login token")
        known = Secrets(sign_in(client_secret), login_token, client_secret)
        return live_smoke(Stack(), known, Report(known.values()))
    except (LiveSmokeFailed, SignInFailed) as failure:
        print(f"live smoke: {failure}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("live smoke: a docker command ran out of time", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("live smoke: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
