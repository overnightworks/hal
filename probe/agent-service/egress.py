"""Probe of the agent service's egress (#189 cells E1-E10, E12, E13; #201 E11, E14 and the real
service; #346 P26, P36): the gateway `agent-egress` and either the stand-in `agent-probe` or
the real `agent-service` of compose.yaml, in a throwaway compose project of their own.

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 50 1780 \\
        python3 probe/agent-service/egress.py --scratch DIR [--target stand-in|service]

Measured teardown: 2 s (K 50 s, CAP 1780 s).

The stack runs from a copy of compose.yaml and of the gateway's static file with each network that
pins the gateway's address (`egress`, `litellm-egress`; edge_copy.GATEWAY_NETWORKS) moved to a free
/24 of its own (the gateway's addresses and the `extra_hosts` follow through the anchors), so it
never collides with the live stack's. E3-E5 and E10 are observed through the packet windows of
capture.py, each with a control; a window that dropped a frame, held a frame it could not decode,
or in which the control did not show, is NOT DRIVEN and fails the run. The service target runs the
image of the pull request's compose.yaml with a dummy login in the scratch HOME (never a real
token) and adds E11 and E14. The probe always removes its containers and networks, and never
touches the live stack: the project name is its own and is set on every command, its copy of
compose.yaml names its fixed networks and volumes `<project>_...` (edge_copy.py), and every call
that starts or removes something resolves only the project's names first (P26). Needs an existing,
empty, writable --scratch directory. Exit 0: every cell held, 1: a cell failed or was not driven.

The subject runs the `Client` class below: the driver sends its source to `python -I -` inside
the container, so the client needs nothing but the standard library of the pinned image.
"""

from __future__ import annotations

import argparse
import inspect
import ipaddress
import json
import os
import re
import secrets
import select
import selectors
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import tomllib
from collections.abc import Callable
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))  # the helper of the probes, importable by path too
sys.path.insert(0, str(Path(__file__).resolve().parent))  # agent_networks.py, likewise
sys.path.insert(0, str(REPO / "src"))  # edge's own facts; its modules need only the stdlib
sys.path.insert(0, str(REPO / "agent-service"))  # the observations shared with live_smoke.py

import edge_copy  # noqa: E402
import egress_observe  # noqa: E402
from agent_networks import cell_p36, gateway_listeners, service_networks  # noqa: E402
from edge_copy import GUARDED_COMPOSE_VERBS, ProbeFailed, expect, scratch_directory  # noqa: E402
from egress_observe import (  # noqa: E402
    PUBLIC_RESOLVER,
    PUBLIC_RESOLVER_V6,
    UNREACHABLE,
    default_routes,
    ipv6_interfaces,
    lan_address,
    listening_sockets,
    resolve_name,
    tcp_connect,
    udp_connect,
)
from scratch_secrets import write_login_folders, write_scratch_secrets  # noqa: E402

from hal.output import write_line  # noqa: E402

PROJECT = "edge-agentegress-probe"
LABEL = f"edge.probe={PROJECT}"
COMPOSE_FILE = REPO / "compose.yaml"
OVERLAY = REPO / "probe" / "agent-service" / "compose.probe.yaml"
GATEWAY_STATIC = REPO / "agent-service" / "egress" / "traefik.yml"
SERVICE_CONFIGURATION = REPO / "agent-service" / "service.toml"
PROVIDER = "api.anthropic.com"
GATEWAY_PORT = 443
SERVICE_PORT = 8080  # the service's own default; service.toml sets only its host
CLI_BINARY = "/opt/claude/claude"
CLI_SECONDS = 120
UPSTREAM_REJECTION = re.compile(r"API Error: 401\b")  # the API's answer, not a local startup error
UPSTREAM_PORT = 443  # the allowed hosts' port, which allowed.yml passes the connection to
SUBNET_CANDIDATES = [f"172.31.{third}.0/24" for third in range(251, 239, -1)]
GATEWAY_HOST_NUMBER = 10
READY_SECONDS = 90
WINDOW_READY_SECONDS = 180  # the first run pulls the capture image
WINDOW_END_SECONDS = 60
HOST_WINDOW_TRIES = 3  # the host's window also sees the operator's traffic and may drop
CONTROL_DELAY_SECONDS = 2
OUTSIDE_NAME = "example.com"
NOT_FOUND = "HTTP/1.1 404 Not Found"  # Traefik's own answer to a request it has no router for
CLIENT_IMPORTS = "import json, selectors, socket, ssl, struct, sys, time\n"


class NotDriven(ProbeFailed):
    """A cell could not be driven to a verdict: a window dropped a frame or missed its control."""


class Target(StrEnum):
    """What sits on the agent networks: the hardened stand-in, or the real service."""

    STAND_IN = "stand-in"
    SERVICE = "service"

    @property
    def compose_service(self) -> str:
        return "agent-probe" if self is Target.STAND_IN else "agent-service"


def service_configuration() -> dict:
    return tomllib.loads(SERVICE_CONFIGURATION.read_text(encoding="utf-8"))


def cli_tables() -> dict[str, dict]:
    """The `[cli.<provider>]` tables of the shipped service.toml."""
    return {
        provider: table
        for provider, table in service_configuration()["cli"].items()
        if isinstance(table, dict)
    }


def token_path() -> str:
    return service_configuration()["cli"]["anthropic"]["token_file"]


def issuer_host() -> str:
    """The host of the JWKS fetch, as the service's own configuration names it."""
    host = urlsplit(service_configuration()["identity"]["jwks_url"]).hostname
    expect(host is not None, "service.toml: jwks_url names no host")
    return host


def classify_syns(
    syns: list[dict], control_started: float, control_addresses: set[str]
) -> tuple[list[tuple[str, int]], list[tuple[str, int]], bool]:
    """The SYNs of a window by the kernel's time of their frame: those from before the control
    started, those after it that do not go to the control's destination (its addresses on
    :443), and whether the control's own SYN is there."""
    early = [(syn["destination"], syn["port"]) for syn in syns if syn["at"] < control_started]
    later = [syn for syn in syns if syn["at"] >= control_started]
    controls = [
        syn
        for syn in later
        if syn["destination"] in control_addresses and syn["port"] == UPSTREAM_PORT
    ]
    stray = [(syn["destination"], syn["port"]) for syn in later if syn not in controls]
    return early, stray, bool(controls)


def alerted(result: dict, what: str) -> None:
    """The gateway ended the handshake of `tls`: an SSLError is its own alert; a reset or a
    timeout would say less."""
    expect(
        not result["handshake"]
        and "certificate" not in result
        and result["error"].startswith("SSLError"),
        f"{what}: {result}",
    )


class Client:
    """What the stand-in does inside its own namespaces; every command prints one JSON line."""

    BATCH = 500  # connects in flight at once, below any file-descriptor limit
    SETTLE_SECONDS = 3.0  # a connect on a quiet network answers or is refused at once

    @staticmethod
    def tls(address: str, server_name: str, port: str, verify: str) -> dict:
        context = ssl.create_default_context()
        if verify != "verify":
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        name = None if server_name == "-" else server_name
        try:
            with (
                socket.create_connection((address, int(port)), timeout=8) as raw,
                context.wrap_socket(raw, server_hostname=name) as secured,
            ):
                return {
                    "handshake": True,
                    "certificate": bool(secured.getpeercert(binary_form=True)),
                }
        except OSError as error:  # ssl.SSLError is one
            return {"handshake": False, "error": f"{type(error).__name__}: {error}"}

    @staticmethod
    def plain(address: str, port: str) -> dict:
        try:
            with socket.create_connection((address, int(port)), timeout=5) as raw:
                raw.sendall(b"GET / HTTP/1.1\r\nHost: probe\r\n\r\n")
                first = raw.recv(64)
        except OSError as error:
            return {"connected": False, "error": f"{type(error).__name__}: {error}"}
        if first.startswith(b"HTTP/"):
            return {"connected": True, "reply": first.split(b"\r\n")[0].decode("ascii", "replace")}
        return {"connected": True, "reply": "closed" if not first else "not http"}

    connect = staticmethod(tcp_connect)
    udp = staticmethod(udp_connect)
    routes = staticmethod(default_routes)
    ipv6 = staticmethod(ipv6_interfaces)
    resolve = staticmethod(resolve_name)
    listeners = staticmethod(listening_sockets)

    @staticmethod
    def rawdns(name: str) -> dict:
        labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
        query = struct.pack("!HHHHHH", 0x5EED, 0x0100, 1, 0, 0, 0) + labels + b"\0\0\1\0\1"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as asking:
            asking.settimeout(4)
            asking.sendto(query, ("127.0.0.11", 53))
            try:
                reply = asking.recv(512)
            except OSError as error:
                return {"answered": False, "error": type(error).__name__}
        return {"answered": True, "response_code": reply[3] & 0x0F}

    @staticmethod
    def scan(addresses: str) -> dict:
        return {address: Client._open_ports(address) for address in addresses.split(",")}

    @staticmethod
    def _open_ports(address: str) -> list[int]:
        # A port is open only when three connects in a row complete: a connect to the address
        # we own can meet itself on an ephemeral port.
        candidates = Client._completing_ports(address, range(1, 65536))
        for _ in range(2):
            candidates = Client._completing_ports(address, candidates)
        return sorted(candidates)

    @staticmethod
    def _completing_ports(address: str, ports) -> list[int]:
        ports, completed = list(ports), []
        for start in range(0, len(ports), Client.BATCH):
            waiting, selector = {}, selectors.DefaultSelector()
            for port in ports[start : start + Client.BATCH]:
                attempt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                attempt.setblocking(False)
                attempt.connect_ex((address, port))
                selector.register(attempt, selectors.EVENT_WRITE)
                waiting[attempt] = port
            deadline = time.monotonic() + Client.SETTLE_SECONDS
            while waiting and time.monotonic() < deadline:
                for key, _ in selector.select(timeout=0.2):
                    attempt = key.fileobj
                    if attempt.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                        completed.append(waiting[attempt])
                    selector.unregister(attempt)
                    del waiting[attempt]
                    attempt.close()
            if waiting:
                raise SystemExit(f"scan of {address}: {len(waiting)} connects did not finish")
            selector.close()
        return completed

    @staticmethod
    def main(arguments: list[str]) -> int:
        print(json.dumps(getattr(Client, arguments[0])(*arguments[1:])), flush=True)  # noqa: T201 - this in-container program imports nothing of hal and prints itself
        return 0


CLIENT_PROGRAM = (
    CLIENT_IMPORTS
    + inspect.getsource(egress_observe)
    + inspect.getsource(Client)
    + "\nsys.exit(Client.main(sys.argv[1:]))\n"
)


class Probe:
    profiles: tuple[str, ...] = ("agent-service", "agent-probe")

    def __init__(self, scratch: Path, target: Target = Target.STAND_IN) -> None:
        live_project = edge_copy.compose_project_name(COMPOSE_FILE.read_text())
        expect(live_project != PROJECT, "the probe must never run in the live project")
        expect(not any(scratch.iterdir()), f"{scratch} is not empty")
        self.target = target
        home = scratch / "home"
        home.mkdir()
        write_login_folders(home)
        self.scratch_secrets = write_scratch_secrets(home, scratch / "ca")
        live = edge_copy.live_gateway_prefixes(COMPOSE_FILE.read_text())
        self.moved = edge_copy.free_gateway_prefixes(
            live, SUBNET_CANDIDATES, edge_copy.daemon_subnets()
        )
        self.address = f"{self.moved[live['egress']]}{GATEWAY_HOST_NUMBER}"
        self.compose_file = scratch / "compose.yaml"
        self.static_file = scratch / "traefik.yml"
        self.environment = {
            **os.environ,
            "HOME": str(home),
            "COMPOSE_PROJECT_NAME": PROJECT,
            "EDGE_DOMAIN": "probe.invalid",
            "DOCKER_GID": "0",
            "PROBE_EGRESS_STATIC": str(self.static_file),
        }
        self.overlays = [OVERLAY]
        self.guard = edge_copy.NetworkGuard(PROJECT, lambda command: self.run(command).stdout)
        self.windows: list[subprocess.Popen] = []
        self.throwaways = 0
        self.held: list[str] = []
        self.listener: socket.socket | None = None

    # --- plumbing -----------------------------------------------------------------------------

    def run(
        self, command: list[str], *, stdin: str | None = None, check: bool = True,
        timeout: int = 300, own_session: bool = False,
    ) -> subprocess.CompletedProcess:  # fmt: skip
        result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            command, input=stdin, capture_output=True, text=True, env=self.environment, cwd=REPO,
            check=False, timeout=timeout, close_fds=True, start_new_session=own_session,
        )  # fmt: skip
        if check and result.returncode != 0:
            tail = (result.stderr or result.stdout).strip().splitlines()
            raise ProbeFailed(f"{' '.join(command[:5])} exited {result.returncode}: {tail[-1:]}")
        return result

    def compose_command(self, *arguments: str, guard: bool = False) -> list[str]:
        """The compose call; `guard` checks its files and profiles for project-only networks (P26)
        even with no verb, for a prefix a caller runs the verbs of."""
        prefix = [
            "docker", "compose", "-p", PROJECT, "--project-directory", str(REPO),
            "--file", str(self.compose_file),
            *(argument for overlay in self.overlays for argument in ("--file", str(overlay))),
            *(argument for profile in self.profiles for argument in ("--profile", profile)),
        ]  # fmt: skip
        if guard or (arguments and arguments[0] in GUARDED_COMPOSE_VERBS):
            self.guard.expect(prefix)
        return [*prefix, *arguments]

    def compose(self, *arguments: str, check: bool = True, timeout: int = 300):
        return self.run(self.compose_command(*arguments), check=check, timeout=timeout)

    def container(self, service: str) -> str:
        found = self.compose("ps", "-q", service).stdout.strip()
        expect(bool(found), f"{service} has no container")
        return found

    def client(self, *arguments: str) -> dict:
        """One Client command inside the target (the stand-in or the service)."""
        container = self.container(self.target.compose_service)
        return self.client_with(["exec", "-i", container], arguments)

    def client_in_namespace_of(self, container: str, *arguments: str) -> dict:
        return self.throwaway([f"--network=container:{container}"], arguments)

    def client_on_network(self, network: str, *arguments: str) -> dict:
        return self.throwaway([f"--network={network}"], arguments)

    def throwaway(self, network: list[str], arguments, program: str = CLIENT_PROGRAM) -> dict:
        self.throwaways += 1
        name = f"{PROJECT}-throwaway-{self.throwaways}"
        return self.client_with(
            ["run", "--rm", "-i", "--name", name, "--label", LABEL, *network, "--read-only",
             "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt",
             "no-new-privileges:true", self.image],
            arguments, program,
        )  # fmt: skip

    def client_with(
        self, docker_arguments: list[str], arguments, program: str = CLIENT_PROGRAM
    ) -> dict:
        command = ["docker", *docker_arguments, "python", "-I", "-", *arguments]
        result = self.run(command, stdin=program, timeout=240)
        return json.loads(result.stdout.strip().splitlines()[-1])

    @cached_property
    def image(self) -> str:
        return json.loads(self.compose("config", "--format", "json").stdout)["services"][
            "agent-probe"
        ]["image"]

    def inspect_network(self, name: str) -> dict:
        return json.loads(self.run(["docker", "network", "inspect", f"{PROJECT}_{name}"]).stdout)[0]

    # --- life cycle ---------------------------------------------------------------------------

    def services_to_start(self) -> tuple[str, ...]:
        return ("agent-egress", self.target.compose_service)

    def __enter__(self) -> Probe:
        try:
            self.write_on_probe_subnet(COMPOSE_FILE, self.compose_file)
            self.write_on_probe_subnet(GATEWAY_STATIC, self.static_file)
            self.remove_stack()  # a crashed earlier run of this project, never anything else
            self.compose("up", "--detach", "--wait", *self.services_to_start(), timeout=600)
        except BaseException:
            self.__exit__()
            raise
        return self

    def write_on_probe_subnet(self, source: Path, copy: Path) -> None:
        """A copy of the file with the live gateway subnets replaced by the probe's: the live
        stack's networks own their /24s, and Docker refuses a second network on one."""
        text = source.read_text()
        # The copy lies in the scratch directory that scratch_directory() made absolute and
        # required at the command line, and the text comes from the repository's own files; the
        # route tried was checking the path once at that boundary, which Sonar does not follow
        # across calls.
        moved = edge_copy.moved_to_probe_subnets(text, self.moved)
        copy.write_text(  # NOSONAR(S2083)
            edge_copy.namespaced_compose(moved, PROJECT) if source == COMPOSE_FILE else moved
        )
        copy.chmod(0o644)

    def __exit__(self, *_: object) -> None:
        edge_copy.begin_teardown()
        if self.listener:
            self.listener.close()
        for window in self.windows:
            if window.poll() is None:
                window.kill()
            window.wait()
        self.remove_stack()
        left = self.run(
            ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}"],
            check=False,
        ).stdout.split()
        if left:
            raise ProbeFailed(f"the teardown left containers {left}")
        self.guard.expect_clean_teardown()

    def remove_stack(self) -> None:
        stray = self.run(
            ["docker", "ps", "-aq", "--filter", f"label={LABEL}"], check=False
        ).stdout.split()
        if stray:
            self.run(["docker", "rm", "-f", *stray], check=False)
        down = self.compose_command("down", "--volumes", "--remove-orphans", "--timeout", "10")
        self.run(down, check=False, own_session=True)  # `timeout`'s group signal must not stop it

    # --- the packet windows -------------------------------------------------------------------

    def window(self, service: str, arguments: list[str], during: Callable[[], None]) -> dict:
        """One bounded window of capture.py in the service's namespace; `during` runs inside it."""
        command = self.compose_command(
            "run", "--rm", "--no-deps", "-T", "--label", LABEL, service, *arguments
        )
        watcher = subprocess.Popen(  # noqa: S603 - argv is built by the program itself and no shell runs
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=self.environment, cwd=REPO, close_fds=True,
        )  # fmt: skip
        self.windows.append(watcher)
        ready, _, _ = select.select([watcher.stdout], [], [], WINDOW_READY_SECONDS)
        first_line = watcher.stdout.readline().strip() if ready else ""
        if first_line != "ready":
            watcher.kill()
            reason = watcher.communicate()[1][-300:]
            raise ProbeFailed(f"{service}: the window did not open: {reason}")
        during()
        out, err = watcher.communicate(timeout=WINDOW_END_SECONDS)
        exited = f"{service}: capture exited {watcher.returncode}: {err[-200:]}"
        expect(watcher.returncode == 0, exited)
        return json.loads(out.strip().splitlines()[-1])

    @staticmethod
    def complete(result: dict, cell: str, control_ended: float) -> None:
        """Complete: nothing dropped, nothing undecoded, still open when the control ended."""
        if result["drops"] or result["undecoded"] or result["ended_at"] < control_ended:
            raise NotDriven(
                f"{cell}: not driven: the window dropped {result['drops']} frames, could not "
                f"decode {result['undecoded']} and ended by "
                f"{result['ended_by']} after {result['frames']} frames in "
                f"{result['ended_at'] - result['started_at']:.1f} s"
                f"{', before the control ended' if result['ended_at'] < control_ended else ''}"
            )

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.wait_until_the_gateway_answers()
        self.cell_e1()
        self.cell_e2()
        self.cells_e3_to_e5()
        self.cell_e6()
        self.cell_e7()
        self.cell_e8()
        self.cell_e9()
        self.cell_e10()
        if self.target is Target.SERVICE:
            self.cell_e11()
        self.cell_e12()
        self.cell_e13()
        if self.target is Target.SERVICE:
            self.cell_e14()
        cell_p36(
            self, project=PROJECT, label=LABEL, service_port=SERVICE_PORT,
            service_listens=self.target is Target.SERVICE,
        )  # fmt: skip

    def hold(self, cell: str, how: str) -> None:
        write_line(f"{cell} held: {how}", flush=True)
        self.held.append(cell)

    def wait_until_the_gateway_answers(self) -> None:
        deadline = time.monotonic() + READY_SECONDS
        while self.client("connect", self.address, str(GATEWAY_PORT))["result"] != "connected":
            expect(time.monotonic() < deadline, "the gateway does not answer on its address")
            time.sleep(1)

    def handshake(self, name: str) -> dict:
        return self.client("tls", name, name, str(GATEWAY_PORT), "verify")

    def cell_e1(self) -> None:
        result = self.handshake(PROVIDER)
        expect(result["handshake"] and result["certificate"], f"E1: {result}")
        self.hold("E1", f"TLS to {PROVIDER} by name completed, certificate verified for it")

    def cell_e2(self) -> None:
        issuer = issuer_host()
        result = self.handshake(issuer)
        expect(result["handshake"] and result["certificate"], f"E2: {issuer}: {result}")
        self.hold("E2", f"TLS to {issuer} by name completed, certificate verified for it")

    def refused_without_a_dial(self, cell: str, attempt: Callable[[], str]) -> None:
        """E3-E5: the attempt ends in the gateway, and no SYN leaves it before the control's."""
        control_started, control_ended, outcome = [], [], []
        destinations = self.gateway_addresses(PROVIDER)

        def during() -> None:
            outcome.append(attempt())
            time.sleep(CONTROL_DELAY_SECONDS)
            control_started.append(time.time())
            control = self.handshake(PROVIDER)
            control_ended.append(time.time())
            expect(control["handshake"], f"{cell}: the control handshake failed: {control}")

        result = self.window("capture-egress", ["syn"], during)
        self.complete(result, cell, control_ended[0])
        destinations |= self.gateway_addresses(PROVIDER)
        early, stray, control_seen = classify_syns(result["syns"], control_started[0], destinations)
        expect(not early, f"{cell}: SYN out of the gateway before the control: {early}")
        expect(not stray, f"{cell}: SYN after the control started, not to the control's: {stray}")
        if not control_seen:
            raise NotDriven(f"{cell}: not driven: the control's SYN to :443 is not in the window")
        self.hold(cell, f"{outcome[0]}; no SYN left the gateway before the control's")

    def gateway_addresses(self, name: str) -> set[str]:
        """What the name resolves to in the gateway's own namespace, where Traefik resolves it."""
        gateway = self.container("agent-egress")
        return set(self.client_in_namespace_of(gateway, "resolve", name)["addresses"])

    def cells_e3_to_e5(self) -> None:
        def sni(name: str) -> Callable[[], str]:
            def attempt() -> str:
                result = self.client("tls", self.address, name, str(GATEWAY_PORT), "noverify")
                alerted(result, name)
                return f"SNI {name!r} refused ({result['error']})"

            return attempt

        def without_sni() -> str:
            result = self.client("tls", self.address, "-", str(GATEWAY_PORT), "noverify")
            alerted(result, "no SNI")
            return f"no SNI refused ({result['error']})"

        def plain_bytes() -> str:
            result = self.client("plain", self.address, str(GATEWAY_PORT))
            refused = not result["connected"] or result["reply"] in ("closed", NOT_FOUND)
            expect(refused, f"plain bytes: {result}")
            return f"plain bytes refused ({result})"

        self.refused_without_a_dial("E3", sni(OUTSIDE_NAME))
        self.refused_without_a_dial("E4 no SNI", without_sni)
        self.refused_without_a_dial("E4 plain bytes", plain_bytes)
        self.refused_without_a_dial("E5 suffix", sni(f"{PROVIDER}.{OUTSIDE_NAME}"))
        self.refused_without_a_dial("E5 prefix", sni(f"x{PROVIDER}"))

    def cell_e6(self) -> None:
        real = socket.getaddrinfo(PROVIDER, GATEWAY_PORT, socket.AF_INET)[0][4][0]
        for target in (PUBLIC_RESOLVER, real):
            result = self.client("connect", target, str(GATEWAY_PORT))
            expect(result["result"] in UNREACHABLE, f"E6: {target}: {result}")
        self.hold("E6", f"TCP to {PUBLIC_RESOLVER}:443 and {real}:443 has no route")

    def cell_e7(self) -> None:
        self.listener = socket.socket()
        self.listener.bind(("0.0.0.0", 0))  # reachable on every host address: that is the point  # noqa: S104 - the listener must be reachable on every host address
        self.listener.listen(8)
        port = str(self.listener.getsockname()[1])
        internet = self.network_gateway(f"{PROJECT}_internet")
        # A host firewall may drop container-to-host traffic on every ordinary bridge; then the
        # control cannot reach the listener either, and the unreachable result says less.
        control = self.client_on_network(f"{PROJECT}_internet", "connect", internet, port)
        targets = {
            "docker0": self.network_gateway("bridge"),
            "the internet bridge": internet,
            "the LAN address": lan_address(),
        }
        errnos = []
        for name, target in targets.items():
            result = self.client("connect", target, port)
            expect(result["result"] in UNREACHABLE, f"E7: {name} {target}:{port}: {result}")
            errnos.append(f"{name} {result['result']}")
        for network in service_networks(self, PROJECT):
            gateways = self.network_gateways(f"{PROJECT}_{network}")
            expect(not gateways, f"E7: {network} has a bridge address: {gateways}")
            free = self.free_address(network)
            result = self.client("connect", free, port)
            expect(result["result"] in UNREACHABLE, f"E7: {network} free {free}:{port}: {result}")
            errnos.append(f"free {network} address {free} {result['result']}")
        defaults = self.client("routes")["default_routes"]
        expect(not defaults, f"E7: the stand-in has a default route on {defaults}")
        self.hold(
            "E7",
            f"a host listener is unreachable via {'; '.join(errnos)}; no bridge address, no "
            f"default route (control from the internet bridge: {control['result']})",
        )

    def free_address(self, network: str) -> str:
        """An address of the network's subnet that no member owns. In isolated mode the first
        member gets .1, so .1 is never taken for a host address."""
        inspected = self.inspect_network(network)
        subnet = ipaddress.IPv4Network(inspected["IPAM"]["Config"][0]["Subnet"])
        owned = {
            ipaddress.IPv4Interface(member["IPv4Address"]).ip
            for member in inspected["Containers"].values()
        }
        first = subnet.network_address + 1
        return str(next(host for host in subnet.hosts() if host != first and host not in owned))

    def network_gateways(self, name: str) -> list[str]:
        inspected = json.loads(self.run(["docker", "network", "inspect", name]).stdout)[0]
        configs = (inspected.get("IPAM") or {}).get("Config") or []
        return [config["Gateway"] for config in configs if config.get("Gateway")]

    def network_gateway(self, name: str) -> str:
        gateways = self.network_gateways(name)
        expect(len(gateways) == 1, f"{name} has gateways {gateways}")
        return gateways[0]

    def cell_e8(self) -> None:
        interfaces = self.client("ipv6")["interfaces"]
        expect(interfaces == ["lo"], f"E8: IPv6 interfaces are {interfaces}")
        result = self.client("connect", PUBLIC_RESOLVER_V6, str(GATEWAY_PORT))
        expect(result["result"] in UNREACHABLE, f"E8: {result}")
        self.hold(
            "E8", f"if_inet6 lists lo only; TCP to [{PUBLIC_RESOLVER_V6}]:443: {result['result']}"
        )

    def cell_e9(self) -> None:
        for port in ("443", "53"):
            result = self.client("udp", PUBLIC_RESOLVER, port)
            expect(result["result"] in UNREACHABLE, f"E9: :{port}: {result}")
        self.hold("E9", f"UDP to {PUBLIC_RESOLVER}:443 and :53 has no route")

    def cell_e10(self) -> None:
        for attempt in range(1, HOST_WINDOW_TRIES + 1):
            try:
                self.drive_dns_window()
                return
            except NotDriven as problem:
                write_line(f"E10 try {attempt}: {problem}", flush=True)
        raise NotDriven(f"E10: not driven in {HOST_WINDOW_TRIES} windows")

    def drive_dns_window(self) -> None:
        asked, control = secrets.token_hex(8), secrets.token_hex(8)
        outcome = {}

        def during() -> None:
            outcome["getaddrinfo"] = self.client("resolve", f"{asked}.example.com")
            outcome["raw"] = self.client("rawdns", f"{asked}.example.com")
            outcome["plain"] = self.client("resolve", "example.com")
            self.client_on_network(f"{PROJECT}_internet", "resolve", f"{control}.example.com")
            outcome["control_ended"] = time.time()

        result = self.window("capture-host", ["dns", asked, control], during)
        self.complete(result, "E10", outcome["control_ended"])
        seen = result["labels"]
        if not seen.get(control):
            raise NotDriven("E10: not driven: the control's question is not in the host window")
        expect(not seen.get(asked), f"E10: the client's question left the container: {seen}")
        for asking in ("getaddrinfo", "plain"):
            expect(outcome[asking]["addresses"] == [], f"E10: {asking} resolved: {outcome[asking]}")
        raw = outcome["raw"]
        expect(not raw.get("answered") or raw["response_code"] != 0, f"E10: the raw query: {raw}")
        peer = self.client("resolve", "agent-egress")["addresses"]
        expect(peer == [self.address], f"E10: agent-egress resolves to {peer}")
        self.hold(
            "E10",
            f"the host window holds the control's label ({seen[control]} frames) and not the "
            f"client's; both queries got no address; agent-egress -> {peer[0]}",
        )

    def cell_e12(self) -> None:
        addresses = re.findall(r'address:\s*"([^"]+)"', self.static_file.read_text())
        gateway_listeners(self, "agent-egress", addresses)
        self.hold(
            "E12", f"the gateway listens on {', '.join(addresses)}/tcp and holds no UDP socket"
        )

    def cell_e11(self) -> None:
        """The allowed names resolve to the gateway (glibc), and the Claude CLI (Bun) reaches the
        real API through it: a dummy token ends in an authentication failure."""
        for name in (PROVIDER, issuer_host()):
            addresses = self.client("resolve", name)["addresses"]
            expect(addresses == [self.address], f"E11: {name} resolves to {addresses}")
        configuration = service_configuration()
        working_root = configuration["cli"]["working_root"]
        token_file = token_path()
        script = (
            'cd "$(mktemp -d -p "$1")" && CLAUDE_CODE_OAUTH_TOKEN="$(cat "$2")" exec "$3" -p hello'
        )
        container = self.container("agent-service")
        started = self.run(
            ["docker", "exec", container, "sh", "-c", script, "sh", working_root, token_file,
             CLI_BINARY],
            check=False, timeout=CLI_SECONDS,
        )  # fmt: skip
        said = (started.stdout + started.stderr).strip()
        expect(started.returncode != 0, f"E11: the CLI exited 0 with a dummy token: {said[:200]!r}")
        expect(
            bool(UPSTREAM_REJECTION.search(said)),
            f"E11: the CLI did not print the API's 401: {said[:300]!r}",
        )
        self.hold(
            "E11",
            f"{PROVIDER} and {issuer_host()} resolve to {self.address}; the CLI started under "
            f"{working_root} and ended with: {said[:120]!r}",
        )

    def scan_network(self, cell: str, network: str) -> None:
        """A TCP connect scan of every port of every member address of the network, from the
        target: only the gateway's :443 and the service's own port may answer."""
        members = {
            member_id: member["IPv4Address"].split("/")[0]
            for member_id, member in self.inspect_network(network)["Containers"].items()
        }
        gateway = self.container("agent-egress")
        expect(
            (gateway in members) == (network == "egress"),
            f"{cell}: the gateway is a member of {network}: {gateway in members}",
        )
        listening = {gateway: [GATEWAY_PORT]}
        if self.target is Target.SERVICE:
            listening[self.container("agent-service")] = [SERVICE_PORT]
        scanned = self.client("scan", ",".join(members.values()))
        wanted = {address: listening.get(member_id, []) for member_id, address in members.items()}
        expect(scanned == wanted, f"{cell}: open ports {scanned}, expected {wanted}")
        found = ", ".join(f"{address} {ports}" for address, ports in sorted(scanned.items()))
        self.hold(cell, f"every port of {len(members)} members of {network} scanned: open {found}")

    def cell_e13(self) -> None:
        self.scan_network("E13", "egress")

    def cell_e14(self) -> None:
        for network in service_networks(self, PROJECT):
            if network != "egress":
                self.scan_network(f"E14 {network}", network)


def interrupt(*_: object) -> None:
    """`timeout`'s SIGTERM unwinds the probe, so its teardown runs."""
    raise KeyboardInterrupt


def run_probe(open_probe: Callable[[], Probe]) -> int:
    """Drive the probe `open_probe` makes; exit 0 when every cell held, 1 when one failed."""
    signal.signal(signal.SIGTERM, interrupt)
    try:
        with open_probe() as probe:
            probe.drive()
    except (ProbeFailed, subprocess.TimeoutExpired, KeyboardInterrupt) as problem:
        write_line(f"PROBE FAILED: {type(problem).__name__}: {problem}", flush=True)
        return 1
    write_line(f"PROBE PASSED: held {', '.join(probe.held)}", flush=True)
    return 0


def run_scratch_probe(description: str, open_probe: Callable[[Path], Probe]) -> int:
    """The entry of a probe whose one argument is `--scratch`: drive the probe `open_probe` makes
    in that directory."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--scratch", type=scratch_directory, required=True)
    scratch = parser.parse_args().scratch
    return run_probe(lambda: open_probe(scratch))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scratch", type=scratch_directory, required=True)
    parser.add_argument("--target", type=Target, choices=list(Target), default=Target.STAND_IN)
    arguments = parser.parse_args()
    return run_probe(lambda: Probe(arguments.scratch, arguments.target))


if __name__ == "__main__":
    sys.exit(main())
