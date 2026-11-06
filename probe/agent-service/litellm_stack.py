"""The throwaway compose project the LiteLLM probes run in: the copy of compose.yaml and of the
gateway's static file beside the live stack, the profile `litellm`, the throwaway clients, the
packet windows of capture.py and the teardown. Nothing here starts a container of its own; a probe
names the services it starts.

The copy moves each network that pins a /24 (edge_subnets, `litellm-egress` among them) to a free
/24 of its own (the addresses and the `extra_hosts` follow through the anchors), so it never
collides with the live stack's. Its project name is its own and is set on every command, its copy
of compose.yaml names its fixed networks and volumes `<project>_...` (edge_copy.py), and every call
that starts or removes something resolves only the project's names first (P26). The probe always
removes its containers and networks.

A client runs the `Client` class below: the driver sends its source to `python -I -` inside a
throwaway, so the client needs nothing but the standard library of the pinned image.
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import select
import selectors
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
from collections.abc import Callable
from functools import cached_property
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))  # the helper of the probes, importable by path too
sys.path.insert(0, str(Path(__file__).resolve().parent))  # the probes beside this one
sys.path.insert(0, str(REPO / "src"))  # edge's own facts; its modules need only the stdlib
sys.path.insert(0, str(REPO / "agent-service"))  # the observations the clients run

import edge_copy  # noqa: E402
import edge_subnets  # noqa: E402
import egress_observe  # noqa: E402
from edge_copy import GUARDED_COMPOSE_VERBS, ProbeFailed, expect, scratch_directory  # noqa: E402
from egress_observe import (  # noqa: E402
    default_routes,
    ipv6_interfaces,
    listening_sockets,
    resolve_name,
    tcp_connect,
    udp_connect,
)
from litellm_ca import write_scratch_ca  # noqa: E402

from hal.output import write_line  # noqa: E402

PROJECT = "edge-litellm-probe"
LABEL = f"edge.probe={PROJECT}"
COMPOSE_FILE = REPO / "compose.yaml"
OVERLAY = REPO / "probe" / "agent-service" / "compose.probe.yaml"
GATEWAY_STATIC = REPO / "agent-service" / "egress" / "traefik.yml"
GATEWAY_NETWORKS = ("litellm-egress",)  # the networks of the static file's addresses
PROFILE = "litellm"
KEYS_SERVICE = "litellm-keys"  # the key step's one-off, whose plain Python the clients run
PROVIDER = "api.anthropic.com"  # the control's name: the gateway passes it
GATEWAY_PORT = 443
UPSTREAM_PORT = 443  # the allowed hosts' port, which allowed.yml passes the connection to
WINDOW_READY_SECONDS = 180  # the first run pulls the capture image
WINDOW_END_SECONDS = 60
CONTROL_DELAY_SECONDS = 2
CLIENT_IMPORTS = "import json, selectors, socket, ssl, struct, sys, time\n"


class NotDriven(ProbeFailed):
    """A cell could not be driven to a verdict: a window dropped a frame or missed its control."""


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
    """What a client does inside the namespace it runs in; every command prints one JSON line."""

    BATCH = 500  # connects in flight at once, below any file-descriptor limit
    SETTLE_SECONDS = 3.0  # a connect on a quiet network answers or is refused at once

    @staticmethod
    def tls(address: str, server_name: str, port: str, verify: str) -> dict:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
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


class StackProbe:
    """The project, its copies and its throwaway clients; a probe adds its overlays and names the
    services it starts (`services_to_start`) and the control handshake of its windows
    (`handshake`)."""

    profiles: tuple[str, ...] = (PROFILE,)

    def __init__(self, scratch: Path) -> None:
        live_project = edge_copy.compose_project_name(COMPOSE_FILE.read_text())
        expect(live_project != PROJECT, "the probe must never run in the live project")
        expect(not any(scratch.iterdir()), f"{scratch} is not empty")
        home = scratch / "home"
        home.mkdir()
        self.scratch_ca = write_scratch_ca(scratch / "ca")
        self.live = edge_subnets.pinned_prefixes(COMPOSE_FILE.read_text())
        self.moved = edge_copy.probe_prefixes(COMPOSE_FILE.read_text(), PROJECT)
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
        self.write_on_probe_subnet(COMPOSE_FILE, self.compose_file)  # the project's names (P26)
        self.write_on_probe_subnet(GATEWAY_STATIC, self.static_file)

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
        """The key step's image: plain Python, which the throwaways and the fakes run."""
        return yaml.safe_load(COMPOSE_FILE.read_text())["services"][KEYS_SERVICE]["image"]

    def container_log(
        self,
        service: str,
        since: int | None = None,
        timeout: int = 300,
        container: str | None = None,
    ) -> str:
        """The log text, from the unix time `since` on when given; a failed read reports the
        command and its exit code, never its output, because the probes print only verdicts,
        counts and event names. `timeout` bounds the read in seconds; a caller that knows the
        `container` of the service saves the lookup, which has no bound of its own."""
        container = container or self.container(service)
        bound = [] if since is None else ["--since", str(since)]
        logs = self.run(["docker", "logs", *bound, container], check=False, timeout=timeout)
        if logs.returncode != 0:
            raise ProbeFailed(f"docker logs {container} exited {logs.returncode}")
        return logs.stdout + logs.stderr

    def inspect_network(self, name: str) -> dict:
        return json.loads(self.run(["docker", "network", "inspect", f"{PROJECT}_{name}"]).stdout)[0]

    # --- life cycle ---------------------------------------------------------------------------

    def services_to_start(self) -> tuple[str, ...]:
        raise NotImplementedError

    def __enter__(self) -> StackProbe:
        try:
            self.remove_stack()  # a crashed earlier run of this project, never anything else
            self.compose("up", "--detach", "--wait", *self.services_to_start(), timeout=600)
        except BaseException:
            self.__exit__()
            raise
        return self

    def write_on_probe_subnet(self, source: Path, copy: Path) -> None:
        """A copy of compose.yaml beside the live stack (edge_copy.compose_beside_the_live_stack),
        or of the static file with its gateway /24s moved alike, off the live stack's."""
        text, gateway = source.read_text(), {self.live[network] for network in GATEWAY_NETWORKS}
        if source == COMPOSE_FILE:
            moved = edge_copy.compose_beside_the_live_stack(text, PROJECT, self.moved)
        else:
            moved = edge_subnets.moved_to_probe_subnets(text, {p: self.moved[p] for p in gateway})
        # The copy lies in the scratch directory that scratch_directory() made absolute and
        # required at the command line, and the text comes from the repository's own files; the
        # route tried was checking the path once at that boundary, which Sonar does not follow
        # across calls.
        copy.write_text(moved)  # NOSONAR(S2083)
        copy.chmod(0o644)

    def __exit__(self, *_: object) -> None:
        edge_copy.begin_teardown()
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

    def hold(self, cell: str, how: str) -> None:
        write_line(f"{cell} held: {how}", flush=True)
        self.held.append(cell)

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

    def handshake(self, name: str) -> dict:
        """The control of `refused_without_a_dial`: a handshake for `name` the gateway passes."""
        raise NotImplementedError


def interrupt(*_: object) -> None:
    """`timeout`'s SIGTERM unwinds the probe, so its teardown runs."""
    raise KeyboardInterrupt


def run_probe(open_probe: Callable[[], StackProbe]) -> int:
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


def run_scratch_probe(description: str, open_probe: Callable[[Path], StackProbe]) -> int:
    """The entry of a probe whose one argument is `--scratch`: drive the probe `open_probe` makes
    in that directory."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--scratch", type=scratch_directory, required=True)
    scratch = parser.parse_args().scratch
    return run_probe(lambda: open_probe(scratch))
