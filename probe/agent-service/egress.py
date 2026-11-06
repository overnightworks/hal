"""Probe of the agent service's egress (#189 cells E1-E10, E12, E13; #201 E11, E14 and the real
service; #346 P26, P36): the gateway `agent-egress` and either the stand-in `agent-probe` or
the real `agent-service` of compose.yaml, in a throwaway compose project of their own.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 50 1780 \\
        python3 probe/agent-service/egress.py --scratch DIR [--target stand-in|service]

Measured teardown: 2 s (K 50 s, CAP 1780 s).

The stack runs from a copy of compose.yaml and of the gateway's static file with each network that
pins a /24 (edge_subnets, `egress` and `litellm-egress` among them) moved to a free /24 of its own
(the addresses and the `extra_hosts` follow through the anchors), so it never collides with the
live stack's. E3-E5 and E10 are observed through the packet windows of
capture.py, each with a control; a window that dropped a frame, held a frame it could not decode,
or in which the control did not show, is NOT DRIVEN and fails the run. The service target runs the
image of the pull request's compose.yaml with a dummy login in the scratch HOME (never a real
token) and adds E11 and E14. The probe always removes its containers and networks, and never
touches the live stack: the project name is its own and is set on every command, its copy of
compose.yaml names its fixed networks and volumes `<project>_...` (edge_copy.py), and every call
that starts or removes something resolves only the project's names first (P26). Needs an existing,
empty, writable --scratch directory. Exit 0: every cell held, 1: a cell failed or was not driven.
Since the gateway serves LiteLLM alone, compose.yaml declares no `egress` network or entrypoint, so
this probe no longer runs; it goes with the agent service (#1086).

The subject runs litellm_stack.py's `Client`: the driver sends its source to `python -I -` inside
the container, so the client needs nothing but the standard library of the pinned image.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import secrets
import socket
import sys
import time
import tomllib
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # the helper of the probes
sys.path.insert(0, str(Path(__file__).resolve().parent))  # the stack of the LiteLLM probes

from agent_networks import cell_p36, gateway_listeners, service_networks
from egress_observe import (
    PUBLIC_RESOLVER,
    PUBLIC_RESOLVER_V6,
    UNREACHABLE,
    lan_address,
)

# The service probes import COMPOSE_FILE, ProbeFailed and classify_syns of the stack from here.
from litellm_stack import COMPOSE_FILE as COMPOSE_FILE
from litellm_stack import (
    GATEWAY_PORT,
    LABEL,
    PROJECT,
    PROVIDER,
    REPO,
    NotDriven,
    StackProbe,
    alerted,
    expect,
    run_probe,
    scratch_directory,
)
from litellm_stack import ProbeFailed as ProbeFailed
from litellm_stack import classify_syns as classify_syns
from scratch_secrets import write_login_folders, write_scratch_secrets

from hal.output import write_line

SERVICE_CONFIGURATION = REPO / "agent-service" / "service.toml"
SERVICE_PORT = 8080  # the service's own default; service.toml sets only its host
CLI_BINARY = "/opt/claude/claude"
CLI_SECONDS = 120
UPSTREAM_REJECTION = re.compile(r"API Error: 401\b")  # the API's answer, not a local startup error
GATEWAY_HOST_NUMBER = 10
READY_SECONDS = 90
HOST_WINDOW_TRIES = 3  # the host's window also sees the operator's traffic and may drop
OUTSIDE_NAME = "example.com"
NOT_FOUND = "HTTP/1.1 404 Not Found"  # Traefik's own answer to a request it has no router for


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


class Probe(StackProbe):
    """The gateway and the stand-in or the service on the agent networks, through the service's
    entrypoint `egress`, which compose.yaml no longer declares: the probe cannot run any more."""

    profiles: tuple[str, ...] = ("agent-service", "agent-probe")

    def __init__(self, scratch: Path, target: Target = Target.STAND_IN) -> None:
        super().__init__(scratch)
        self.target = target
        home = Path(self.environment["HOME"])
        write_login_folders(home)
        self.scratch_secrets = write_scratch_secrets(home, scratch / "service-ca")
        self.address = f"{self.moved[self.live['egress']]}{GATEWAY_HOST_NUMBER}"
        self.listener: socket.socket | None = None

    def __exit__(self, *_: object) -> None:
        if self.listener:
            self.listener.close()
        super().__exit__()

    # --- plumbing -----------------------------------------------------------------------------

    def client(self, *arguments: str) -> dict:
        """One Client command inside the target (the stand-in or the service)."""
        container = self.container(self.target.compose_service)
        return self.client_with(["exec", "-i", container], arguments)

    def services_to_start(self) -> tuple[str, ...]:
        return ("agent-egress", self.target.compose_service)

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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scratch", type=scratch_directory, required=True)
    parser.add_argument("--target", type=Target, choices=list(Target), default=Target.STAND_IN)
    arguments = parser.parse_args()
    return run_probe(lambda: Probe(arguments.scratch, arguments.target))


if __name__ == "__main__":
    sys.exit(main())
