"""The speech probe's network cells: where the speech app can be reached from and what it reaches.

D3 exposure, N1-N5 the networks and their peers, E1-E3 egress, K1-K6 Keycloak's key set through
traefik-mcp, M1 the other routers traefik-mcp offers on the issuer network. Every name is read from
its owner: the copy's resolved compose.yaml (which service joins which speech network), the
release's compose.yaml (the app's service and port) and the copy's mcp/dynamic routers.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from app_isolation import speech_prefix
from copy_isolation import routable_by_live_edge
from edge_copy import ProbeFailed, expect
from speech_docker import (
    FIXED_RESPONSE_SERVER,
    Answer,
    Curl,
    addresses_of,
    docker,
    fixed_server,
    inspected,
    networks_of,
    plain_http,
    wait_healthy,
)

from hal.output import write_line
from hal.stack.realm.reconcile import KEYCLOAK, KEYCLOAK_SERVICE

ISOLATED_MODE = ("com.docker.network.bridge.gateway_mode_ipv4", "isolated")
TRAEFIK_404 = b"404 page not found\n"
NO_TCP = {7, 28}  # curl: connection refused or unreachable, or timed out
NOT_RESOLVED = 6
TLS_UNTRUSTED = 60
KEY_SET = b'"keys"'  # a body that carries it is a key set
LEAKS = (b'"issuer"', b"access_token", b"<html", b"<!DOCTYPE")
HEALTH_PORT = re.compile(r"127\.0\.0\.1:(?P<port>\d+)/health")
ROUTER_HOST = re.compile(r"Host\(`(?P<host>[^`]+)`\)")
PUBLIC_ADDRESS = "1.1.1.1"  # NOSONAR(S1313) a public address the speech service must not reach
PUBLIC_NAME = "example.org"
HEALTHY_SECONDS = 300
SERVER_SECONDS = 30  # until a probe's fixed-response container answers
RESTARTED_SECONDS = 90  # until a restarted traefik-mcp serves the key set again
PEER_PORT = 8080
FORGED_KID = "forged"
E2_LIMIT = (
    "E2 limit: the host drops container-to-host traffic for every bridge, so isolation is not "
    "separately provable here; gateway_mode_ipv4 isolated is proven by C1"
)


@dataclass(frozen=True)
class Topology:
    """Who joins which speech network in the copy, by relationship: the gateway is the copy's one
    service on a single speech network (the issuer's), the helper the one on several."""

    project: str
    gateway: str
    helper: str
    issuer: str  # network names
    callers: dict[str, str]  # caller app -> its network
    keys: str  # the network the gateway shares with Keycloak

    @classmethod
    def of(cls, resolved: dict[str, Any], project: str) -> Topology:
        names = {key: network["name"] for key, network in resolved["networks"].items()}
        prefix = speech_prefix(project)
        speech = {key for key, name in names.items() if name.startswith(prefix)}
        services = resolved["services"]

        def joins(service: str) -> set[str]:
            return set(services[service].get("networks") or {})

        on_one = [s for s in services if len(joins(s) & speech) == 1]
        on_several = [s for s in services if len(joins(s) & speech) > 1]
        expect(len(on_one) == len(on_several) == 1, f"speech members {on_one} {on_several}")
        (gateway,), (helper,) = on_one, on_several
        (issuer,) = joins(gateway) & speech
        shared = joins(gateway) & joins(KEYCLOAK_SERVICE)
        expect(len(shared) == 1, f"{gateway} and keycloak share {sorted(shared)}")
        callers = {names[k].removeprefix(prefix): names[k] for k in speech - {issuer}}
        return cls(project, gateway, helper, names[issuer], callers, names[shared.pop()])


class NetworkCells:
    """Mixed into the speech probe, which provides these."""

    hold: Any
    topology: Topology
    curl: Curl
    speech_id: str
    speech_service: str
    release_compose: str
    copy: Path
    copy_kids: Any
    gateway_id: str
    app_image: str
    project_container: Any

    @property
    def port(self) -> int:
        found = HEALTH_PORT.search(self.release_compose)
        expect(found is not None, "the release's health check names no port")
        return int(found["port"])

    def health_url(self, host: str) -> str:
        return plain_http(host, self.port, "/health")

    def in_speech(self, *arguments: str, **options: Any) -> Answer:
        return self.curl.at(f"container:{self.speech_id}", arguments, **options)

    def certs_url(self, path: str | None = None) -> str:
        return f"https://{self.key_set_host}{path or self.certs_path}"

    @property
    def key_set_router(self) -> dict[str, Any]:
        routers = yaml.safe_load((self.copy / "mcp" / "dynamic" / "keycloak.yml").read_text())
        (router,) = routers["http"]["routers"].values()
        return router

    @property
    def key_set_host(self) -> str:
        return ROUTER_HOST.search(self.key_set_router["rule"])["host"]

    @property
    def certs_path(self) -> str:
        return re.search(r"Path\(`(?P<path>[^`]+)`\)", self.key_set_router["rule"])["path"]

    @property
    def key_set_upstream(self) -> tuple[str, int]:
        """The host and port traefik-mcp sends the key-set route to."""
        routers = yaml.safe_load((self.copy / "mcp" / "dynamic" / "keycloak.yml").read_text())
        service = routers["http"]["services"][self.key_set_router["service"]]
        (server,) = service["loadBalancer"]["servers"]
        upstream = urlsplit(server["url"])
        return upstream.hostname, upstream.port

    def answered_within(self, network: str, url: str) -> Answer:
        """The first 200 from `url` on `network` within SERVER_SECONDS, else the last answer."""
        return within(
            SERVER_SECONDS,
            lambda: self.curl.at(network, ["--connect-timeout", "2", url], trusted=False),
        )

    def kids(self, answer: Answer) -> set[str]:
        expect(answer.status == 200, f"the key set answered {answer.status} ({answer.exit_code})")
        return {key["kid"] for key in answer.json()["keys"]}

    # --- D3, N1-N5 ---------------------------------------------------------------------------

    def cell_d3(self, entry: str) -> None:
        container = inspected("container", self.speech_id)
        ports = container["HostConfig"].get("PortBindings") or {}
        labels = container["Config"]["Labels"] or {}
        traefik = sorted(label for label in labels if label.startswith("traefik."))
        expect(
            not ports and not traefik and not routable_by_live_edge(labels),
            f"D3: ports {ports}, traefik labels {traefik}",
        )
        expect("hosts" not in entry, f"D3: the entry {entry!r} names hosts")
        self.hold("D3", "no published port, no traefik or live edge.name label, no hosts entry")

    def network(self, name: str) -> dict[str, Any]:
        return inspected("network", name)

    def members(self, name: str) -> set[str]:
        return set(self.network(name).get("Containers") or {})

    def cell_n1(self) -> None:
        t, keycloak = self.topology, self.project_container(KEYCLOAK_SERVICE)
        wanted = {
            **{name: {self.speech_id} for name in t.callers.values()},
            t.issuer: {self.speech_id, self.gateway_id},
            t.keys: {keycloak, self.gateway_id},
        }
        host = host_addresses()
        for name, members in wanted.items():
            network = self.network(name)
            options = network.get("Options") or {}
            subnets = [ipaddress.ip_network(c["Subnet"]) for c in network["IPAM"]["Config"] or []]
            on_host = [str(a) for a in host for subnet in subnets if a in subnet]
            expect(
                network["Internal"] and options.get(ISOLATED_MODE[0]) == ISOLATED_MODE[1],
                f"N1: {name} is not internal and isolated: {options}",
            )
            expect(not on_host, f"N1: the host has {on_host} on {name}")
            expect(self.members(name) == members, f"N1: {name} has {self.members(name)}")
        own = inspected("container", self.gateway_id)["NetworkSettings"]["Networks"][t.issuer]
        automatic = {t.gateway, self.gateway_id[:12], own.get("Aliases", [None])[0]}
        aliases = set(own.get("DNSNames") or own.get("Aliases") or []) - automatic
        expect(
            aliases == {self.key_set_host}, f"N1: {t.gateway} answers on the issuer as {aliases}"
        )
        self.hold(
            "N1",
            f"{sorted(wanted)} internal, isolated, no host address; members as declared; "
            f"{t.gateway} on {t.issuer} as {sorted(aliases)} beside Compose's own names",
        )

    def cell_n2_n3(self) -> None:
        answers = {
            app: self.curl.at(net, [self.health_url(self.speech_service)])
            for app, net in self.topology.callers.items()
        }
        expect(
            all(a.status == 200 for a in answers.values()),
            f"N2/N3: { ({app: a.status for app, a in answers.items()}) }",
        )
        self.hold("N2", f"/health 200 from {sorted(self.topology.callers.values())}")
        addresses = addresses_of(self.speech_id)
        crossed = {
            f"{caller}->{other}": self.curl.at(net, [self.health_url(addresses[other_net])])
            for caller, net in self.topology.callers.items()
            for other, other_net in self.topology.callers.items()
            if other != caller
        }
        reached = {k: a.status for k, a in crossed.items() if a.status or a.exit_code not in NO_TCP}
        expect(not reached, f"N3: an app reaches the speech service by another's address {reached}")
        self.hold(
            "N3",
            "; ".join(
                [
                    *self.peers_kept_apart(),
                    f"the speech service's address on another app's network: not {sorted(crossed)}",
                ]
            ),
        )

    def peers_kept_apart(self) -> list[str]:
        """A peer on each caller network answers there and not from any other caller network: one
        line each."""
        callers, held = self.topology.callers, []
        for app, network in callers.items():
            body = f"{app} peer"
            with fixed_server(
                self.app_image, self.topology.project, [network], body, port=PEER_PORT
            ) as peer:
                address = addresses_of(peer)[network]
                url = plain_http(address, PEER_PORT)
                own = self.answered_within(network, url)
                expect(
                    own.status == 200 and own.body == body.encode(),
                    f"N3: the {app} peer does not answer on {network}: {own.status}",
                )
                crossed = {
                    other: self.curl.at(net, ["--connect-timeout", "2", url], trusted=False)
                    for other, net in callers.items()
                    if other != app
                }
            reached = {
                o: a.status for o, a in crossed.items() if a.status or a.exit_code not in NO_TCP
            }
            expect(not reached, f"N3: the {app} peer at {address} answered from {reached}")
            held.append(
                f"a {app} peer at {address} answers on {network}, not from {sorted(crossed)}"
            )
        return held

    def cell_n4(self) -> None:
        speech_networks = {*self.topology.callers.values(), self.topology.issuer}
        others = [n for n in networks_of(self.topology.project) if n not in speech_networks]
        targets = [self.speech_service, *addresses_of(self.speech_id).values()]
        reached = []
        for network in [*others, "bridge"]:
            for target in targets:
                answer = self.curl.at(network, ["--connect-timeout", "2", self.health_url(target)])
                if answer.status:
                    reached.append(f"{network}->{target}")
        for address in addresses_of(self.speech_id).values():
            if tcp_answers(address, self.port):
                reached.append(f"host->{address}")
        expect(not reached, f"N4: reached {reached}")
        self.hold(
            "N4",
            f"the speech service is unreachable by name and address from {others}, "
            "the default bridge and the host",
        )

    def cell_n5(self) -> None:
        address = addresses_of(self.speech_id)[self.topology.issuer]
        answer = self.curl.at(f"container:{self.gateway_id}", [self.health_url(address)])
        expect(answer.status == 200, f"N5: {self.topology.gateway} got {answer.status}")
        self.hold(
            "N5",
            f"{self.topology.gateway}'s namespace reaches {address}:{self.port}/health "
            "(200): the accepted peer",
        )

    # --- E1-E3 -------------------------------------------------------------------------------

    def cell_e1(self) -> None:
        answers = {
            target: self.in_speech(f"https://{target}/", trusted=False)
            for target in (PUBLIC_ADDRESS, PUBLIC_NAME)
        }
        got = {target: (a.exit_code, a.status) for target, a in answers.items()}
        expect(all(a.status == 0 and a.exit_code for a in answers.values()), f"E1: {got}")
        self.hold(
            "E1",
            f"from the speech service a public address and name fail (curl exit, status): {got}",
        )

    def cell_e2(self, listener: HostListener) -> None:
        gateways = {
            c.get("Gateway")
            for name in (*self.topology.callers.values(), self.topology.issuer)
            for c in self.network(name)["IPAM"]["Config"] or []
        } - {None, ""}
        targets = sorted({*gateways, *(str(a) for a in host_addresses())})
        reached = [
            t for t in targets if self.in_speech(plain_http(t, listener.port), trusted=False).status
        ]
        bridge = self.network("bridge")["IPAM"]["Config"][0]["Gateway"]
        control = self.curl.at("bridge", [plain_http(bridge, listener.port)], trusted=False)
        expect(not reached, f"E2: the speech service reached the host listener at {reached}")
        if control.status != 200:
            write_line(E2_LIMIT, flush=True)
            return
        self.hold(
            "E2",
            f"a host listener on :{listener.port} is unreachable from the speech service "
            f"at {targets}; a bridge container reaches it at {bridge} (200)",
        )

    def cell_e3(self) -> None:
        started = time.monotonic()
        docker("restart", self.speech_id)
        wait_healthy(self.speech_id, HEALTHY_SECONDS)
        self.hold(
            "E3",
            f"restarted without egress, healthy again in "
            f"{time.monotonic() - started:.0f} s on the baked models",
        )

    # --- K1-K6, M1 ---------------------------------------------------------------------------

    def cell_k1(self) -> None:
        kids = self.kids(self.in_speech(self.certs_url()))
        expect(kids == self.copy_kids(), f"K1: kids {kids} are not the copy's")
        self.hold(
            "K1",
            f"{self.certs_url()} from the speech service: 200, kids {sorted(kids)} = the "
            "scratch Keycloak's through the copy's edge",
        )

    def k2_rows(self) -> list[tuple[str, str, str]]:
        base = self.certs_path
        realm = base.removesuffix("/protocol/openid-connect/certs")
        token = f"{realm}/protocol/openid-connect/token"
        master = base.replace(realm, "/realms/master")
        return [
            ("GET", base, "certs"),
            ("GET", f"{base}/", "404"),
            ("GET", f"{realm}/.well-known/openid-configuration", "404"),
            ("POST", token, "404"),
            ("GET", master, "404"),
            ("GET", "/admin/", "404"),
            ("GET", f"/admin{realm}", "404"),
            ("GET", f"{base}/../token", "404"),
            ("GET", f"{token}/../certs", "certs"),
            ("GET", f"/{base}", "certs"),
            # an encoded path matches no exact Path rule: Traefik's own 404 (run, not read)
            ("GET", f"{base}%2F..%2Ftoken", "404"),
            ("GET", f"{base}%3Fx", "404"),
            ("GET", f"{base};jsessionid=x", "404"),
            ("GET", f"{base}?x=1", "certs"),
            ("POST", base, "error 405"),
        ]

    def classify(self, answer: Answer) -> str:
        if answer.status == 200 and KEY_SET in answer.body:
            return "certs" if self.kids(answer) == self.copy_kids() else "foreign certs"
        if any(leak in answer.body for leak in LEAKS):
            return f"leak {answer.status}"
        if answer.status == 404 and answer.body == TRAEFIK_404:
            return "404"
        if answer.status == 400:
            return "400"
        if answer.status >= 400 and KEY_SET not in answer.body:
            return f"error {answer.status}"
        return str(answer.status)

    def cell_k2(self) -> None:
        table = []
        for method, path, wanted in self.k2_rows():
            form = (
                ["--data", "grant_type=client_credentials&client_id=probe"]
                if method == "POST"
                else []
            )
            answer = self.in_speech(
                "--path-as-is", "--request", method, *form, self.certs_url(path)
            )
            got = self.classify(answer)
            table.append(f"{method} {path} -> {answer.status} {got}")
            expect(
                got == wanted,
                f"K2: {method} {path} answered {answer.status} as {got}, not {wanted}",
            )
        self.hold("K2", "; ".join(table))

    def cell_k3(self) -> None:
        answers = [
            self.in_speech(plain_http(self.key_set_host, port, self.certs_path), trusted=False)
            for port in (443, 80)
        ]
        got = [(a.exit_code, a.status) for a in answers]
        expect(all(KEY_SET not in a.body for a in answers), f"K3: plain HTTP answered {got}")
        self.hold("K3", f"plain HTTP to {self.topology.gateway} on :443 and :80: no key set {got}")

    def cell_k4(self) -> None:
        by_name = self.in_speech(plain_http(KEYCLOAK_SERVICE, 8080), trusted=False)
        expect(
            by_name.exit_code == NOT_RESOLVED, f"K4: {KEYCLOAK_SERVICE} gave {by_name.exit_code}"
        )
        keycloak = addresses_of(self.project_container(KEYCLOAK_SERVICE)).values()
        database = addresses_of(self.project_container(KEYCLOAK.database)).values()
        targets = [plain_http(a, 8080) for a in keycloak] + [plain_http(a, 5432) for a in database]
        answered = {
            t: a.exit_code
            for t in targets
            if (a := self.in_speech("--connect-timeout", "2", t, trusted=False)).exit_code
            not in NO_TCP
        }
        expect(not answered, f"K4: a TCP answer from {answered}")
        self.hold("K4", f"{KEYCLOAK_SERVICE} does not resolve; no TCP answer on {targets}")

    def cell_k5(self) -> None:
        untrusted = self.in_speech(self.certs_url(), trusted=False)
        expect(
            untrusted.exit_code == TLS_UNTRUSTED, f"K5: without the root curl {untrusted.exit_code}"
        )
        self.hold(
            "K5",
            "TLS verifies with the scratch step-ca root (K1) and is refused without it "
            f"(curl {TLS_UNTRUSTED})",
        )

    def cell_k6(self) -> None:
        """A squatter answering as Keycloak's upstream name on traefik-mcp's other networks, proven
        to answer there, and the key set after traefik-mcp's restart opened fresh connections."""
        t = self.topology
        host, port = self.key_set_upstream
        networks = [n for n in addresses_of(self.gateway_id) if n not in {t.keys, t.issuer}]
        forged = json.dumps({"keys": [{"kid": FORGED_KID, "kty": "RSA", "n": "AQAB", "e": "AQAB"}]})
        with fixed_server(self.app_image, t.project, networks, forged, port=port, alias=host):
            controls = {n: self.answered_within(n, plain_http(host, port)) for n in networks}
            silent = {n: a.status for n, a in controls.items() if a.body != forged.encode()}
            expect(not silent, f"K6: the squatter does not answer as {host} on {silent}")
            docker("restart", self.gateway_id)
            answer = within(RESTARTED_SECONDS, lambda: self.in_speech(self.certs_url()))
        kids = self.kids(answer)
        expect(kids == self.copy_kids(), f"K6: a squatter on {networks} served the kids {kids}")
        self.hold(
            "K6",
            f"a squatter on {networks} answered {host}:{port} there with the kid {FORGED_KID}; "
            f"after a restart of {t.gateway} (no kept upstream connection) the key set from the "
            f"speech service carries Keycloak's kids {sorted(kids)}",
        )

    def cell_m1(self) -> None:
        dynamic = self.copy / "mcp" / "dynamic"
        hosts = sorted(
            {
                found["host"]
                for file in dynamic.glob("*.yml")
                for router in (
                    yaml.safe_load(file.read_text())["http"].get("routers") or {}
                ).values()
                if (found := ROUTER_HOST.search(router["rule"]))
                and found["host"] != self.key_set_host
            }
        )
        address = addresses_of(self.gateway_id)[self.topology.issuer]
        unknown = f"unknown.{self.key_set_host.partition('.')[2]}"
        got = {}
        for host in [*hosts, unknown]:
            answer = self.in_speech(
                "--insecure",
                "--resolve",
                f"{host}:443:{address}",
                f"https://{host}/mcp",
                trusted=False,
            )
            got[host] = answer.status
        configured = {h: s for h, s in got.items() if h != unknown}
        expect(
            all(500 <= s < 600 for s in configured.values()) and got[unknown] == 404, f"M1: {got}"
        )
        self.hold(
            "M1",
            f"from the speech service, traefik-mcp's other routers answer {configured} "
            f"(no backend in the copy), an unknown host {got[unknown]}",
        )


def within(seconds: int, ask: Callable[[], Answer]) -> Answer:
    """The first answer of `ask` with status 200 within `seconds`, else its last one."""
    deadline = time.monotonic() + seconds
    while True:
        answer = ask()
        if answer.status == 200 or time.monotonic() > deadline:
            return answer
        time.sleep(1)


def host_addresses() -> list[ipaddress.IPv4Address]:
    listed = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True, check=True)  # noqa: S603, S607 - fixed argv
    return [ipaddress.ip_interface(line.split()[3]).ip for line in listed.stdout.splitlines()]


def tcp_answers(address: str, port: int) -> bool:
    try:
        with socket.create_connection((address, port), timeout=2):
            return True
    except OSError:
        return False


class HostListener:
    """A fixed-response HTTP listener on every host address for E2, serving no file, under
    `timeout`, its pid in the scratch."""

    def __init__(self, scratch: Path, port: int) -> None:
        self.port, self.pid_file = port, scratch / "e2-listener.pid"
        bind = "0.0.0.0"  # noqa: S104 - E2 needs a listener on every host address
        server = [sys.executable, "-I", "-c", FIXED_RESPONSE_SERVER, bind, "E2", str(port)]
        self.process = subprocess.Popen(  # noqa: S603 - argv built here from fixed words
            ["timeout", "600", *server],  # noqa: S607 - timeout found on PATH
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.pid_file.write_text(f"{self.process.pid}\n")
        for _ in range(50):
            if tcp_answers("127.0.0.1", port):
                return
            time.sleep(0.1)
        self.stop()
        raise ProbeFailed("E2: the host listener did not start")

    def stop(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=10)
        self.pid_file.unlink(missing_ok=True)
