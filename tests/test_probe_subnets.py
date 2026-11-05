"""The /24s a probe's copy or overlay of compose.yaml pins (#872): probe/edge_subnets.py's rule and
every copy writer of the probes, which must keep each pinned network off the live stack's /24."""

import ipaddress
import json
import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
import support.keycloak_probe as keycloak_support
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "probe"))
sys.path.insert(0, str(ROOT / "src"))

import edge_copy  # noqa: E402
import edge_subnets  # noqa: E402
from support.script_module import loaded_script  # noqa: E402

from hal.backup.docker import PROJECT_LABEL  # noqa: E402

PROJECT = "edge-some-probe"
SHIPPED_COMPOSE = (ROOT / "compose.yaml").read_text()
IPV4 = re.compile(r"\b\d+\.\d+\.\d+\.\d+\b")
# The Keycloak probe's module and the docker host it runs on: the support module's fixtures.
keycloak_probe, docker_host = keycloak_support.probe, keycloak_support.docker_host


def subnets_of(compose: dict) -> list[ipaddress.IPv4Network]:
    return [
        ipaddress.IPv4Network(config["subnet"])
        for network in compose["networks"].values()
        for config in ((network or {}).get("ipam") or {}).get("config", [])
    ]


def pinned_addresses(compose: dict) -> dict[str, set[str]]:
    """Each network on which a service holds a fixed address, with those addresses."""
    pinned: dict[str, set[str]] = {}
    for service in compose["services"].values():
        networks = service.get("networks")
        for network, joined in networks.items() if isinstance(networks, dict) else ():
            if (joined or {}).get("ipv4_address"):
                pinned.setdefault(network, set()).add(joined["ipv4_address"])
    return pinned


def assert_pins_moved_off(moved: dict, shipped: dict) -> None:
    """Each network of `moved` that pins an address lies off every subnet of `shipped` and holds
    its addresses, and each extra_hosts entry of `moved` names one of them."""
    addresses = pinned_addresses(moved)
    assert addresses
    for network, members in addresses.items():
        (config,) = moved["networks"][network]["ipam"]["config"]
        subnet = ipaddress.IPv4Network(config["subnet"])
        assert not any(subnet.overlaps(live) for live in subnets_of(shipped)), network
        assert all(ipaddress.ip_address(member) in subnet for member in members), network
    named = {a for s in moved["services"].values() for a in (s.get("extra_hosts") or {}).values()}
    assert named
    assert named <= set().union(*addresses.values())


def assert_beside_the_live_stack(text: str, project: str, taken: list[str]) -> None:
    """The copy pins a /24 for each the shipped file pins, none a shipped or `taken` one; names no
    address of a shipped /24; holds each pinned and extra_hosts address on its moved network; and
    names each fixed network and volume inside `project`."""
    copy, shipped = yaml.safe_load(text), yaml.safe_load(SHIPPED_COMPOSE)
    live, moved = subnets_of(shipped), subnets_of(copy)
    occupied = [*live, *map(ipaddress.IPv4Network, taken)]
    assert len(moved) == len(live)
    assert not [subnet for subnet in moved if any(subnet.overlaps(o) for o in occupied)]
    named = {ipaddress.ip_address(address) for address in IPV4.findall(text)}
    assert not [address for address in named if any(address in subnet for subnet in live)]
    assert_pins_moved_off(copy, shipped)
    assert all(name.startswith(f"{project}_") for name in edge_copy.fixed_names(text))


def a_daemon(directory: Path, monkeypatch: pytest.MonkeyPatch, networks: dict[str, str]) -> None:
    """A docker executable on PATH whose daemon holds `networks`, each subnet with the compose
    project that made it."""
    directory.mkdir()
    listed, inspected = directory / "ids", directory / "inspect.json"
    listed.write_text("".join(f"{subnet}\n" for subnet in networks))
    inspected.write_text(json.dumps([
        {"Labels": {PROJECT_LABEL: project}, "IPAM": {"Config": [{"Subnet": subnet}]}}
        for subnet, project in networks.items()
    ]))  # fmt: skip
    docker = directory / "docker"
    docker.write_text(
        f'#!/bin/sh\ncase "$*" in\n  "network ls -q") cat "{listed}" ;;\n'
        f'  "network inspect "*) cat "{inspected}" ;;\n  *) exit 1 ;;\nesac\n'
    )
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(edge_copy, "live_networks", set)


@pytest.fixture(scope="module")
def step_ca_probe() -> Iterator:
    yield from loaded_script("step_ca_probe", ROOT / "probe" / "step-ca" / "probe.py")


@pytest.fixture(scope="module")
def copy_isolation(keycloak_probe) -> Iterator:
    yield from loaded_script("copy_isolation", ROOT / "probe" / "keycloak" / "copy_isolation.py")


@pytest.fixture(scope="module")
def egress_probe() -> Iterator:
    path_before = list(sys.path)  # egress.py inserts its own directories
    yield from loaded_script("egress_probe", ROOT / "probe" / "agent-service" / "egress.py")
    sys.path[:] = path_before


def step_ca_copy(request: pytest.FixtureRequest, scratch: Path) -> tuple[str, str]:
    probe = request.getfixturevalue("step_ca_probe")
    return probe.Probe(scratch).compose_file.read_text(), probe.PROJECT


def repository_copy_compose(_: pytest.FixtureRequest, scratch: Path) -> tuple[str, str]:
    scratch.mkdir()  # the file every repository_copy writes, litellm_unit's among them
    return edge_copy.write_namespaced_compose(ROOT, scratch, PROJECT).read_text(), PROJECT


def in_copy_install(request: pytest.FixtureRequest, _: Path) -> tuple[str, str]:
    isolation = request.getfixturevalue("copy_isolation")
    stand = SimpleNamespace(isolation=isolation.Isolation.allocate(PROJECT, SHIPPED_COMPOSE))
    return isolation.isolated_compose(SHIPPED_COMPOSE, stand), PROJECT


def egress_copy(request: pytest.FixtureRequest, scratch: Path) -> tuple[str, str]:
    egress = request.getfixturevalue("egress_probe")
    scratch.mkdir()
    probe = egress.Probe(scratch)
    probe.write_on_probe_subnet(egress.COMPOSE_FILE, probe.compose_file)
    return probe.compose_file.read_text(), egress.PROJECT


@pytest.mark.parametrize(
    "write_copy", [step_ca_copy, repository_copy_compose, in_copy_install, egress_copy],
    ids=["step-ca", "repository_copy", "in_copy install", "egress"],
)  # fmt: skip
def test_a_probes_copy_of_compose_takes_free_subnets_and_the_same_again_beside_its_own(
    request, tmp_path, monkeypatch, write_copy
):
    taken = {edge_subnets.PROBE_SUBNETS[0]: "another-project"}
    a_daemon(tmp_path / "daemon", monkeypatch, taken)

    text, project = write_copy(request, tmp_path / "first")
    assert_beside_the_live_stack(text, project, list(taken))

    own = {str(subnet): project for subnet in subnets_of(yaml.safe_load(text))}
    a_daemon(tmp_path / "daemon-with-the-copy", monkeypatch, taken | own)
    again, _ = write_copy(request, tmp_path / "again")
    assert subnets_of(yaml.safe_load(again)) == subnets_of(yaml.safe_load(text))


def test_a_copy_that_would_keep_a_pin_the_probe_does_not_hold_is_refused():
    with pytest.raises(edge_copy.ProbeFailed, match="does not hold"):
        edge_copy.compose_beside_the_live_stack(SHIPPED_COMPOSE, PROJECT, {})


def test_the_keycloak_probe_moves_keycloaks_networks_and_pinned_address_onto_its_own_subnets(
    keycloak_probe, docker_host, tmp_path
):
    stack = keycloak_probe.Stack(tmp_path)

    # compose's `!override` tag says only how the overlay's values merge
    overlay = yaml.safe_load(stack.network_overlay.read_text().replace("!override", ""))

    taken = {stack.keycloak_subnet, stack.key_set_subnet}
    assert len(taken) == 2
    assert {str(subnet) for subnet in subnets_of(overlay)} == taken
    assert_pins_moved_off(overlay, yaml.safe_load(SHIPPED_COMPOSE))


OCCUPIED = ["172.31.250.0/24", "172.31.251.0/24", "10.0.0.0/8"]
CANDIDATES = ["172.31.250.0/24", "172.31.251.0/24", "172.31.249.0/24"]


def test_the_first_candidate_that_overlaps_no_occupied_subnet_is_free():
    assert str(edge_subnets.free_subnet(CANDIDATES, OCCUPIED)) == "172.31.249.0/24"


def test_a_candidate_inside_a_wider_occupied_subnet_is_taken():
    with pytest.raises(ValueError, match="no free /24"):
        edge_subnets.free_subnet(CANDIDATES, ["172.31.0.0/16"])
