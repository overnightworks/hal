"""The /24s a probe's copy or overlay of compose.yaml pins (#872): probe/edge_subnets.py's rule and
every copy writer of the probes, which must keep each pinned network off the live stack's /24; and
the app H's copy runs, which joins only the copy's own speech networks (probe/speech)."""

import ipaddress
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
import support.keycloak_probe as keycloak_support
import support.probe_modules as probe_modules
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "probe"))
sys.path.insert(0, str(ROOT / "src"))

import edge_copy  # noqa: E402
import edge_subnets  # noqa: E402
from support.script_module import loaded_script  # noqa: E402

from hal.stack import catalog  # noqa: E402

PROJECT = "edge-some-probe"
SHIPPED_COMPOSE = (ROOT / "compose.yaml").read_text()
IPV4 = re.compile(r"\b\d+\.\d+\.\d+\.\d+\b")
# The Keycloak probe's module and the docker host it runs on, and the probes this file loads: the
# support modules' fixtures.
keycloak_probe, docker_host = keycloak_support.probe, keycloak_support.docker_host
step_ca_probe, egress_probe = probe_modules.step_ca_probe, probe_modules.egress_probe


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


def a_copys_daemon(directory: Path, monkeypatch: pytest.MonkeyPatch, networks: dict[str, str]):
    """probe_modules.a_daemon, with no live network for a copy's checks to find."""
    probe_modules.a_daemon(directory, monkeypatch, networks)
    monkeypatch.setattr(edge_copy, "live_networks", set)


@pytest.fixture(scope="module")
def copy_isolation(keycloak_probe) -> Iterator:
    yield from loaded_script("copy_isolation", ROOT / "probe" / "keycloak" / "copy_isolation.py")


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
    a_copys_daemon(tmp_path / "daemon", monkeypatch, taken)

    text, project = write_copy(request, tmp_path / "first")
    assert_beside_the_live_stack(text, project, list(taken))

    own = {str(subnet): project for subnet in subnets_of(yaml.safe_load(text))}
    a_copys_daemon(tmp_path / "daemon-with-the-copy", monkeypatch, taken | own)
    again, _ = write_copy(request, tmp_path / "again")
    assert subnets_of(yaml.safe_load(again)) == subnets_of(yaml.safe_load(text))


def test_a_copy_that_would_keep_a_pin_the_probe_does_not_hold_is_refused():
    with pytest.raises(edge_copy.ProbeFailed, match="does not hold"):
        edge_copy.compose_beside_the_live_stack(SHIPPED_COMPOSE, PROJECT, {})


def test_the_keycloak_probe_moves_keycloaks_networks_and_pinned_address_onto_free_subnets(
    keycloak_probe, tmp_path, monkeypatch
):
    taken = {edge_subnets.PROBE_SUBNETS[0]: "another-project"}
    probe_modules.a_daemon(tmp_path / "daemon", monkeypatch, taken)
    stack = keycloak_probe.Stack(tmp_path / "scratch")

    # compose's `!override` tag says only how the overlay's values merge
    overlay = yaml.safe_load(stack.network_overlay.read_text().replace("!override", ""))

    moved = {stack.keycloak_subnet, stack.key_set_subnet}
    assert len(moved) == 2
    assert {str(subnet) for subnet in subnets_of(overlay)} == moved
    assert not moved & set(taken)
    assert_pins_moved_off(overlay, yaml.safe_load(SHIPPED_COMPOSE))


OCCUPIED = ["172.31.250.0/24", "172.31.251.0/24", "10.0.0.0/8"]
CANDIDATES = ["172.31.250.0/24", "172.31.251.0/24", "172.31.249.0/24"]


def test_the_first_candidate_that_overlaps_no_occupied_subnet_is_free():
    assert str(edge_subnets.free_subnet(CANDIDATES, OCCUPIED)) == "172.31.249.0/24"


def test_a_candidate_inside_a_wider_occupied_subnet_is_taken():
    with pytest.raises(ValueError, match="no free /24"):
        edge_subnets.free_subnet(CANDIDATES, ["172.31.0.0/16"])


COPY_PROJECT = "edge-kc-in-copy"
APP_KEY = f"{COPY_PROJECT}-speech"


@pytest.fixture(scope="module")
def app_isolation(copy_isolation) -> Iterator:
    yield from loaded_script("app_isolation", ROOT / "probe" / "speech" / "app_isolation.py")


def test_the_copys_fleet_runs_the_stands_app_alone_and_refuses_another(copy_isolation):
    entry = f"  {APP_KEY}:\n    repo: {{default_branch: main}}\n    run: {{enabled: true}}\n"
    fleet = copy_isolation.Fleet(frozenset({"keycloak"}), {APP_KEY: SimpleNamespace(entry=entry)})
    stand = SimpleNamespace(fleet=fleet)
    text = copy_isolation.probe_fleet((ROOT / "fleet.yaml").read_text(), stand)
    apps = {key for key, one in catalog.parse(text.encode())["services"].items()
            if catalog.is_app(one)}  # fmt: skip
    assert apps == {APP_KEY}
    other = "  other-app:\n    repo: {default_branch: main}\n    run: {enabled: true}\n"
    with pytest.raises(edge_copy.ProbeFailed, match=r"has the apps \['other-app'\]"):
        copy_isolation.expect_fleet_isolated(text + other, stand)


def a_release(home: Path) -> dict:
    """A resolved app configuration on the copy's speech networks with its secret in the HOME."""
    return {
        "services": {"speech": {"networks": {"issuer": None}, "secrets": [{"source": "root"}]}},
        "networks": {"issuer": {"name": f"{COPY_PROJECT}_speech_issuer", "external": True}},
        "secrets": {"root": {"file": str(home / ".secrets" / "root.crt")}},
    }


def on_network_mode(mode: str):
    """The service on `mode` instead of its networks, as Compose resolves a `network_mode`."""

    def change(resolved: dict) -> None:
        speech = resolved["services"]["speech"]
        del speech["networks"]
        speech["network_mode"] = mode

    return change


def with_volume(name: str, **declared: object):
    """The service mounting a top-level volume that resolves to `name`."""

    def change(resolved: dict) -> None:
        resolved["volumes"] = {"data": {"name": name, **declared}}
        mount = {"type": "volume", "source": "data", "target": "/data"}
        resolved["services"]["speech"]["volumes"] = [mount]

    return change


def live_edge_name() -> str:
    shipped = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]["keycloak"]
    return shipped["labels"]["edge.name"]


APP_REFUSALS = {
    "a published port": (lambda r: r["services"]["speech"].update(ports=[{"target": 8080}]),
                         "publish a host port"),
    "the host network": (lambda r: r["services"]["speech"].update(network_mode="host"),
                         "host network"),
    "a live container's network": (lambda r: r["services"]["speech"].update(
        network_mode="container:hal-traefik-1"), "outside the copy"),
    "a fixed name outside the project": (lambda r: r["services"]["speech"].update(
        container_name="hal-speech"), "outside the copy"),
    "a bind outside the HOME": (lambda r: r["services"]["speech"].update(volumes=[
        {"type": "bind", "source": "/srv", "target": "/srv"}]), "outside the scratch HOME"),
    "the docker socket": (lambda r: r["services"]["speech"].update(volumes=[{"type": "bind",
        "source": "/var/run/docker.sock", "target": "/s"}]), "docker socket"),
    "a secret file outside the HOME": (lambda r: r["secrets"]["root"].update(
        file="/etc/hostname"), "outside the scratch HOME"),
    "privileged": (lambda r: r["services"]["speech"].update(privileged=True), "widen"),
    "the live speech network": (lambda r: r["networks"]["issuer"].update(
        name="hal_speech_issuer"), "networks not the copy's"),
    "a network compose creates": (lambda r: r["networks"]["issuer"].pop("external"),
                                  "networks not the copy's"),
    "a live edge name": (lambda r: r["services"]["speech"].update(
        labels={"edge.name": live_edge_name()}), "would route"),
    "the default bridge by network_mode": (on_network_mode("bridge"), "network_mode"),
    "no network by network_mode": (on_network_mode("none"), "network_mode"),
    "an app service's namespace": (on_network_mode("service:speech"), "network_mode"),
    "a live network by network_mode": (on_network_mode("hal_keycloak"), "network_mode"),
    "no declared network": (lambda r: r["services"]["speech"].pop("networks"),
                            "default bridge"),
    "a live external volume": (with_volume("hal_keycloak-db", external=True),
                               "volumes outside"),
    "another project's volume": (with_volume("other_models"), "volumes outside"),
    "a copy's speech name compose would create": (with_volume(f"{COPY_PROJECT}_speech_models"),
                                                  "volumes outside"),
}  # fmt: skip

APP_VOLUMES = {
    "its own project's volume": with_volume(f"{APP_KEY}_models"),
    "an external volume of the copy's speech names": with_volume(
        f"{COPY_PROJECT}_speech_models", external=True),
}  # fmt: skip


def test_the_apps_release_on_the_copys_speech_networks_passes(app_isolation, tmp_path):
    checked = app_isolation.expect_app_config_isolated(
        a_release(tmp_path), APP_KEY, COPY_PROJECT, tmp_path
    )
    assert checked == 1


@pytest.mark.parametrize("change", APP_VOLUMES.values(), ids=APP_VOLUMES)
def test_an_app_volume_named_inside_the_app_or_the_copys_speech_names_passes(
    app_isolation, tmp_path, change
):
    resolved = a_release(tmp_path)
    change(resolved)
    assert app_isolation.expect_app_config_isolated(resolved, APP_KEY, COPY_PROJECT, tmp_path) == 1


@pytest.mark.parametrize("change, reason", APP_REFUSALS.values(), ids=APP_REFUSALS)
def test_an_app_configuration_that_reaches_beyond_the_copy_is_refused(
    app_isolation, tmp_path, change, reason
):
    resolved = a_release(tmp_path)
    change(resolved)
    with pytest.raises(edge_copy.ProbeFailed, match=reason):
        app_isolation.expect_app_config_isolated(resolved, APP_KEY, COPY_PROJECT, tmp_path)
