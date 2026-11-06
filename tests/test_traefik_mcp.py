"""traefik-mcp: compose.yaml, traefik-mcp.yml, mcp/dynamic/ and ca.json as files, no containers.

The running TLS path is proven by probe/step-ca/probe.py; these tests pin the facts the probe
cannot see in one run: the three-network split, the one names list, and the lifetime the resolver
assumes of the CA.
"""

import ipaddress
import re
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
NETWORKS = {"mcp-ca", "mcp", "mcp-backends"}
ISOLATED_MODE = {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}
ROUTER_HOST = re.compile(r"^Host\(`([^`]+)`\)")
ROUTER_RULE = re.compile(r"^Host\(`[^`]+`\)( && Path\(`/[^`]*`\))?$")
ROUTER_PATH = re.compile(r"Path\(`([^`]+)`\)")
SPEECH_NETWORK_PREFIX = "hal_speech_"  # speech-runtime's compose joins these names as external
KEY_SET_PATH = "/protocol/openid-connect/certs"  # Keycloak's JWKS path under a realm
CA_DEFAULT_LIFETIME_HOURS = 24  # step-ca's default; ca.json sets no claims


def load(path: str):
    return yaml.safe_load((ROOT / path).read_text())


@pytest.fixture(scope="module")
def compose() -> dict:
    return load("compose.yaml")


@pytest.fixture(scope="module")
def traefik_mcp(compose) -> dict:
    return compose["services"]["traefik-mcp"]


@pytest.fixture(scope="module")
def static_config() -> dict:
    return load("traefik-mcp.yml")


def merged_dynamic(kind: str) -> dict:
    merged = {}
    for file in sorted((ROOT / "mcp" / "dynamic").glob("*.yml")):
        merged.update(yaml.safe_load(file.read_text())["http"][kind])
    return merged


@pytest.fixture(scope="module")
def services() -> dict:
    return merged_dynamic("services")


@pytest.fixture(scope="module")
def routers() -> dict:
    return merged_dynamic("routers")


def members(compose: dict, network: str) -> list[str]:
    return [
        name
        for name, service in compose["services"].items()
        if network in (service.get("networks") or [])
    ]


def speech_networks(compose: dict) -> set[str]:
    """The networks whose fixed name the speech service joins as an external network."""
    return {
        key
        for key, network in compose["networks"].items()
        if (network or {}).get("name", "").startswith(SPEECH_NETWORK_PREFIX)
    }


@pytest.fixture(scope="module")
def key_set_network(compose, traefik_mcp) -> str:
    """The one network Keycloak and traefik-mcp share."""
    (shared,) = set(compose["services"]["keycloak"]["networks"]) & set(traefik_mcp["networks"])
    return shared


@pytest.fixture(scope="module")
def key_set_router(routers, services) -> tuple[dict, SplitResult]:
    """The router whose upstream is the Keycloak service, with that upstream's URL."""
    (found,) = [
        (router, upstream)
        for router in routers.values()
        for server in services[router["service"]]["loadBalancer"]["servers"]
        if (upstream := urlsplit(server["url"])).hostname == "keycloak"
    ]
    return found


def test_the_ca_the_gateway_and_its_helpers_start_only_with_the_step_ca_profile(compose):
    """#48 rule 2: a plain `docker compose up -d` starts none of them."""
    services = ("step-ca", "traefik-mcp", "traefik-mcp-acme-owner", "speech-networks")

    assert {name: compose["services"][name].get("profiles") for name in services} == {
        name: ["step-ca"] for name in services
    }


def test_the_three_mcp_networks_are_internal(compose):
    """#48 rule 1: the three MCP networks have no route out."""

    assert {name: compose["networks"][name].get("internal") for name in NETWORKS} == {
        name: True for name in NETWORKS
    }


def test_the_mcp_network_gets_no_address_on_the_host(compose):
    """#189: the network the agent service joins is isolated, so no host listener is reachable."""

    assert compose["networks"]["mcp"]["driver_opts"] == ISOLATED_MODE


def test_songmakers_mcp_network_is_internal_isolated_and_joined_by_traefik_mcp_alone(compose):
    """P25: hal_mcp_songmaker has no route out and no host address, and no service of the
    stack but traefik-mcp joins it (songmaker-web joins it as an external network)."""

    network = compose["networks"]["mcp-songmaker"]
    members = [
        name
        for name, service in compose["services"].items()
        if "mcp-songmaker" in (service.get("networks") or [])
    ]

    assert network["internal"] is True
    assert network["driver_opts"] == ISOLATED_MODE
    assert members == ["traefik-mcp"]
    assert "aliases" not in (compose["services"]["traefik-mcp"]["networks"]["mcp-songmaker"] or {})


def test_traefik_mcp_is_the_only_service_on_all_three_networks(compose):
    """#48 rule 1: only traefik-mcp bridges the three networks."""

    on_all = [
        name
        for name, service in compose["services"].items()
        if set(service.get("networks") or []) >= NETWORKS
    ]

    assert on_all == ["traefik-mcp"]


def test_traefik_mcp_answers_to_the_same_names_on_mcp_ca_and_mcp(traefik_mcp):
    """#48 rule 1: one alias list serves mcp-ca and mcp, none on mcp-backends."""

    aliases = {
        network: traefik_mcp["networks"][network]["aliases"] for network in ("mcp-ca", "mcp")
    }

    assert aliases["mcp-ca"] == aliases["mcp"]
    assert "aliases" not in traefik_mcp["networks"]["mcp-backends"]


def test_every_alias_is_a_router_host_inside_the_names_the_ca_allows(traefik_mcp, routers):
    """#48 rule 5: aliases, router hosts and the CA policy name the same origins."""

    ca_policy = load("step-ca/ca.json")["authority"]["policy"]["x509"]["allow"]["dns"]
    aliases = set(traefik_mcp["networks"]["mcp"]["aliases"])
    router_hosts = {ROUTER_HOST.match(router["rule"]).group(1) for router in routers.values()}

    assert all(any(fnmatch(alias, pattern) for pattern in ca_policy) for alias in aliases)
    assert router_hosts == aliases
    assert all(any(fnmatch(host, pattern) for host in router_hosts) for pattern in ca_policy)


def test_every_router_matches_one_host_and_at_most_one_exact_path_and_keeps_the_host_header(
    routers, services
):
    """E4: no router takes a path prefix, and no service rewrites the Host header."""
    assert all(ROUTER_RULE.match(router["rule"]) for router in routers.values())
    assert not [router for router in routers.values() if "PathPrefix" in router["rule"]]
    assert not [
        service for service in services.values() if "passHostHeader" in service["loadBalancer"]
    ]


def test_every_router_asks_the_internal_resolver_on_the_mcp_entrypoint(routers, static_config):
    """#48 rule 5: each router takes its certificate from the internal resolver."""

    entrypoint = next(iter(static_config["entryPoints"]))

    assert routers
    for router in routers.values():
        assert router["tls"] == {"certResolver": "internal"}
        assert router["entryPoints"] == [entrypoint]


def test_traefik_mcp_shares_the_public_traefiks_image_and_hardening(compose, traefik_mcp):
    """#48 rule 2b: one image digest and one hardening for both Traefiks."""

    shared = ("image", "user", "read_only", "cap_drop", "security_opt")
    public = compose["services"]["traefik"]

    assert {key: traefik_mcp[key] for key in shared} == {key: public[key] for key in shared}


def test_traefik_mcp_cannot_reach_the_docker_api(traefik_mcp, static_config):
    """#48 rule 2b: no Docker API access (network_mode is pinned by CI)."""

    assert not any(
        "docker.sock" in volume or "socket-proxy" in volume for volume in traefik_mcp["volumes"]
    )
    assert "socket-proxy" not in traefik_mcp.get("depends_on", {})
    assert set(static_config["providers"]) == {"file"}


def test_traefik_mcp_adds_no_capability(traefik_mcp):
    """#48 rule 2b: cap_drop ALL stays, no cap_add (the 443 sysctl is pinned by CI)."""

    assert traefik_mcp["cap_drop"] == ["ALL"]
    assert "cap_add" not in traefik_mcp


def test_the_static_configuration_has_one_entrypoint_and_no_management_api(static_config):
    """#48 rule 3: one entrypoint, no api, ping or metrics."""

    (entrypoint,) = static_config["entryPoints"].values()

    assert "tls" in entrypoint["http"]
    assert not {"api", "ping", "metrics"} & set(static_config)


def test_the_file_provider_reads_a_directory_of_its_own(traefik_mcp, static_config):
    """#48 rule 3: the file provider reads mcp/dynamic, never the public Traefik's directory."""

    directory = static_config["providers"]["file"]["directory"]
    public_directory = load("traefik.yml")["providers"]["file"]["directory"]

    assert f"./mcp/dynamic:{directory}:ro" in traefik_mcp["volumes"]
    assert directory != public_directory


def provisioned_challenges(acme: dict) -> set[str]:
    """The ACME challenge types the resolver is configured for, in the CA provisioner's names."""
    names = {"httpChallenge": "http-01", "dnsChallenge": "dns-01", "tlsChallenge": "tls-alpn-01"}
    return {name for key, name in names.items() if key in acme}


def test_the_internal_resolver_trusts_only_the_cas_root_over_tls_alpn_01(
    compose, static_config, traefik_mcp
):
    """#48 rule 4: the resolver trusts the CA root alone, over TLS-ALPN-01."""

    acme = static_config["certificatesResolvers"]["internal"]["acme"]
    ca_server_host = acme["caServer"].split("/")[2]

    assert ca_server_host == f"step-ca:{load('step-ca/ca.json')['address'].lstrip(':')}"
    assert acme["caSystemCertPool"] is False
    (root_certificate,) = acme["caCertificates"]
    root_secret = Path(root_certificate).name
    assert root_secret in traefik_mcp["secrets"]
    assert "file" in compose["secrets"][root_secret]
    assert provisioned_challenges(acme) == {
        challenge
        for provisioner in load("step-ca/ca.json")["authority"]["provisioners"]
        for challenge in provisioner["challenges"]
    }
    assert provisioned_challenges(acme)
    assert not {"httpChallenge", "dnsChallenge"} & set(acme)


def test_the_resolver_assumes_the_24_hour_lifetime_the_ca_keeps_by_default(static_config):
    """#48 rule 4: certificatesDuration equals step-ca's 24 h lifetime."""

    acme = static_config["certificatesResolvers"]["internal"]["acme"]
    ca = load("step-ca/ca.json")

    assert acme["certificatesDuration"] == CA_DEFAULT_LIFETIME_HOURS
    assert "claims" not in ca["authority"]
    assert all("claims" not in provisioner for provisioner in ca["authority"]["provisioners"])


def test_the_acme_storage_is_a_named_volume_that_traefik_mcp_can_write(
    compose, traefik_mcp, static_config
):
    """#48 rule 4: the ACME storage is a named volume that the gateway's user can write."""

    storage = static_config["certificatesResolvers"]["internal"]["acme"]["storage"]
    owner = compose["services"]["traefik-mcp-acme-owner"]

    assert f"traefik-mcp-acme:{Path(storage).parent}" in traefik_mcp["volumes"]
    assert "traefik-mcp-acme" in compose["volumes"]
    assert owner["entrypoint"] == ["chown", traefik_mcp["user"], str(Path(storage).parent)]
    assert not traefik_mcp["user"].startswith(("0", "root"))
    assert owner["network_mode"] == "none"
    assert traefik_mcp["depends_on"]["traefik-mcp-acme-owner"] == {
        "condition": "service_completed_successfully"
    }


def test_every_speech_network_is_internal_and_gets_no_address_on_the_host(compose):
    """#872: the speech service's networks have no route out and reach no host listener."""
    networks = speech_networks(compose)

    assert networks
    for name in networks:
        assert compose["networks"][name]["internal"] is True
        assert compose["networks"][name]["driver_opts"] == ISOLATED_MODE


def test_traefik_mcp_alone_joins_one_speech_network_under_the_key_set_name_alone(
    compose, traefik_mcp, key_set_router
):
    """#872: on the issuer network the speech service finds traefik-mcp by the key set's host
    and no other name, and no other service of the stack is there."""
    (issuer,) = speech_networks(compose) & set(traefik_mcp["networks"])
    router, _ = key_set_router

    assert members(compose, issuer) == ["traefik-mcp"]
    assert traefik_mcp["networks"][issuer] == {"aliases": [ROUTER_HOST.match(router["rule"])[1]]}


def test_the_other_speech_networks_are_joined_by_a_one_shot_that_traefik_mcp_waits_for(
    compose, traefik_mcp
):
    """#872: each app's speech network exists while step-ca is on, and no running service of the
    stack is on it."""
    app_networks = speech_networks(compose) - set(traefik_mcp["networks"])
    (helper,) = {name for network in app_networks for name in members(compose, network)}
    one_shot = compose["services"][helper]

    assert len(app_networks) >= 2
    assert all(members(compose, network) == [helper] for network in app_networks)
    assert traefik_mcp["depends_on"][helper] == {"condition": "service_completed_successfully"}
    assert one_shot["restart"] == "no"
    assert one_shot["entrypoint"] == ["true"]
    assert "ports" not in one_shot
    assert one_shot["cap_drop"] == ["ALL"]


def test_keycloak_and_traefik_mcp_share_one_internal_isolated_network_alone(
    compose, key_set_network
):
    """#872: no MCP backend reaches Keycloak's port; only traefik-mcp does."""
    network = compose["networks"][key_set_network]

    assert sorted(members(compose, key_set_network)) == ["keycloak", "traefik-mcp"]
    assert network["internal"] is True
    assert network["driver_opts"] == ISOLATED_MODE


def test_traefik_mcp_finds_keycloak_at_its_pinned_address_never_by_dns(
    compose, traefik_mcp, key_set_network, key_set_router
):
    """#872: the key set's upstream name resolves through extra_hosts to Keycloak's pinned
    address, which the network's dynamic range never hands to another container."""
    _, upstream = key_set_router
    pinned = compose["services"]["keycloak"]["networks"][key_set_network]["ipv4_address"]
    (config,) = compose["networks"][key_set_network]["ipam"]["config"]
    address = ipaddress.ip_address(pinned)

    assert traefik_mcp["extra_hosts"][upstream.hostname] == pinned
    assert address in ipaddress.ip_network(config["subnet"])
    assert address not in ipaddress.ip_network(config["ip_range"])


def test_the_key_set_router_serves_only_the_realms_key_set_on_keycloaks_http_port(
    compose, key_set_router
):
    """#872: one exact path, the key set of the realm hal ships, to the port Traefik reaches
    Keycloak on."""
    router, upstream = key_set_router
    realm = load("keycloak/realm.yaml")["realm"]
    labels = compose["services"]["keycloak"]["labels"]

    assert ROUTER_PATH.search(router["rule"])[1] == f"/realms/{realm}{KEY_SET_PATH}"
    assert str(upstream.port) == labels["traefik.http.services.auth.loadbalancer.server.port"]
