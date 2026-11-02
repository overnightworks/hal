"""The agents client of keycloak/realm.yaml against fleet.yaml: each app's MCP group, scope and
audience hold together, and the client keeps the settings its rulings name."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from hal.stack import catalog

REPOSITORY = Path(__file__).resolve().parents[1]
AGENTS = "agents"


def read(name: str) -> dict[str, Any]:
    return yaml.safe_load((REPOSITORY / name).read_text())


def agents_client(realm: dict[str, Any]) -> dict[str, Any]:
    return next(client for client in realm["clients"] if client["clientId"] == AGENTS)


def app_groups(realm: dict[str, Any]) -> dict[str, list[str]]:
    apps = next(group for group in realm["groups"] if group["name"] == "apps")
    return {
        app["name"]: [child["name"] for child in app.get("subGroups", [])]
        for app in apps["subGroups"]
    }


def mcp_audiences(scope: dict[str, Any]) -> list[str]:
    return [
        mapper["config"]["included.custom.audience"]
        for mapper in scope.get("protocolMappers", [])
        if mapper["protocolMapper"] == "oidc-audience-mapper"
    ]


def mcp_problems(realm: dict[str, Any], fleet: dict[str, Any]) -> list[str]:
    """What breaks an app's MCP front: no group, no optional scope, or an audience that is not
    the app's `/mcp` address."""
    scopes = {scope["name"]: scope for scope in realm["clientScopes"]}
    optional = agents_client(realm)["optionalClientScopes"]
    zone = catalog.zone(fleet)
    problems = []
    for app, children in app_groups(realm).items():
        scope = f"mcp-{app}"
        host = fleet["services"][app]["hosts"][0]["name"]
        if "mcp" not in children:
            problems.append(f"/apps/{app} has no mcp subgroup")
        if scope not in optional:
            problems.append(f"{AGENTS} does not offer {scope}")
        expected = [f"https://{catalog.fqdn_of(host, zone)}/mcp"]
        if mcp_audiences(scopes.get(scope, {})) != expected:
            problems.append(f"{scope} does not name the audience {expected}")
    return problems


def test_each_app_has_its_group_scope_and_audience() -> None:
    assert mcp_problems(read("keycloak/realm.yaml"), read("fleet.yaml")) == []


def test_a_wrong_host_in_the_catalog_fails_the_relation() -> None:
    fleet = read("fleet.yaml")
    fleet["services"]["hopin"]["hosts"][0]["name"] = "elsewhere"

    assert mcp_problems(read("keycloak/realm.yaml"), fleet) == [
        "mcp-hopin does not name the audience ['https://elsewhere.hallucinai.de/mcp']"
    ]


@pytest.mark.parametrize("app", ["songmaker", "presentator", "hopin"])
def test_a_scope_that_is_not_offered_fails_the_relation(app: str) -> None:
    realm = read("keycloak/realm.yaml")
    offered = agents_client(realm)["optionalClientScopes"]
    offered.remove(f"mcp-{app}")

    assert mcp_problems(realm, read("fleet.yaml")) == [f"{AGENTS} does not offer mcp-{app}"]


def test_the_client_is_public_with_the_rulings_settings() -> None:
    client = agents_client(read("keycloak/realm.yaml"))
    attributes = client["attributes"]

    assert client["publicClient"] is True
    assert "secret" not in client
    assert "access.token.lifespan" not in attributes
    assert attributes["use.refresh.tokens"] == "false"
    assert attributes["pkce.code.challenge.method"] == "S256"
    assert client["consentRequired"] is True
