"""Keycloak as a catalog unit (#64): the repository's real fleet.yaml and compose.yaml."""

import copy
import dataclasses
import json
import re
import subprocess
from importlib import metadata
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
import yaml

from hal.stack import appkit_step, catalog, compose, legal_section, unit_plans
from hal.stack.realm import reconcile

REPOSITORY = Path(__file__).resolve().parents[1]
KEYCLOAK_SERVICES = ("keycloak-db", "keycloak")
CLIENT_SECRET_REFERENCE = re.compile(r"\$\(env:(\w+)\)")


def compose_document() -> dict:
    return yaml.safe_load((REPOSITORY / "compose.yaml").read_text())


def resolved_like_compose(document: dict) -> dict:
    """compose.yaml with the short volume syntax spelled out, as `docker compose config` does."""
    services = {}
    for name, service in document["services"].items():
        mounts = [
            {"type": "volume", "source": mount.split(":")[0]}
            for mount in service.get("volumes", [])
            if isinstance(mount, str) and mount.split(":")[0] in document.get("volumes", {})
        ]
        services[name] = {**service, "volumes": mounts}
    return {"services": services}


@pytest.fixture(scope="module")
def keycloak_unit() -> catalog.Unit:
    profiles = compose.profile_services(compose_document())
    units = catalog.load(REPOSITORY, profiles)
    return next(unit for unit in units if unit.key == "keycloak")


@pytest.fixture
def keycloak_unit_off(keycloak_unit) -> catalog.Unit:
    return dataclasses.replace(keycloak_unit, enabled=False)


def test_switching_keycloak_off_names_its_database_volume_as_staying(keycloak_unit_off):
    """#64 rule 4: switching Keycloak off stops both services and keeps its database volume."""
    document = resolved_like_compose(compose_document())
    profiles = compose.profile_services(document)
    running = {name: {"running"} for name in KEYCLOAK_SERVICES}

    plans = unit_plans.plan_switches([keycloak_unit_off], profiles, document, running, {})

    assert [(plan.action, plan.services, plan.volumes) for plan in plans] == [
        (unit_plans.Action.OFF, KEYCLOAK_SERVICES, ("keycloak-db",))
    ]


def test_keycloak_that_is_off_and_gone_needs_no_change(keycloak_unit_off):
    """#64 rules 1 and 5: Keycloak that is off and not running needs no change."""
    document = resolved_like_compose(compose_document())
    profiles = compose.profile_services(document)

    assert unit_plans.plan_switches([keycloak_unit_off], profiles, document, {}, {}) == []


def client_secret_problems(realm: dict, compose_file: dict, overlay: dict) -> list[str]:
    """What is wrong between a client secret in realm.yaml and the compose secret feeding it."""
    mounted = {
        secret["target"]: secret["source"]
        for secret in compose_file["services"]["keycloak-config-cli"]["secrets"]
        if isinstance(secret, dict)
    }
    problems = []
    for client in realm["clients"]:
        reference = CLIENT_SECRET_REFERENCE.fullmatch(client.get("secret", ""))
        if reference is None:
            continue
        variable, name = reference.group(1), client["clientId"]
        source = mounted.get(variable)
        expected_file = f"${{HOME}}/.secrets/keycloak/clients/{name}"
        if source is None:
            problems.append(f"{name}: keycloak-config-cli has no secret with target {variable}")
        elif compose_file["secrets"][source]["file"] != expected_file:
            problems.append(f"{name}: secret {source} is not the file {expected_file}")
        elif source not in overlay["secrets"]:
            problems.append(f"{name}: the probe overlay does not override secret {source}")
        elif overlay["secrets"][source].get("file") != f"${{PROBE_SECRETS_DIR}}/clients/{name}":
            problems.append(f"{name}: the probe overlay does not mount its scratch file")
    return problems


def drop_mount(realm: dict, compose_file: dict, overlay: dict) -> None:
    secrets = compose_file["services"]["keycloak-config-cli"]["secrets"]
    secrets.remove(next(s for s in secrets if s["target"] == "SONGMAKER_CLIENT_SECRET"))


def drop_override(realm: dict, compose_file: dict, overlay: dict) -> None:
    del overlay["secrets"]["keycloak_client_songmaker"]


def override_with_production_path(realm: dict, compose_file: dict, overlay: dict) -> None:
    overlay["secrets"]["keycloak_client_songmaker"]["file"] = (
        "${HOME}/.secrets/keycloak/clients/songmaker"
    )


def override_without_file(realm: dict, compose_file: dict, overlay: dict) -> None:
    overlay["secrets"]["keycloak_client_songmaker"] = {}


def move_file(realm: dict, compose_file: dict, overlay: dict) -> None:
    compose_file["secrets"]["keycloak_client_songmaker"]["file"] = "${HOME}/.secrets/elsewhere"


def test_every_client_secret_in_realm_yaml_has_a_mount_a_file_and_a_probe_override():
    """#108 T11 (rule 5): a client secret reaches keycloak-config-cli from its own file, and
    the probe never mounts the operator's file."""
    realm = yaml.safe_load((REPOSITORY / "keycloak/realm.yaml").read_text())
    overlay = yaml.safe_load((REPOSITORY / "probe/keycloak/compose.probe.yaml").read_text())

    assert client_secret_problems(realm, compose_document(), overlay) == []
    assert any(CLIENT_SECRET_REFERENCE.fullmatch(c.get("secret", "")) for c in realm["clients"])


@pytest.mark.parametrize(
    "break_wiring",
    [drop_mount, drop_override, override_with_production_path, override_without_file, move_file],
)
def test_a_client_secret_without_its_mount_file_or_probe_override_is_named(break_wiring):
    """#108 T11 (rule 5): the cross-check goes red when a client secret's wiring is incomplete."""
    realm = yaml.safe_load((REPOSITORY / "keycloak/realm.yaml").read_text())
    overlay = yaml.safe_load((REPOSITORY / "probe/keycloak/compose.probe.yaml").read_text())
    compose_file = copy.deepcopy(compose_document())
    break_wiring(realm, compose_file, overlay)

    assert len(client_secret_problems(realm, compose_file, overlay)) == 1


@pytest.mark.parametrize("realm_setting", ["loginTheme", "accountTheme"])
def test_each_realm_theme_is_mounted_read_only_on_keycloak_only(realm_setting):
    """#105 rule 1, cell T2: a realm theme is mounted on keycloak only."""
    realm = yaml.safe_load((REPOSITORY / "keycloak" / "realm.yaml").read_text())
    theme = realm[realm_setting]
    document = compose_document()
    mount = f"./keycloak/themes/{theme}:/opt/keycloak/themes/{theme}:ro"
    mounted_on = [
        name
        for name, service in document["services"].items()
        if mount in service.get("volumes", [])
    ]

    assert mounted_on == ["keycloak"]


def test_keycloaks_gzip_cache_is_a_tmpfs_owned_by_its_user_so_a_restart_empties_it():
    """A bare tmpfs comes back root-owned after a restart and Keycloak then answers 404 for gzip."""
    tmpfs = compose_document()["services"]["keycloak"]["tmpfs"]
    _, _, options = tmpfs[0].partition(":")
    options = options.split(",")

    assert ("uid=1000" in options, "mode=0700" in options) == (True, True)


def theme_properties(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    return dict(line.split("=", 1) for line in lines)


THEME_AREAS = ("login", "account")
PARENT_STYLESHEET = "css/styles.css"  # keycloak.v2's, in the image; a child's `styles=` replaces it


def theme_styles(area: str) -> list[str]:
    properties = REPOSITORY / "keycloak/themes/hallucinai" / area / "theme.properties"
    return theme_properties(properties)["styles"].split()


@pytest.mark.parametrize("area", THEME_AREAS)
def test_a_theme_loads_the_pinned_appkit_stylesheet_first_and_every_other_entry_resolves(area):
    """#532: appkit's tokens and fonts come first; an appkit bump that deletes the old target
    cannot leave `styles=` dangling."""
    resources = REPOSITORY / "keycloak/themes/hallucinai" / area / "resources"
    first, *others = theme_styles(area)

    assert first == f"appkit-{metadata.version(appkit_step.DISTRIBUTION)}/appkit.css"
    assert all((resources / entry).is_file() or entry == PARENT_STYLESHEET for entry in others)


def test_no_tracked_theme_stylesheet_carries_a_font_face_or_a_family_token():
    """#532: the tokens and fonts have one owner, appkit. Tracked files only: the written
    `appkit-*/appkit.css` is git-ignored and does hold them."""
    tracked = subprocess.run(
        ["git", "ls-files", "keycloak/themes"],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    stylesheets = [REPOSITORY / name for name in tracked if name.endswith(".css")]
    family_token = re.compile(
        r"(?<![\w-])--(?:h-)?(?:bg|bg-deep|surface|surface-hover|border|text|text-muted|card-bg|header-bg|font-display|font-body)\s*:"
    )

    assert stylesheets
    assert [
        path.name
        for path in stylesheets
        if "@font-face" in path.read_text() or family_token.search(path.read_text())
    ] == []
    assert not [
        name for name in tracked if name.endswith((".woff2", "OFL-oswald.txt", "OFL-open-sans.txt"))
    ]


def test_the_apps_are_listed_in_the_account_console_only_for_people_who_used_them():
    """#205 rule 5: no app client is shown to everyone; Keycloak lists the apps a person used."""
    realm = yaml.safe_load((REPOSITORY / "keycloak/realm.yaml").read_text())
    apps = [client for client in realm["clients"] if client.get("standardFlowEnabled")]

    assert apps
    assert [client["clientId"] for client in apps if client["alwaysDisplayInConsole"]] == []


@pytest.mark.parametrize("app", ["songmaker", "hopin", "presentator"])
def test_an_app_back_channel_is_an_internal_isolated_network_only_keycloak_joins(app):
    """#293, #254: the app joins the fixed name as an external network; only keycloak is on it."""
    document = compose_document()
    network = document["networks"][f"backchannel-{app}"]
    members = [
        name
        for name, service in document["services"].items()
        if f"backchannel-{app}" in service.get("networks", [])
    ]

    assert network["internal"] is True
    assert network["driver_opts"] == document["x-isolated-bridge"]
    assert members == ["keycloak"]


def test_no_service_but_keycloak_joins_any_back_channel_network():
    """#382 cell 2 (#254 invariant): Keycloak is the only edge member of a back-channel network."""
    document = compose_document()
    back_channels = {name for name in document["networks"] if name.startswith("backchannel-")}

    joiners = {
        name
        for name, service in document["services"].items()
        if back_channels & set(service.get("networks", []))
    }

    assert joiners == {"keycloak"}


def test_keycloak_trusts_forwarded_from_its_own_network_only():
    """#382 cell 3: Keycloak trusts forwarded headers from its own network only."""
    document = compose_document()
    keycloak = document["services"]["keycloak"]

    assert (
        keycloak["environment"]["KC_PROXY_TRUSTED_ADDRESSES"]
        == document["networks"]["keycloak"]["ipam"]["config"][0]["subnet"]
    )


def test_the_probe_overlay_renames_every_fixed_back_channel_network_keycloak_joins():
    """#382: a name left fixed would make the probe create the live `hal_backchannel_*` network."""
    document = compose_document()
    overlay = yaml.safe_load((REPOSITORY / "probe/keycloak/compose.probe.yaml").read_text())
    joined = [
        name
        for name in document["services"]["keycloak"]["networks"]
        if name.startswith("backchannel-")
    ]

    assert joined
    for name in joined:
        app = name.removeprefix("backchannel-")
        assert overlay["networks"][name]["name"] == f"${{COMPOSE_PROJECT_NAME}}_backchannel_{app}"


def realm_clients() -> dict[str, dict]:
    realm = yaml.safe_load((REPOSITORY / "keycloak/realm.yaml").read_text())
    return {client["clientId"]: client for client in realm["clients"]}


def clients_with_a_back_channel_logout_address() -> dict[str, dict]:
    return {
        client_id: client
        for client_id, client in realm_clients().items()
        if "backchannel.logout.url" in client.get("attributes", {})
    }


def test_a_back_channel_logout_call_needs_no_session_id():
    """#293: webauth ends every session of the subject and ignores `sid`, so a client that
    requires one would never be logged out."""
    attributes = [
        client["attributes"]
        for client in realm_clients().values()
        if "backchannel.logout.url" in client.get("attributes", {})
    ]

    assert attributes
    assert [a for a in attributes if a["backchannel.logout.session.required"] != "false"] == []


def test_a_client_with_a_back_channel_logout_address_has_its_own_back_channel_network_on_keycloak():
    """The address is reached over the client's isolated network; a client given one without
    a network of its own would send keycloak's call through a shared route."""
    keycloak_networks = compose_document()["services"]["keycloak"]["networks"]
    with_address = clients_with_a_back_channel_logout_address()

    assert with_address
    assert all(f"backchannel-{client_id}" in keycloak_networks for client_id in with_address)


def test_a_back_channel_logout_address_points_at_its_clients_own_host():
    """A logout address on another host would carry keycloak's call off the client's back
    channel."""
    with_address = clients_with_a_back_channel_logout_address()

    assert with_address
    assert all(
        urlsplit(client["attributes"]["backchannel.logout.url"]).hostname
        == urlsplit(client["baseUrl"]).hostname
        for client in with_address.values()
    )


def test_the_account_console_offers_no_groups_page():
    content = REPOSITORY / "keycloak/themes/hallucinai/account/resources/content.json"

    assert "groups" not in [entry["label"] for entry in json.loads(content.read_text())]


def test_hopin_has_a_workload_service_account_in_no_group_and_without_personal_scopes():
    """#506: the account holds only declared workload roles; no `email`, `web-origins` or
    `acr`."""
    realm = yaml.safe_load((REPOSITORY / "keycloak/realm.yaml").read_text())
    account = next(user for user in realm["users"] if user["username"] == "service-account-hopin")

    assert account["serviceAccountClientId"] == "hopin"
    declared_roles = {role["name"] for role in realm["roles"]["realm"]}
    assert set(account["realmRoles"]) == {"agent-workload", "speech-workload"}
    assert set(account["realmRoles"]) <= declared_roles
    assert "groups" not in account
    assert realm_clients()["hopin"]["serviceAccountsEnabled"] is True
    assert not {"email", "web-origins", "acr"} & set(
        realm_clients()["hopin"]["defaultClientScopes"]
    )


def test_only_songmaker_allows_the_device_grant():
    """#297: the live smoke signs in by device grant; a stranger needs songmaker's secret."""
    realm = yaml.safe_load((REPOSITORY / "keycloak/realm.yaml").read_text())

    allowing = [
        client["clientId"]
        for client in realm["clients"]
        if client.get("attributes", {}).get("oauth2.device.authorization.grant.enabled") == "true"
    ]

    assert allowing == ["songmaker"]


@pytest.mark.parametrize(
    ("client_id", "answers"),
    [
        ("songmaker", {"with": 200, "without": 401}),
        ("hopin", {"with": 400, "without": 400}),
    ],
)
def test_the_device_grant_cell_accepts_only_songmaker_with_its_secret(
    monkeypatch, client_id, answers
):
    """#297: the cell reports a held cell for the ruled answers and no other."""
    monkeypatch.syspath_prepend(str(REPOSITORY / "probe" / "keycloak"))
    import device_grant_cell

    def answer(status):
        body = {"device_code": "d", "user_code": "u"} if status == 200 else {"error": "x"}
        return SimpleNamespace(status=status, text=json.dumps(body), json=lambda: body)

    class FakeProbe:
        def __init__(self, status_for):
            self.status_for = status_for
            self.held_lines = []

        def through_tunnel(self, _method, _path, form):
            return answer(self.status_for(form.get("client_secret")))

        def held(self, proof, detail):
            self.held_lines.append((proof, detail))

    def expecting(failures):
        return lambda held, message: held or failures.append(message)

    failures = []
    ruled = FakeProbe(lambda secret: answers["with" if secret == "s3" else "without"])
    device_grant_cell.prove(ruled, client_id, "s3", expecting(failures))
    assert failures == []
    assert [proof for proof, _ in ruled.held_lines] == ["DG1"]

    device_grant_cell.prove(FakeProbe(lambda _secret: 200), client_id, "s3", expecting(failures))
    assert failures


def test_the_device_grant_cell_names_no_part_of_an_answer_that_lacks_the_user_code(monkeypatch):
    """#297: a device_code in a malformed answer must not reach the probe's output."""
    monkeypatch.syspath_prepend(str(REPOSITORY / "probe" / "keycloak"))
    import device_grant_cell

    body = {"device_code": "SECRET-DEVICE-CODE"}
    started = SimpleNamespace(status=200, text=json.dumps(body), json=lambda: body)

    class FakeProbe:
        def through_tunnel(self, _method, _path, form):
            return started

        def held(self, proof, detail):
            pass

    messages = []
    device_grant_cell.prove(
        FakeProbe(), "songmaker", "s3", lambda held, message: held or messages.append(message)
    )

    assert (
        messages[0]
        == "a device request for songmaker with its secret answered 200 without user_code"
    )
    assert "SECRET-DEVICE-CODE" not in "".join(messages)


def test_the_back_channel_cell_keeps_the_client_secret_out_of_the_exec_arguments(monkeypatch):
    """#293: process arguments are visible to the host; the secret goes through stdin."""
    monkeypatch.syspath_prepend(str(REPOSITORY / "probe" / "keycloak"))
    import backchannel_cell

    secret = "probe-client-secret-value"
    calls = []

    class FakeStack:
        def compose(self, *arguments, stdin=None):
            calls.append((arguments, stdin))
            seen = {"token": "400", "address": "10.0.0.2", "admin": "404", "management": "-"}
            return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(seen))

    class FakeProbe:
        stack = FakeStack()

        def keep_secret(self, _name, value):
            return value

    class FakeAdmin:
        def create_user(self, *_arguments):
            return "user-id"

        def get(self, _path):
            return [{"type": "LOGIN_ERROR", "ipAddress": "10.0.0.2"}]

    backchannel_cell.prove(FakeProbe(), FakeAdmin(), secret, lambda _held, _message: None)

    ((arguments, stdin),) = calls
    assert secret not in " ".join(arguments)
    assert json.loads(stdin)["client_secret"] == secret


@pytest.mark.parametrize("locale", ["de", "en"])
def test_the_terms_page_of_the_login_links_the_legal_units_terms_page_on_the_catalogs_zone(locale):
    """N8: Keycloak shows a title and a link, never a copy of the terms."""
    zone = yaml.safe_load((REPOSITORY / "fleet.yaml").read_text())["cloudflare"]["zone"]
    terms = next(page for page in legal_section.PAGES if "bedingungen" in page)
    messages = theme_properties(
        REPOSITORY / f"keycloak/themes/hallucinai/login/messages/messages_{locale}.properties"
    )

    assert re.findall(r'href="([^"]*)"', messages["termsText"]) == [f"https://{zone}/{terms}"]
    assert messages["termsTitle"]


def test_every_required_action_the_realm_declares_states_its_priority():
    """config-cli writes 0 for a missing priority, so an unstated one would reorder the actions."""
    realm = yaml.safe_load((REPOSITORY / "keycloak/realm.yaml").read_text())

    assert all("priority" in action for action in realm["requiredActions"])


# An SVG's xmlns names a namespace; no browser fetches it.
XML_NAMESPACE_HOST = "www.w3.org"


def test_the_theme_sources_name_no_host_but_hallucinai_de():
    """#205: a source check of the theme, not proof of browser requests; the driven page is that."""
    theme = REPOSITORY / "keycloak/themes/hallucinai"
    texts = [
        path.read_text()
        for path in theme.rglob("*")
        if path.suffix in {".css", ".ftl", ".js", ".json", ".properties", ".svg"}
    ]
    hosts = {host for text in texts for host in re.findall(r"(?:https?:)?//([^/\"'\s)]+)", text)}

    assert hosts <= {"hallucinai.de", XML_NAMESPACE_HOST}


def test_the_auth_host_opens_only_the_realm_paths_and_the_admin_console_only_on_localhost():
    """The auth host serves the realm's own paths and resources; the admin console answers on
    `localhost` only."""
    labels = compose_document()["services"]["keycloak"]["labels"]

    assert {
        "auth rule": labels["traefik.http.routers.auth.rule"].replace("\n", " "),
        "auth-admin rule": labels["traefik.http.routers.auth-admin.rule"],
    } == {
        "auth rule": (
            "Host(`auth.${EDGE_DOMAIN}`) && (PathPrefix(`/realms/hallucinai/`) "
            "|| PathPrefix(`/resources/hallucinai/`) || PathRegexp(`^/resources/[a-z0-9]{5}/`))"
        ),
        "auth-admin rule": "Host(`localhost`)",
    }


@pytest.fixture
def backchannel_cell(monkeypatch):
    monkeypatch.syspath_prepend(str(REPOSITORY / "probe" / "keycloak"))
    import backchannel_cell

    return backchannel_cell


@pytest.mark.parametrize(
    ("client_id", "changes", "wrong"),
    [
        pytest.param("hopin", {}, set(), id="hopin as ruled"),
        pytest.param(
            "hopin",
            {"backchannel.logout.url": "http://x"},
            {"backchannel.logout.url"},
            id="hopin wrong url",
        ),
        pytest.param(
            "hopin",
            {"backchannel.logout.session.required": "differs"},
            {"backchannel.logout.session.required"},
            id="hopin session required",
        ),
        pytest.param(
            "hopin",
            {"use.refresh.tokens": "differs"},
            {"use.refresh.tokens"},
            id="hopin refresh tokens",
        ),
        pytest.param("songmaker", {}, set(), id="songmaker as ruled"),
        pytest.param(
            "songmaker",
            {"use.refresh.tokens": "differs"},
            {"use.refresh.tokens"},
            id="songmaker with the refresh line",
        ),
        pytest.param("presentator", {}, set(), id="presentator as ruled"),
        pytest.param(
            "presentator",
            {
                "backchannel.logout.url": "http://presentator.hallucinai.de:1/auth/backchannel-logout"
            },
            {"backchannel.logout.url"},
            id="presentator wrong port",
        ),
        pytest.param(
            "presentator",
            {"use.refresh.tokens": "differs"},
            {"use.refresh.tokens"},
            id="presentator with the refresh line",
        ),
    ],
)
def test_wrong_logout_settings_names_what_differs_from_the_ruling(
    backchannel_cell, client_id, changes, wrong
):
    """#382 cell 8: a wrong logout setting names what differs from the ruling."""
    attributes = backchannel_cell.ruled_settings(client_id) | changes

    assert set(backchannel_cell.wrong_logout_settings(client_id, attributes)) == wrong


def test_the_config_cli_the_reconcile_follows_is_a_compose_service():
    assert reconcile.CONFIG_CLI in compose_document()["services"]


def test_wrong_logout_settings_names_every_ruled_setting_a_client_lacks(backchannel_cell):
    """#382 cell 8: a client with no attributes lacks all its ruled settings."""
    assert set(backchannel_cell.wrong_logout_settings("hopin", {})) == set(
        backchannel_cell.ruled_settings("hopin")
    )
