"""The realm observer (#66) against a fake Keycloak 26.8.1 admin API; each test names its cell of
the item's scenario matrix (U8-U29) or its rule."""

import copy
import importlib.util
import io
import json
import shutil
import signal
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest
import yaml
from support.realm_fake import (
    KEY,
    PLANTED,
    REFUSAL_BODY,
    SECRET,
    TOKEN,
    FakeKeycloak,
    FakeRealm,
    Group,
    client_rep,
    component,
    role_rep,
    serving,
    step_rep,
    uid,
)

from hal.stack.realm import change_lines
from hal.stack.realm import observe as observer

REPOSITORY = Path(__file__).resolve().parents[1]


@pytest.fixture
def keycloak() -> Iterator[FakeKeycloak]:
    with serving() as server:
        yield server


@pytest.fixture
def proxy() -> Iterator[FakeKeycloak]:
    """A second fake that stands in for a proxy Docker injects: whatever reaches it is logged."""
    with serving() as server:
        yield server


def observe(keycloak: FakeKeycloak) -> observer.Inventory:
    session = observer.Session(keycloak.url, SECRET)
    return observer.observe(session, observer.Digester(bytes.fromhex(KEY)))


def lines_after(
    keycloak: FakeKeycloak, change: Callable[[dict[str, FakeRealm]], None]
) -> list[str]:
    before = observe(keycloak)
    change(keycloak.realms)
    return change_lines(before, observe(keycloak))


@dataclass(frozen=True)
class Run:
    exit_code: int
    stdout: str
    stderr: str


@pytest.fixture
def run_observer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> Iterator[Callable[..., Run]]:
    """The observer's command line as the compose service runs it, the key on stdin; SIGINT
    raises KeyboardInterrupt as in the container, whatever the test runner set."""
    secret_file = tmp_path / "config-cli-secret"
    secret_file.write_text(SECRET + "\n")
    previous = {stop: signal.getsignal(stop) for stop in (signal.SIGTERM, signal.SIGINT)}
    signal.signal(signal.SIGINT, signal.default_int_handler)

    def run(
        base_url: str,
        command: Callable[..., int] = observer.main,
        key_line: str = KEY,
        secret: Path = secret_file,
        flags: tuple[str, ...] = (),
    ) -> Run:
        code = command(["--base-url", base_url, *flags], io.StringIO(key_line + "\n"), secret)
        captured = capsys.readouterr()
        return Run(code, captured.out, captured.err)

    yield run
    for stop, handler in previous.items():
        signal.signal(stop, handler)


# --- U8-U12, U23, U25: what the lines say ------------------------------------------------------


def add_client(realms: dict[str, FakeRealm]) -> None:
    realms["hallucinai"].clients.append(client_rep("hallucinai", "probe-rp"))


def longer_tokens(realms: dict[str, FakeRealm]) -> None:
    realms["hallucinai"].realm["accessTokenLifespan"] = 360


def rename_hopin(realms: dict[str, FakeRealm]) -> None:
    groups = realms["hallucinai"].groups
    groups["/apps/hop-in"] = groups.pop("/apps/hopin")
    groups["/apps/hop-in/admin"] = groups.pop("/apps/hopin/admin")


def swap_forms_steps(realms: dict[str, FakeRealm]) -> None:
    steps = realms["master"].executions["browser-mfa"]
    steps[2]["index"], steps[3]["index"] = 1, 0


def master_only(realms: dict[str, FakeRealm]) -> None:
    realms["master"].realm["accessTokenLifespan"] = 120
    realms["master"].roles.append(role_rep("master", "", "probe-console-role"))


def new_uuids_and_access(realms: dict[str, FakeRealm]) -> None:
    realm = realms["hallucinai"]
    for client in realm.clients:
        old_id, client["id"] = client["id"], str(uuid.uuid4())
        client["access"] = {"view": False}
        if old_id in realm.client_roles:
            realm.client_roles[client["id"]] = realm.client_roles.pop(old_id)
    realms["hallucinai"].realm["id"] = str(uuid.uuid4())
    realms["hallucinai"].realm["defaultRole"]["id"] = str(uuid.uuid4())
    realms["hallucinai"].realm["attributes"]["de.adorsys.keycloak.config.state-default"] = "x"


def grant_config_cli_a_client_role_and_a_group(realms: dict[str, FakeRealm]) -> None:
    master = realms["master"]
    account_id = next(iter(master.role_mappings))
    view_users = {"name": "view-users"}
    master.role_mappings[account_id]["clientMappings"] = {
        "hallucinai-realm": {"mappings": [view_users]}
    }
    master.user_groups[account_id] = ["/operators"]


def change_unlisted_and_secrets(realms: dict[str, FakeRealm]) -> None:
    agent = realms["hallucinai"].clients[0]
    agent["attributes"]["probe.unlisted"] = "another-hidden-value"
    agent["secret"] = "another-client-secret"
    agent["attributes"]["client.secret.rotated"] = "another-rotated-secret"
    realms["hallucinai"].providers[0]["config"]["clientSecret"] = "another-idp-secret"
    realms["hallucinai"].realm["smtpServer"]["password"] = "another-smtp-password"
    realms["hallucinai"].components[0]["config"] = {"privateKey": ["another-key"]}


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        pytest.param(add_client, ["hallucinai: addition client probe-rp"], id="U8-client-added"),
        pytest.param(
            longer_tokens,
            ["hallucinai: change realm hallucinai accessTokenLifespan: 300 → 360"],
            id="U9-setting-changed-old-to-new",
        ),
        pytest.param(
            rename_hopin,
            [
                "hallucinai: addition group /apps/hop-in (2 members)",
                "hallucinai: addition group /apps/hop-in/admin (0 members)",
                "hallucinai: removal group /apps/hopin (2 members)",
                "hallucinai: removal group /apps/hopin/admin (0 members)",
            ],
            id="U10-group-renamed-is-removal-plus-addition-with-members",
        ),
        pytest.param(
            swap_forms_steps,
            [
                "master: change flow step browser-mfa-forms/auth-username-password-form#1 "
                "place: 0 → 1",
                "master: change flow step browser-mfa-forms/browser-mfa-totp#1 place: 1 → 0",
            ],
            id="U11-reordered-step-is-a-change",
        ),
        pytest.param(
            master_only,
            [
                "master: change realm master accessTokenLifespan: 60 → 120",
                "master: addition realm role probe-console-role",
            ],
            id="U12-each-realm-named-on-its-own",
        ),
        pytest.param(new_uuids_and_access, [], id="U23-identity-not-uuid-volatile-excluded"),
        pytest.param(
            grant_config_cli_a_client_role_and_a_group,
            [
                "master: addition service-account client role "
                "service-account-config-cli/hallucinai-realm/view-users",
                "master: addition service-account group service-account-config-cli/operators",
            ],
            id="rule-3-service-account-client-role-and-group-by-identity",
        ),
        pytest.param(
            change_unlisted_and_secrets,
            ["hallucinai: change client speech-service attributes.probe.unlisted: changed"],
            id="U25-unlisted-key-changed-without-value-secret-silent",
        ),
    ],
)
def test_the_lines_name_each_addition_change_and_removal_by_identity(
    keycloak: FakeKeycloak, change: Callable[[dict[str, FakeRealm]], None], expected: list[str]
) -> None:
    assert lines_after(keycloak, change) == expected


def test_two_equal_steps_in_one_flow_are_told_apart_by_their_ordinal(
    keycloak: FakeKeycloak,
) -> None:
    """U11: a second auth-otp-form in the same sub-flow is its own step, #2."""

    def second_otp_step(realms: dict[str, FakeRealm]) -> None:
        extra = step_rep("master", "browser-mfa", 2, 2, authenticator="auth-otp-form")
        realms["master"].executions["browser-mfa"].append(extra)

    assert lines_after(keycloak, second_otp_step) == [
        "master: addition flow step browser-mfa-totp/auth-otp-form#2"
    ]


def test_a_removed_step_in_a_declared_sub_flow_is_one_removal(keycloak: FakeKeycloak) -> None:
    """U1 measurement, P3 in miniature: an extra step config-cli removes shows as a removal."""

    def remove_otp_step(realms: dict[str, FakeRealm]) -> None:
        realms["master"].executions["browser-mfa"].pop()

    assert lines_after(keycloak, remove_otp_step) == [
        "master: removal flow step browser-mfa-totp/auth-otp-form#1"
    ]


def test_service_account_roles_and_mappers_are_removed_one_line_each(
    keycloak: FakeKeycloak,
) -> None:
    """Rule 3 and the U1 three: a lost realm role on the service account and a lost scope mapper."""

    def lose_role_and_mapper(realms: dict[str, FakeRealm]) -> None:
        account = next(iter(realms["master"].role_mappings.values()))
        account["realmMappings"] = account["realmMappings"][1:]
        realms["hallucinai"].client_scopes[0]["protocolMappers"] = []

    assert lines_after(keycloak, lose_role_and_mapper) == [
        "hallucinai: removal protocol mapper scope groups/groups",
        "master: removal service-account realm role service-account-config-cli/admin",
    ]


def test_a_name_holding_esc_and_a_newline_prints_as_one_escaped_line(
    keycloak: FakeKeycloak,
) -> None:
    """Rule 7: every name passes through hal.output.printable."""

    def console_group(realms: dict[str, FakeRealm]) -> None:
        realms["hallucinai"].groups["/probe\x1b[31mred\nline"] = Group()

    assert lines_after(keycloak, console_group) == [
        "hallucinai: addition group /probe\\x1b[31mred\\nline (0 members)"
    ]


def test_the_inventory_holds_no_secret_value_and_no_unlisted_value(
    keycloak: FakeKeycloak, run_observer: Callable[[str], Run]
) -> None:
    """Rule 4 and U25: named secrets never leave, unlisted values leave only as digests."""
    run = run_observer(keycloak.url)

    assert run.exit_code == 0
    leaked = [name for name, value in PLANTED.items() if value in run.stdout + run.stderr]
    assert leaked == []
    assert TOKEN not in run.stdout + run.stderr
    assert SECRET not in run.stdout + run.stderr
    client = json.loads(run.stdout)["hallucinai"]["client"]["speech-service"]
    assert "attributes.probe.unlisted" in client["digests"]
    assert "secret" not in client["digests"]
    assert "secret" not in client["fields"]


def test_the_nested_service_rights_groups_appear_in_the_inventory(
    keycloak: FakeKeycloak, run_observer: Callable[[str], Run]
) -> None:
    run = run_observer(keycloak.url)

    observed = json.loads(run.stdout)["hallucinai"]["group"]
    assert {"/services/agent-service/api", "/services/litellm/admin"} <= set(observed)


def test_a_component_identity_includes_its_sub_type(keycloak: FakeKeycloak) -> None:
    """Rule 5: Keycloak's two `Allowed Client Scopes` policies differ only by their sub-type."""
    components = observe(keycloak)["hallucinai"]["component"]

    assert sorted(components) == [
        "org.keycloak.keys.KeyProvider/rsa-generated//rsa-generated",
        "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy/"
        "allowed-client-templates/anonymous/Allowed Client Scopes",
        "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy/"
        "allowed-client-templates/authenticated/Allowed Client Scopes",
    ]


def test_a_component_without_a_name_is_known_by_its_type_and_provider(
    keycloak: FakeKeycloak,
) -> None:
    """Rule 5: Keycloak 26.8.1 keeps master's declarative user profile as a component that
    carries no name; missing equals null."""
    user_profile = component(
        "master", "", "org.keycloak.userprofile.UserProfileProvider", "declarative-user-profile"
    )
    del user_profile["name"]
    keycloak.realms["master"].components.append(user_profile)

    components = observe(keycloak)["master"]["component"]

    assert "org.keycloak.userprofile.UserProfileProvider/declarative-user-profile//" in components


def test_a_missing_sub_type_and_a_missing_name_keep_their_places(keycloak: FakeKeycloak) -> None:
    """Rule 5: a component named `x` without a sub-type differs from one of sub-type `x`
    without a name."""
    named = component("master", "x", "T", "P")
    typed = component("master", "", "T", "P", sub_type="x")
    typed["name"] = None
    keycloak.realms["master"].components += [named, typed]

    components = observe(keycloak)["master"]["component"]

    assert {"T/P//x", "T/P/x/"} <= components.keys()


def test_a_duplicate_component_identity_fails_loudly(keycloak: FakeKeycloak) -> None:
    """Rule 5: a duplicate fails loudly."""
    realm = keycloak.realms["hallucinai"]
    realm.components.append(copy.deepcopy(realm.components[0]))

    with pytest.raises(observer.ObserveError, match="two component objects in hallucinai"):
        observe(keycloak)


# --- U13, U14: paging and counts -------------------------------------------------------------


def test_more_than_a_page_of_everything_is_read_in_full(keycloak: FakeKeycloak) -> None:
    """U13: >100 subgroups, members, clients and roles; every page is read."""
    realm = keycloak.realms["hallucinai"]
    for number in range(150):
        realm.groups[f"/apps/app-{number:03}"] = Group()
    realm.groups["/apps/songmaker"].members = [uid("member", str(n)) for n in range(120)]
    realm.clients += [client_rep("hallucinai", f"client-{n:03}") for n in range(130)]
    realm.roles += [role_rep("hallucinai", "", f"role-{n:03}") for n in range(110)]

    inventory = observe(keycloak)["hallucinai"]

    assert len([path for path in inventory["group"] if path.startswith("/apps/app-")]) == 150
    assert inventory["group"]["/apps/songmaker"]["fields"]["members"] == 120
    assert len(inventory["client"]) == 132
    assert len(inventory["realm role"]) == 112


def test_a_page_that_repeats_an_earlier_item_fails_loudly(keycloak: FakeKeycloak) -> None:
    """U13: a server that ignores `first` would loop or double the clients; it fails instead."""
    realm = keycloak.realms["hallucinai"]
    realm.clients += [client_rep("hallucinai", f"client-{n:03}") for n in range(130)]
    keycloak.faults.first_page_again = {"/admin/realms/hallucinai/clients"}

    with pytest.raises(
        observer.ObserveError, match=r"^/admin/realms/hallucinai/clients repeats an item"
    ):
        observe(keycloak)


def test_children_fewer_than_the_sub_group_count_fail_loudly(keycloak: FakeKeycloak) -> None:
    """U14: the count check measures that nothing was truncated."""
    keycloak.faults.truncate_children = True

    with pytest.raises(observer.ObserveError, match=r"children returned \d+ of \d+"):
        observe(keycloak)


# --- U19, U20, U22, U27: the door ------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "line"),
    [
        (401, "sign-in refused (status 401 at /realms/master/protocol/openid-connect/token)"),
        (500, "sign-in answered status 500 at /realms/master/protocol/openid-connect/token"),
    ],
    ids=["U19-wrong-secret-refused", "U19-sign-in-failing"],
)
def test_a_failed_sign_in_is_one_line_without_body_or_token(
    keycloak: FakeKeycloak, run_observer: Callable[[str], Run], status: int, line: str
) -> None:
    keycloak.faults.token_status = status

    run = run_observer(keycloak.url)

    assert (run.exit_code, run.stdout) == (1, "")
    assert run.stderr.splitlines() == [f"realm-observer: {line}"]
    assert REFUSAL_BODY not in run.stderr
    assert SECRET not in run.stderr


def test_a_5xx_mid_read_is_one_line_and_no_inventory(
    keycloak: FakeKeycloak, run_observer: Callable[[str], Run]
) -> None:
    """U20."""
    keycloak.faults.status = {"/admin/realms/hallucinai/client-scopes": 503}

    run = run_observer(keycloak.url)

    assert (run.exit_code, run.stdout) == (1, "")
    assert run.stderr.splitlines() == [
        "realm-observer: status 503 at /admin/realms/hallucinai/client-scopes"
    ]


def test_a_timeout_mid_read_fails_the_observe_naming_the_path(keycloak: FakeKeycloak) -> None:
    """U20: the 5xx case above proves a failed observe prints one line and no inventory."""
    keycloak.faults.delay = {"/admin/realms/master/components": 1.0}
    session = observer.Session(keycloak.url, SECRET, timeout=0.3)
    digest = observer.Digester(bytes.fromhex(KEY))

    with pytest.raises(
        observer.ObserveError,
        match=r"^Keycloak does not answer /admin/realms/master/components \(timed out\)$",
    ):
        observer.observe(session, digest)


@pytest.mark.parametrize(
    ("key_line", "missing_secret", "line"),
    [
        ("", False, "no digest key of 32 bytes or more in hex on stdin"),
        ("not-hex-" * 8, False, "no digest key of 32 bytes or more in hex on stdin"),
        ("ab" * 31, False, "no digest key of 32 bytes or more in hex on stdin"),
        (KEY, True, "cannot read the secret file {secret}"),
    ],
    ids=["no-key", "key-not-hex", "key-of-31-bytes", "secret-file-missing"],
)
def test_a_door_it_cannot_open_is_one_line_before_any_request(
    keycloak: FakeKeycloak,
    run_observer: Callable[..., Run],
    tmp_path: Path,
    key_line: str,
    missing_secret: bool,
    line: str,
) -> None:
    """Rule 1 and Rule 4: the door's secret file and the host's digest key are checked before
    the observer asks Keycloak anything."""
    secret = tmp_path / "absent-secret" if missing_secret else tmp_path / "config-cli-secret"

    run = run_observer(keycloak.url, key_line=key_line, secret=secret)

    assert (run.exit_code, run.stdout) == (1, "")
    assert run.stderr.splitlines() == [f"realm-observer: {line.format(secret=secret)}"]
    assert keycloak.requests == []


@pytest.mark.parametrize("stop", [signal.SIGINT, signal.SIGTERM])
def test_a_stop_mid_read_is_one_stopped_line_exit_130_and_no_inventory(
    keycloak: FakeKeycloak, run_observer: Callable[[str], Run], stop: signal.Signals
) -> None:
    """P17 in miniature: the stop reaches the observer's own process, as `docker kill` sends it."""
    keycloak.faults.stop = {"/admin/realms/master/groups": stop}

    run = run_observer(keycloak.url)

    assert (run.exit_code, run.stdout) == (130, "")
    assert run.stderr.splitlines() == ["realm-observer: stopped"]


def test_keycloak_that_does_not_answer_is_one_line(run_observer: Callable[[str], Run]) -> None:
    """P18 in miniature: no Keycloak behind the URL."""
    run = run_observer("http://127.0.0.1:9")

    assert (run.exit_code, run.stdout) == (1, "")
    assert run.stderr.splitlines() == [
        "realm-observer: Keycloak does not answer "
        "/realms/master/protocol/openid-connect/token (unreachable)"
    ]


def test_the_observer_sends_get_only_plus_one_token_post(keycloak: FakeKeycloak) -> None:
    """Rule 1 and U22: read-only is a protocol contract."""
    observe(keycloak)

    not_admin_reads = [
        (method, path)
        for method, path in keycloak.requests
        if not (method == "GET" and path.startswith("/admin/realms/"))
    ]
    assert not_admin_reads == [("POST", "/realms/master/protocol/openid-connect/token")]


def test_import_checksums_prints_only_each_realms_checksum_attributes_and_needs_no_key(
    keycloak: FakeKeycloak, run_observer: Callable[..., Run]
) -> None:
    """#242: the host's trigger read; the realm's other attributes and every inventory object stay
    unread, and the digest key is neither needed nor read."""
    key = "de.adorsys.keycloak.config.import-checksum-default"

    run = run_observer(keycloak.url, key_line="", flags=("--import-checksums",))

    assert (run.exit_code, run.stderr) == (0, "")
    assert json.loads(run.stdout) == {
        "master": {key: "a-checksum"},
        "hallucinai": {key: "a-checksum"},
    }
    assert [path for method, path in keycloak.requests if method == "GET"] == [
        "/admin/realms/master",
        "/admin/realms/hallucinai",
    ]


def fresh_observer(name: str) -> ModuleType:
    """observe.py loaded anew from its file, so its opener is built under the current
    environment rather than the one the test session imported it in."""
    spec = importlib.util.spec_from_file_location(
        name, REPOSITORY / "src/hal/stack/realm/observe.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[name]
    return module


def test_a_proxy_in_the_environment_never_sees_the_secret_or_the_token(
    keycloak: FakeKeycloak,
    proxy: FakeKeycloak,
    run_observer: Callable[..., Run],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rule 1 and Rule 4: Docker may inject HTTP(S)_PROXY; the token POST and the bearer GETs
    still go to Keycloak alone."""
    for variable in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(variable, proxy.url)
    for variable in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(variable, raising=False)
    expected = run_observer(keycloak.url)
    keycloak.requests.clear()

    run = run_observer(keycloak.url, fresh_observer("observe_under_a_proxy").main)

    assert (run.exit_code, run.stdout) == (0, expected.stdout)
    assert proxy.requests == []
    assert keycloak.requests[0] == ("POST", "/realms/master/protocol/openid-connect/token")
    assert {method for method, _ in keycloak.requests[1:]} == {"GET"}


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS", "TRACE", "PUT", "PROPFIND"])
def test_the_fake_records_every_method_the_read_only_test_judges(
    keycloak: FakeKeycloak, method: str
) -> None:
    """Rule 1: a method the fake has no handler for still reaches its request log."""
    path = "/admin/realms/hallucinai/clients"
    request = urllib.request.Request(keycloak.url + path, method=method)  # noqa: S310 - the URL is that of the loopback test server

    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(request)  # noqa: S310 - the URL is that of the loopback test server

    assert keycloak.requests == [(method, path)]


@pytest.mark.parametrize(
    "location",
    ["{url}/realms/elsewhere", "http://localhost:{port}/admin/realms/hallucinai"],
    ids=["outside-the-admin-path", "another-origin"],
)
def test_a_redirect_is_refused_as_its_status_and_never_followed(
    keycloak: FakeKeycloak, location: str
) -> None:
    """Rule 1: GET only under /admin/realms/ of the base URL; the token never follows a 30x."""
    redirecting = "/admin/realms/hallucinai/client-scopes"
    keycloak.faults.redirect = {
        redirecting: location.format(url=keycloak.url, port=keycloak.server_port)
    }

    with pytest.raises(observer.ObserveError, match=f"^status 302 at {redirecting}$"):
        observe(keycloak)
    assert keycloak.requests[-1] == ("GET", redirecting)


def test_a_reordered_set_keeps_its_digest_while_reordered_objects_change_it() -> None:
    """U23 and U25: Keycloak returns its sets in no fixed order, so their order is volatile; a list
    of objects keeps the order it has (U11)."""
    digest = observer.Digester(bytes.fromhex(KEY))

    assert digest(["b", "a"]) == digest(["a", "b"])
    assert digest([{"n": 2}, {"n": 1}]) != digest([{"n": 1}, {"n": 2}])


def test_two_observes_of_an_unchanged_keycloak_are_equal(keycloak: FakeKeycloak) -> None:
    """U22: nothing volatile reaches the inventory."""
    first = observe(keycloak)

    assert observe(keycloak) == first


def test_an_expired_token_mid_read_signs_in_once_more_and_completes(
    keycloak: FakeKeycloak,
) -> None:
    """U27."""
    expected = observe(keycloak)
    keycloak.requests.clear()
    keycloak.gets = 0
    keycloak.faults.unauthorized_after = 5

    assert observe(keycloak) == expected
    assert [method for method, _ in keycloak.requests].count("POST") == 2


def test_a_401_right_after_signing_in_again_fails_loudly(keycloak: FakeKeycloak) -> None:
    """U27: a second 401 is a loud failure."""
    keycloak.faults.unauthorized_after = 5
    keycloak.faults.unauthorized_times = 2

    with pytest.raises(observer.ObserveError, match=r"^status 401 at /admin/realms/master"):
        observe(keycloak)


# --- U21: required and optional fields ------------------------------------------------------


@pytest.mark.parametrize(
    ("field_name", "message"),
    [
        ("enabled", r"^a client representation lacks enabled$"),
        ("clientId", r"^a reply lacks the key 'clientId'$"),
    ],
)
def test_a_missing_required_field_fails_loudly(
    keycloak: FakeKeycloak, field_name: str, message: str
) -> None:
    """U21, also for the identity, which is read before the representation is projected."""
    del keycloak.realms["hallucinai"].clients[0][field_name]

    with pytest.raises(observer.ObserveError, match=message):
        observe(keycloak)


def test_a_reply_that_is_not_json_fails_naming_its_path(keycloak: FakeKeycloak) -> None:
    """Rule 4: one line with the path, never the body."""
    keycloak.faults.not_json = {"/admin/realms/master/components"}

    with pytest.raises(
        observer.ObserveError, match=r"^no JSON at /admin/realms/master/components$"
    ):
        observe(keycloak)


def test_a_missing_optional_field_is_null(keycloak: FakeKeycloak) -> None:
    """U21: Keycloak leaves out empty fields."""
    del keycloak.realms["hallucinai"].clients[0]["name"]

    client = observe(keycloak)["hallucinai"]["client"]["speech-service"]

    assert client["fields"]["name"] is None


# --- U28, U29: coverage and the import ------------------------------------------------------


@pytest.mark.parametrize("config_file", ["master.yaml", "realm.yaml"])
def test_every_top_level_key_of_the_realm_files_is_read_or_a_named_gap(config_file: str) -> None:
    """U28: a key the coverage table does not name fails here."""
    declared = yaml.safe_load((REPOSITORY / "keycloak" / config_file).read_text())

    assert sorted(set(declared) - observer.COVERAGE.keys()) == []


# keycloak-config-cli 6.5.1's import types (its `import.managed.*` switches and the realm and
# user imports), each onto the realm representation key above it reads or leaves out.
IMPORT_TYPES = {
    "realm": "realm",
    "user": "users",
    "group": "groups",
    "sub-group": "groups",
    "role": "roles",
    "client": "clients",
    "client-scope": "clientScopes",
    "scope-mapping": "scopeMappings",
    "client-scope-mapping": "clientScopeMappings",
    "authentication-flow": "authenticationFlows",
    "required-action": "requiredActions",
    "identity-provider": "identityProviders",
    "identity-provider-mapper": "identityProviderMappers",
    "component": "components",
    "sub-component": "subComponents",
    "client-authorization-resources": "authorizationSettings",
    "client-authorization-policies": "authorizationSettings",
    "client-authorization-scopes": "authorizationSettings",
    "client-policies": "clientPolicies",
    "client-profiles": "clientProfiles",
    "message-bundles": "messageBundles",
    "user-profile": "userProfile",
    "organization": "organizations",
    "workflow": "workflows",
}


def test_every_config_cli_import_type_maps_onto_the_coverage_table() -> None:
    """Rule 3: each config-cli 6.5.1 import type is a read or a named gap."""
    assert sorted(set(IMPORT_TYPES.values()) - observer.COVERAGE.keys()) == []


def test_observe_py_imports_alone_with_python_isolated(tmp_path: Path) -> None:
    """Rule 2 and U29: standard library only, nothing of src on the path."""
    alone = tmp_path / "observe.py"
    shutil.copy(REPOSITORY / "src/hal/stack/realm/observe.py", alone)

    result = subprocess.run(
        [sys.executable, "-I", str(alone), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert sys.version_info >= (3, 12)
