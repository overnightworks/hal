"""The inference path as files, no containers (#768): the compose services of LiteLLM and its
front, their configuration, `start.sh` against a stub `litellm`, and the fake provider's answers.

The running path is proven by probe/agent-service/litellm.py and the CI job `front`; these tests
hold the static facts those do not see.
"""

import ipaddress
import json
import re
import secrets
import stat
import subprocess
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
import yaml
from support.probe_support import probe_imports
from support.script_module import loaded_script

from hal.stack import litellm_keys

ROOT = Path(__file__).resolve().parents[1]
LITELLM_DIRECTORY = ROOT / "agent-service" / "litellm"
LITELLM, FRONT, SERVICE, GATEWAY = "litellm", "litellm-front", "agent-service", "agent-egress"
DATABASE = "litellm-db"
KEYS = litellm_keys.KEYS_SERVICE
NEW_NETWORKS = ("litellm-api", "litellm-backend", "litellm-egress", "litellm-db")
ISOLATED_MODE = {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}
DIGEST_PINNED = re.compile(r"^[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}$")
KEY_SECRET = "litellm_anthropic_key"
MASTER_SECRET, PASSWORD_SECRET = "litellm_master_key", "litellm_db_password"
CLAUDE_ID = re.compile(r"anthropic/claude-(?P<family>[a-z]+)-[\w.-]+")
START_SCRIPT = (LITELLM_DIRECTORY / "start.sh").read_text()
START_LISTENER = re.compile(r"--port (?P<port>\d+)")
APP_NETWORK_NAME = re.compile(r"hal_agent_[a-z]+")
ROUTE_FILE = LITELLM_DIRECTORY / "front" / "dynamic" / "route.yml"


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


@pytest.fixture(scope="module")
def compose() -> dict:
    return load(ROOT / "compose.yaml")


@pytest.fixture(scope="module")
def config() -> dict:
    return load(LITELLM_DIRECTORY / "config.yaml")


@pytest.fixture(scope="module")
def front_static() -> dict:
    return load(LITELLM_DIRECTORY / "front" / "traefik.yml")


def test_the_four_new_networks_are_internal_and_isolated(
    compose,
):
    for name in NEW_NETWORKS:
        network = compose["networks"][name]
        assert network["internal"] is True
        assert network["driver_opts"] == ISOLATED_MODE


def test_every_pinned_network_the_agent_probe_joins_is_one_the_probe_moves(compose, litellm):
    from edge_copy import PINNED_NETWORKS  # on the path while the probe module is imported

    services = compose["services"]
    probe_services = [SERVICE, GATEWAY] + [
        name for name, service in services.items() if "litellm" in service.get("profiles", [])
    ]
    joined = {network for name in probe_services for network in services[name]["networks"]}
    pinned = {name for name, network in compose["networks"].items() if "ipam" in (network or {})}

    assert pinned & joined == set(PINNED_NETWORKS)


def app_networks(compose: dict) -> set[str]:
    """The networks of compose.yaml whose fixed name is `hal_agent_<app>`."""
    return {
        key
        for key, network in compose["networks"].items()
        if APP_NETWORK_NAME.fullmatch((network or {}).get("name", ""))
    }


def test_each_member_joins_exactly_the_networks_the_boundary_declares(compose):
    services = compose["services"]

    assert app_networks(compose)
    assert set(services[FRONT]["networks"]) == {"litellm-api", "litellm-backend"} | app_networks(
        compose
    )
    assert set(services[LITELLM]["networks"]) == {"litellm-backend", "litellm-egress", "litellm-db"}
    assert services[DATABASE]["networks"] == ["litellm-db"]
    assert {n for n, s in services.items() if "litellm-db" in s.get("networks", [])} == {
        LITELLM,
        DATABASE,
    }
    assert "litellm-api" in services[SERVICE]["networks"]
    assert "litellm-backend" not in services[SERVICE]["networks"]
    assert "egress" not in services[LITELLM]["networks"]
    assert "litellm-egress" in services[GATEWAY]["networks"]


def test_only_litellm_holds_a_static_backend_address_and_it_lies_outside_the_dynamic_range(
    compose,
):
    backend = "litellm-backend"
    members = {
        name: service["networks"]
        for name, service in compose["services"].items()
        if backend in service.get("networks", [])
    }
    static = {
        name: networks[backend]["ipv4_address"]
        for name, networks in members.items()
        if isinstance(networks, dict) and (networks[backend] or {}).get("ipv4_address")
    }
    (pinned,) = compose["networks"][backend]["ipam"]["config"]
    subnet = ipaddress.ip_network(pinned["subnet"])
    dynamic = ipaddress.ip_network(pinned["ip_range"])
    address = ipaddress.ip_address(static[LITELLM])

    assert set(members) == {FRONT, LITELLM, KEYS}
    assert set(static) == {LITELLM}
    assert dynamic.subnet_of(subnet)
    assert address in subnet
    assert address not in dynamic


def test_the_front_finds_litellm_at_its_fixed_backend_address_and_never_by_dns(compose):
    backend = compose["services"][LITELLM]["networks"]["litellm-backend"]

    assert compose["services"][FRONT]["extra_hosts"] == {LITELLM: backend["ipv4_address"]}


def test_litellm_is_pinned_by_digest_hardened_and_reaches_the_provider_through_the_gateway(compose):
    service = compose["services"][LITELLM]

    assert DIGEST_PINNED.match(service["image"])
    uid, gid = (int(part) for part in service["user"].split(":"))
    assert uid != 0
    assert gid != 0
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["ulimits"] == {"core": 0}
    assert service["init"] is True
    assert not {"ports", "expose", "network_mode", "cap_add"} & service.keys()
    assert service["extra_hosts"] == {"api.anthropic.com": compose["x-litellm-egress-address"]}
    assert service["profiles"] == ["litellm"]


def test_litellm_keeps_telemetry_off_and_uses_the_local_cost_map(compose):
    environment = compose["services"][LITELLM]["environment"]

    assert environment["LITELLM_LOCAL_MODEL_COST_MAP"] == "True"
    assert environment["LITELLM_TELEMETRY"] == "False"
    assert "LITELLM_DISABLE_LAZY_ROUTES" not in environment


def test_the_front_shares_the_public_traefiks_image_and_hardening_and_reads_no_secret(compose):
    shared = ("image", "user", "read_only", "cap_drop", "security_opt")
    front = compose["services"][FRONT]

    assert {key: front[key] for key in shared} == {
        key: compose["services"]["traefik"][key] for key in shared
    }
    assert not {"secrets", "ports", "expose", "depends_on", "environment"} & front.keys()


def test_litellm_waits_for_a_healthy_database_and_both_read_only_the_password(compose):
    services = compose["services"]

    assert services[LITELLM]["depends_on"] == {DATABASE: {"condition": "service_healthy"}}
    assert "healthcheck" in services[DATABASE]
    assert {n for n, s in services.items() if PASSWORD_SECRET in s.get("secrets", [])} == {
        LITELLM,
        DATABASE,
    }


def test_the_database_keeps_keycloaks_postgres_image_and_hardening_and_its_volume_is_its_own(
    compose,
):
    services = compose["services"]
    hardening = ("image", "user", "read_only", "tmpfs", "cap_drop", "security_opt", "restart")

    assert {key: services[DATABASE][key] for key in hardening} == {
        key: services["keycloak-db"][key] for key in hardening
    }
    assert services[DATABASE]["profiles"] == [LITELLM]
    assert services[DATABASE]["volumes"] == [
        f"{DATABASE}:{services['keycloak-db']['volumes'][0].split(':')[1]}"
    ]
    assert DATABASE in compose["volumes"]


def test_only_litellm_reads_the_provider_key_and_only_it_and_the_key_step_the_master_key(compose):
    holders = {
        secret: {n for n, s in compose["services"].items() if secret in s.get("secrets", [])}
        for secret in (KEY_SECRET, MASTER_SECRET)
    }

    assert holders == {KEY_SECRET: {LITELLM}, MASTER_SECRET: {LITELLM, KEYS}}


def test_the_fronts_http_block_global_and_log_are_those_of_the_public_traefik(front_static):
    public = load(ROOT / "traefik.yml")

    assert front_static["entryPoints"]["api"]["http"] == public["entryPoints"]["edge"]["http"]
    assert {key: front_static[key] for key in ("global", "log")} == {
        key: public[key] for key in ("global", "log")
    }
    assert set(front_static["entryPoints"]) == {"api"}
    assert not {"api", "ping", "metrics"} & front_static.keys()
    assert set(front_static["providers"]) == {"file"}


def test_the_fronts_dynamic_file_has_one_router_for_the_completion_call_and_nothing_else():
    dynamic = load(ROUTE_FILE)

    assert set(dynamic) == {"http"}
    (router,) = dynamic["http"]["routers"].values()
    assert router["rule"] == "Method(`POST`) && Path(`/v1/chat/completions`)"
    assert router["entryPoints"] == ["api"]
    (server,) = dynamic["http"]["services"][router["service"]]["loadBalancer"]["servers"]
    assert server["url"] == f"http://{LITELLM}:{START_LISTENER.search(START_SCRIPT).group('port')}"


def test_the_key_steps_route_is_the_one_path_the_front_serves():
    dynamic = load(ROUTE_FILE)
    (router,) = dynamic["http"]["routers"].values()

    assert re.findall(r"Path\(`([^`]+)`\)", router["rule"]) == [litellm_keys.ROUTE]


def test_the_completion_router_chains_only_middlewares_the_file_declares():
    dynamic = load(ROUTE_FILE)["http"]
    (router,) = dynamic["routers"].values()

    assert router["middlewares"]
    assert set(router["middlewares"]) <= set(dynamic["middlewares"])


def test_the_fronts_directories_are_mounted_where_its_static_file_reads_them(compose, front_static):
    mounted = {volume.split(":")[1] for volume in compose["services"][FRONT]["volumes"]}

    assert front_static["providers"]["file"]["directory"] in mounted
    assert "/etc/traefik/traefik.yml" in mounted


def test_each_text_name_maps_to_a_claude_id_of_its_own_family_and_retries_nothing(config):
    entries = {e["model_name"]: e["litellm_params"] for e in config["model_list"]}
    families = {name: CLAUDE_ID.fullmatch(p["model"])["family"] for name, p in entries.items()}

    assert all(name == f"text/{family}" for name, family in families.items())
    assert len(set(families.values())) == 3
    assert all(parameters["max_retries"] == 0 for parameters in entries.values())


def test_each_text_name_carries_a_positive_whole_max_tokens(config):
    ceilings = [entry["litellm_params"]["max_tokens"] for entry in config["model_list"]]

    assert all(type(ceiling) is int and ceiling > 0 for ceiling in ceilings)


def test_litellm_retries_nothing_logs_no_messages_and_has_no_callback_cache_or_spend_log(config):
    assert config["router_settings"] == {"num_retries": 0}
    assert config["litellm_settings"].keys() - {"max_end_user_budget_id"} == {
        "turn_off_message_logging",
        "redact_messages_in_exceptions",
        "disable_add_user_agent_to_request_tags",
    }
    assert config["litellm_settings"]["turn_off_message_logging"] is True
    assert config["litellm_settings"]["redact_messages_in_exceptions"] is True
    assert config["litellm_settings"]["disable_add_user_agent_to_request_tags"] is True
    assert set(config) == {"model_list", "router_settings", "litellm_settings", "general_settings"}
    assert config["general_settings"].keys() - {"enforce_user_param"} == {
        "disable_spend_logs",
        "disable_error_logs",
        "store_prompts_in_spend_logs",
    }
    assert config["general_settings"]["disable_spend_logs"] is True
    assert config["general_settings"]["disable_error_logs"] is True
    assert config["general_settings"]["store_prompts_in_spend_logs"] is False


def test_litellm_demands_a_user_and_loads_no_auth_hook(config):
    assert config["general_settings"]["enforce_user_param"] is True
    assert "custom_auth" not in config["general_settings"]


def setting_keys(node: object) -> Iterator[str]:
    """Every key of a YAML document, at any depth."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from setting_keys(value)
    elif isinstance(node, list):
        for item in node:
            yield from setting_keys(item)


def string_values(node: object) -> Iterator[str]:
    """Every string a YAML document holds as a value, at any depth."""
    if isinstance(node, dict):
        for value in node.values():
            yield from string_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from string_values(item)
    elif isinstance(node, str):
        yield node


PREMIUM_SETTINGS = (
    "LITELLM_LICENSE", "enforced_params", "allowed_ips", "allowed_routes", "tags",
    "model_max_budget",
)  # fmt: skip
PREMIUM_ROUTE = "regenerate"


def premium_names(document: object) -> set[str]:
    """The premium settings a document sets as keys and the premium route it names in a value."""
    named = set(PREMIUM_SETTINGS) & set(setting_keys(document))
    return named | {PREMIUM_ROUTE for value in string_values(document) if PREMIUM_ROUTE in value}


@pytest.mark.parametrize(
    ("document", "named"),
    [
        ({"general_settings": {"allowed_routes": ["/chat"]}}, {"allowed_routes"}),
        ({"litellm_settings": [{"model_max_budget": {}}]}, {"model_max_budget"}),
        ({"LITELLM_LICENSE": "x"}, {"LITELLM_LICENSE"}),
        ({"some_routes": ["/key/regenerate"]}, {PREMIUM_ROUTE}),
        ({"general_settings": {"enforce_user_param": True}}, set()),
    ],
)
def test_a_premium_setting_is_found_by_its_key_and_a_premium_route_by_its_value(document, named):
    assert premium_names(document) == named


def test_litellm_holds_no_license_and_none_of_the_settings_behind_the_premium_check(
    compose, config
):
    environment = compose["services"][LITELLM]["environment"]

    assert premium_names(config) | premium_names(environment) == set()
    assert "LITELLM_LICENSE" not in START_SCRIPT


def test_litellm_names_one_person_budget_for_every_fingerprint(config):
    budget_id = config["litellm_settings"]["max_end_user_budget_id"]

    assert isinstance(budget_id, str)
    assert budget_id.strip()


def test_litellm_mounts_only_its_config_and_start_script_and_loads_no_hal_code(compose):
    service = compose["services"][LITELLM]
    mounts = dict(volume.split(":")[:2] for volume in service["volumes"])
    target = {Path(source).name: Path(mounted) for source, mounted in mounts.items()}

    for source in mounts:
        assert (ROOT / source).resolve().parent == LITELLM_DIRECTORY
    assert set(target) == {"config.yaml", "start.sh"}
    assert "PYTHONPATH" not in service["environment"]
    assert service["entrypoint"][0] == str(target["start.sh"])
    assert f"--config {target['config.yaml']} " in START_SCRIPT


@pytest.fixture
def stub_path(tmp_path) -> Path:
    """A directory with a `litellm` that reports whether the key arrived in its environment."""
    directory = tmp_path / "bin"
    directory.mkdir()
    stub = directory / "litellm"
    stub.write_text(
        '#!/bin/sh\n[ "$ANTHROPIC_API_KEY" = "$(cat "$KEY_FILE")" ] '
        '&& [ "$LITELLM_MASTER_KEY" = "$(cat "$MASTER_FILE")" ] && echo "$DATABASE_URL"\n'
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    return directory


def start(
    stub_path, key_file: Path, master_file: Path | None = None, password_file: Path | None = None
):
    if master_file is None:
        master_file = key_file.with_name("master")
        master_file.write_text(secrets.token_urlsafe(32) + "\n")
    if password_file is None:
        password_file = key_file.with_name("password")
        password_file.write_text(secrets.token_urlsafe(32) + "\n")
    return subprocess.run(
        [
            str(LITELLM_DIRECTORY / "start.sh"),
            str(key_file),
            str(master_file),
            str(password_file),
        ],
        capture_output=True,
        text=True,
        check=False,
        env={
            "PATH": f"{stub_path}:/usr/bin:/bin",
            "KEY_FILE": str(key_file),
            "MASTER_FILE": str(master_file),
        },
    )


def test_start_execs_litellm_with_the_database_url_of_the_composed_database(
    stub_path, tmp_path, compose
):
    key_file, password_file = tmp_path / "key", tmp_path / "password"
    key_file.write_text(secrets.token_urlsafe(32) + "\n")
    password = secrets.token_urlsafe(32)
    password_file.write_text(password + "\n")
    database = compose["services"][DATABASE]["environment"]

    result = start(stub_path, key_file, password_file=password_file)

    assert result.returncode == 0
    assert result.stdout.strip() == (
        f"postgresql://{database['POSTGRES_USER']}:{password}@{DATABASE}:5432/{database['POSTGRES_DB']}"
    )
    assert result.stderr == ""


@pytest.mark.parametrize("bad", ["provider", "master", "password"])
@pytest.mark.parametrize(
    "contents",
    [
        None,
        "",
        "\n",
        "first\nsecond\n",
        "tok1\ntok2",
        "abc\n\x01\x02",
        "has space\n",
        "tab\there\n",
        "bell\x07\n",
        "\x00\n",
    ],
    ids=[
        "missing", "empty", "blank", "two-lines", "two-lines-unterminated",
        "control-on-a-later-line", "space", "tab", "control", "null",
    ],
)  # fmt: skip
def test_start_refuses_a_bad_key_file_with_one_line_that_names_the_path_only(
    stub_path, tmp_path, contents, bad
):
    good, refused = tmp_path / "good", tmp_path / "refused"
    good.write_text(secrets.token_urlsafe(32) + "\n")
    if contents is not None:
        refused.write_text(contents)
    files = {"provider": good, "master": good, "password": good} | {bad: refused}

    result = start(stub_path, files["provider"], files["master"], files["password"])

    assert result.returncode != 0
    assert result.stdout == ""
    assert result.stderr.strip().splitlines() == [
        f"litellm: {refused} does not hold exactly one printable key line"
    ]


def test_start_never_prints_a_key_it_refuses(stub_path, tmp_path):
    key = secrets.token_urlsafe(32)
    key_file = tmp_path / "key"
    key_file.write_text(f"{key}\n{key}\n")

    result = start(stub_path, key_file)

    assert key not in result.stdout + result.stderr


@pytest.fixture(scope="module")
def fake_provider():
    path = ROOT / "probe" / "agent-service" / "fake_anthropic.py"
    yield from loaded_script("fake_anthropic", path)


@pytest.mark.parametrize(
    ("body", "expected"),
    [(b'{"prompt": "before CANARY after"}', "CANARY"), (b'{"prompt": "other"}', "probe")],
)
def test_the_fake_quotes_the_canary_a_request_holds_and_nothing_else_of_it(
    fake_provider, body, expected
):
    steering = {"mode": "echo", "status": 400, "request_canary": "CANARY"}

    handler = fake_provider.handler("provider", {})

    status, reply = handler.provider_answer(None, steering, body)

    assert (status, json.loads(reply)["error"]["message"]) == (400, expected)


def test_the_fakes_stream_answers_with_one_delta_per_steered_text_and_no_byte_of_the_request(
    fake_provider,
):
    steering = {"texts": ["first-7c1d", "second-2b9e"], "request_canary": "request-5a0f"}

    frames = b"".join(fake_provider.stream_events(steering)).decode()

    events = [block.splitlines() for block in frames.split("\n\n") if block]
    names = [lines[0].removeprefix("event: ") for lines in events]
    data = [json.loads(lines[1].removeprefix("data: ")) for lines in events]
    assert names == [
        "message_start", "content_block_start", "content_block_delta", "content_block_delta",
        "content_block_stop", "message_delta", "message_stop",
    ]  # fmt: skip
    assert [item["type"] for item in data] == names
    assert [item["delta"]["text"] for item in data if item["type"] == "content_block_delta"] == (
        steering["texts"]
    )
    assert steering["request_canary"] not in frames


# --- the probe's reading of LiteLLM's processes and listeners, on synthetic scans ---------------

ENGINE_BINARY = "/opt/prisma/engine"
PROXY_SOCKET = {"address": "00000000:0FA0", "version": 4}
ENGINE_SOCKET = {"address": "0100007F:15B3", "version": 4}


def snapshot_of(litellm, processes: dict, listeners: list[dict]):
    """The probe's reading of one scan of a LiteLLM container."""
    scan = {"processes": processes, "listeners": listeners}
    return litellm.snapshot_of(scan, "0.0.0.0:4000", ENGINE_BINARY)


@pytest.fixture(scope="module")
def litellm() -> Iterator[ModuleType]:
    with probe_imports():
        import litellm as probe

        yield probe


@pytest.mark.parametrize(
    ("executable", "parent", "is_engine"),
    [
        pytest.param(ENGINE_BINARY, 7, True, id="the image's engine under the proxy"),
        pytest.param(ENGINE_BINARY + "-other", 7, False, id="a name that starts like the engine"),
        pytest.param(
            "/opt/other/query-engine", 7, False, id="the engine's name in another directory"
        ),
        pytest.param(ENGINE_BINARY, 1, False, id="the engine binary under another parent"),
    ],
)
def test_only_the_images_engine_binary_under_the_proxy_is_the_query_engine(
    litellm, executable, parent, is_engine
):
    row = {"parent": parent, "executable": executable}

    assert litellm.is_engine(row, 7, ENGINE_BINARY) is is_engine


def test_the_proxy_listens_once_it_owns_the_declared_address_and_the_engine_is_told_apart(
    litellm,
):
    processes = {
        "7": {"parent": 1, "executable": "/app/python"},
        "9": {"parent": 7, "executable": ENGINE_BINARY},
    }
    listeners = [{**PROXY_SOCKET, "owners": [7]}, {**ENGINE_SOCKET, "owners": [9]}]

    snapshot = snapshot_of(litellm, processes, listeners)

    assert (snapshot.listening, snapshot.engines, snapshot.outside) == (
        True,
        {9: ["127.0.0.1:5555"]},
        ["0.0.0.0:4000"],
    )


def test_a_lone_engine_socket_is_no_listening_proxy(litellm):
    processes = {
        "7": {"parent": 1, "executable": "/app/python"},
        "9": {"parent": 7, "executable": ENGINE_BINARY},
    }

    snapshot = snapshot_of(litellm, processes, [{**ENGINE_SOCKET, "owners": [9]}])

    assert (snapshot.listening, snapshot.engines) == (False, {})


def test_a_listener_of_a_look_alike_engine_stays_outside_the_engine(litellm):
    processes = {
        "7": {"parent": 1, "executable": "/app/python"},
        "9": {"parent": 7, "executable": "/opt/other/query-engine-other"},
    }
    listeners = [{**PROXY_SOCKET, "owners": [7]}, {**ENGINE_SOCKET, "owners": [9]}]

    snapshot = snapshot_of(litellm, processes, listeners)

    assert (snapshot.engines, snapshot.outside) == ({}, ["0.0.0.0:4000", "127.0.0.1:5555"])
