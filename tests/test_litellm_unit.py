"""The inference path as files, no containers (#768): the compose services of LiteLLM and its
front, their configuration, `start.sh` against a stub `litellm`, and the canary's verdict lines.

The running path is proven by probe/agent-service/litellm.py and the CI job `front`; these tests
hold the static facts those do not see.
"""

import importlib
import io
import json
import re
import secrets
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml
from support.script_module import loaded_script

ROOT = Path(__file__).resolve().parents[1]
LITELLM_DIRECTORY = ROOT / "agent-service" / "litellm"
LITELLM, FRONT, SERVICE, GATEWAY = "litellm", "litellm-front", "agent-service", "agent-egress"
NEW_NETWORKS = ("litellm-api", "litellm-backend", "litellm-egress")
ISOLATED_MODE = {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}
DIGEST_PINNED = re.compile(r"^[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}$")
KEY_SECRET, CREDENTIAL_SECRET = "litellm_anthropic_key", "agent_service_api_credential"
MASTER_SECRET = "litellm_master_key"
START_SCRIPT = (LITELLM_DIRECTORY / "start.sh").read_text()
START_LISTENER = re.compile(r"--port (?P<port>\d+)")


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


def test_the_three_new_networks_are_internal_and_isolated_and_litellm_egress_pins_a_subnet(
    compose,
):
    for name in NEW_NETWORKS:
        network = compose["networks"][name]
        assert network["internal"] is True
        assert network["driver_opts"] == ISOLATED_MODE
    assert "ipam" in compose["networks"]["litellm-egress"]
    assert not any("ipam" in compose["networks"][name] for name in NEW_NETWORKS[:2])


def test_each_member_joins_exactly_the_networks_the_boundary_declares(compose):
    services = compose["services"]

    assert set(services[FRONT]["networks"]) == {"litellm-api", "litellm-backend"}
    assert set(services[LITELLM]["networks"]) == {"litellm-backend", "litellm-egress"}
    assert "litellm-api" in services[SERVICE]["networks"]
    assert "litellm-backend" not in services[SERVICE]["networks"]
    assert "egress" not in services[LITELLM]["networks"]
    assert "litellm-egress" in services[GATEWAY]["networks"]
    assert [n for n, s in services.items() if "litellm-backend" in s.get("networks", [])] == [
        FRONT,
        LITELLM,
    ]


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
    assert not {"ports", "expose", "depends_on", "network_mode", "cap_add"} & service.keys()
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


def test_only_litellm_reads_the_provider_key_and_only_it_and_later_the_service_the_credential(
    compose,
):
    holders = {
        secret: [n for n, s in compose["services"].items() if secret in s.get("secrets", [])]
        for secret in (KEY_SECRET, MASTER_SECRET, CREDENTIAL_SECRET)
    }

    assert holders[KEY_SECRET] == [LITELLM]
    assert holders[MASTER_SECRET] == [LITELLM]
    assert set(holders[CREDENTIAL_SECRET]) <= {LITELLM, SERVICE}
    assert LITELLM in holders[CREDENTIAL_SECRET]


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
    dynamic = load(LITELLM_DIRECTORY / "front" / "dynamic" / "route.yml")

    assert set(dynamic) == {"http"}
    (router,) = dynamic["http"]["routers"].values()
    assert router["rule"] == "Method(`POST`) && Path(`/v1/chat/completions`)"
    assert router["entryPoints"] == ["api"]
    (server,) = dynamic["http"]["services"][router["service"]]["loadBalancer"]["servers"]
    assert server["url"] == f"http://{LITELLM}:{START_LISTENER.search(START_SCRIPT).group('port')}"


def test_the_fronts_directories_are_mounted_where_its_static_file_reads_them(compose, front_static):
    mounted = {volume.split(":")[1] for volume in compose["services"][FRONT]["volumes"]}

    assert front_static["providers"]["file"]["directory"] in mounted
    assert "/etc/traefik/traefik.yml" in mounted


def test_the_three_model_names_map_to_the_family_of_the_service_configurations_cli_models(config):
    cli_models = tomllib.loads((ROOT / "agent-service/service.toml").read_text())["cli"][
        "anthropic"
    ]["models"]
    entries = {e["model_name"]: e["litellm_params"] for e in config["model_list"]}

    assert set(entries) == {f"anthropic/{model}" for model in cli_models}
    for name, parameters in entries.items():
        family = name.removeprefix("anthropic/")
        assert parameters["model"].startswith("anthropic/claude-")
        assert family in parameters["model"]
        assert parameters["max_retries"] == 0


def test_litellm_retries_nothing_logs_no_messages_and_has_no_callback_cache_or_database(config):
    assert config["router_settings"] == {"num_retries": 0}
    assert config["litellm_settings"] == {
        "turn_off_message_logging": True,
        "redact_messages_in_exceptions": True,
    }
    assert set(config) == {"model_list", "router_settings", "litellm_settings", "general_settings"}
    assert config["general_settings"] == {"custom_auth": "auth.user_api_key_auth"}


def test_litellm_finds_its_config_hook_and_start_script_where_compose_mounts_them(compose, config):
    service = compose["services"][LITELLM]
    mounts = dict(volume.split(":")[:2] for volume in service["volumes"])
    target = {Path(source).name: Path(mounted) for source, mounted in mounts.items()}
    hook_module = config["general_settings"]["custom_auth"].split(".")[0]

    for source in mounts:
        assert (ROOT / source).resolve().parent == LITELLM_DIRECTORY
    assert target[f"{hook_module}.py"].parent == Path(service["environment"]["PYTHONPATH"])
    assert target["gate.py"].parent == target[f"{hook_module}.py"].parent
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
        '&& [ "$LITELLM_MASTER_KEY" = "$(cat "$MASTER_FILE")" ] && echo started\n'
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    return directory


def start(stub_path, key_file: Path, master_file: Path | None = None):
    if master_file is None:
        master_file = key_file.with_name("master")
        master_file.write_text(secrets.token_urlsafe(32) + "\n")
    return subprocess.run(
        [str(LITELLM_DIRECTORY / "start.sh"), str(key_file), str(master_file)],
        capture_output=True,
        text=True,
        check=False,
        env={
            "PATH": f"{stub_path}:/usr/bin:/bin",
            "KEY_FILE": str(key_file),
            "MASTER_FILE": str(master_file),
        },
    )


def test_start_execs_litellm_with_a_one_line_key_in_its_environment(stub_path, tmp_path):
    key_file = tmp_path / "key"
    key_file.write_text(secrets.token_urlsafe(32) + "\n")

    result = start(stub_path, key_file)

    assert (result.returncode, result.stdout.strip()) == (0, "started")


@pytest.mark.parametrize("bad", ["provider", "master"])
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
    key_file, master_file = (refused, good) if bad == "provider" else (good, refused)

    result = start(stub_path, key_file, master_file)

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


@pytest.fixture(scope="module")
def canary():
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(ROOT / "agent-service"))  # the canary imports smoke.py
        yield from loaded_script("api_canary", ROOT / "agent-service" / "api_canary.py")


class StreamedResponse:
    def __init__(self, status: int, frames: list[tuple[str, dict]]) -> None:
        self.status = status
        body = "".join(
            f"event: {event}\ndata: {json.dumps({'v': 4, **data})}\n\n" for event, data in frames
        )
        self.readline = io.BytesIO(body.encode()).readline


class StreamedConnection:
    def __init__(self, response: StreamedResponse) -> None:
        self.response = response

    def request(self, *_: object) -> None:
        return None

    def getresponse(self) -> StreamedResponse:
        return self.response


def run_canary(canary, monkeypatch, response, marker="m4rker"):
    monkeypatch.setattr(
        canary.http.client, "HTTPConnection", lambda *_, **__: StreamedConnection(response)
    )
    out = io.StringIO()
    code = canary.main(["--marker", marker], stdin=io.StringIO("person\nworkload\n"), out=out)
    return code, out.getvalue().splitlines()


def test_the_canary_prints_only_verdict_lines_for_a_succeeded_run_that_holds_the_marker(
    canary, monkeypatch
):
    response = StreamedResponse(
        200,
        [("run_started", {"route": "api"}), ("succeeded", {"text": "the m4rker", "files": []})],
    )

    code, lines = run_canary(canary, monkeypatch, response)

    assert (code, lines) == (
        0,
        ["answer 200", "event run_started", "route api", "event succeeded", "marker yes"],
    )


class RequestRecordingConnection(StreamedConnection):
    def __init__(self) -> None:
        super().__init__(StreamedResponse(403, []))
        self.bodies: list[bytes] = []

    def request(self, _method: str, _path: str, body: bytes, _headers: dict) -> None:
        self.bodies.append(body)


def prompt_sent_by(canary, monkeypatch, options: list[str]) -> str:
    connection = RequestRecordingConnection()
    monkeypatch.setattr(canary.http.client, "HTTPConnection", lambda *_, **__: connection)
    canary.main(
        ["--marker", "m4rker", *options], stdin=io.StringIO("person\nworkload\n"), out=io.StringIO()
    )
    (body,) = connection.bodies
    return json.loads(body)["turn"]["messages"][0]["text"]


def test_the_canary_adds_the_request_marker_to_the_prompt_it_sends(canary, monkeypatch):
    prompt = prompt_sent_by(canary, monkeypatch, ["--request-marker", "r3quest-9c1"])

    assert "r3quest-9c1" in prompt


def test_the_canary_sends_the_plain_prompt_without_a_request_marker(canary, monkeypatch):
    prompt = prompt_sent_by(canary, monkeypatch, [])

    assert prompt == canary.ANSWER_PROMPT


def test_the_canary_prints_the_route_as_other_when_run_started_names_none_in_a_closed_word(
    canary, monkeypatch
):
    response = StreamedResponse(200, [("run_started", {"route": "A route!"})])

    _, lines = run_canary(canary, monkeypatch, response)

    assert "route other" in lines


def test_the_canary_names_the_code_of_a_failed_run_and_exits_non_zero(canary, monkeypatch):
    response = StreamedResponse(
        200, [("failed", {"code": "provider_unavailable", "message": "free text"})]
    )

    code, lines = run_canary(canary, monkeypatch, response)

    assert code != 0
    assert lines == ["answer 200", "event failed", "code provider_unavailable", "marker no"]


def test_the_canary_reports_a_refusal_by_its_status_alone(canary, monkeypatch):
    code, lines = run_canary(canary, monkeypatch, StreamedResponse(403, []))

    assert (code, lines) == (1, ["answer 403", "marker no"])


class RecordConnection(StreamedConnection):
    """The service for a cancelled run: the run's stream, then one record per status read."""

    def __init__(self, response, records: list[tuple[int, dict]]) -> None:
        super().__init__(response)
        self.records = records
        self.requests: list[tuple[str, str]] = []
        self.current = response

    def request(self, method, path, *_):
        self.requests.append((method, path))
        if method == "GET":
            status, document = self.records.pop(0)
            body = document if isinstance(document, bytes) else json.dumps(document).encode()
            self.current = StreamedResponse(status, [])
            self.current.read = lambda *_: body

    def getresponse(self):
        return self.current

    def close(self):
        return None


def run_cancelled_canary(canary, monkeypatch, run_id, records):
    started = StreamedResponse(200, [("run_started", {"route": "api", "run_id": run_id})])
    connection = RecordConnection(started, records)
    monkeypatch.setattr(canary.http.client, "HTTPConnection", lambda *_, **__: connection)
    monkeypatch.setattr(canary.time, "sleep", lambda _: None)
    out = io.StringIO()
    code = canary.main(
        ["--marker", "m", "--cancel"], stdin=io.StringIO("person\nworkload\n"), out=out
    )
    return code, out.getvalue().splitlines(), connection


RUN = "0123abcd-0123-4abc-8def-0123456789ab"


@pytest.mark.parametrize("polls_before_the_end", [0, 2], ids=["ended at once", "ended later"])
def test_the_canary_with_cancel_reads_the_ended_record_and_prints_only_its_state(
    canary, monkeypatch, polls_before_the_end
):
    records = [(200, {"state": "running", "ended_at": None})] * polls_before_the_end + [
        (200, {"state": "cancelled", "ended_at": "t"})
    ]

    code, lines, connection = run_cancelled_canary(canary, monkeypatch, RUN, records)

    assert (code, lines) == (
        0,
        ["answer 200", "event run_started", "route api", "status cancelled"],
    )
    assert {path for method, path in connection.requests if method == "GET"} == {f"/runs/{RUN}"}
    assert RUN not in "".join(lines)


def test_the_canary_with_cancel_exits_non_zero_when_the_run_did_not_end_cancelled(
    canary, monkeypatch
):
    records = [(200, {"state": "succeeded", "ended_at": "t"})]

    code, lines, _ = run_cancelled_canary(canary, monkeypatch, RUN, records)

    assert (code, lines[-1]) == (1, "status succeeded")


@pytest.mark.parametrize("state", ["running", "cancelled"])
def test_the_canary_with_cancel_fails_when_no_record_ended_within_the_polls(
    canary, monkeypatch, state
):
    records = [(200, {"state": state, "ended_at": None})] * canary.STATUS_POLLS

    code, lines, _ = run_cancelled_canary(canary, monkeypatch, RUN, records)

    assert (code, lines[-1]) == (1, f"status {canary.NOT_ENDED}")


@pytest.fixture(scope="module")
def smoke(canary):
    return importlib.import_module("smoke")


@pytest.mark.parametrize(
    "record",
    [
        (404, {}),
        (200, ["cancelled"]),
        (200, b"{not json"),
        (404, b"not json"),
        "over the limit",
    ],
    ids=["refused", "no object", "no JSON", "refused without JSON", "over the limit"],
)
def test_the_canary_with_cancel_reports_a_refused_or_unusable_record_as_other(
    canary, smoke, monkeypatch, record
):
    if record == "over the limit":
        ended = json.dumps({"state": "cancelled", "ended_at": "t"})
        record = (200, ended.ljust(smoke.MAX_RECORD_BYTES + 1).encode())

    code, lines, _ = run_cancelled_canary(canary, monkeypatch, RUN, [record])

    assert (code, lines[-1]) == (1, "status other")


def test_the_canary_with_cancel_reads_no_record_for_a_run_id_it_cannot_trust(canary, monkeypatch):
    code, lines, connection = run_cancelled_canary(canary, monkeypatch, "../x", [])

    assert (code, lines[-1]) == (1, "status other")
    assert [method for method, _ in connection.requests] == ["POST"]
