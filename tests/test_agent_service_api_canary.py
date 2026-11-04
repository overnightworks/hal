"""The canary of the direct route (`agent-service/api_canary.py`) and its one-off `agent-canary`:
what it sends, what it prints, and where compose places it. No container and no network: the
connection is a scripted one."""

import io
import json
import re
from pathlib import Path, PurePosixPath

import pytest
import yaml
from support.script_module import loaded_script

ROOT = Path(__file__).resolve().parents[1]
LITELLM_DIRECTORY = ROOT / "agent-service" / "litellm"
CANARY_SERVICE = "agent-canary"
OBSERVER = "realm-observer"
FINGERPRINT = re.compile(r"fp-[0-9a-f]{64}")
KEY = "sk-scratch-0a1b2c3d4e5f"
SENTINEL = "sentinel-9e8d7c6b5a4f"


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


@pytest.fixture(scope="module")
def canary():
    yield from loaded_script("api_canary", ROOT / "agent-service" / "api_canary.py")


@pytest.fixture(scope="module")
def compose() -> dict:
    return load(ROOT / "compose.yaml")


@pytest.fixture(scope="module")
def one_off(compose) -> dict:
    return compose["services"][CANARY_SERVICE]


class Response:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body

    def read(self, *_: object) -> bytes:
        return self.body


class Connection:
    """The front as the canary meets it: one answer, and every request recorded."""

    def __init__(self, response: Response, *address: object, **_: object) -> None:
        self.response = response
        self.address = address
        self.requests: list[tuple[str, str, bytes, dict]] = []

    def request(self, method: str, path: str, body: bytes, headers: dict) -> None:
        self.requests.append((method, path, body, headers))

    def getresponse(self) -> Response:
        return self.response

    def close(self) -> None:
        return None


def completion(content: object) -> bytes:
    return json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": content}}]}
    ).encode()


def run_canary(canary, monkeypatch, tmp_path, response: Response, marker: str = "m4rker"):
    key_file = tmp_path / "hopin"
    key_file.write_text(f"{KEY}\n")
    connections: list[Connection] = []

    def connect(*address: object, **options: object) -> Connection:
        connections.append(Connection(response, *address, **options))
        return connections[-1]

    monkeypatch.setattr(canary.http.client, "HTTPConnection", connect)
    out = io.StringIO()
    arguments = ["--key-file", str(key_file), "--model", "text/opus", "--marker", marker]
    code = canary.main(arguments, out=out)
    return code, out.getvalue().splitlines(), connections


def sent(connections: list[Connection]) -> tuple[str, str, dict, dict]:
    ((connection,),) = [connections]
    ((method, path, body, headers),) = connection.requests
    return method, path, json.loads(body), headers


# --- what the canary sends ----------------------------------------------------------------------


def test_the_canary_sends_only_the_model_one_message_with_the_marker_and_a_fresh_fingerprint(
    canary, monkeypatch, tmp_path
):
    drawn = iter(["a" * 64, "b" * 64])
    monkeypatch.setattr(canary.secrets, "token_hex", lambda _bytes: next(drawn))
    _, _, first = run_canary(canary, monkeypatch, tmp_path, Response(200, completion("m4rker")))
    _, _, second = run_canary(canary, monkeypatch, tmp_path, Response(200, completion("m4rker")))

    method, _, body, _ = sent(first)
    (message,) = body["messages"]
    assert method == "POST"
    assert set(body) == {"model", "messages", "user"}
    assert body["model"] == "text/opus"
    assert message["role"] == "user"
    assert "m4rker" in message["content"]
    assert FINGERPRINT.fullmatch(body["user"])
    assert body["user"].endswith("a" * 64)
    assert sent(second)[2]["user"].endswith("b" * 64)


def test_the_canary_sends_the_key_files_key_as_bearer_and_no_litellm_or_anthropic_header(
    canary, monkeypatch, tmp_path
):
    _, _, connections = run_canary(canary, monkeypatch, tmp_path, Response(200, completion("x")))

    _, _, _, headers = sent(connections)
    assert headers["Authorization"] == f"Bearer {KEY}"
    assert not [name for name in headers if name.lower().startswith(("x-litellm-", "anthropic-"))]


def test_the_canary_calls_the_fronts_service_at_its_entrypoint_port_and_one_of_its_paths(
    canary, monkeypatch, tmp_path, compose
):
    static = load(LITELLM_DIRECTORY / "front" / "traefik.yml")
    routers = load(LITELLM_DIRECTORY / "front" / "dynamic" / "route.yml")["http"]["routers"]
    front_port = int(static["entryPoints"]["api"]["address"].rpartition(":")[2])

    _, _, connections = run_canary(canary, monkeypatch, tmp_path, Response(200, completion("x")))

    (connection,) = connections
    host, port = connection.address[:2]
    mounted = {volume.split(":")[0] for volume in compose["services"][host]["volumes"]}
    assert "./agent-service/litellm/front/traefik.yml" in mounted
    assert port == front_port
    assert any(f"Path(`{sent(connections)[1]}`)" in router["rule"] for router in routers.values())


# --- what the canary prints ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (Response(200, completion("the m4rker")), (0, ["answer 200", "marker yes"])),
        (Response(200, completion("another value")), (1, ["answer 200", "marker no"])),
        (Response(200, completion(None)), (1, ["answer 200", "marker no"])),
        (Response(200, b"{not json"), (1, ["answer 200", "marker no"])),
        (Response(401, json.dumps({"error": {"message": SENTINEL}}).encode()),
         (1, ["answer 401", "marker no"])),
        (Response(500, completion("the m4rker")), (1, ["answer 500", "marker no"])),
    ],
    ids=["served", "missing", "no content", "no JSON", "refused", "server error"],
)  # fmt: skip
def test_the_canary_prints_its_status_and_whether_the_answer_held_the_marker_alone(
    canary, monkeypatch, tmp_path, response, expected
):
    code, lines, _ = run_canary(canary, monkeypatch, tmp_path, response)

    expected_code, expected_lines = expected
    assert code == expected_code
    assert lines == expected_lines


def test_an_exception_ends_the_canary_with_the_type_of_it_alone(canary, monkeypatch, tmp_path):
    class Refusing(Connection):
        def request(self, *_: object) -> None:
            raise ConnectionRefusedError(f"{SENTINEL} 10.0.0.7")

    monkeypatch.setattr(canary.http.client, "HTTPConnection", lambda *_, **__: Refusing(None))
    key_file = tmp_path / "hopin"
    key_file.write_text(KEY)
    out = io.StringIO()

    code = canary.main(
        ["--key-file", str(key_file), "--model", "text/opus", "--marker", "m"], out=out
    )

    assert code == 1
    assert out.getvalue() == "crashed ConnectionRefusedError\n"


def test_a_missing_key_file_is_a_crash_by_its_type_alone(canary, tmp_path):
    out = io.StringIO()

    code = canary.main(
        ["--key-file", str(tmp_path / "absent"), "--model", "text/opus", "--marker", "m"], out=out
    )

    assert code == 1
    assert out.getvalue() == "crashed FileNotFoundError\n"


def test_no_key_reaches_the_canarys_output(canary, monkeypatch, tmp_path):
    echoed = json.dumps({"choices": [{"message": {"content": f"m4rker {KEY}"}}]}).encode()

    _, lines, _ = run_canary(canary, monkeypatch, tmp_path, Response(200, echoed))

    assert KEY not in "\n".join(lines)


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        ("answer 200\nmarker yes\n", {"answer": "200", "marker": "yes", "unknown": "0"}),
        ("answer 4o3\nmarker maybe\nhello\n", {"unknown": "3"}),
        ("crashed Value_Error\ncrashed ValueError\n", {"crashed": "ValueError", "unknown": "1"}),
        ("route api\nevent succeeded\n", {"unknown": "2"}),
        ("", {"unknown": "0"}),
    ],
)
def test_a_line_outside_the_grammar_is_counted_and_never_kept(canary, stdout, expected):
    assert canary.verdicts(stdout, 3) == {**expected, "exit": "3"}


# --- the one-off --------------------------------------------------------------------------------


def test_agent_canary_is_on_one_app_network_that_the_front_joins(compose, one_off):
    (network,) = one_off["networks"]

    assert network in compose["services"]["litellm-front"]["networks"]
    assert network.startswith("agent-")


def test_agent_canarys_one_secret_is_the_key_of_its_networks_app_mounted_where_key_file_reads(
    compose, one_off
):
    (network,) = one_off["networks"]
    (mounted,) = one_off["secrets"]
    source = mounted if isinstance(mounted, str) else mounted["source"]
    target = mounted if isinstance(mounted, str) else mounted.get("target", source)
    entrypoint = one_off["entrypoint"]

    assert compose["secrets"][source]["file"].endswith(
        f"/litellm/apps/{network.removeprefix('agent-')}"
    )
    assert entrypoint[entrypoint.index("--key-file") + 1] == str(
        PurePosixPath("/run/secrets", target)
    )


def test_agent_canarys_model_is_a_model_name_of_litellms_configuration(one_off):
    names = {entry["model_name"] for entry in load(LITELLM_DIRECTORY / "config.yaml")["model_list"]}
    entrypoint = one_off["entrypoint"]

    assert entrypoint[entrypoint.index("--model") + 1] in names


def test_agent_canary_runs_its_one_mounted_script_isolated_without_writing_bytecode(one_off):
    (volume,) = one_off["volumes"]
    source, target, mode = volume.split(":")

    assert (ROOT / source).resolve() == (ROOT / "agent-service" / "api_canary.py").resolve()
    assert mode == "ro"
    assert one_off["entrypoint"][:4] == ["python", "-I", "-B", target]


def test_agent_canary_runs_as_the_realm_observers_user_with_no_port_address_or_dependency(
    compose, one_off
):
    assert one_off["user"] == compose["services"][OBSERVER]["user"]
    assert not {
        "ports", "expose", "depends_on", "extra_hosts", "network_mode", "cap_add", "restart",
    } & one_off.keys()  # fmt: skip
    assert one_off["environment"] == {"PYTHONDONTWRITEBYTECODE": "1"}
