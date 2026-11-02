"""The operator's smoke of the agent service (#214 cells S3 and S5): `agent-service/smoke.py`
against a fake stream, and the `agent-smoke` service of compose.yaml as a file.

The smoke against the real service is proven by probe/agent-service/unit.py (S4) and by the
operator's runbook (docs/agent-service.md, "Proofs").
"""

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PERSON_TOKEN = "person-token-0123456789abcdef"
WORKLOAD_TOKEN = "workload-token-fedcba9876543210"
BOTH_TOKENS = f"{PERSON_TOKEN}\n{WORKLOAD_TOKEN}\n"


def load_smoke():
    spec = importlib.util.spec_from_file_location("agent_smoke", ROOT / "agent-service/smoke.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


smoke = load_smoke()


def stream_of(*events: tuple[str, dict]) -> bytes:
    frames = (
        (number, name, json.dumps({"v": smoke.PROTOCOL_VERSION, "type": name, **data}))
        for number, (name, data) in enumerate(events)
    )
    return b"".join(
        f"id: {number}\nevent: {name}\ndata: {data}\n\n".encode() for number, name, data in frames
    )


class FakeResponse(io.BytesIO):
    def __init__(self, status: int, body: bytes) -> None:
        super().__init__(body)
        self.status = status


class StalledResponse(FakeResponse):
    """A stream whose service sends nothing more for now: the next read times out."""

    def readline(self, *_) -> bytes:
        line = super().readline()
        if not line:
            raise TimeoutError
        return line


class FakeSocket:
    def settimeout(self, seconds: float) -> None:
        self.timeout = seconds


class FakeConnection:
    """What the service answers; it records the request and whether it was closed."""

    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.requests: list[tuple[str, str, bytes, dict]] = []
        self.closed = False
        self.sock = FakeSocket()
        self.holds: list[tuple[float, bool]] = []  # each pause, and whether it was closed by then

    def request(self, method: str, path: str, body: bytes, headers: dict) -> None:
        self.requests.append((method, path, body, headers))

    def getresponse(self) -> FakeResponse:
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self) -> None:
        self.closed = True


def drive(
    answer: FakeResponse | Exception, *arguments: str, stdin: str = BOTH_TOKENS
) -> tuple[int, str, FakeConnection]:
    connection = FakeConnection(answer)
    out = io.StringIO()
    exit_code = smoke.main(
        list(arguments),
        io.StringIO(stdin),
        out,
        lambda *_: connection,
        lambda seconds: connection.holds.append((seconds, connection.closed)),
    )
    return exit_code, out.getvalue(), connection


def run_events(*events: tuple[str, dict]) -> FakeResponse:
    return FakeResponse(200, stream_of(*events))


SUCCESS = (
    ("run_started", {"heartbeat_interval_s": 15, "model": "anthropic/opus", "route": "cli"}),
    ("assistant_text", {"text": "ok"}),
    ("succeeded", {"text": "ok", "files": []}),
)


def test_a_successful_run_prints_the_event_types_and_the_text_and_exits_0():
    exit_code, out, connection = drive(run_events(*SUCCESS))

    assert exit_code == 0
    assert out.splitlines() == [
        "event: run_started",
        "served by anthropic/opus on route cli",
        "event: assistant_text",
        "ok",
        "event: succeeded",
        "ok",
    ]
    assert connection.closed


def test_the_tokens_go_to_the_service_as_headers_and_nowhere_else():
    _, _, connection = drive(run_events(*SUCCESS))

    ((method, path, body, headers),) = connection.requests
    assert (method, path) == ("POST", "/runs")
    assert headers["Authorization"] == f"Bearer {PERSON_TOKEN}"
    assert headers["Agent-Workload-Token"] == WORKLOAD_TOKEN
    assert PERSON_TOKEN.encode() not in body
    assert WORKLOAD_TOKEN.encode() not in body


def test_the_run_is_asked_for_in_the_current_wire_version_naming_an_agent_and_no_model():
    _, _, connection = drive(run_events(*SUCCESS))

    ((_, _, body, _),) = connection.requests
    document = json.loads(body)
    assert (document["v"], document["tools"], document["roles"]) == (
        smoke.PROTOCOL_VERSION,
        {},
        ["admin", "user"],
    )
    assert document["agent"] == "chat"
    assert "purpose" not in document
    assert "model" not in document


def test_a_run_started_without_model_and_route_prints_a_route_line_that_names_neither():
    _, out, _ = drive(run_events(("run_started", {"heartbeat_interval_s": 15})))

    assert out.splitlines()[:2] == ["event: run_started", "served by  on route "]


def test_each_tool_option_names_a_tool_and_its_effect_in_the_request():
    _, _, connection = drive(
        run_events(*SUCCESS), "--tool", "step:read_only", "--tool", "bare:read_only"
    )

    ((_, _, body, _),) = connection.requests
    assert json.loads(body)["tools"] == {"step": "read_only", "bare": "read_only"}


def test_a_failed_run_prints_its_code_and_message_and_exits_1():
    failure = ("failed", {"code": "provider_error", "message": "The provider failed."})

    exit_code, out, _ = drive(run_events(SUCCESS[0], failure))

    assert exit_code == 1
    assert "provider_error: The provider failed." in out


def test_a_refusal_prints_the_services_code_and_message_and_exits_1():
    refusal = json.dumps(
        {"v": smoke.PROTOCOL_VERSION, "code": "unauthorized", "message": "Sign in again."}
    ).encode()

    exit_code, out, _ = drive(FakeResponse(401, refusal))

    assert exit_code == 1
    assert out.strip() == "refused with 401 unauthorized: Sign in again."


def test_a_refusal_that_is_no_typed_body_prints_the_status_only():
    exit_code, out, _ = drive(FakeResponse(502, b"<html>bad gateway</html>"))

    assert exit_code == 1
    assert out.strip() == "refused with 502"


@pytest.mark.parametrize(
    "answer",
    [
        run_events(("assistant_text", {"text": 5})),
        FakeResponse(200, b'event: assistant_text\ndata: ["ok"]\n\n'),
        FakeResponse(
            200,
            b'event: succeeded\ndata: {"v": %d, "type": "succeeded"}\n\n'
            % (smoke.PROTOCOL_VERSION - 1),
        ),
    ],
    ids=["text of no text", "data of no object", "frame of the previous version"],
)
def test_a_frame_of_the_wrong_shape_ends_the_run_as_broken_off(answer):
    exit_code, out, _ = drive(answer)

    assert exit_code == 1
    assert out.splitlines()[-1] == "the run broke off: ValueError"


def test_a_succeeded_run_with_files_prints_no_line_for_them_and_exits_0():
    files = [{"name": "report.txt", "content": "b2s="}]
    succeeded = ("succeeded", {"text": "ok", "files": files})

    exit_code, out, _ = drive(run_events(SUCCESS[0], succeeded))

    assert exit_code == 0
    assert out.splitlines() == [
        "event: run_started",
        "served by anthropic/opus on route cli",
        "event: succeeded",
        "ok",
    ]


def test_a_succeeded_run_without_files_ends_the_run_as_broken_off():
    exit_code, out, _ = drive(run_events(SUCCESS[0], ("succeeded", {"text": "ok"})))

    assert exit_code == 1
    assert out.splitlines()[-1] == "the run broke off: ValueError"


def test_a_stream_cut_short_fails_the_run():
    exit_code, _, _ = drive(run_events(SUCCESS[0]))

    assert exit_code == 1


def test_cancel_closes_a_stream_that_is_still_running_after_the_hold():
    response = StalledResponse(200, stream_of(SUCCESS[0]))

    exit_code, out, connection = drive(response, "--cancel")

    assert exit_code == 0
    assert out.splitlines()[0] == "event: run_started"
    assert out.splitlines()[-1] == "closing the stream before the answer"
    assert connection.closed
    assert connection.holds == [(smoke.CANCEL_HOLD_SECONDS, False)]


@pytest.mark.parametrize("ending", ["succeeded", "failed", "cancelled"])
def test_cancel_fails_when_the_run_ends_during_the_hold(ending):
    response = StalledResponse(200, stream_of(SUCCESS[0], (ending, {"text": "ok", "files": []})))

    exit_code, out, _ = drive(response, "--cancel")

    assert exit_code == 1
    assert f"the run ended before the close (sent {ending}); L4 is not proven" in out
    assert "closing the stream before the answer" not in out


def test_cancel_fails_when_the_run_ending_waits_behind_another_frame():
    response = StalledResponse(200, stream_of(*SUCCESS))

    exit_code, out, _ = drive(response, "--cancel")

    assert exit_code == 1
    assert "the run ended before the close (sent succeeded); L4 is not proven" in out


def test_cancel_of_a_run_that_succeeded_without_a_start_to_cancel_at_fails():
    exit_code, out, _ = drive(run_events(*SUCCESS[1:]), "--cancel")

    assert exit_code == 1
    assert "ended before the stream could be closed" in out


@pytest.mark.parametrize(
    "stdin", ["", f"{PERSON_TOKEN}\n", f"{PERSON_TOKEN}\n\n", f"{BOTH_TOKENS}third\n", "a b\nc\n"]
)
def test_anything_but_two_token_lines_on_stdin_starts_no_run(stdin, capsys):
    exit_code, out, connection = drive(run_events(*SUCCESS), stdin=stdin)

    assert exit_code == 1
    assert connection.requests == []
    assert out == ""
    assert "two lines" in capsys.readouterr().err


def test_a_token_in_the_environment_is_not_taken(monkeypatch):
    monkeypatch.setenv("AGENT_PERSON_TOKEN", PERSON_TOKEN)
    monkeypatch.setenv("AGENT_WORKLOAD_TOKEN", WORKLOAD_TOKEN)

    exit_code, _, connection = drive(run_events(*SUCCESS), stdin="")

    assert exit_code == 1
    assert connection.requests == []


@pytest.mark.parametrize(
    "argv",
    [
        ["--person-token", PERSON_TOKEN, WORKLOAD_TOKEN],
        [f"--timeout={PERSON_TOKEN}"],
        ["--timeout", WORKLOAD_TOKEN],
        [f"--can{PERSON_TOKEN}"],
        ["--tool", PERSON_TOKEN],
        ["--tool", f":{PERSON_TOKEN}"],
        ["--tool", f"{PERSON_TOKEN}:read_only", "--tool", f"{PERSON_TOKEN}:mutating"],
        ["--offer"],
    ],
    ids=[
        "unknown option",
        "bad timeout",
        "bad timeout value",
        "abbreviated option",
        "tool without an effect",
        "tool without a name",
        "tool named twice",
        "removed offer option",
    ],
)
def test_a_rejected_argument_is_never_printed(argv, capsys):
    stdin = io.StringIO(BOTH_TOKENS)
    with pytest.raises(SystemExit) as exit_info:
        smoke.main(argv, stdin)

    captured = capsys.readouterr()
    assert exit_info.value.code == 2
    assert captured.err
    for token in (PERSON_TOKEN, WORKLOAD_TOKEN):
        assert token not in captured.out + captured.err


@pytest.mark.parametrize(
    "answer",
    [
        run_events(
            SUCCESS[0],
            ("assistant_text", {"text": f"I was given {PERSON_TOKEN}"}),
            ("failed", {"code": "provider_error", "message": f"{WORKLOAD_TOKEN} failed"}),
        ),
        FakeResponse(401, json.dumps({"code": "unauthorized", "message": PERSON_TOKEN}).encode()),
        OSError(f"connection to the service broke with {WORKLOAD_TOKEN}"),
        FakeResponse(200, b"event: x\ndata: {" + PERSON_TOKEN.encode() + b"\n\n"),
        run_events(("assistant_text", {"text": [PERSON_TOKEN]})),
        FakeResponse(200, f'event: x\ndata: ["{PERSON_TOKEN}"]\n\n'.encode()),
        run_events(("run_started", {"model": PERSON_TOKEN, "route": WORKLOAD_TOKEN})),
    ],
    ids=[
        "events",
        "refusal",
        "connection error",
        "broken frame",
        "text of no text",
        "data of no object",
        "run_started naming a token",
    ],
)
def test_no_token_reaches_the_output_whichever_path_a_run_takes(answer, capsys):
    _, out, _ = drive(answer)

    captured = capsys.readouterr()
    printed = out + captured.out + captured.err
    assert PERSON_TOKEN not in printed
    assert WORKLOAD_TOKEN not in printed


# --- the compose service (S5) ---------------------------------------------------------------


@pytest.fixture(scope="module")
def services() -> dict:
    return yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]


ONE_OFFS = pytest.mark.parametrize("name", ["agent-smoke", "agent-canary"])


@ONE_OFFS
def test_a_one_off_is_in_the_apply_profile_so_its_tokens_on_stdin_reach_no_journal(services, name):
    """The one-offs are the services of the `apply` profile, which test_stack_compose_one_offs.py
    shows log to none."""
    assert services[name]["profiles"] == services["realm-observer"]["profiles"]


@ONE_OFFS
def test_a_one_off_is_hardened_like_the_realm_observer(services, name):
    one_off, observer = services[name], services["realm-observer"]

    for key in ("user", "read_only", "cap_drop", "security_opt"):
        assert one_off[key] == observer[key]


@ONE_OFFS
def test_a_one_off_runs_the_service_image_that_is_never_pulled(services, name):
    assert services[name]["image"] == services["agent-service"]["image"]
    assert services[name]["pull_policy"] == "never"


@ONE_OFFS
def test_a_one_off_has_no_port_secret_or_address(services, name):
    one_off = services[name]

    assert not {"ports", "expose", "secrets", "extra_hosts", "network_mode", "depends_on"} & (
        one_off.keys()
    )
    assert all(volume.endswith(":ro") for volume in one_off["volumes"])
    assert "environment" not in one_off


@ONE_OFFS
def test_a_one_off_starts_its_mounted_script_without_writing_bytecode(services, name):
    one_off = services[name]
    mounted = {volume.split(":")[1] for volume in one_off["volumes"]}

    assert one_off["entrypoint"][0] == "python"
    assert "-B" in one_off["entrypoint"]
    assert one_off["entrypoint"][-1] in mounted


def test_agent_smoke_starts_in_isolated_mode(services):
    assert "-I" in services["agent-smoke"]["entrypoint"]


@ONE_OFFS
def test_a_one_off_reaches_the_service_by_the_name_it_connects_to(services, name):
    assert smoke.SERVICE_HOST in services
    assert set(services[name]["networks"]) <= set(services["agent-service"]["networks"])
    assert len(services[name]["networks"]) == 1


@pytest.mark.parametrize("key", ["agent-songmaker", "agent-presentator", "agent-hopin"])
def test_each_agent_network_is_internal_and_no_shared_one_exists(key):
    """P35: one internal network per app (isolated: test_agent_egress.py), and no shared one."""
    networks = yaml.safe_load((ROOT / "compose.yaml").read_text())["networks"]

    assert networks[key]["internal"] is True
    assert "agent" not in networks
    assert "hal_agent" not in {network.get("name") for network in networks.values()}
