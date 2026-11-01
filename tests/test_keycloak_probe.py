"""The Keycloak probe's credential bookkeeping and teardown, checked without a Keycloak stack."""

import json
import os
import re
import signal
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from types import FrameType, ModuleType, SimpleNamespace
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request
from urllib.response import addinfourl

import pytest
import support.keycloak_probe as keycloak_support
import yaml
from support.fake_docker import DAEMON_GONE, LATE_APPLY, RUNNING_APPLY, SERVICE_CONTAINER
from support.keycloak_probe import DockerHost

REPOSITORY = Path(__file__).resolve().parents[1]
LOGIN_URL = "http://localhost:8090/realms/master/login-actions/authenticate"

# The probe's module and the docker host are the support module's fixtures.
probe, docker_host = keycloak_support.probe, keycloak_support.docker_host


def response_setting(*set_cookie_lines: str) -> addinfourl:
    headers = Message()
    for line in set_cookie_lines:
        headers["Set-Cookie"] = line
    return addinfourl(BytesIO(b""), headers, LOGIN_URL)


def test_every_cookie_value_reaches_proof_7_although_a_later_response_replaces_or_expires_it(
    probe: ModuleType,
) -> None:
    kept: dict[str, str] = {}
    jar = probe.ReceivedCookies(lambda name, value: kept.setdefault(name, value))
    request = Request(LOGIN_URL)

    jar.extract_cookies(
        response_setting(
            "KC_RESTART=restart-1; Path=/realms/master/; HttpOnly",
            "AUTH_SESSION_ID=session-1; Path=/realms/master/",
        ),
        request,
    )
    jar.extract_cookies(
        response_setting(
            "KC_RESTART=; Max-Age=0; Path=/realms/master/",
            "AUTH_SESSION_ID=session-2; Path=/realms/master/",
        ),
        request,
    )

    assert sorted(kept.values()) == ["restart-1", "session-1", "session-2"]


@pytest.mark.parametrize(
    ("apply_lands_during_down", "unlistable_kind", "teardown_line", "removed", "containers_left"),
    [
        (False, None, "teardown: stack edge-kc-probe removed", True, set()),
        (
            True,
            None,
            f"teardown: stack edge-kc-probe FAILED (still there: container {LATE_APPLY})",
            False,
            {LATE_APPLY},
        ),
        (
            False,
            "volume",
            f"teardown: stack edge-kc-probe FAILED (still there: volumes unlisted ({DAEMON_GONE}))",
            False,
            set(),
        ),
    ],
    ids=[
        "a-sigterm-mid-apply-leaves-nothing",
        "a-container-left-behind-is-named",
        "a-failing-listing-is-not-taken-for-nothing-left",
    ],
)
def test_teardown_says_removed_only_when_nothing_of_the_stack_is_left(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    docker_host: DockerHost,
    apply_lands_during_down: bool,
    unlistable_kind: str | None,
    teardown_line: str,
    removed: bool,
    containers_left: set[str],
) -> None:
    docker_host.configure(
        containers=[SERVICE_CONTAINER, RUNNING_APPLY],
        one_offs=[RUNNING_APPLY, LATE_APPLY],
        apply_lands_during_down=apply_lands_during_down,
        unlistable_kind=unlistable_kind,
    )

    said_removed = probe.Stack(tmp_path).down()

    assert capsys.readouterr().out.splitlines() == [teardown_line]
    assert said_removed == removed
    assert docker_host.containers == containers_left


def run_main(
    probe: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    scratch: Path,
    *,
    run_signal: signal.Signals | None,
    down_signal: signal.Signals | None,
    construct_signal: signal.Signals | None = None,
) -> int:
    """main() over a stack and proofs that each receive a signal, as `timeout` or Ctrl-C would."""

    class FakeProbe:
        def __init__(self, _stack: object) -> None: ...

        def run(self) -> None:
            if run_signal:
                os.kill(os.getpid(), run_signal)

    class FakeStack:
        def __init__(self, _scratch: Path) -> None:
            if construct_signal:
                os.kill(os.getpid(), construct_signal)

        def down(self) -> bool:
            if down_signal:
                os.kill(os.getpid(), down_signal)
            sys.stdout.write("teardown: stack edge-kc-probe removed\n")
            return True

    monkeypatch.setattr(sys, "argv", ["probe.py", "--scratch", str(scratch)])
    monkeypatch.setattr(probe, "Probe", FakeProbe)
    return probe.main(FakeStack)


@pytest.mark.parametrize("signal_name", [signal.SIGTERM, signal.SIGINT])
def test_a_signal_during_the_teardown_does_not_cut_it_short(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    restored_signal_handlers: None,
    signal_name: signal.Signals,
) -> None:
    exit_code = run_main(
        probe, monkeypatch, tmp_path / "s", run_signal=None, down_signal=signal_name
    )

    assert exit_code == 0
    assert "teardown: stack edge-kc-probe removed" in capsys.readouterr().out


@pytest.mark.parametrize("signal_name", [signal.SIGTERM, signal.SIGINT])
def test_a_signal_during_the_proofs_tears_down_and_ends_with_one_failed_line(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    restored_signal_handlers: None,
    signal_name: signal.Signals,
) -> None:
    exit_code = run_main(
        probe, monkeypatch, tmp_path / "s", run_signal=signal_name, down_signal=None
    )

    assert exit_code == 1
    assert capsys.readouterr().out.splitlines() == [
        "teardown: stack edge-kc-probe removed",
        f"PROBE FAILED: stopped by {signal_name.name}",
    ]


@pytest.mark.parametrize("signal_name", [signal.SIGTERM, signal.SIGINT])
def test_a_signal_while_the_stack_is_built_fails_without_a_teardown(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    restored_signal_handlers: None,
    signal_name: signal.Signals,
) -> None:
    exit_code = run_main(
        probe,
        monkeypatch,
        tmp_path / "s",
        run_signal=None,
        down_signal=None,
        construct_signal=signal_name,
    )

    assert exit_code == 1
    assert capsys.readouterr().out.splitlines() == [f"PROBE FAILED: stopped by {signal_name.name}"]


def test_a_scratch_that_is_a_file_or_not_empty_is_refused_with_the_usage_exit_code(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    a_file = tmp_path / "file"
    a_file.write_text("x")
    non_empty = tmp_path / "dir"
    non_empty.mkdir()
    (non_empty / "x").write_text("x")

    for scratch in (a_file, non_empty):
        with pytest.raises(SystemExit) as refused:
            run_main(probe, monkeypatch, scratch, run_signal=None, down_signal=None)
        assert refused.value.code == 2
        assert f"{scratch} is not an empty directory" in capsys.readouterr().err


def test_the_stack_listens_on_ports_of_its_own_beside_the_live_edge(
    probe: ModuleType, tmp_path: Path, docker_host: DockerHost
) -> None:
    stack = probe.Stack(tmp_path)
    stack.write_traefik_config()

    config = stack.traefik_config.read_text()
    assert f'address: "127.0.0.1:{stack.edge_port}"' in config
    assert f'address: "127.0.0.1:{stack.admin_port}"' in config
    assert {stack.edge_port, stack.admin_port}.isdisjoint({8081, 8090})
    assert stack.edge_url == f"http://127.0.0.1:{stack.edge_port}"
    assert stack.admin_url == f"http://localhost:{stack.admin_port}"


def test_the_probes_traefik_constraint_takes_its_own_project_and_the_live_one_refuses_its_keycloak(
    probe: ModuleType, tmp_path: Path, docker_host: DockerHost
) -> None:
    live_config = (REPOSITORY / "traefik.yml").read_text()
    live_constraint = re.search(r'constraints: "LabelRegex\(`edge.name`, `(.+?)`\)"', live_config)
    assert live_constraint is not None
    overlay = yaml.safe_load((REPOSITORY / "probe/keycloak/compose.probe.yaml").read_text())
    probe_name = overlay["services"]["keycloak"]["labels"]["edge.name"]
    stack = probe.Stack(tmp_path)

    stack.write_traefik_config()

    assert re.fullmatch(live_constraint.group(1), probe_name) is None
    probe_config = stack.traefik_config.read_text()
    assert "Label(`com.docker.compose.project`, `edge-kc-probe`)" in probe_config
    assert "LabelRegex" not in probe_config


GO_LIVE_OVERRIDES = [
    "ADMIN_URL",
    "EDGE_URL",
    "MASTER_ISSUER",
    "MASTER_TOKEN_URL",
    "ADMIN_REALMS",
]


class InterceptedKeycloak:
    """What go-live's HTTP reaches instead of a network: every URL it was asked for."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def __call__(self, request: Request, timeout: float) -> addinfourl:
        self.urls.append(request.full_url)
        path = urlsplit(request.full_url).path
        method = request.get_method()
        status, body = 200, "[]"
        if path.endswith("/token"):
            body = '{"access_token": "token"}'
        elif method == "POST" and path.endswith("/users"):
            status, body = 201, ""
        elif method == "POST":
            status, body = 204, ""
        elif path.endswith("/users"):
            body = '[{"id": "user-1"}]' if "username" in request.full_url else "[]"
        elif path.endswith("/roles/admin"):
            body = '{"name": "admin"}'
        reply = addinfourl(BytesIO(body.encode()), Message(), request.full_url, status)
        return reply


@pytest.fixture
def go_live_probe(
    probe: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[object, InterceptedKeycloak, str]:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    for name in ("config-cli-secret", "bootstrap-admin-password"):
        (secrets_dir / name).write_text("secret")
    admin_url = "http://localhost:41002"
    stack = SimpleNamespace(
        scratch=tmp_path,
        secrets_dir=secrets_dir,
        admin_url=admin_url,
        edge_url="http://127.0.0.1:41001",
        master_issuer=f"{admin_url}/realms/master",
        master_token_url=f"{admin_url}/realms/master/protocol/openid-connect/token",
    )
    intercepted = InterceptedKeycloak()
    load_go_live = probe.load_go_live

    def go_live_without_a_network() -> ModuleType:
        module = load_go_live()
        module.urlopen = intercepted
        return module

    monkeypatch.setattr(probe, "load_go_live", go_live_without_a_network)
    return probe.Probe(stack), intercepted, admin_url


def test_proof_11s_admin_step_sends_every_request_to_the_probes_admin_entrypoint(
    go_live_probe: tuple[Any, InterceptedKeycloak, str],
) -> None:
    probe_run, intercepted, admin_url = go_live_probe

    step = probe_run.go_live_admin_step("first-password", typed_answers=True)
    assert not step.is_done()
    step.do()

    assert intercepted.urls
    assert {urlsplit(url).netloc for url in intercepted.urls} == {urlsplit(admin_url).netloc}
    assert not any("8090" in url or "8081" in url for url in intercepted.urls)


@pytest.mark.parametrize("override", GO_LIVE_OVERRIDES)
def test_proof_11_refuses_to_run_when_go_live_still_names_the_live_edge(
    probe: ModuleType,
    go_live_probe: tuple[Any, InterceptedKeycloak, str],
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    probe_run, _intercepted, _admin_url = go_live_probe
    load_go_live = probe.load_go_live

    class IgnoresOneAssignment(ModuleType):
        def __setattr__(self, name: str, value: object) -> None:
            if name != override:
                super().__setattr__(name, value)

    def go_live_keeping_its_live_address() -> ModuleType:
        module = load_go_live()
        module.__class__ = IgnoresOneAssignment
        return module

    monkeypatch.setattr(probe, "load_go_live", go_live_keeping_its_live_address)

    with pytest.raises(probe.ProbeFailure, match=f"go-live's {override} still names the live edge"):
        probe_run.go_live_admin_step("first-password", typed_answers=True)


def docker_answering(
    monkeypatch: pytest.MonkeyPatch, probe: ModuleType, *, networks: list[str], subnets: str
) -> None:
    def answer(*arguments: str) -> subprocess.CompletedProcess[str]:
        if arguments[:2] == ("network", "ls"):
            return subprocess.CompletedProcess(arguments, 0, "\n".join(networks), "")
        return subprocess.CompletedProcess(arguments, 0, subnets, "")

    monkeypatch.setattr(probe, "docker", answer)


def test_the_probe_skips_a_candidate_subnet_that_a_network_overlaps(
    probe: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker_answering(
        monkeypatch, probe, networks=["live"], subnets="172.31.253.0/24 172.31.200.128/25 "
    )

    assert probe.free_subnet() == "172.31.201.0/24"


def test_the_probe_fails_when_every_candidate_subnet_is_taken(
    probe: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker_answering(monkeypatch, probe, networks=["wide"], subnets="172.31.0.0/16")

    with pytest.raises(probe.ProbeFailure, match="no free /24"):
        probe.free_subnet()


@pytest.mark.parametrize("fault", ["a docker failure", "every subnet taken"])
def test_a_failure_while_building_the_stack_ends_with_one_failure_and_no_teardown(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    restored_signal_handlers: None,
    fault: str,
) -> None:
    if fault == "a docker failure":
        monkeypatch.setattr(
            probe,
            "docker",
            lambda *arguments: subprocess.CompletedProcess(arguments, 1, "", "daemon is gone"),
        )
    else:
        docker_answering(monkeypatch, probe, networks=["wide"], subnets="172.31.0.0/16")
    monkeypatch.setattr(sys, "argv", ["probe.py", "--scratch", str(tmp_path / "s")])
    exit_code = probe.main()

    output = capsys.readouterr().out
    assert exit_code == 1
    assert output.startswith("PROBE FAILED: ")
    assert output.count("PROBE FAILED") == 1
    assert "teardown" not in output


FRESH_APPLY_LINE = "fresh apply done"


class OperatorInput:
    """Stdin that ends the way a caller would: by a signal or by closing the pipe."""

    def __init__(self, signal_to_send: signal.Signals | None) -> None:
        self.signal_to_send = signal_to_send

    def read(self) -> str:
        if self.signal_to_send:
            os.kill(os.getpid(), self.signal_to_send)
        return ""


class SignallingStdout:
    """Stdout that sends a signal as READY is written, while the stop signals are blocked."""

    def __init__(self, real: object, signal_to_send: signal.Signals) -> None:
        self.real = real
        self.signal_to_send = signal_to_send

    def write(self, text: str) -> int:
        written = self.real.write(text)
        if text.startswith("READY "):
            os.kill(os.getpid(), self.signal_to_send)
        return written

    def __getattr__(self, name: str) -> object:
        return getattr(self.real, name)


class KeycloakAnswers(BaseHTTPRequestHandler):
    """Keycloak as the bring-up asks it: ready, and handing out a token."""

    def do_GET(self) -> None:
        self.reply({"realm": "hallucinai"})

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers["Content-Length"]))
        status = self.server.token_status
        self.reply(
            {"access_token": "an-access-token"} if status == 200 else {"error": "denied"}, status
        )

    def reply(self, body: dict[str, str], status: int = 200) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_: object) -> None:
        pass


@pytest.fixture
def fake_keycloak(request: pytest.FixtureRequest) -> Iterator[str]:
    """Keycloak on an ephemeral port; yields the admin URL the probe is told to use.

    Hands out tokens unless a test parametrizes this fixture with another token status."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), KeycloakAnswers)
    server.token_status = getattr(request, "param", 200)
    # Threads inherit the signal mask; a server thread must not take a stop signal meant for main.
    stop_signals = {signal.SIGTERM, signal.SIGINT}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, stop_signals)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def hold_host(docker_host: DockerHost, restored_signal_handlers: None) -> DockerHost:
    """The host a hold runs on: fake docker, signal handlers restored."""
    return docker_host


def run_hold(
    probe: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    scratch: Path,
    hold_host: DockerHost,
    admin_url: str,
    *,
    while_ready_is_written: signal.Signals | None = None,
    after_ready: signal.Signals | None = None,
) -> int:
    monkeypatch.setattr(
        sys,
        "argv",
        ["probe.py", "hold", "--scratch", str(scratch)],
    )
    monkeypatch.setattr(sys, "stdin", OperatorInput(after_ready))
    if while_ready_is_written:
        monkeypatch.setattr(sys, "stdout", SignallingStdout(sys.stdout, while_ready_is_written))
    return probe.main(lambda path: probe.Stack(path, admin_url, write_appkit=lambda: None))


def test_the_admin_url_is_not_part_of_the_command_line(
    probe: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#34 finding 2: a caller passing the test-only flag gets a usage error."""
    argv = ["probe.py", "hold", "--scratch", str(tmp_path / "s"), "--admin-url", "http://x:1"]
    monkeypatch.setattr(sys, "argv", argv)

    with pytest.raises(SystemExit) as refused:
        probe.main()

    assert refused.value.code == 2


def ready_lines(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith("READY ")]


def test_hold_prints_one_ready_line_naming_the_secret_file_and_no_secret_value(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    hold_host: DockerHost,
    fake_keycloak: str,
) -> None:
    """#21 D1a: hold prints one READY line naming the secret file, never the secret value."""
    scratch = tmp_path / "s"
    run_hold(probe, monkeypatch, scratch, hold_host, fake_keycloak)

    output = capsys.readouterr().out
    [ready] = ready_lines(output)
    details = json.loads(ready.removeprefix("READY "))
    assert re.fullmatch(r"http://127\.0\.0\.1:\d+", details["edge_url"])
    assert details["edge_url"] not in ("http://127.0.0.1:8081", "http://127.0.0.1:8090")
    assert details | {"edge_url": ""} == {
        "admin_url": fake_keycloak,
        "edge_url": "",
        "realm": "hallucinai",
        "public_issuer": "https://auth.hallucinai.de/realms/hallucinai",
        "admin_client_id": "config-cli",
        "admin_client_secret_file": str(scratch.resolve() / "secrets" / "config-cli-secret"),
    }
    secret_file = Path(json.loads(ready.removeprefix("READY "))["admin_client_secret_file"])
    assert secret_file.read_text() not in output


@pytest.mark.parametrize(
    "ending", [signal.SIGTERM, signal.SIGINT, None], ids=["sigterm", "sigint", "stdin-eof"]
)
def test_hold_ends_normally_when_told_to_stop_after_ready(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    hold_host: DockerHost,
    fake_keycloak: str,
    ending: signal.Signals | None,
) -> None:
    """#21 D1a: SIGTERM, SIGINT or stdin EOF after READY tears down, prints HOLD ENDED, exits 0."""
    exit_code = run_hold(
        probe, monkeypatch, tmp_path / "s", hold_host, fake_keycloak, after_ready=ending
    )

    lines = capsys.readouterr().out.splitlines()
    assert exit_code == 0
    assert [line.split(" ")[0] for line in lines] == ["stack:", "READY", "teardown:", "HOLD"]
    assert lines[-2:] == ["teardown: stack edge-kc-probe removed", "HOLD ENDED"]


def test_hold_stopped_by_a_signal_before_ready_tears_down_and_fails(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    hold_host: DockerHost,
    fake_keycloak: str,
) -> None:
    """#21 D1a: a stop signal before READY tears down and ends with PROBE FAILED, exit 1."""
    hold_host.configure(signal_parent_on_run="SIGTERM")

    exit_code = run_hold(probe, monkeypatch, tmp_path / "s", hold_host, fake_keycloak)

    lines = capsys.readouterr().out.splitlines()
    assert exit_code == 1
    assert ready_lines("\n".join(lines)) == []
    assert lines[-2:] == [
        "teardown: stack edge-kc-probe removed",
        "PROBE FAILED: stopped by SIGTERM",
    ]


@pytest.mark.parametrize("stop_signal", [signal.SIGTERM, signal.SIGINT])
def test_hold_stopped_while_ready_is_written_still_ends_normally(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    hold_host: DockerHost,
    fake_keycloak: str,
    stop_signal: signal.Signals,
) -> None:
    """#21 D1a: a stop signal arriving as READY is flushed is a stop: HOLD ENDED, exit 0."""
    exit_code = run_hold(
        probe,
        monkeypatch,
        tmp_path / "s",
        hold_host,
        fake_keycloak,
        while_ready_is_written=stop_signal,
    )

    lines = capsys.readouterr().out.splitlines()
    assert exit_code == 0
    assert lines[-2:] == ["teardown: stack edge-kc-probe removed", "HOLD ENDED"]


def test_hold_stopped_again_between_ignoring_the_two_stop_signals_still_tears_down(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    hold_host: DockerHost,
    fake_keycloak: str,
) -> None:
    """#21 D1a: a SIGINT after SIGTERM, before SIGINT is ignored, cannot skip the teardown."""
    sent = []

    def sigint_once_sigterm_is_ignored(frame: FrameType, event: str, _arg: object) -> None:
        sigterm_ignored = signal.getsignal(signal.SIGTERM) == signal.SIG_IGN
        if (
            event == "return"
            and frame.f_code is signal.signal.__code__
            and sigterm_ignored
            and signal.getsignal(signal.SIGINT) != signal.SIG_IGN
            and not sent
        ):
            sent.append(signal.SIGINT)
            os.kill(os.getpid(), signal.SIGINT)

    sys.setprofile(sigint_once_sigterm_is_ignored)
    try:
        exit_code = run_hold(
            probe, monkeypatch, tmp_path / "s", hold_host, fake_keycloak, after_ready=signal.SIGTERM
        )
    finally:
        sys.setprofile(None)

    assert sent
    assert exit_code == 0
    assert capsys.readouterr().out.splitlines()[-2:] == [
        "teardown: stack edge-kc-probe removed",
        "HOLD ENDED",
    ]
    assert hold_host.containers == set()


def test_hold_whose_teardown_leaves_the_stack_after_ready_fails(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    hold_host: DockerHost,
    fake_keycloak: str,
) -> None:
    """#21 D1a: a teardown that leaves the stack after READY is PROBE FAILED, exit 1."""
    hold_host.configure(apply_lands_during_down=True)

    exit_code = run_hold(probe, monkeypatch, tmp_path / "s", hold_host, fake_keycloak)

    last_line = capsys.readouterr().out.splitlines()[-1]
    assert exit_code == 1
    assert last_line.startswith("PROBE FAILED: stack edge-kc-probe is left behind")


def test_run_proves_3b_before_the_fresh_apply_and_3a_after_it(
    probe: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#21 D1a: the run mode keeps its proof order (3b before the fresh apply, 3a after it)."""

    def start_with_bootstrap_admin(_self: object) -> object:
        sys.stdout.write("stack: up with the temporary bootstrap admin\n")
        return object()

    def missing_variable_fails_loudly(self: object, _admin: object) -> None:
        self.held("3b", "an undefined variable fails the apply")

    def apply_and_restart(self: Any) -> None:
        sys.stdout.write(f"{FRESH_APPLY_LINE}\n")
        self.admin = object()

    monkeypatch.setattr(probe.logout_actions_cell, "prove", lambda *_: None)
    for later_proof in (
        "fresh_realm_has_nothing_only_in_keycloak",
        "seed_member",
        "apply_removes_what_the_observer_names",
        "public_issuer_and_paths",
        "go_live_creates_the_admin",
        "admin_console_only_on_loopback",
        "changed_yaml_applies",
        "create_probe_rp",
        "member_token_carries_groups_and_audience",
        "disabled_user_refused_on_refresh",
        "backchannel_logout_reaches_rp",
        "only_logins_and_failed_logins_are_stored",
        "app_client",
        "the_realm_step",
        "the_observer_door",
        "no_secret_leaked",
    ):
        monkeypatch.setattr(probe.Probe, later_proof, lambda *_: None)
    monkeypatch.setattr(probe.Probe, "start_with_bootstrap_admin", start_with_bootstrap_admin)
    monkeypatch.setattr(probe.Probe, "missing_variable_fails_loudly", missing_variable_fails_loudly)
    monkeypatch.setattr(probe.Probe, "apply_and_restart", apply_and_restart)
    probe.Probe(stack=object()).run()

    lines = capsys.readouterr().out.splitlines()
    assert [line.split(" held:")[0] for line in lines] == [
        "stack: up with the temporary bootstrap admin",
        "PROOF 3b",
        FRESH_APPLY_LINE,
        "PROOF 3a",
    ]


def test_hold_stopped_again_as_the_teardown_is_entered_still_tears_down(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    hold_host: DockerHost,
    fake_keycloak: str,
) -> None:
    """#21 D1a: a second stop signal as the stop handling starts cannot skip the teardown."""
    sent = []

    def sigint_on_first_call_of_ignoring(frame: FrameType, event: str, _arg: object) -> None:
        if event == "call" and frame.f_code is probe.ignore_stop_signals.__code__ and not sent:
            sent.append(signal.SIGINT)
            os.kill(os.getpid(), signal.SIGINT)

    sys.setprofile(sigint_on_first_call_of_ignoring)
    try:
        exit_code = run_hold(
            probe, monkeypatch, tmp_path / "s", hold_host, fake_keycloak, after_ready=signal.SIGTERM
        )
    finally:
        sys.setprofile(None)

    assert sent
    assert exit_code == 0
    assert capsys.readouterr().out.splitlines()[-2:] == [
        "teardown: stack edge-kc-probe removed",
        "HOLD ENDED",
    ]
    assert hold_host.containers == set()


def stop_signal_as_the_teardown_is_entered(
    probe: ModuleType, sent: list[signal.Signals]
) -> Callable[[FrameType, str, object], None]:
    """A profile hook that sends SIGTERM when main's own teardown entry calls the ignoring."""

    def hook(frame: FrameType, event: str, _arg: object) -> None:
        if event == "call" and frame.f_code is probe.ignore_stop_signals.__code__ and not sent:
            sent.append(signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGTERM)

    return hook


@pytest.mark.parametrize(
    ("fake_keycloak", "exit_code", "last_line"),
    [
        (200, 0, "HOLD ENDED"),
        (
            401,
            1,
            "PROBE FAILED: stopped by SIGTERM; "
            'the token request for temp-admin answered 401: {"error": "denied"}',
        ),
    ],
    ids=["stdin-eof-after-ready", "bring-up-failure"],
    indirect=["fake_keycloak"],
)
def test_hold_signalled_as_the_teardown_is_entered_without_a_prior_signal_still_tears_down(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    hold_host: DockerHost,
    fake_keycloak: str,
    exit_code: int,
    last_line: str,
) -> None:
    """#21 D1a: a stop signal at teardown entry after stdin EOF or a failure cannot skip it."""
    sent: list[signal.Signals] = []
    sys.setprofile(stop_signal_as_the_teardown_is_entered(probe, sent))
    try:
        result = run_hold(probe, monkeypatch, tmp_path / "s", hold_host, fake_keycloak)
    finally:
        sys.setprofile(None)

    assert sent
    assert result == exit_code
    lines = capsys.readouterr().out.splitlines()
    assert lines[-1] == last_line
    assert "teardown: stack edge-kc-probe removed" in lines
    assert hold_host.containers == set()


class ImportedClients:
    def __init__(self, client: dict[str, object]) -> None:
        self.client = client

    def find(self, path: str, key: str, value: str) -> dict[str, object]:
        return self.client


HOPIN_SCOPES = ["basic", "profile", "groups", "roles", "service_account", "agent-service-audience"]
SONGMAKER_SCOPES = [*HOPIN_SCOPES, "email", "web-origins", "acr"]


def imported_client(client: object, **changes: object) -> dict[str, object]:
    return {
        "publicClient": False,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "frontchannelLogout": False,
        "redirectUris": list(client.callbacks),
        "baseUrl": f"{client.origin}/",
        "alwaysDisplayInConsole": False,
        "optionalClientScopes": sorted(client.optional_scopes),
        "defaultClientScopes": sorted(client.default_scopes),
        "attributes": sys.modules["backchannel_cell"].ruled_settings(client.client_id),
    } | changes


@pytest.mark.parametrize(
    ("client_name", "changes", "accepted"),
    [
        pytest.param("PRESENTATOR", {}, True, id="a workload client as decided"),
        pytest.param("HOPIN", {}, True, id="hopin as decided"),
        pytest.param(
            "PRESENTATOR",
            {"defaultClientScopes": SONGMAKER_SCOPES[::-1]},
            True,
            id="another order of the scopes",
        ),
        pytest.param(
            "PRESENTATOR",
            {"defaultClientScopes": HOPIN_SCOPES},
            False,
            id="presentator with hopin's smaller set",
        ),
        pytest.param(
            "PRESENTATOR", {"serviceAccountsEnabled": False}, False, id="no service account"
        ),
        pytest.param(
            "HOPIN", {"serviceAccountsEnabled": False}, False, id="no service account on hopin"
        ),
        pytest.param(
            "HOPIN", {"defaultClientScopes": SONGMAKER_SCOPES}, False, id="songmaker's set on hopin"
        ),
        pytest.param(
            "HOPIN", {"defaultClientScopes": HOPIN_SCOPES[:-1]}, False, id="hopin without audience"
        ),
        pytest.param("HOPIN", {"optionalClientScopes": []}, False, id="hopin without its scope"),
        pytest.param(
            "PRESENTATOR",
            {"optionalClientScopes": ["speech-service-audience"]},
            False,
            id="presentator with hopin's optional scope",
        ),
    ],
)
def test_an_app_client_is_accepted_only_with_exactly_its_decided_scopes_and_service_account(
    probe: ModuleType, client_name: str, changes: dict[str, object], accepted: bool
) -> None:
    client = getattr(probe, client_name)
    imported = ImportedClients(imported_client(client, **changes))
    check = probe.Probe.app_client_representation

    if accepted:
        check(imported, client)
    else:
        with pytest.raises(probe.ProbeFailure):
            check(imported, client)


def test_an_app_client_is_accepted_with_its_callbacks_in_another_order(probe: ModuleType) -> None:
    client = probe.PRESENTATOR
    imported = ImportedClients(imported_client(client, redirectUris=list(client.callbacks)[::-1]))

    probe.Probe.app_client_representation(imported, client)


@pytest.mark.parametrize(
    ("service", "role"),
    [("agent-service", "agent-workload"), ("speech-service", "speech-workload")],
)
@pytest.mark.parametrize(
    ("changes", "accepted"),
    [
        pytest.param({}, True, id="a correct workload token"),
        pytest.param({"client_id": None}, False, id="client_id missing"),
        pytest.param({"client_id": "hopin"}, False, id="client_id naming the other app"),
        pytest.param({"azp": "hopin"}, False, id="azp naming the other app"),
        pytest.param({"groups": ["/services/agent-service/api"]}, False, id="a group on the token"),
        pytest.param({"groups": []}, True, id="empty groups"),
        pytest.param({"aud": ["account"]}, False, id="the service's audience missing"),
        pytest.param({"realm_access": {"roles": []}}, False, id="the workload role missing"),
    ],
)
def test_a_token_is_the_workload_identity_only_with_role_audience_client_and_no_group(
    probe: ModuleType, service: str, role: str, changes: dict[str, object], accepted: bool
) -> None:
    claims = {
        "realm_access": {"roles": [role]},
        "aud": [service],
        "client_id": "songmaker",
        "azp": "songmaker",
    } | changes
    claims = {key: value for key, value in claims.items() if value is not None}

    assert probe.is_workload_identity_of(claims, "songmaker", service) is accepted


@pytest.mark.parametrize(
    ("login_address", "error_address", "accepted"),
    [
        ("198.51.100.23", "198.51.100.23", True),
        (None, "198.51.100.23", False),
        ("198.51.100.23", None, False),
        (None, None, False),
        ("", "", False),
        ("198.51.100.23", "192.0.2.123", False),
        ("192.0.2.123", "192.0.2.123", False),
        ("127.0.0.1", "127.0.0.1", False),
        ("0.0.0.0", "0.0.0.0", False),  # noqa: S104 - the wildcard address as a client address the probe must not accept
    ],
)
def test_the_stored_login_events_must_both_carry_the_forwarded_client_address(
    probe: ModuleType, login_address: str | None, error_address: str | None, accepted: bool
) -> None:
    client_address = "198.51.100.23"
    events = [
        {"type": "LOGIN_ERROR", "ipAddress": error_address},
        {"type": "LOGIN", "ipAddress": login_address},
    ]
    if accepted:
        assert probe.stored_event_types(events, client_address) == ["LOGIN", "LOGIN_ERROR"]
    else:
        with pytest.raises(probe.ProbeFailure):
            probe.stored_event_types(events, client_address)


@pytest.mark.parametrize(
    ("address", "header"),
    [
        ("198.51.100.23", "for=198.51.100.23;proto=https"),
        ("2001:db8::23", 'for="[2001:db8::23]";proto=https'),
    ],
)
def test_the_simulated_cloudflare_rule_quotes_only_an_ipv6_address(
    probe: ModuleType, address: str, header: str
) -> None:
    assert probe.cloudflare_forwarded(address) == header
