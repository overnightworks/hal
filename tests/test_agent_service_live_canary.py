"""The live canary (`agent-service/live_canary.py`) against a scripted docker and a scripted issuer:
what it prints on every path, and that nothing but verdict lines reaches stdout and nothing but the
sign-in prompt reaches stderr. No real issuer, token, key or browser is involved."""

import io
import json
import subprocess
import sys
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent-service"))

import live_canary  # noqa: E402
from live_smoke import LiveSmokeFailed  # noqa: E402
from retention_census import ROUTE_SERVICES, Completed  # noqa: E402
from support.live_smoke_fakes import FakeStack, completed, resolved_configuration  # noqa: E402
from support.probe_support import probe_imports  # noqa: E402

with probe_imports():
    from litellm_live_canary import LAST_LINES as FINAL  # the grammar table, written from the issue
    from litellm_live_canary import fits_grammar

SENTINEL = "sentinel-0f8e7d6c5b4a3921"
FRONT, LITELLM = "litellm-front", "litellm"
GOOD_TOML = '[api]\ncompletion_url = "http://litellm-front:4000/v1/chat/completions"\n'
GOOD_TURN = "answer 200\nevent run_started\nroute api\nevent succeeded\nmarker yes\n"
INSPECTED = {
    "Mounts": [],
    "HostConfig": {"Tmpfs": None, "MaskedPaths": [], "LogConfig": {"Type": "json-file"}},
}
HOST_TABLE = b"20 1 0:18 / / ro - overlay overlay ro"
PYTHON_REPORT = {"table": [["/", "overlay", False]], "mounts": []}


def container_of(service: str) -> str:
    return f"{service}-1"


# --- the scripted docker and issuer ------------------------------------------------------------


@dataclass
class Route:
    """What the route's docker answers. Every answer carries `SENTINEL` on standard error."""

    turn: str = GOOD_TURN
    turn_code: int = 0
    toml: str | Exception = GOOD_TOML
    toml_code: int = 0
    missing: str | None = None
    leftover_removal: int = 0
    log_dirty_in: str | None = None
    unreadable_log_of: str | None = None
    census_raises: Exception | None = None
    turn_raises: Exception | None = None
    marker: str = ""
    census_calls: list[list[str]] = field(default_factory=list)
    asked: list[list[str]] = field(default_factory=list)
    timeline: list[str] = field(default_factory=list)

    def docker(self, command: list[str]) -> subprocess.CompletedProcess:
        self.asked.append(command)
        if "config" in command:
            return completed(json.dumps(resolved_configuration()))
        if "ps" in command and "-q" in command and "compose" in command:
            service = command[-1]
            return completed("" if service == self.missing else f"id-{service}\n", stderr=SENTINEL)
        if command[:2] == ["docker", "inspect"]:
            return completed(f"/{container_of(command[-1].removeprefix('id-'))}\n")
        if "exec" in command and "cat" in command:
            if isinstance(self.toml, Exception):
                raise self.toml
            return completed(self.toml, self.toml_code, SENTINEL)
        if "agent-canary" in command:
            self.marker = command[command.index("--marker") + 1]
            self.timeline.append("canary")
            if self.turn_raises:
                raise self.turn_raises
            return completed(self.turn, self.turn_code, SENTINEL)
        if "-aq" in command:
            return completed("left-over\n" if self.leftover_removal else "", 0, SENTINEL)
        if command[:2] == ["docker", "rm"]:
            return completed("", self.leftover_removal, SENTINEL)
        return completed("", 0, SENTINEL)

    def census(self, command, stdin=None) -> Completed:
        self.census_calls.append(list(command))
        self.timeline.append("census")
        if self.census_raises:
            raise self.census_raises
        name = command[-1] if command[1] != "exec" else command[2 + (command[2] == "-i")]
        if command[:2] == ["docker", "inspect"]:
            return Completed(0, json.dumps([INSPECTED]).encode(), SENTINEL.encode())
        if command[:2] == ["docker", "logs"]:
            if name == self.unreadable_log_of:
                return Completed(1, b"", SENTINEL.encode())
            dirty = name == self.log_dirty_in
            return Completed(0, self.marker.encode() if dirty else b"", SENTINEL.encode())
        if command[-3:] == ["python", "-I", "-"]:
            return Completed(0, json.dumps(PYTHON_REPORT).encode(), SENTINEL.encode())
        return Completed(0, HOST_TABLE, SENTINEL.encode())

    def stack(self) -> FakeStack:
        return FakeStack(answer=self.docker)


class Issuer:
    """The device grant of a Keycloak that never existed: no network, tokens are stand-ins."""

    def __init__(self, fails: bool = False) -> None:
        self.fails = fails
        self.requests = 0

    def __call__(self, request, timeout=None):
        self.requests += 1
        if self.fails:
            raise OSError("no issuer")
        path = request.full_url.rsplit("/", 1)[-1]
        body = request.data.decode()
        if path == "device":
            document = {
                "device_code": "d-code", "user_code": "USER-CODE", "expires_in": 600, "interval": 7,
                "verification_uri_complete": "https://sign-in.example/confirm",
            }  # fmt: skip
        else:
            grant = "device_code" in body
            document = {"access_token": "stand-in-person" if grant else "stand-in-workload"}
        return Reply(json.dumps(document).encode())


class Reply:
    def __init__(self, body: bytes) -> None:
        self.body = io.BytesIO(body)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read1(self, size: int) -> bytes:
        return self.body.read(size)


@dataclass
class Run:
    code: int
    stdout: list[str]
    stderr: list[str]
    secret_reads: int
    issuer: Issuer
    route: Route


def drive(route: Route, capsys, issuer: Issuer | None = None, secret=None) -> Run:
    issuer = issuer or Issuer()
    reads = []
    ticks = iter(range(10**6))

    def read_client_secret() -> str:
        reads.append(1)
        if secret:
            raise secret
        return "stand-in-client-secret"

    out = io.StringIO()
    code = live_canary.main(
        stack_of=route.stack, read_client_secret=read_client_secret, urlopen=issuer,
        pause=lambda seconds: route.timeline.append(f"pause {seconds:g}"),
        clock=lambda: next(ticks) / 1000, census_run=route.census, out=out,
    )  # fmt: skip
    captured = capsys.readouterr()
    return Run(
        code, out.getvalue().splitlines(), captured.err.splitlines(), len(reads), issuer, route
    )


def assert_only_verdicts(run: Run) -> None:
    assert [line for line in run.stdout if not fits_grammar(line)] == []
    assert run.stdout[-1] in FINAL
    assert (run.code == 0) == (run.stdout[-1] == "canary and census held")
    assert [line for line in run.stderr if not line.startswith("Open https://")] == []
    printed = "\n".join([*run.stdout, *run.stderr])
    for secret in (SENTINEL, "stand-in-", run.route.marker or SENTINEL):
        assert secret not in printed


# --- the clean run ---------------------------------------------------------------------------


def test_a_clean_run_prints_three_held_cells_and_the_prompt_alone_on_standard_error(capsys):
    run = drive(Route(), capsys)

    assert run.code == 0
    assert run.stdout == [
        "C0 gateway held: the service's gateway is the front",
        "C1 canary held: route api, the answer held the marker",
        f"C2 census held: {len(ROUTE_SERVICES)} sinks searched, the canary is in none",
        "canary and census held",
    ]
    assert len(run.stderr) == 1
    assert_only_verdicts(run)


def test_the_census_waits_for_a_settle_after_the_turn_and_before_any_sink_is_read(capsys):
    run = drive(Route(), capsys)

    settle = f"pause {live_canary.SETTLE_SECONDS:g}"
    timeline = run.route.timeline
    assert timeline.index("canary") < timeline.index(settle) < timeline.index("census")


def test_the_sign_in_never_reaches_a_browser(capsys, monkeypatch):
    opened = []
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(webbrowser, "open", lambda link: opened.append(link))

    run = drive(Route(), capsys)

    assert run.code == 0
    assert opened == []


# --- C0: nothing secret exists before the containers and the gateway hold -------------------


@pytest.mark.parametrize("missing", list(ROUTE_SERVICES))
def test_a_missing_container_stops_the_run_before_any_secret_or_sign_in(capsys, missing):
    run = drive(Route(missing=missing), capsys)

    assert run.stdout == [
        "C0 gateway FAILED: a container is missing",
        "canary and census FAILED",
    ]
    assert (run.code, run.secret_reads, run.issuer.requests, run.stderr) == (1, 0, 0, [])
    assert_only_verdicts(run)


@pytest.mark.parametrize(
    ("route", "reason"),
    [
        (Route(toml="", toml_code=1), "the configuration could not be read"),
        (Route(toml="[unclosed"), "the configuration could not be read"),
        (Route(toml='[apps]\nx = "y"\n'), "the service has no api table"),
        (
            Route(toml='[api]\ncompletion_url = "http://example.com/v1/chat/completions"\n'),
            "the service names another gateway",
        ),
        (Route(toml="[api]\n"), "the service names another gateway"),
        (
            Route(toml='[api]\ncompletion_url = "http://litellm-front.evil.test:4000/v1"\n'),
            "the service names another gateway",
        ),
    ],
    ids=["unreadable", "malformed", "no api", "other host", "no url", "host that only starts so"],
)
def test_a_service_that_does_not_name_the_front_stops_the_run_before_any_sign_in(
    capsys, route, reason
):
    run = drive(route, capsys)

    assert run.stdout == [f"C0 gateway FAILED: {reason}", "canary and census FAILED"]
    assert (run.code, run.secret_reads, run.issuer.requests, run.stderr) == (1, 0, 0, [])
    assert_only_verdicts(run)


def test_a_docker_that_cannot_be_asked_is_a_missing_container(capsys):
    run = drive(Route(toml=subprocess.TimeoutExpired("docker", 1)), capsys)

    assert run.stdout[0] == "C0 gateway FAILED: a container is missing"
    assert run.code == 1


# --- C1 ------------------------------------------------------------------------------------


def turn_of(*lines: str) -> str:
    return "".join(f"{line}\n" for line in lines)


API_START = ("answer 200", "event run_started", "route api")
C1_FAILURES = {
    "sign-in": ({}, {"issuer": Issuer(fails=True)}, "the sign-in failed"),
    "secret": ({}, {"secret": LiveSmokeFailed("cannot read")}, "the sign-in failed"),
    "timeout": (
        {"turn_raises": subprocess.TimeoutExpired("docker", 1)}, {}, "the turn timed out",
    ),
    "docker raises": ({"turn_raises": RuntimeError(SENTINEL)}, {}, "crashed RuntimeError"),
    "no start": ({"turn": "", "turn_code": 1}, {}, "the turn could not start"),
    "answer": ({"turn": turn_of("answer 403", "marker no"), "turn_code": 1}, {}, "answer 403"),
    "route": (
        {"turn": turn_of("answer 200", "event run_started", "route cli", "marker yes")},
        {}, "route cli",
    ),
    "code": (
        {"turn": turn_of(*API_START, "event failed", "code provider_error", "marker no"),
         "turn_code": 1},
        {}, "code provider_error",
    ),
    "marker": (
        {"turn": turn_of(*API_START, "event succeeded", "marker no"), "turn_code": 1},
        {}, "the answer lacked the marker",
    ),
    "crash": (
        {"turn": turn_of("crashed ConnectionRefusedError"), "turn_code": 1},
        {}, "crashed ConnectionRefusedError",
    ),
    "unknown": ({"turn": GOOD_TURN + "something else\n"}, {}, "1 unknown lines"),
    "planted": (
        {"turn": GOOD_TURN + turn_of(f"route {SENTINEL}", SENTINEL)}, {}, "2 unknown lines"
    ),
    "token shape": (
        {"turn": GOOD_TURN + turn_of("answer eyJhbGciOi.eyJzdWIi.abc")}, {}, "1 unknown lines"
    ),
}  # fmt: skip


@pytest.mark.parametrize(("arrangement", "drives", "figure"), C1_FAILURES.values(), ids=C1_FAILURES)
def test_a_canary_that_fails_prints_its_closed_reason_and_runs_no_census(
    capsys, arrangement, drives, figure
):
    run = drive(Route(**arrangement), capsys, **drives)

    assert run.stdout[0].startswith("C0 gateway held")
    assert run.stdout[1] == f"C1 canary FAILED: {figure}"
    assert run.stdout[-1] == "canary and census FAILED"
    assert run.code == 1
    assert run.route.census_calls == []
    assert_only_verdicts(run)


# --- the cleanup ---------------------------------------------------------------------------


def test_the_cleanup_of_a_turn_lists_the_containers_of_the_canary_service_alone(capsys):
    route = Route()

    drive(route, capsys)

    listings = [" ".join(c) for c in route.asked if "-aq" in c]
    assert listings
    assert all("service=agent-canary" in listing for listing in listings)


def test_a_container_that_cannot_be_removed_fails_the_run_without_its_diagnostic(capsys):
    run = drive(Route(leftover_removal=1), capsys)

    assert "cleanup FAILED: a container was left" in run.stdout
    assert run.code == 1
    assert_only_verdicts(run)


# --- C2 ------------------------------------------------------------------------------------


def test_a_canary_found_in_a_log_names_the_container_and_the_log_only(capsys):
    run = drive(Route(log_dirty_in=container_of(LITELLM)), capsys)

    assert f"C2 census FAILED: found in {container_of(LITELLM)} log" in run.stdout
    assert run.code == 1
    assert_only_verdicts(run)


def test_a_sink_the_census_could_not_read_is_counted_and_never_named(capsys):
    run = drive(Route(unreadable_log_of=container_of(FRONT)), capsys)

    assert "C2 census FAILED: 1 sinks not examined" in run.stdout
    assert not any("held: " in line and "C2" in line for line in run.stdout)
    assert_only_verdicts(run)


def test_a_dirty_and_unexamined_run_prints_both_reasons(capsys):
    route = Route(log_dirty_in=container_of(LITELLM), unreadable_log_of=container_of(FRONT))

    run = drive(route, capsys)

    assert run.stdout[2:4] == [
        f"C2 census FAILED: found in {container_of(LITELLM)} log",
        "C2 census FAILED: 1 sinks not examined",
    ]
    assert_only_verdicts(run)


def test_a_census_that_raises_prints_the_type_of_the_exception_only(capsys):
    run = drive(Route(census_raises=RuntimeError(SENTINEL)), capsys)

    assert "C2 census FAILED: crashed RuntimeError" in run.stdout
    assert run.code == 1
    assert_only_verdicts(run)


def test_a_missing_container_during_the_census_is_an_unexamined_sink_and_no_crash(capsys):
    route = Route()
    gone = route.census

    def census(command, stdin=None):
        if command[:3] == ["docker", "inspect", container_of(FRONT)]:
            return Completed(1, b"", SENTINEL.encode())
        return gone(command, stdin)

    route.census = census  # type: ignore[method-assign]

    run = drive(route, capsys)

    assert "C2 census FAILED: 1 sinks not examined" in run.stdout
    assert_only_verdicts(run)


def test_an_interrupt_ends_the_run_with_130_and_no_last_line(capsys):
    route = Route(turn_raises=KeyboardInterrupt())

    run = drive(route, capsys)

    assert run.code == 130
    assert [line for line in run.stdout if not fits_grammar(line)] == []
    assert not set(run.stdout) & FINAL


# --- the table of the grammar itself ---------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "C1 canary FAILED: route eyJhbGciOi",
        "C1 canary FAILED: crashed Value_Error",
        "C2 census FAILED: found in a/b log",
        "C1 canary held: route api",
        "C3 other held: x",
        "canary and census held.",
    ],
)
def test_the_test_grammar_refuses_a_line_outside_the_table(line):
    assert not fits_grammar(line)
