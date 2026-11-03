"""The live canary (`agent-service/live_canary.py`) against a scripted docker: what it prints on
every path, and that nothing but verdict lines reaches stdout and nothing reaches stderr. No real
container, key or provider is involved."""

import io
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent-service"))

import live_canary  # noqa: E402
from retention_census import DATABASE, ROUTE_SERVICES, Completed  # noqa: E402
from support.live_smoke_fakes import FakeStack, completed, resolved_configuration  # noqa: E402
from support.probe_support import probe_imports  # noqa: E402

with probe_imports():
    from litellm_live_canary import LAST_LINES as FINAL  # the grammar table, written from the issue
    from litellm_live_canary import fits_grammar

SENTINEL = "sentinel-0f8e7d6c5b4a3921"
FRONT, LITELLM = "litellm-front", "litellm"
LOGIN = {"POSTGRES_USER": "keeper", "POSTGRES_DB": "store"}
GOOD_TURN = "answer 200\nmarker yes\n"
INSPECTED = {
    "Mounts": [],
    "HostConfig": {"Tmpfs": None, "MaskedPaths": [], "LogConfig": {"Type": "json-file"}},
}
HOST_TABLE = b"20 1 0:18 / / ro - overlay overlay ro"
PYTHON_REPORT = {"table": [["/", "overlay", False]], "mounts": []}
TOOL_COPY = 'COPY public."LiteLLM_ToolTable" (tool_name) FROM stdin;'


def container_of(service: str) -> str:
    return f"{service}-1"


def configuration() -> dict:
    """The resolved compose configuration, with the database's login."""
    resolved = resolved_configuration()
    resolved["services"][DATABASE] = {"environment": {**LOGIN, "POSTGRES_PASSWORD_FILE": "/x"}}
    return resolved


# --- the scripted docker -----------------------------------------------------------------------


@dataclass
class Route:
    """What the route's docker answers. Every answer carries `SENTINEL` on standard error."""

    turn: str = GOOD_TURN
    turn_code: int = 0
    missing: str | None = None
    doubled: str | None = None
    listing_raises: Exception | None = None
    leftover_removal: int = 0
    log_dirty_in: str | None = None
    unreadable_log_of: str | None = None
    dump: str = ""  # the dump's rows; the marker joins them when `dump_dirty`
    dump_dirty: bool = False
    census_raises: Exception | None = None
    turn_raises: BaseException | None = None
    marker: str = ""
    census_calls: list[list[str]] = field(default_factory=list)
    asked: list[tuple[list[str], str | None]] = field(default_factory=list)
    timeline: list[str] = field(default_factory=list)

    def docker(self, command: list[str], stdin: str | None) -> subprocess.CompletedProcess:
        self.asked.append((command, stdin))
        if "config" in command:
            return completed(json.dumps(configuration()))
        if "ps" in command and "-q" in command and "compose" in command:
            if self.listing_raises:
                raise self.listing_raises
            service = command[-1]
            listed = "" if service == self.missing else f"id-{service}\n"
            listed += f"other-{service}\n" if service == self.doubled else ""
            return completed(listed, stderr=SENTINEL)
        if command[:2] == ["docker", "inspect"]:
            return completed(f"/{container_of(command[-1].removeprefix('id-'))}\n")
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
        if "pg_dump" in command:
            rows = f"{self.dump}{self.marker if self.dump_dirty else ''}"
            return Completed(0, f"{TOOL_COPY}\n{rows}\n\\.\n".encode(), SENTINEL.encode())
        if command[-3:] == ["python", "-I", "-"]:
            return Completed(0, json.dumps(PYTHON_REPORT).encode(), SENTINEL.encode())
        return Completed(0, HOST_TABLE, SENTINEL.encode())

    def stack(self) -> FakeStack:
        return RecordingStack(route=self)


@dataclass(frozen=True)
class RecordingStack(FakeStack):
    """The scripted docker, which also sees each command's standard input."""

    route: Route | None = None

    def run(self, command, stdin=None, timeout=300):
        return self.route.docker(list(command), stdin)


@dataclass
class Run:
    code: int
    stdout: list[str]
    stderr: str
    route: Route
    stray_stdout: str


def drive(route: Route, capsys) -> Run:
    out = io.StringIO()
    code = live_canary.main(
        stack_of=route.stack, census_run=route.census, out=out,
        pause=lambda seconds: route.timeline.append(f"pause {seconds:g}"),
    )  # fmt: skip
    captured = capsys.readouterr()
    return Run(code, out.getvalue().splitlines(), captured.err, route, captured.out)


def assert_only_verdicts(run: Run) -> None:
    assert [line for line in run.stdout if not fits_grammar(line)] == []
    assert run.stdout[-1] in FINAL
    assert (run.code == 0) == (run.stdout[-1] == "canary and census held")
    assert run.stderr == ""
    assert run.stray_stdout == ""
    printed = "\n".join(run.stdout)
    for secret in (SENTINEL, run.route.marker or SENTINEL):
        assert secret not in printed


def canary_commands(route: Route) -> list[tuple[list[str], str | None]]:
    return [(command, stdin) for command, stdin in route.asked if "agent-canary" in command]


# --- the clean run ---------------------------------------------------------------------------


def test_a_clean_run_prints_three_held_cells_and_nothing_on_standard_error(capsys):
    run = drive(Route(), capsys)

    searched = len(ROUTE_SERVICES) + 1  # each container's log, and the database's dump
    assert run.code == 0
    assert run.stdout == [
        "C0 route held: the route's containers run",
        "C1 canary held: the answer held the marker",
        f"C2 census held: {searched} sinks searched, the canary is in none",
        "canary and census held",
    ]
    assert_only_verdicts(run)


def test_the_census_waits_for_a_settle_after_the_turn_and_before_any_sink_is_read(capsys):
    run = drive(Route(), capsys)

    settle = f"pause {live_canary.ROUTE_SETTLE_SECONDS:g}"
    timeline = run.route.timeline
    assert timeline.index("canary") < timeline.index(settle) < timeline.index("census")


def test_the_settle_outlasts_the_longest_interval_of_any_of_litellms_database_writers():
    longest_batch = live_canary.LITELLM_BATCH_SECONDS + live_canary.LITELLM_BATCH_JITTER_SECONDS
    tag_job = int(longest_batch * live_canary.LITELLM_TAG_MULTIPLIER)

    assert tag_job <= live_canary.ROUTE_SETTLE_SECONDS


def test_the_canary_runs_once_as_a_one_off_with_the_marker_alone_and_no_standard_input(capsys):
    route = Route()

    drive(route, capsys)

    ((command, stdin),) = canary_commands(route)
    one_off = command.index("agent-canary")
    assert command[one_off - 3 :] == ["run", "--rm", "-T", "agent-canary", "--marker", route.marker]
    assert stdin is None


def test_the_census_dumps_the_database_with_the_login_compose_resolves(capsys):
    route = Route()

    drive(route, capsys)

    (dump,) = [command for command in route.census_calls if "pg_dump" in command]
    assert dump == [
        "docker", "exec", container_of(DATABASE), "pg_dump",
        f"--username={LOGIN['POSTGRES_USER']}", f"--dbname={LOGIN['POSTGRES_DB']}",
    ]  # fmt: skip


def test_a_new_run_has_a_new_marker(capsys):
    markers = []
    for _ in range(2):
        route = Route()
        drive(route, capsys)
        markers.append(route.marker)

    assert markers[0]
    assert markers[0] != markers[1]


# --- C0 --------------------------------------------------------------------------------------


@pytest.mark.parametrize("missing", list(ROUTE_SERVICES))
def test_a_missing_container_stops_the_run_before_the_canary(capsys, missing):
    run = drive(Route(missing=missing), capsys)

    assert run.stdout == ["C0 route FAILED: a container is missing", "canary and census FAILED"]
    assert run.code == 1
    assert canary_commands(run.route) == []
    assert_only_verdicts(run)


def test_two_containers_for_one_service_are_a_missing_container(capsys):
    run = drive(Route(doubled=FRONT), capsys)

    assert run.stdout[0] == "C0 route FAILED: a container is missing"


@pytest.mark.parametrize("failure", [subprocess.TimeoutExpired("docker", 1), OSError("no docker")])
def test_a_docker_that_cannot_be_asked_is_a_missing_container(capsys, failure):
    run = drive(Route(listing_raises=failure), capsys)

    assert run.stdout[0] == "C0 route FAILED: a container is missing"
    assert run.code == 1


# --- C1 ------------------------------------------------------------------------------------


def turn_of(*lines: str) -> str:
    return "".join(f"{line}\n" for line in lines)


C1_FAILURES = {
    "timeout": ({"turn_raises": subprocess.TimeoutExpired("docker", 1)}, "the turn timed out"),
    "docker raises": ({"turn_raises": RuntimeError(SENTINEL)}, "crashed RuntimeError"),
    "no start": ({"turn": "", "turn_code": 1}, "the turn could not start"),
    "refused": ({"turn": turn_of("answer 401", "marker no"), "turn_code": 1}, "answer 401"),
    "exit code 1 though the marker is there": (
        {"turn": GOOD_TURN, "turn_code": 1}, "the answer lacked the marker",
    ),
    "marker": (
        {"turn": turn_of("answer 200", "marker no"), "turn_code": 1},
        "the answer lacked the marker",
    ),
    "crash": (
        {"turn": turn_of("crashed ConnectionRefusedError"), "turn_code": 1},
        "crashed ConnectionRefusedError",
    ),
    "unknown": ({"turn": GOOD_TURN + "something else\n"}, "1 unknown lines"),
    "planted": ({"turn": GOOD_TURN + turn_of(f"route {SENTINEL}", SENTINEL)}, "2 unknown lines"),
    "token shape": (
        {"turn": GOOD_TURN + turn_of("answer eyJhbGciOi.eyJzdWIi.abc")}, "1 unknown lines",
    ),
}  # fmt: skip


@pytest.mark.parametrize(("arrangement", "figure"), C1_FAILURES.values(), ids=C1_FAILURES)
def test_a_canary_that_fails_prints_its_closed_reason_and_runs_no_census(
    capsys, arrangement, figure
):
    run = drive(Route(**arrangement), capsys)

    assert run.stdout[0] == "C0 route held: the route's containers run"
    assert run.stdout[1] == f"C1 canary FAILED: {figure}"
    assert run.stdout[-1] == "canary and census FAILED"
    assert run.code == 1
    assert run.route.census_calls == []
    assert_only_verdicts(run)


# --- the cleanup ---------------------------------------------------------------------------


def test_the_cleanup_of_a_turn_lists_the_containers_of_the_canary_service_alone(capsys):
    route = Route()

    drive(route, capsys)

    listings = [" ".join(command) for command, _ in route.asked if "-aq" in command]
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

    assert run.stdout[2:] == [
        f"C2 census FAILED: found in {container_of(LITELLM)} log",
        "canary and census FAILED",
    ]
    assert run.code == 1
    assert_only_verdicts(run)


def test_a_canary_found_in_the_dump_names_the_database_and_the_table_only(capsys):
    run = drive(Route(dump=f"{SENTINEL}\t", dump_dirty=True), capsys)

    assert run.stdout[2:] == [
        f"C2 census FAILED: found in {container_of(DATABASE)} dump LiteLLM_ToolTable",
        "canary and census FAILED",
    ]
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


def test_a_label_outside_the_grammar_is_never_printed_and_fails_the_census(capsys):
    label = f"/{SENTINEL} with spaces"
    route = Route()
    census = route.census

    def census_with_odd_mount(command, stdin=None):
        if command[-3:] == ["python", "-I", "-"]:
            odd = {"mount": label, "found": {"canary": 1}, "skips": {}}
            report = {"table": [[label, "overlay", True]], "mounts": [odd]}
            return Completed(0, json.dumps(report).encode(), b"")
        return census(command, stdin)

    route.census = census_with_odd_mount  # type: ignore[method-assign]

    run = drive(route, capsys)

    assert "C2 census FAILED: crashed GrammarBroken" in run.stdout
    assert SENTINEL not in "\n".join(run.stdout)
    assert run.code == 1


# --- the whole run -------------------------------------------------------------------------


def test_an_interrupt_ends_the_run_with_130_and_the_failed_last_line(capsys):
    run = drive(Route(turn_raises=KeyboardInterrupt()), capsys)

    assert run.code == 130
    assert run.stdout[-1] == "canary and census FAILED"
    assert_only_verdicts(run)


def test_an_exception_nothing_foresaw_ends_with_the_failed_last_line_and_no_text(capsys):
    route = Route()
    route.stack = lambda: (_ for _ in ()).throw(RuntimeError(SENTINEL))  # type: ignore[method-assign]

    run = drive(route, capsys)

    assert (run.code, run.stdout, run.stderr) == (1, ["canary and census FAILED"], "")


# --- the table of the grammar itself ---------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "C1 canary FAILED: route api",
        "C1 canary FAILED: crashed Value_Error",
        "C2 census FAILED: found in a/b log",
        "C2 census FAILED: found in db dump two words",
        "C0 gateway held: the service's gateway is the front",
        "C1 canary held: route api, the answer held the marker",
        "C3 other held: x",
        "canary and census held.",
    ],
)
def test_the_test_grammar_refuses_a_line_outside_the_table(line):
    assert not fits_grammar(line)
