"""`hal expire` at its entry, with `docker` and the container's `psql` scripted by label."""

import signal
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import pytest

from hal import cli, litellm_expiry
from hal.backup import host
from hal.grammar import ExitCode

PROJECT = "expire-test"
CONTAINER = "c" * 64
DAYS = litellm_expiry.RETENTION_DAYS
NEXT = "next: hal expire"


@dataclass
class LitellmHost:
    """`docker` answering for the `litellm-db` of one compose project, and that container's psql."""

    containers: list[str] = field(default_factory=lambda: [CONTAINER])
    state: bytes = b"running healthy\n"
    answer: bytes | int | type[BaseException] | Callable[[], None] = b"0|0|0|0|0\n"
    """What psql prints, the exit it ends with, what interrupts it, or what it does first."""
    settings: bytes = b"litellm\nlitellm\n"
    docker_silent: bool = False
    silent_after_psql: bool = False
    psql_runs: int = 0

    def run(
        self,
        argv: Sequence[str],
        *,
        label: str,
        stdin: Path | None = None,
        stdout: Path | None = None,
        timeout: timedelta | None = None,
        discard_stderr: bool = False,
    ) -> bytes:
        if self.docker_silent or (self.silent_after_psql and self.psql_runs):
            raise host.HostCommandError(label, "ended with exit 1", 1)
        if argv[:2] == ["docker", "ps"]:
            ours = f"label=com.docker.compose.project={PROJECT}" in argv
            service = "label=com.docker.compose.service=litellm-db" in argv
            return "\n".join(self.containers if ours and service else []).encode()
        if argv[:2] == ["docker", "inspect"]:
            return self.state
        assert argv[:3] == ["docker", "exec", CONTAINER]
        if argv[3] == "printenv":
            return self.settings
        assert argv[3] == "psql"
        self.psql_runs += 1
        return self.psql(label)

    def psql(self, label: str) -> bytes:
        match self.answer:
            case bytes():
                return self.answer
            case int():
                raise host.HostCommandError(label, f"ended with exit {self.answer}", self.answer)
            case type():
                raise self.answer()
            case _:
                self.answer()
                return b"0|0|0|0|0\n"


class NoExit(host.HostCommandError):
    """A psql call that ended without an exit code."""

    def __init__(self) -> None:
        super().__init__("psql", "ended without an exit code")


@pytest.fixture
def litellm_host(monkeypatch: pytest.MonkeyPatch) -> LitellmHost:
    scripted = LitellmHost()
    monkeypatch.setattr(host, "run", scripted.run)
    monkeypatch.setattr(host, "monotonic", lambda: 0.0)
    return scripted


def expire(capsys: pytest.CaptureFixture[str]) -> tuple[int, list[str], list[str]]:
    code = cli.main(["expire", "--project", PROJECT])
    captured = capsys.readouterr()
    return code, captured.out.splitlines(), captured.err.splitlines()


@pytest.mark.parametrize(
    ("containers", "state"),
    [([], b"running healthy\n"), ([CONTAINER], b"running starting\n")],
    ids=["no-container", "not-ready"],
)
def test_without_a_ready_litellm_db_the_run_deletes_nothing_and_exits_0(
    litellm_host: LitellmHost,
    capsys: pytest.CaptureFixture[str],
    containers: list[str],
    state: bytes,
) -> None:
    litellm_host.containers, litellm_host.state = containers, state

    assert expire(capsys) == (
        ExitCode.OK,
        ["  · litellm         not running    nothing deleted", "✓ expire done"],
        [],
    )
    assert litellm_host.psql_runs == 0


def test_a_run_shows_one_row_per_kind_and_the_total(
    litellm_host: LitellmHost, capsys: pytest.CaptureFixture[str]
) -> None:
    litellm_host.answer = b"41|12|7|0|2\n"

    assert expire(capsys) == (
        ExitCode.OK,
        [
            f"  ✓ person days     deleted        41 rows · older than {DAYS} days",
            f"  ✓ tool days       deleted        12 rows · older than {DAYS} days",
            f"  ✓ label days      deleted        7 rows · older than {DAYS} days",
            f"  · tools           deleted        0 rows · unused for {DAYS} days",
            f"  ✓ people          deleted        2 rows · idle for {DAYS} days",
            "✓ expire done · 62 rows · <1s",
        ],
        [],
    )


def test_a_failure_psql_itself_reports_says_nothing_deleted_and_exits_3(
    litellm_host: LitellmHost, capsys: pytest.CaptureFixture[str]
) -> None:
    litellm_host.answer = 1

    assert expire(capsys) == (
        ExitCode.FAILURE,
        ["  ✗ litellm         not expired    psql ended with exit 1 · nothing deleted"],
        ["error: litellm not expired · nothing deleted", NEXT],
    )


UNKNOWN_ERROR = "error: litellm not expired · outcome unknown · the next run repeats it"


@pytest.mark.parametrize(
    ("answer", "silent_after_psql", "reason"),
    [
        (1, True, "psql ended with exit 1, unconfirmed by docker"),
        (2, False, "psql ended with exit 2"),
        (-9, False, "psql ended with exit -9"),
        (137, False, "psql ended with exit 137"),
        (NoExit, False, "psql ended without an exit code"),
        (b"41|12\n", False, "psql's answer is unreadable"),
    ],
    ids=[
        "docker-silent-after-psql",
        "connection-lost-exit-2",
        "client-killed-negative-exit",
        "psql-killed-in-container",
        "no-exit-code",
        "unreadable-answer",
    ],
)
def test_a_failure_whose_outcome_is_unknown_says_so_and_exits_3(
    litellm_host: LitellmHost,
    capsys: pytest.CaptureFixture[str],
    answer: bytes | int | type[BaseException],
    silent_after_psql: bool,
    reason: str,
) -> None:
    litellm_host.answer, litellm_host.silent_after_psql = answer, silent_after_psql

    assert expire(capsys) == (
        ExitCode.FAILURE,
        [f"  ✗ litellm         not expired    {reason} · outcome unknown"],
        [UNKNOWN_ERROR, NEXT],
    )


def test_an_interrupt_during_the_statement_says_the_outcome_is_unknown(
    litellm_host: LitellmHost, capsys: pytest.CaptureFixture[str]
) -> None:
    litellm_host.answer = KeyboardInterrupt

    assert expire(capsys) == (
        ExitCode.INTERRUPTED,
        ["  ✗ litellm         not expired    interrupted · outcome unknown"],
        [UNKNOWN_ERROR, NEXT],
    )


@pytest.mark.parametrize(
    ("containers", "docker_silent", "reason"),
    [
        ([CONTAINER, "d" * 64], False, "2 database containers for litellm instead of exactly one"),
        ([CONTAINER], True, "docker does not answer: docker ps ended with exit 1"),
    ],
    ids=["two-containers", "docker-silent"],
)
def test_a_lookup_that_fails_runs_no_statement_and_exits_3(
    litellm_host: LitellmHost,
    capsys: pytest.CaptureFixture[str],
    containers: list[str],
    docker_silent: bool,
    reason: str,
) -> None:
    litellm_host.containers, litellm_host.docker_silent = containers, docker_silent

    assert expire(capsys) == (
        ExitCode.FAILURE,
        [f"  ✗ litellm         not expired    {reason}"],
        [f"error: litellm not expired · {reason}", NEXT],
    )
    assert litellm_host.psql_runs == 0


def test_a_sigterm_during_the_statement_says_the_outcome_is_unknown_and_exits_130(
    litellm_host: LitellmHost,
    capsys: pytest.CaptureFixture[str],
    restored_signal_handlers: None,
) -> None:
    def terminated_by_systemd() -> None:
        assert callable(signal.getsignal(signal.SIGTERM)), "SIGTERM would kill"
        signal.raise_signal(signal.SIGTERM)

    litellm_host.answer = terminated_by_systemd

    assert expire(capsys) == (
        ExitCode.INTERRUPTED,
        ["  ✗ litellm         not expired    interrupted · outcome unknown"],
        [UNKNOWN_ERROR, NEXT],
    )


def test_unreadable_database_settings_run_no_statement_and_exit_3(
    litellm_host: LitellmHost, capsys: pytest.CaptureFixture[str]
) -> None:
    litellm_host.settings = b"litellm\n"
    reason = "the database settings of litellm are unreadable"

    assert expire(capsys) == (
        ExitCode.FAILURE,
        [f"  ✗ litellm         not expired    {reason}"],
        [f"error: litellm not expired · {reason}", NEXT],
    )
    assert litellm_host.psql_runs == 0
