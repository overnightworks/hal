"""The publish of `hal apply`: the plan is shown, written encrypted, applied only after `yes`.

Exit 0 applied or nothing to apply, 1 refused, aborted or failed, 2 cannot plan; `ClosingCheck`
says whether the host check follows, and `cli.apply_command` maps its verdict into the exit.
The guard stops accidental and non-interactive runs; it does not identify the operator.
"""

import fcntl
import os
import signal
import sys
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from enum import Enum, IntEnum, StrEnum, auto
from http import HTTPStatus
from pathlib import Path
from typing import Any, TextIO

from hal.output import Stream, confirmed, write_line, write_row
from hal.output.command import Verb, command
from hal.stack import catalog, terminal
from hal.stack.external import host_probe, publish_rows, secrets, tofu

SENDER = publish_rows.SUBJECT
PLANS_DIRECTORY = secrets.OPENTOFU_DIRECTORY / "plans"
_PLAN_SUFFIX = ".tfplan"
_LOCK_SUFFIX = ".lock"
_OWNED_SUFFIXES = {_PLAN_SUFFIX, _LOCK_SUFFIX}
_STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM)
UNCHECKED_CONSEQUENCE = f"live services may be partly changed; run {command(Verb.CHECK, 'hosts')}"


class ApplyExit(IntEnum):
    APPLIED_OR_NOTHING = 0
    REFUSED = 1
    CANNOT_PLAN = 2


class Step(StrEnum):
    PLAN = "preparing the plan"
    READINESS = "the readiness check"
    CONFIRMATION = "the confirmation"
    APPLY = "tofu apply"
    CLEANUP = "the cleanup"


class ClosingCheck(Enum):
    """What follows the tofu session: the host check, or why it does not run."""

    NO_CHECK_REFUSED = auto()  # nothing was applied and no plan was empty
    CHECK_NO_CHANGES = auto()
    CHECK_APPLIED = auto()
    CHECK_APPLY_FAILED = auto()  # tofu apply was reached and did not exit 0
    NO_CHECK_INTERRUPTED = auto()  # interrupted after tofu apply was reached

    @property
    def runs_the_check(self) -> bool:
        return self.name.startswith("CHECK_")


@dataclass(frozen=True)
class ApplyOutcome:
    exit: ApplyExit
    closing: ClosingCheck


@dataclass
class Progress:
    step: Step = Step.PLAN
    apply_reached: bool = False
    plan_was_empty: bool = False
    apply_exit_code: int | None = None
    interrupted: bool = False  # recorded where the interrupt is caught, never inferred later
    reported: bool = False  # set once `report_interrupt` has printed the interrupt line


def closing_after(progress: Progress) -> ClosingCheck:
    """The one decider of the closing; cleanup runs after it, so a cleanup failure keeps it."""
    if progress.apply_reached:
        if progress.interrupted:
            return ClosingCheck.NO_CHECK_INTERRUPTED
        if progress.apply_exit_code == 0:
            return ClosingCheck.CHECK_APPLIED
        return ClosingCheck.CHECK_APPLY_FAILED
    if progress.plan_was_empty and not progress.interrupted:
        return ClosingCheck.CHECK_NO_CHANGES
    return ClosingCheck.NO_CHECK_REFUSED


class StepFailed(Exception):
    """A step after the plan failed; `cause` is the OSError, or after `apply_reached` any error."""

    exit_code = ApplyExit.REFUSED

    def __init__(self, step: Step, cause: Exception, closing: ClosingCheck) -> None:
        super().__init__(step)
        self.step = step
        self.cause = cause
        self.closing = closing


def refusal_without_terminal() -> ApplyExit | None:
    """The refusal of a run that is not at a terminal; asked before any token is read."""
    if terminal.refused_without_terminal(SENDER):
        return ApplyExit.REFUSED
    return None


def _lock_without_waiting(descriptor: int) -> None:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def remove_leftover_plans(
    home: Path, take_lock: Callable[[int], None] = _lock_without_waiting
) -> None:
    """A plan file whose run is gone (SIGKILL) is named and deleted; a live run's is kept."""
    directory = home / PLANS_DIRECTORY
    stems = {entry.stem for entry in directory.glob("*") if entry.suffix in _OWNED_SUFFIXES}
    for stem in sorted(stems):
        lock = directory / f"{stem}{_LOCK_SUFFIX}"
        plan_file = directory / f"{stem}{_PLAN_SUFFIX}"
        try:
            descriptor = os.open(lock, os.O_RDWR)
        except FileNotFoundError:
            # A live run takes its lock before its plan exists and deletes the plan first, so
            # a bare plan is dead; claim the stem before deleting it, as a live run would block.
            try:
                descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            except FileExistsError:
                continue  # a run created the lock since the glob
        try:
            try:
                take_lock(descriptor)
            except BlockingIOError:
                continue
            if not _names_the_open_file(descriptor, lock):
                continue  # the lock was replaced after the open: a live run owns the new one
            _remove_leftover(plan_file)
            lock.unlink()
        finally:
            os.close(descriptor)


def _remove_leftover(plan_file: Path) -> None:
    if plan_file.exists():
        plan_file.unlink()
        write_line(f"{SENDER}: removed the leftover plan file {plan_file}", stream=Stream.STDERR)


def _names_the_open_file(descriptor: int, path: Path) -> bool:
    try:
        return os.fstat(descriptor).st_ino == path.stat().st_ino
    except FileNotFoundError:
        return False


def _hold_lock(lock: Path) -> int:
    """Take the exclusive lock of a file this run still owns; the cleanup skips what is locked."""
    while True:
        descriptor = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if _names_the_open_file(descriptor, lock):
            return descriptor
        os.close(descriptor)  # a cleanup deleted the lock between open and flock


@contextmanager
def private_plan_file(home: Path) -> Iterator[Path]:
    directory = home / PLANS_DIRECTORY
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    name = uuid.uuid4().hex
    lock = directory / f"{name}{_LOCK_SUFFIX}"
    plan_file = directory / f"{name}{_PLAN_SUFFIX}"
    descriptor = _hold_lock(lock)
    try:
        yield plan_file
    finally:
        try:
            plan_file.unlink(missing_ok=True)
        finally:
            lock.unlink(missing_ok=True)
            os.close(descriptor)


def _raise_interrupt(_signal_number: int, _frame: object) -> None:
    raise KeyboardInterrupt


@contextmanager
def terminate_like_interrupt() -> Iterator[None]:
    previous = signal.signal(signal.SIGTERM, _raise_interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@contextmanager
def signals_ignored() -> Iterator[None]:
    """A protected region: a stop signal inside it is dropped, so its work is one step."""
    previous: dict[int, Any] = {}
    try:
        for number in _STOP_SIGNALS:
            previous[number] = signal.signal(number, signal.SIG_IGN)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def show_tofu_output(text: str, stream: TextIO) -> None:
    """The one publication of tofu's output: what `stream` cannot encode becomes a replacement,
    so printing it after a live apply never raises."""
    encoding = stream.encoding or "utf-8"
    print(text.encode(encoding, errors="replace").decode(encoding), file=stream)


def print_interrupted_output(interrupted: tofu.Interrupted, token_values: dict[str, str]) -> None:
    show_tofu_output(secrets.redact(interrupted.completed.output, token_values), sys.stderr)


def apply_plan(
    home: Path,
    token_values: dict[str, str],
    plan_file_scope: Callable[[Path], AbstractContextManager[Path]] = private_plan_file,
    progress: Progress | None = None,
    hosts: Sequence[catalog.Host] = (),
    prober_for: Callable[[str], host_probe.Prober] = host_probe.HttpProber,
    catalog_bytes: bytes | None = None,
) -> ApplyOutcome:
    """`progress` is the caller's record of this run: an interrupt that arrives after this function
    returned is decided from it, since the outcome is lost with the raise. `hosts` are the enabled
    hosts of the catalog tofu was started on, those that declare `ready` are asked; `prober_for`
    makes the prober that asks one target; `catalog_bytes` are the bytes `hosts` came from, which
    tofu is handed to plan on, so what is probed and what is published rest on the same read."""
    progress = progress or Progress()
    try:
        with (
            terminate_like_interrupt(),
            tofu.session(home, token_values) as session,
            plan_file_scope(home) as plan_file,
        ):
            result = _recording_interrupts(
                session, plan_file, token_values, progress, hosts, prober_for, catalog_bytes
            )
            progress.step = Step.CLEANUP
    except tofu.Interrupted, KeyboardInterrupt:
        return _interrupted(progress)
    except OSError as error:
        if progress.step is Step.PLAN:
            raise
        raise _failed_during_cleanup_or_step(progress, error) from error
    except Exception as error:
        if not progress.apply_reached:
            raise
        raise _failed_during_cleanup_or_step(progress, error) from error
    return ApplyOutcome(result, closing_after(progress))


def _failed_during_cleanup_or_step(progress: Progress, error: Exception) -> StepFailed:
    """An interrupt the body re-raised was replaced by the cleanup's own failure: report the
    interrupt, which `_interrupted` can no longer do, and name the cleanup as the failed step."""
    step = progress.step
    if progress.interrupted:
        report_interrupt(progress, plan_file_deleted=False)
        step = Step.CLEANUP
    return StepFailed(step, error, closing_after(progress))


def _recording_interrupts(
    session: tofu.Session,
    plan_file: Path,
    token_values: dict[str, str],
    progress: Progress,
    hosts: Sequence[catalog.Host],
    prober_for: Callable[[str], host_probe.Prober],
    catalog_bytes: bytes | None,
) -> ApplyExit:
    """The interrupt is recorded here, before the cleanup runs, so the cleanup's own failure
    cannot be mistaken for it."""
    try:
        return _show_confirm_apply(
            session, plan_file, token_values, progress, hosts, prober_for, catalog_bytes
        )
    except tofu.Interrupted as interrupted:
        progress.interrupted = True
        # the output of the plan steps is a machine stream and tofu's plan text, not for a person
        if progress.step is not Step.PLAN:
            print_interrupted_output(interrupted, token_values)
        raise
    except KeyboardInterrupt:
        progress.interrupted = True
        raise


def _interrupted(progress: Progress) -> ApplyOutcome:
    progress.interrupted = True
    report_interrupt(progress)
    return ApplyOutcome(ApplyExit.REFUSED, closing_after(progress))


def report_interrupt(progress: Progress, *, plan_file_deleted: bool = True) -> None:
    step = progress.step
    consequence = UNCHECKED_CONSEQUENCE if progress.apply_reached else "nothing was applied"
    plan_file = "; the plan file is deleted" if plan_file_deleted else ""
    with signals_ignored():  # the line and the record that it was printed are one step
        write_line(
            f"\n{SENDER}: interrupted during {step}, {consequence}{plan_file}",
            stream=Stream.STDERR,
        )
        progress.reported = True


def _unanswered(
    hosts: Sequence[catalog.Host], prober_for: Callable[[str], host_probe.Prober]
) -> list[str]:
    """One line for each host with a `ready` path whose target does not answer it with a 2xx; every
    host is asked, and no answer body is quoted."""
    lines = []
    for host in hosts:
        if host.ready is None:
            continue
        answer = prober_for(host.target).ask(host.fqdn, host.ready)
        if isinstance(answer, host_probe.Unreachable):
            reason = answer.kind.value
        elif HTTPStatus.OK <= answer.status < HTTPStatus.MULTIPLE_CHOICES:
            continue
        else:
            reason = f"status {answer.status}"
        lines.append(f"{host.fqdn} did not answer {host.ready} on {host.target}: {reason}")
    return lines


def _print_plan(
    planned: tofu.Completed,
    plan_file: Path,
    session: tofu.Session,
    token_values: dict[str, str],
    progress: Progress,
) -> ApplyExit | None:
    """The plan as rows and, with changes, tofu's rendering of the written file. The exit when the
    run ends here (nothing to publish, or a plan that cannot be shown); None when changes wait."""
    try:
        stream = tofu.read_plan_stream(planned.output, token_values)
    except tofu.MalformedPlanStream:
        write_row(publish_rows.malformed_stream_row())
        return ApplyExit.CANNOT_PLAN
    for row in publish_rows.warning_rows(stream, token_values):
        write_row(row)
    if (
        planned.exit_code in (tofu.PlanExit.NO_CHANGES, tofu.PlanExit.CHANGES)
        and (unparsed := publish_rows.unparsed_row(stream)) is not None
    ):
        write_row(unparsed)
    if planned.exit_code == tofu.PlanExit.NO_CHANGES:
        progress.plan_was_empty = True
        write_row(publish_rows.current_row())
        return ApplyExit.APPLIED_OR_NOTHING
    if planned.exit_code != tofu.PlanExit.CHANGES:
        for row in publish_rows.failed_plan_rows(stream, token_values):
            write_row(row)
        return ApplyExit.CANNOT_PLAN
    rendered = tofu.run(session.tofu, tofu.show_arguments(plan_file), session.environment)
    if rendered.exit_code != 0:
        write_row(publish_rows.failed_show_row(rendered.output, token_values))
        return ApplyExit.CANNOT_PLAN
    show_tofu_output(secrets.redact(rendered.output, token_values).rstrip("\n"), sys.stdout)
    return None


def _show_confirm_apply(
    session: tofu.Session,
    plan_file: Path,
    token_values: dict[str, str],
    progress: Progress,
    hosts: Sequence[catalog.Host],
    prober_for: Callable[[str], host_probe.Prober],
    catalog_bytes: bytes | None,
) -> ApplyExit:
    plan_arguments = (
        tofu.PLAN_ARGUMENTS if catalog_bytes is None else session.plan_arguments_on(catalog_bytes)
    )
    planned = tofu.run(session.tofu, [*plan_arguments, f"-out={plan_file}"], session.environment)
    if (ended := _print_plan(planned, plan_file, session, token_values, progress)) is not None:
        return ended
    progress.step = Step.READINESS
    if unanswered := _unanswered(hosts, prober_for):
        for line in unanswered:
            write_line(f"{SENDER}: {line}", stream=Stream.STDERR)
        write_line(
            f"{SENDER}: refused, a ready host does not answer, nothing applied",
            stream=Stream.STDERR,
        )
        return ApplyExit.REFUSED
    progress.step = Step.CONFIRMATION
    if not confirmed("apply exactly this plan"):
        write_line(f"{SENDER}: aborted, nothing applied", stream=Stream.STDERR)
        return ApplyExit.REFUSED
    progress.step = Step.APPLY
    progress.apply_reached = True
    applied = tofu.run(session.tofu, ["apply", str(plan_file)], session.environment)
    show_tofu_output(secrets.redact(applied.output, token_values).rstrip("\n"), sys.stdout)
    progress.apply_exit_code = applied.exit_code
    progress.step = Step.CLEANUP
    if applied.exit_code != 0:
        write_line(f"{SENDER}: tofu apply failed (exit {applied.exit_code})", stream=Stream.STDERR)
        return ApplyExit.REFUSED
    return ApplyExit.APPLIED_OR_NOTHING
