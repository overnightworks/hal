"""`hal setup`: quality, its engines and the global commit hook, then the user units, Ansible, the system step and the secrets.

It shows its plan, asks one `yes` and only then runs; `--dry-run` only shows. Nothing, and no sudo, comes before the yes.

The activation comes before the user units and the system step, so a wrong sudo password never keeps the commit hook from being active.
The user units come before the system step, which is the one that asks for sudo.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import tomllib
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from pathlib import Path
from shlex import join as shell_join
from shlex import quote
from typing import TYPE_CHECKING

from hal.output import Glyph, Noun, Row, TrailingNoun, Verdict, confirmed, counted, write_error, write_row, write_verdict
from hal.output.command import Verb, command
from hal.workstation import secrets_setup
from hal.workstation.secrets_setup import WalkEnd
from hal.workstation.secrets_view import ManifestError, Presence, SecretEntry
from hal.workstation.system_step import (
    AGENT_USER,
    Applied,
    CheckState,
    StepFailed,
    SystemStep,
    SystemStepInterrupted,
    UnresolvableRunningUser,
)
from hal.workstation.layout import CommandRunner, Layout
from hal.workstation.path_link import PathLink
from hal.workstation.user_units import UnitsApplied, UnitsPartial, UserUnits

if TYPE_CHECKING:
    from hal.workstation.ports import Downloader, Ports

# Quality v0.8.0. A commit SHA cannot move; a bump is a one-line change here.
QUALITY_SOURCE = "overnightworks-quality @ git+https://github.com/overnightworks/quality@64009e7eba23ba7d3c5d2b2df0e7d68b71b27a73"
# The release binary of mise and its sha256 (the same in the release's SHASUMS256.txt); a bump is a two-line change here.
MISE_VERSION = "2026.10.23"
MISE_SHA256 = "a6ac620e73fb58cefbdfef8fb154856fbd8ae08d75ae88103e4b81daef3a836e"
MISE_URL = f"https://github.com/jdx/mise/releases/download/v{MISE_VERSION}/mise-v{MISE_VERSION}-linux-x64"
# The engine of the system step; a bump is a one-line change here.
ANSIBLE_SOURCE = "ansible-core==2.21.5"
HOOK_NAMES = ("pre-commit", "pre-merge-commit")
HOOK_TEMPLATE = Path(__file__).parent / "hooks" / "commit-hook"
HOOK_MODE = 0o755
MISE_MODE = 0o755
HOOK_WHY = "without the hook no commit is checked for secrets"
MISE_WHY = "without mise the pinned quality gate cannot install its scanners"
PATH_WHY = "without the link your terminal finds no hal, or the one of a checkout that has moved"
UNITS_WHY = "without the units and the reload the timers run no hal job, or an older one"
SECRETS_WHY = "without them the services and the tunnel have no token, password or key to start with"
SYSTEM_WHY = (
    "without it the tunnel ignores edge's global stop after a reboot, and only root may stop it"
)
SUDO_WILL_BE_ASKED_FOR = "tunnel, polkit, journal, mail, agent account"
SKIPPED_FOR_THE_AGENT = "the operator's step"
RERUN = command(Verb.SETUP)
SUDO_CHECKS_AFTER_THE_YES = "sudo checks it after your yes"
APPLY_PLAN = command(Verb.APPLY)


class SetupRow(StrEnum):
    """The five rows `hal setup` prints, in the order it runs them."""

    COMMIT_HOOK = "commit hook"
    PATH = "path"
    TIMERS = "timers"
    SYSTEM = "system"
    SECRETS = "secrets"


class SetupEvent(StrEnum):
    CHANGED = "changed"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"
    WILL_CHANGE = "will change"
    NOT_CHECKED = "not checked"
    MISSING = "missing"
    STORED = "stored"
    COMPLETE = "complete"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    NOT_RUN = "not run"
    NEEDS_SUDO = "needs sudo"
    OPEN = "open"


class Tally(StrEnum):
    """What the verdict counts a row as."""

    CHANGED = "changed"
    OPEN = "open"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class EventLook:
    """`severity` ranks the events of one row's steps: the worst one is the row's."""

    glyph: Glyph
    severity: int
    tally: Tally | None


EVENT_LOOK: dict[SetupEvent, EventLook] = {
    SetupEvent.FAILED: EventLook(Glyph.FAILED, 5, None),
    SetupEvent.INTERRUPTED: EventLook(Glyph.FAILED, 5, None),
    SetupEvent.NOT_CHECKED: EventLook(Glyph.NEEDS_YOU, 4, Tally.OPEN),
    SetupEvent.MISSING: EventLook(Glyph.NEEDS_YOU, 4, Tally.OPEN),
    SetupEvent.OPEN: EventLook(Glyph.NEEDS_YOU, 4, Tally.OPEN),
    SetupEvent.CHANGED: EventLook(Glyph.DONE, 3, Tally.CHANGED),
    SetupEvent.STORED: EventLook(Glyph.DONE, 3, Tally.CHANGED),
    SetupEvent.WILL_CHANGE: EventLook(Glyph.CHANGE, 3, Tally.OPEN),
    SetupEvent.UNCHANGED: EventLook(Glyph.UNCHANGED, 2, Tally.UNCHANGED),
    SetupEvent.COMPLETE: EventLook(Glyph.UNCHANGED, 2, Tally.UNCHANGED),
    SetupEvent.SKIPPED: EventLook(Glyph.UNCHANGED, 1, Tally.SKIPPED),
    SetupEvent.NOT_RUN: EventLook(Glyph.UNCHANGED, 0, None),
    SetupEvent.NEEDS_SUDO: EventLook(Glyph.ANNOUNCE, 0, None),
}


class SecretsStillOpen(StepFailed):
    """The wizard walked every secret and some are still open; `names` are their row names, from disk."""

    def __init__(self, names: tuple[str, ...]) -> None:
        super().__init__()
        self.names = names


class WalkTold(StepFailed):
    """The wizard stopped and already wrote the error pair that ends the run; setup adds no row and no second pair."""


class StillOpenSecret(Noun):
    SECRET = "secret still open"  # noqa: S105 - a noun for a count and no credential


class OpenRow(TrailingNoun):
    ROW = "open row"


class SetupEnd(Enum):
    """How `hal setup` ended: it ran or showed, a step failed, the person did not say yes, or there was nobody to ask."""

    DONE = "done"
    FAILED = "failed"
    DECLINED = "declined"
    NO_TERMINAL = "no terminal"


class Pass(Enum):
    """`DRY_RUN` is what `--dry-run` shows, with Ansible's check under sudo at a terminal; `PLAN` is the same before the yes
    except that the root step is not checked; `RUN` is the run after the yes."""

    DRY_RUN = "dry run"
    PLAN = "plan"
    RUN = "run"


@dataclass(frozen=True)
class Outcome:
    """What a step, or the worst of a row's steps, found or did; `fact` is the one sentence the row shows."""

    event: SetupEvent
    fact: str = ""
    count: int | None = None

    def row(self, subject: SetupRow) -> Row:
        return Row(EVENT_LOOK[self.event].glyph, subject, self.event, self.fact, self.count)


@dataclass(frozen=True)
class StepEvents:
    """The words a step reports in; the secrets step says what its wizard did, not what a file did."""

    changed: SetupEvent = SetupEvent.CHANGED
    unchanged: SetupEvent = SetupEvent.UNCHANGED
    open: SetupEvent = SetupEvent.WILL_CHANGE


SECRETS_EVENTS = StepEvents(
    changed=SetupEvent.STORED, unchanged=SetupEvent.COMPLETE, open=SetupEvent.MISSING
)


def open_rows_of(outcomes: Sequence[Outcome]) -> int:
    return sum(EVENT_LOOK[outcome.event].tally is Tally.OPEN for outcome in outcomes)


def verdict_of(outcomes: Sequence[Outcome], ran: bool, elapsed_seconds: float) -> Verdict:
    tallies = Counter(EVENT_LOOK[outcome.event].tally for outcome in outcomes)
    counts = tuple((tallies[tally], tally) for tally in Tally)
    if ran:
        walk_stored = any(outcome.event is SetupEvent.STORED for outcome in outcomes)
        return Verdict(Glyph.DONE, "setup done", counts, elapsed_seconds=elapsed_seconds, next_step=APPLY_PLAN if walk_stored else "")
    if open_rows_of(outcomes):
        return Verdict(Glyph.CHANGE, "setup plan", counts, f"run {RERUN}", elapsed_seconds)
    return Verdict(Glyph.DONE, "setup up to date", counts, elapsed_seconds=elapsed_seconds)


class ExecutionRole(Enum):
    """Who runs `hal setup`: exactly the agents' account, or anyone else (root and a sudoers-only admin included)."""

    AGENT = "agent"
    OPERATOR = "operator"

    @classmethod
    def of(cls, running_user: str) -> ExecutionRole:
        return cls.AGENT if running_user == AGENT_USER else cls.OPERATOR


@dataclass(frozen=True)
class Step:
    """`check` is the dry run, `apply` the run.

    `row` is the line the step reports on; `failure` is the one sentence its failure shows when it raises nothing better,
    and `next_step` the command that goes on from there.
    `needs_first` names what a `not checked` dry run lacks; only the system step can end up there.
    `open_fact` names what a dry run that found something to change shows on its row.
    `apply` may return `UnitsApplied`, which adds the fact the row of a changed step shows.
    `before_apply` is the row printed before an apply that waits on the operator (the wizard, sudo's password), or nothing.
    `operators_only` marks a step the agents' account skips: it needs sudo, the operator's units or the operator's secrets.
    `may_leave_system_partial` marks the step that runs as root, whose failed apply leaves /etc half written.
    """

    name: str
    row: SetupRow
    check: Callable[[], CheckState]
    apply: Callable[[], Applied | UnitsApplied]
    why: str
    failure: str
    next_step: str = RERUN
    needs_first: Callable[[], str] = lambda: ""
    open_fact: Callable[[], str] = lambda: ""
    before_apply: Callable[[], Outcome | None] = lambda: None
    events: StepEvents = field(default_factory=StepEvents)
    operators_only: bool = False
    may_leave_system_partial: bool = False

    def runs_for(self, role: ExecutionRole) -> bool:
        return not (self.operators_only and role is ExecutionRole.AGENT)

    def run(self, apply: bool) -> Outcome:
        if apply:
            done = self.apply()
            if isinstance(done, UnitsApplied):
                event = self.events.changed if done.applied is Applied.CHANGED else self.events.unchanged
                return Outcome(event, done.fact)
            return Outcome(self.events.changed if done is Applied.CHANGED else self.events.unchanged)
        match self.check():
            case CheckState.NOT_CHECKED:
                return Outcome(SetupEvent.NOT_CHECKED, f"needs {self.needs_first()}")
            case CheckState.WOULD_CHANGE:
                return Outcome(self.events.open, self.open_fact())
        return Outcome(self.events.unchanged)


HOOKS_PATH_KEY = "core.hooksPath"


def _local_step(
    name: str,
    row: SetupRow,
    is_current: Callable[[], bool],
    install: Callable[[], bool],
    why: str,
    failure: str,
    next_step: str = RERUN,
    *,
    operators_only: bool = False,
) -> Step:
    """A step in the user's own home: its check needs no password, so it is never `not checked`."""

    def check() -> CheckState:
        return CheckState.UNCHANGED if is_current() else CheckState.WOULD_CHANGE

    def apply() -> Applied:
        if is_current():
            return Applied.UNCHANGED
        if not install():
            raise StepFailed
        return Applied.CHANGED

    return Step(
        name, row, check, apply, why, failure, next_step, operators_only=operators_only
    )


def _secrets_step(layout: Layout, ports: Ports) -> Step:
    """The wizard as a step: verified by `stat` when no live secret is open or undeterminable, applied through the wizard itself."""
    boundaries = ports.secrets_setup

    def open_secrets() -> list[tuple[SecretEntry, Presence]]:
        try:
            return secrets_setup.open_entries(layout)
        except ManifestError as error:
            raise StepFailed(str(error)) from None

    def nothing_open() -> bool:
        return not open_secrets()

    def check() -> CheckState:
        return CheckState.UNCHANGED if nothing_open() else CheckState.WOULD_CHANGE

    def apply() -> Applied:
        if nothing_open():
            return Applied.UNCHANGED
        end = secrets_setup.run_setup(layout, boundaries, ports.now)
        if end is WalkEnd.ABORTED:
            raise KeyboardInterrupt  # the wizard has said so; the caller's own handling gives the exit code
        if end is WalkEnd.STILL_OPEN:
            raise SecretsStillOpen(_open_names(open_secrets()))
        if end.wrote_its_pair:
            raise WalkTold
        return Applied.CHANGED

    def open_names() -> str:
        return ", ".join(_open_names(open_secrets()))

    def announce_missing() -> Outcome | None:
        missing = open_secrets()
        return Outcome(SetupEvent.MISSING, ", ".join(_open_names(missing)), count=len(missing)) if missing else None

    return Step(
        "Geheimnisse",
        SetupRow.SECRETS,
        check,
        apply,
        SECRETS_WHY,
        "not every secret is set up",
        open_fact=open_names,
        before_apply=announce_missing,
        events=SECRETS_EVENTS,
        operators_only=True,
    )


def _open_names(open_entries: list[tuple[SecretEntry, Presence]]) -> tuple[str, ...]:
    return tuple(_open_name(entry, found) for entry, found in open_entries)


def _open_name(entry: SecretEntry, found: Presence) -> str:
    if found is Presence.UNKNOWN:
        return f"{entry.name} (unknown)"
    return entry.name if entry.written_by_setup else f"{entry.name} (by hand)"


def render_hook(layout: Layout) -> str:
    template = HOOK_TEMPLATE.read_text()
    return template.replace("@QUALITY@", quote(str(layout.quality_executable))).replace("@ENGINES@", quote(str(layout.quality_engines_dir)))


def _is_executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _has_hook_mode(path: Path) -> bool:
    return path.is_file() and path.stat().st_mode & 0o777 == HOOK_MODE


def _uv_recorded(receipt_path: Path, requirement: Mapping[str, str]) -> bool:
    """Whether uv's receipt for a tool records this requirement, so a pin that moved reinstalls the tool."""
    try:
        receipt = tomllib.loads(receipt_path.read_text())
    except (OSError, ValueError):
        return False
    recorded = receipt.get("tool", {}).get("requirements", [])
    return any(all(entry.get(key) == value for key, value in requirement.items()) for entry in recorded)


def _recorded_quality_source_matches(layout: Layout) -> bool:
    """uv records a git requirement as `<url>?rev=<sha>`."""
    name, _, source = QUALITY_SOURCE.partition(" @ ")
    url, _, revision = source.removeprefix("git+").rpartition("@")
    return _uv_recorded(layout.quality_uv_receipt, {"name": name, "git": f"{url}?rev={revision}"})


def _recorded_ansible_source_matches(layout: Layout) -> bool:
    """uv records a pinned version as its specifier."""
    name, _, version = ANSIBLE_SOURCE.partition("==")
    return _uv_recorded(layout.ansible_uv_receipt, {"name": name, "specifier": f"=={version}"})


def _write_atomically(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(content)
    temporary.chmod(HOOK_MODE)
    temporary.replace(path)


def mise_hash_is_pinned(path: Path) -> bool:
    with path.open("rb") as binary:
        return hashlib.file_digest(binary, "sha256").hexdigest() == MISE_SHA256


def mise_is_current(layout: Layout) -> bool:
    return _is_executable(layout.mise_executable) and mise_hash_is_pinned(layout.mise_executable)


def _install_mise(layout: Layout, download: Downloader) -> bool:
    """Downloads into a private staging file beside the destination and publishes it only whole, hash-checked and executable."""
    destination = layout.mise_executable
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, staging_name = tempfile.mkstemp(prefix=".mise-", dir=destination.parent)
    staging = Path(staging_name)
    try:
        with os.fdopen(descriptor, "wb") as writer:
            try:
                download(MISE_URL, writer)
            except OSError as error:
                raise StepFailed(f"mise could not be downloaded: {error.strerror or error}") from error
        if not mise_hash_is_pinned(staging):
            raise StepFailed("the download of mise does not match its pinned sha256")
        staging.chmod(MISE_MODE)
        os.replace(staging, destination)
    except OSError as error:
        raise StepFailed(f"mise could not be installed: {error.strerror or error}") from error
    finally:
        staging.unlink(missing_ok=True)
    return True


def _quality_steps(layout: Layout, run: CommandRunner, download: Downloader) -> tuple[Step, ...]:
    quality, engines_dir = str(layout.quality_executable), str(layout.quality_engines_dir)

    def quality_current() -> bool:
        return _recorded_quality_source_matches(layout) and _is_executable(layout.quality_executable)

    def install_quality() -> bool:
        return run(["uv", "tool", "install", "--force", QUALITY_SOURCE]) is not None and _is_executable(layout.quality_executable)

    def engines_current() -> bool:
        return _is_executable(layout.quality_executable) and run([quality, "engines", "verify", engines_dir]) is not None

    def install_engines() -> bool:
        return run([quality, "engines", "install", engines_dir]) is not None and engines_current()

    return (
        _local_step(
            "mise",
            SetupRow.COMMIT_HOOK,
            lambda: mise_is_current(layout),
            lambda: _install_mise(layout, download),
            MISE_WHY,
            "mise did not install",
        ),
        _local_step(
            "quality",
            SetupRow.COMMIT_HOOK,
            quality_current,
            install_quality,
            HOOK_WHY,
            "uv could not install quality",
            shell_join(["uv", "tool", "install", "--force", QUALITY_SOURCE]),
        ),
        _local_step(
            "Engines",
            SetupRow.COMMIT_HOOK,
            engines_current,
            install_engines,
            HOOK_WHY,
            "the quality engines did not install",
            shell_join([quality, "engines", "install", engines_dir]),
        ),
    )


def _hook_steps(layout: Layout, run: CommandRunner) -> tuple[Step, ...]:
    hook_content = render_hook(layout)
    hook_paths = [layout.git_hooks_dir / name for name in HOOK_NAMES]

    def hook_current(path: Path) -> bool:
        return _has_hook_mode(path) and path.read_text() == hook_content

    def write_hooks() -> bool:
        for path in hook_paths:
            if not hook_current(path):
                _write_atomically(path, hook_content)
        return True

    def hooks_active() -> bool:
        return (run(["git", "config", "--global", "--get", HOOKS_PATH_KEY]) or "").strip() == str(layout.git_hooks_dir)

    def activate_hooks() -> bool:
        return run(["git", "config", "--global", HOOKS_PATH_KEY, str(layout.git_hooks_dir)]) is not None

    return (
        _local_step(
            "Hook-Dateien",
            SetupRow.COMMIT_HOOK,
            lambda: all(hook_current(path) for path in hook_paths),
            write_hooks,
            HOOK_WHY,
            "could not write the hook files",
        ),
        _local_step(
            "Aktivierung",
            SetupRow.COMMIT_HOOK,
            hooks_active,
            activate_hooks,
            HOOK_WHY,
            "git could not set core.hooksPath",
            shell_join(["git", "config", "--global", HOOKS_PATH_KEY, str(layout.git_hooks_dir)]),
        ),
    )


def _path_steps(layout: Layout) -> tuple[Step, ...]:
    link = PathLink(layout)
    return (
        Step(
            "PATH link",
            SetupRow.PATH,
            link.check,
            link.apply,
            PATH_WHY,
            "the link could not be made",
            open_fact=link.fact,
            operators_only=True,
        ),
    )


def _system_steps(layout: Layout, ports: Ports) -> tuple[Step, ...]:
    run = ports.run
    system = SystemStep(layout, ports.system)
    units = UserUnits(layout, ports.timer_jobs, run)
    system_row = SetupRow.SYSTEM

    def ansible_current() -> bool:
        return _recorded_ansible_source_matches(layout) and _is_executable(layout.ansible_playbook_executable)

    def install_ansible() -> bool:
        return run(["uv", "tool", "install", "--force", ANSIBLE_SOURCE]) is not None and ansible_current()

    return (
        Step(
            "User units",
            SetupRow.TIMERS,
            units.check,
            units.apply,
            UNITS_WHY,
            "the user units did not come up",
            open_fact=units.open_fact,
            operators_only=True,
        ),
        _local_step(
            "Ansible",
            system_row,
            ansible_current,
            install_ansible,
            SYSTEM_WHY,
            "uv could not install Ansible",
            shell_join(["uv", "tool", "install", "--force", ANSIBLE_SOURCE]),
            operators_only=True,
        ),
        Step(
            "System",
            system_row,
            system.check,
            system.apply,
            SYSTEM_WHY,
            "the system step did not finish",
            needs_first=system.needs_first,
            before_apply=lambda: Outcome(SetupEvent.NEEDS_SUDO, SUDO_WILL_BE_ASKED_FOR),
            operators_only=True,
            may_leave_system_partial=True,
        ),
    )


def _steps(layout: Layout, ports: Ports) -> tuple[Step, ...]:
    return (*_quality_steps(layout, ports.run, ports.download), *_hook_steps(layout, ports.run), *_path_steps(layout), *_system_steps(layout, ports), _secrets_step(layout, ports))


def _role(ports: Ports) -> ExecutionRole:
    return ExecutionRole.of(ports.system.operator_user())


def _failure_sentence(step: Step, error: OSError | StepFailed) -> str:
    if isinstance(error, StepFailed):
        return str(error) or step.failure
    return f"{step.failure}: {error.strerror or type(error).__name__}"


def _stopped(row: SetupRow, step: Step, detail: str) -> None:
    """The error pair after a failed row: what stopped, what it left behind, and the command that goes on."""
    write_error(f"setup stopped at {row}{detail}", step.next_step)


class _RowStopped(Exception):
    def __init__(self, step: Step, error: OSError | StepFailed) -> None:
        super().__init__(str(error))
        self.step = step
        self.error = error


def _run_row(row: SetupRow, steps: tuple[Step, ...], role: ExecutionRole, mode: Pass) -> Outcome:
    outcomes: list[Outcome] = []
    for step in (step for step in steps if step.row is row):
        if not step.runs_for(role):
            outcomes.append(Outcome(SetupEvent.SKIPPED, SKIPPED_FOR_THE_AGENT))
            continue
        if mode is Pass.PLAN and step.may_leave_system_partial:
            outcomes.append(Outcome(SetupEvent.NOT_CHECKED, SUDO_CHECKS_AFTER_THE_YES))
            continue
        try:
            if mode is Pass.RUN and (announced := step.before_apply()):
                write_row(announced.row(row))
            outcomes.append(step.run(mode is Pass.RUN))
        except (OSError, StepFailed) as error:
            raise _RowStopped(step, error) from error
    return max(outcomes, key=lambda candidate: EVENT_LOOK[candidate.event].severity)


def _failure_detail(row: SetupRow, error: OSError | StepFailed, step: Step, mode: Pass) -> str:
    """What the failed row left behind, for the rows that say: no mutation is tracked, so `may` is true whether or not anything changed."""
    match row:
        case SetupRow.SYSTEM:
            leaves = "/etc may be partial" if step.may_leave_system_partial and mode is Pass.RUN else "/etc unchanged"
            return f" · {leaves}"
        case SetupRow.PATH:
            return " · nothing changed" if mode is not Pass.RUN else ""
        case SetupRow.TIMERS:
            return " · units may be partial" if isinstance(error, UnitsPartial) else " · nothing changed"
    return ""


def _stop_after_failure(rows: list[SetupRow], position: int, stopped: _RowStopped, mode: Pass) -> None:
    step = stopped.step
    match stopped.error:
        case WalkTold():
            return
        case SecretsStillOpen(names=names):
            outcome = Outcome(SetupEvent.OPEN, ", ".join(names), count=len(names))
            detail = f" · {counted(len(names), StillOpenSecret.SECRET)}"
        case SystemStepInterrupted() as error:
            outcome = Outcome(SetupEvent.INTERRUPTED, str(error))
            detail = _failure_detail(rows[position], error, step, mode)
        case error:
            outcome = Outcome(SetupEvent.FAILED, _failure_sentence(step, error))
            detail = _failure_detail(rows[position], error, step, mode)
    write_row(outcome.row(rows[position]), fresh_line=outcome.event is SetupEvent.INTERRUPTED)
    for later in rows[position + 1 :]:
        write_row(Outcome(SetupEvent.NOT_RUN).row(later))
    _stopped(rows[position], step, detail)


def _go_through(steps: tuple[Step, ...], role: ExecutionRole, mode: Pass) -> list[Outcome] | None:
    """Every row in order, printed as it ends; stops at the first failed step, so a missing scanner never gets a hook
    activated, and the later rows say `not run`. `None` says a step failed and its error pair is written;
    a Ctrl-C in the system step prints the same and then raises `KeyboardInterrupt`."""
    outcomes: list[Outcome] = []
    rows = list(SetupRow)
    for position, row in enumerate(rows):
        try:
            outcome = _run_row(row, steps, role, mode)
        except _RowStopped as stopped:
            _stop_after_failure(rows, position, stopped, mode)
            if isinstance(stopped.error, SystemStepInterrupted):
                raise KeyboardInterrupt from stopped
            return None
        write_row(outcome.row(row))
        outcomes.append(outcome)
    return outcomes


def setup(layout: Layout, ports: Ports, dry_run: bool) -> SetupEnd:
    """Shows the plan, asks one yes and runs; `dry_run` only shows. Without a terminal an open row ends in a refusal before any step."""
    try:
        role = _role(ports)
    except UnresolvableRunningUser as error:
        write_error(str(error))
        return SetupEnd.FAILED
    started = ports.clock()
    steps = _steps(layout, ports)
    planned = _go_through(steps, role, Pass.DRY_RUN if dry_run else Pass.PLAN)
    if planned is None:
        return SetupEnd.FAILED
    open_rows = open_rows_of(planned)
    if dry_run or not open_rows:
        write_verdict(verdict_of(planned, False, ports.clock() - started))
        return SetupEnd.DONE
    if not ports.secrets_setup.terminal.is_interactive():
        write_error("setup asks yes at a terminal · nothing changed", f"{RERUN} in your own terminal window")
        return SetupEnd.NO_TERMINAL
    if not confirmed(f"set up {counted(open_rows, OpenRow.ROW)}"):
        write_error("aborted, nothing changed")
        return SetupEnd.DECLINED
    ran = _go_through(steps, role, Pass.RUN)
    if ran is None:
        return SetupEnd.FAILED
    write_verdict(verdict_of(ran, True, ports.clock() - started))
    return SetupEnd.DONE
