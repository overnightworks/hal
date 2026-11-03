"""The system step of `hal setup`: edge's cloudflared files and the stop-only polkit rule, written by Ansible as root under one sudo call.

The root work is `system/playbook.yml`. This module runs it with the terminal passed through, says what its check found in one
of three states.
"""

from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from hal.workstation import secrets_setup
from hal.workstation.layout import Layout, run_command
from hal.output import Tone, is_verbose, live_line, write_detail
from hal.output.command import Verb, command

PLAYBOOK = Path(__file__).parent / "system" / "playbook.yml"
# The agents' own OS account: the play creates it dormant, and `hal setup` skips the operator's steps for exactly this user.
AGENT_USER = "agent"
# The ruled bound on every server log on this PC: „ja 30 tage für alle“.
LOG_RETENTION_DAYS = 30
# The default log driver of Docker, which the play merges into daemon.json and `hal check` expects.
DOCKER_LOG_DRIVER = "journald"
DOCKER_DEFAULT_DRIVER = ["docker", "info", "--format", "{{.LoggingDriver}}"]
DOCKER_RUNNING_CONTAINERS = ["docker", "ps", "--quiet", "--no-trunc"]
DOCKER_RESTART_POLICY = ["docker", "inspect", "--format", "{{.HostConfig.RestartPolicy.Name}}"]
# The only policies Docker promises to start again after its own restart.
RESTARTED_POLICIES = frozenset({"always", "unless-stopped"})
DOCKER_DOES_NOT_ANSWER = "Docker does not answer `docker info`"
DOCKER_STATUS = "systemctl status docker"
# journalctl deletes whole archive files by the age of their oldest entry: one day for a file's span
# and one day of slack for a PC that is off at midnight keep every line under LOG_RETENTION_DAYS.
JOURNAL_VACUUM_DAYS = LOG_RETENTION_DAYS - 2
# The files rsyslog wrote: the play deletes them (and their rotations) once rsyslog is purged, and `hal check` reports them.
RSYSLOG_FILE_NAMES = ("syslog", "auth.log", "kern.log", "mail.log", "mail.err", "ufw.log")
# The line prefix the packaged `hal_events` callback writes before each event, and the shell under sudo before its first; the callback
# runs in Ansible's own interpreter, which cannot import hal, so `system/callback_plugins/hal_events.py` states the same mark.
EVENT_MARK = "\x1ehal_events "
SUDO_REFUSED = "sudo refused"
# The row the system step's live line and verdict row stand under; `hal setup` names its row with the same word.
SYSTEM_ROW = "system"


class CheckState(Enum):
    """What a step's check found; only the system step can end up not checked."""

    UNCHANGED = "unchanged"
    WOULD_CHANGE = "would change"
    NOT_CHECKED = "not checked"


NEEDS_A_TERMINAL = "sudo at a terminal"
NEEDS_ANSIBLE = f"Ansible, which `{command(Verb.SETUP)}` installs first"


class Applied(Enum):
    UNCHANGED = "unchanged"
    CHANGED = "changed"


class StepFailed(Exception):
    """A step that did not finish; its message says why."""


class PlayChangedNothing(StepFailed):
    """/etc is as it was: sudo never started the play, or the play stopped and its final counts report no change."""


class DockerDoesNotAnswer(PlayChangedNothing):
    """The operator's `docker info` got no answer before the password; `DOCKER_STATUS` is the way on."""


class SystemStepInterrupted(StepFailed):
    """The person pressed Ctrl-C during the play; the message is the ticket sentence when `sudo -k` failed after it, else empty."""


class EventKind(Enum):
    STARTED = "started"
    TASK = "task"
    CHANGED = "changed"
    RESULT = "result"
    COUNTS = "counts"


# What root's shell writes before it starts Ansible: it proves sudo ran the command, which no event of Ansible's own can.
STARTED_LINE = EVENT_MARK + json.dumps({"event": EventKind.STARTED.value})


class TaskStatus(Enum):
    FAILED = "failed"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True)
class PlaybookFinished:
    changed: int
    tasks: tuple[str, ...] = ()


@dataclass(frozen=True)
class TasksWouldChange:
    """What the system step's check returns where it found something to change: the names of the tasks that would."""

    tasks: tuple[str, ...]


@dataclass(frozen=True)
class PlaybookUnfinished:
    """A run that did not finish; `reason` is empty unless the play itself failed, then it is the message of its last failed result.

    `changed` is the higher of the play's final count and the number of changed tasks named, `None` when no final counts could be read.
    """

    reason: str = ""
    changed: int | None = None


@dataclass(frozen=True)
class PlaybookNotStarted:
    """A run whose sudo never ran the shell: it was refused, so nothing ran."""


PlaybookRun = PlaybookFinished | PlaybookUnfinished | PlaybookNotStarted
PlaybookRunner = Callable[[Sequence[str]], PlaybookRun]


def _count(event: dict[str, object], name: str) -> int:
    count = event[name]
    if type(count) is not int or count < 0:
        raise ValueError(f"{name} is no count")
    return count


def _task_name(event: dict[str, object]) -> str:
    name = event["task"]
    if type(name) is not str:
        raise ValueError("task is no name")
    return name


_UNREADABLE_EVENT = (ValueError, KeyError, TypeError)


def _event_of(event_line: str) -> tuple[EventKind, dict[str, object]]:
    """The kind and the fields of a marked line; one of `_UNREADABLE_EVENT` when it holds no known event."""
    event = json.loads(event_line.removeprefix(EVENT_MARK))
    return EventKind(event["event"]), event


def _read_run_after_start(returncode: int, event_lines: Sequence[str]) -> PlaybookRun:
    """Reads the marked lines after the started line.

    A second started line, an event that is no known event, a task's name that is no string, or a count that is no non-negative integer,
    is a run that did not finish and carries no counts; so is a run with other than one counts event.
    The reason is the message of the last failed or unreachable result, given only when the counts name a failed or unreachable host:
    inside a rescue it is the rescue's own failure that ended the play, and a rescued failure is no cause.
    `tasks` are the names of the changed tasks, in the order they changed; a task's start is read only for its name and shown by the runner.
    A run that did not finish after its counts carries them, with `changed` the higher of the count and the number of changed tasks named,
    because Ansible's count leaves out a failed task, even one that changed, while the callback names it; an ignored failure is counted.
    """
    message = ""
    tasks: list[str] = []
    counts: list[tuple[int, int, int]] = []
    for line in event_lines:
        try:
            kind, event = _event_of(line)
            if kind is EventKind.STARTED:
                return PlaybookUnfinished()
            if kind is EventKind.TASK:
                _task_name(event)
            elif kind is EventKind.CHANGED:
                tasks.append(_task_name(event))
            elif kind is EventKind.RESULT:
                TaskStatus(event["status"])
                message = str(event["msg"])
            else:
                counts.append((_count(event, "changed"), _count(event, "failed"), _count(event, "unreachable")))
        except _UNREADABLE_EVENT:
            return PlaybookUnfinished()
    if len(counts) != 1:
        return PlaybookUnfinished()
    changed, failed, unreachable = counts[0]
    if failed or unreachable:
        return PlaybookUnfinished(message, max(changed, len(tasks)))
    return PlaybookFinished(changed, tuple(tasks)) if returncode == 0 else PlaybookUnfinished(changed=max(changed, len(tasks)))


def read_events(returncode: int, event_lines: Sequence[str]) -> PlaybookRun:
    """A run whose sudo never ran the shell (no marked line at all, a non-zero exit) is `PlaybookNotStarted`.

    Every other run reads from the started line the shell writes first; a run whose first marked line is another did not finish.
    A run finished when Ansible exited 0 and the callback reported exactly one count without a failed or unreachable host;
    `_read_run_after_start` reads the lines after the started line.
    """
    if not event_lines and returncode != 0:
        return PlaybookNotStarted()
    if not event_lines or event_lines[0].rstrip("\n") != STARTED_LINE:
        return PlaybookUnfinished()
    return _read_run_after_start(returncode, event_lines[1:])


def _forget_the_sudo_ticket() -> StepFailed | None:
    try:
        subprocess.run(["sudo", "-k"], check=True)  # noqa: S607 - sudo is found on PATH by design
    except subprocess.CalledProcessError as failure:
        unforgotten = StepFailed(f"sudo could not forget its ticket (exit {failure.returncode}) · it may still be valid")
        unforgotten.__cause__ = failure
        return unforgotten
    return None


def _started_task(event_line: str) -> str | None:
    """The task name a `task` event carries, or None for any other line; an unreadable line is `read_events`'s to judge."""
    try:
        kind, event = _event_of(event_line)
        return _task_name(event) if kind is EventKind.TASK else None
    except _UNREADABLE_EVENT:
        return None


def run_playbook_as_root(argv: Sequence[str]) -> PlaybookRun:
    """Runs `argv` under one `sudo` in the packaged `system/` directory, then makes sudo forget its ticket.

    The system asks for the password at the terminal, which stays stdin and stderr's; Ansible's stderr joins its stdout inside
    sudo, and the lines the callback marks are read as events and not shown. The shell under sudo writes the started line first,
    so a run without any marked line and a non-zero exit is one sudo refused.
    No `ANSIBLE_*` variable reaches the play, so the packaged `ansible.cfg` there decides. `sudo -k` follows whatever
    the play did, and a failing `sudo -k` fails the step;
    a Ctrl-C in the play, or between the start of sudo and the reading, is a `SystemStepInterrupted`, which a failing `sudo -k` keeps;
    it never follows a sudo that did not start.
    The pipe is read to its end either way; a line the callback does not mark is shown only with `-v`, indented, escaped and dim.
    Without `-v` at a terminal, each task start the callback marks is the live line of the `system` row until the play ends.
    Root's Python writes no bytecode, which would leave root-owned files in the operator's tool environment.
    No timeout: a person types the password; the run asks its yes at a terminal first and `--dry-run` reaches here only when `needs_first` finds one.
    """
    environment = {name: value for name, value in os.environ.items() if not name.startswith("ANSIBLE_")}
    event_lines: list[str] = []
    unforgotten: StepFailed | None = None
    forgotten = False
    try:
        with subprocess.Popen(["sudo", "env", "PYTHONDONTWRITEBYTECODE=1", "sh", "-c", 'printf \'%s\\n\' "$1" && shift && exec "$@" 2>&1', "sh", STARTED_LINE, *argv], stdout=subprocess.PIPE, text=True, cwd=PLAYBOOK.parent, env=environment) as playbook:  # noqa: S603, S607 - argv is the packaged playbook and sudo is found on PATH by design
            try:
                with live_line(SYSTEM_ROW) as show_task:
                    for line in playbook.stdout:
                        if line.startswith(EVENT_MARK):
                            event_lines.append(line)
                            if (task := _started_task(line)) is not None:
                                show_task(task)
                        elif is_verbose():
                            write_detail(line.rstrip("\n"), tone=Tone.DIM, flush=True)
            finally:
                unforgotten = _forget_the_sudo_ticket()
                forgotten = True
                if unforgotten is not None and not isinstance(sys.exception(), KeyboardInterrupt):
                    raise unforgotten
    except KeyboardInterrupt as ctrl_c:
        if not forgotten:
            unforgotten = _forget_the_sudo_ticket()
        raise SystemStepInterrupted("" if unforgotten is None else str(unforgotten)) from ctrl_c
    return read_events(playbook.returncode, event_lines)


def _unfinished_fact(who: str, *flags: str) -> str:
    """Without `-v` the fact says how to see why; under `-v` the text above it already does."""
    why = "its output above says why" if is_verbose() else f"{command(Verb.SETUP, *flags, '-v')} shows why"
    return f"{who} did not finish · {why}"


class UnresolvableRunningUser(ValueError):
    """The running uid has no passwd name, or `agent` shares it with another name; the role cannot be told from the name."""


def _running_user() -> str:
    uid = os.getuid()
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        raise UnresolvableRunningUser(f"no passwd entry for uid {uid}") from None
    names = [entry.pw_name for entry in pwd.getpwall() if entry.pw_uid == uid]
    if len(names) > 1 and AGENT_USER in names:
        raise UnresolvableRunningUser(f"uid {uid} has the names {', '.join(names)}; {AGENT_USER} must have a uid of its own")
    return name


@dataclass(frozen=True)
class Boundaries:
    """The terminal the sudo prompt needs, Ansible itself, who runs `home`, the log driver Docker tells the operator (`None` when it does not answer),
    and the restart policy of each running container (`None` when they cannot be read)."""

    has_terminal: Callable[[], bool]
    run_playbook: PlaybookRunner
    operator_user: Callable[[], str]
    docker_driver: Callable[[], str | None]
    running_restart_policies: Callable[[], tuple[str, ...] | None]


@dataclass(frozen=True)
class RestartForecast:
    """The Docker restart the play will make; `stay_down` counts the running containers Docker will not start again, `None` when their policies could not be read."""

    stay_down: int | None


def _docker_driver() -> str | None:
    """The log driver `docker info` tells the operator; None for a Docker that cannot be run or does not answer (a `docker` that is not executable raises `PermissionError`)."""
    try:
        output = run_command(DOCKER_DEFAULT_DRIVER)
    except OSError:
        return None
    return None if output is None else output.strip()


def _running_restart_policies() -> tuple[str, ...] | None:
    """The restart policy of each running container as the operator reads it; None when `docker ps` or `docker inspect` fails."""
    try:
        listing = run_command(DOCKER_RUNNING_CONTAINERS)
        if listing is None:
            return None
        container_ids = listing.split()
        if not container_ids:
            return ()
        policies = run_command([*DOCKER_RESTART_POLICY, *container_ids])
    except OSError:
        return None
    return None if policies is None else tuple(policies.splitlines())


# The terminal fact is the one the wizard asks: both ends are a terminal.
TERMINAL_BOUNDARIES = Boundaries(secrets_setup.TERMINAL_BOUNDARIES.terminal.is_interactive, run_playbook_as_root, _running_user, _docker_driver, _running_restart_policies)


@dataclass(frozen=True)
class SystemStep:
    layout: Layout
    boundaries: Boundaries

    def extra_vars(self) -> dict[str, str | int | tuple[str, ...]]:
        """The values the playbook fills in; the tunnel id it reads itself, as root, from cloudflared's config.

        sudo logs its whole argv, so nothing here may ever be a secret.
        """
        return {
            "home": str(self.layout.home),
            "operator_user": self.boundaries.operator_user(),
            "agent_user": AGENT_USER,
            "edge_tunnel_dir": str(self.layout.edge_tunnel_dir),
            "journal_vacuum_days": JOURNAL_VACUUM_DAYS,
            "docker_log_driver": DOCKER_LOG_DRIVER,
            "rsyslog_file_names": RSYSLOG_FILE_NAMES,
        }

    def needs_first(self) -> str:
        """What the check needs before it can look, empty when it can: a terminal for sudo, then the engine to check with."""
        if not self.boundaries.has_terminal():
            return NEEDS_A_TERMINAL
        if not self.layout.ansible_playbook_executable.is_file():
            return NEEDS_ANSIBLE
        return ""

    def _answering_docker_driver(self) -> str:
        driver = self.boundaries.docker_driver()
        if driver is None:
            raise DockerDoesNotAnswer(DOCKER_DOES_NOT_ANSWER)
        return driver

    def refuse_unless_docker_answers(self) -> None:
        """Docker is read as the operator, so a Docker that does not answer ends the step before sudo asks for a password."""
        self._answering_docker_driver()

    def restart_forecast(self) -> RestartForecast | None:
        """The restart the play makes when Docker's default driver is not the journal, `None` when it makes none; a Docker that does not answer refuses first."""
        if self._answering_docker_driver() == DOCKER_LOG_DRIVER:
            return None
        policies = self.boundaries.running_restart_policies()
        return RestartForecast(None if policies is None else sum(policy not in RESTARTED_POLICIES for policy in policies))

    def check(self) -> CheckState | TasksWouldChange:
        """At a terminal, Ansible's check mode asks for sudo once and names the tasks that would change; without what it needs nothing is read."""
        if self.needs_first():
            return CheckState.NOT_CHECKED
        self.refuse_unless_docker_answers()
        match self._run_playbook(check=True):
            case PlaybookFinished(changed, tasks):
                return TasksWouldChange(tasks) if changed else CheckState.UNCHANGED
            case PlaybookNotStarted():
                raise StepFailed(SUDO_REFUSED)
            case unfinished:
                raise StepFailed(unfinished.reason or _unfinished_fact("Ansible's check", "--dry-run"))

    def apply(self) -> Applied:
        match self._run_playbook(check=False):
            case PlaybookFinished(changed):
                return Applied.CHANGED if changed else Applied.UNCHANGED
            case PlaybookNotStarted():
                raise PlayChangedNothing(SUDO_REFUSED)
            case PlaybookUnfinished(changed=0) as unfinished:
                raise PlayChangedNothing(unfinished.reason or _unfinished_fact("Ansible"))
            case unfinished:
                raise StepFailed(unfinished.reason or _unfinished_fact("Ansible"))

    def _run_playbook(self, check: bool) -> PlaybookRun:
        argv = [
            str(self.layout.ansible_playbook_executable),
            str(PLAYBOOK),
            "--inventory",
            "localhost,",
            "--diff",
            "--extra-vars",
            json.dumps({**self.extra_vars(), "ansible_python_interpreter": "auto_silent"}),
            *(["--check"] if check else []),
        ]
        return self.boundaries.run_playbook(argv)
