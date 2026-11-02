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
from hal.workstation.layout import Layout
from hal.output import is_verbose, write_detail
from hal.output.command import Verb, command

PLAYBOOK = Path(__file__).parent / "system" / "playbook.yml"
# The agents' own OS account: the play creates it dormant, and `hal setup` skips the operator's steps for exactly this user.
AGENT_USER = "agent"
# The ruled bound on every server log on this PC: „ja 30 tage für alle“.
LOG_RETENTION_DAYS = 30
# The default log driver of Docker, which the play merges into daemon.json and `hal check` expects.
DOCKER_LOG_DRIVER = "journald"
# journalctl deletes whole archive files by the age of their oldest entry: one day for a file's span
# and one day of slack for a PC that is off at midnight keep every line under LOG_RETENTION_DAYS.
JOURNAL_VACUUM_DAYS = LOG_RETENTION_DAYS - 2
# The files rsyslog wrote: the play deletes them (and their rotations) once rsyslog is purged, and `hal check` reports them.
RSYSLOG_FILE_NAMES = ("syslog", "auth.log", "kern.log", "mail.log", "mail.err", "ufw.log")
# The line prefix the packaged `hal_events` callback writes before each event; the callback runs in Ansible's own
# interpreter, which cannot import hal, so `system/callback_plugins/hal_events.py` states the same mark.
EVENT_MARK = "\x1ehal_events "


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


class SystemStepInterrupted(StepFailed):
    """The person pressed Ctrl-C during the play; the message is the ticket sentence when `sudo -k` failed after it, else empty."""


class EventKind(Enum):
    CHANGED = "changed"
    RESULT = "result"
    COUNTS = "counts"


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
    """A run that did not finish; `reason` is empty unless the play itself failed, then it is the message of its last failed result."""

    reason: str = ""


PlaybookRun = PlaybookFinished | PlaybookUnfinished
PlaybookRunner = Callable[[Sequence[str]], PlaybookRun]


def _count(event: dict[str, object], name: str) -> int:
    count = event[name]
    if type(count) is not int or count < 0:
        raise ValueError(f"{name} is no count")
    return count


def read_events(returncode: int, event_lines: Sequence[str]) -> PlaybookRun:
    """A run finished when Ansible exited 0 and the callback reported exactly one count without a failed or unreachable host.

    The reason is the message of the last failed or unreachable result, given only when the counts name a failed or unreachable host:
    inside a rescue it is the rescue's own failure that ended the play, and a rescued failure is no cause.
    `tasks` are the names of the changed tasks, in the order they changed.
    An event that is no known event, or a count that is no non-negative integer, is a run that did not finish.
    """
    message = ""
    tasks: list[str] = []
    counts: list[tuple[int, int, int]] = []
    for line in event_lines:
        try:
            event = json.loads(line.removeprefix(EVENT_MARK))
            kind = EventKind(event["event"])
            if kind is EventKind.CHANGED:
                tasks.append(str(event["task"]))
            elif kind is EventKind.RESULT:
                TaskStatus(event["status"])
                message = str(event["msg"])
            else:
                counts.append((_count(event, "changed"), _count(event, "failed"), _count(event, "unreachable")))
        except (ValueError, KeyError, TypeError):
            return PlaybookUnfinished()
    if len(counts) != 1:
        return PlaybookUnfinished()
    changed, failed, unreachable = counts[0]
    if failed or unreachable:
        return PlaybookUnfinished(message)
    return PlaybookFinished(changed, tuple(tasks)) if returncode == 0 else PlaybookUnfinished()


def _forget_the_sudo_ticket() -> StepFailed | None:
    try:
        subprocess.run(["sudo", "-k"], check=True)  # noqa: S607 - sudo is found on PATH by design
    except subprocess.CalledProcessError as failure:
        unforgotten = StepFailed(f"sudo could not forget its ticket (exit {failure.returncode}) · it may still be valid")
        unforgotten.__cause__ = failure
        return unforgotten
    return None


def run_playbook_as_root(argv: Sequence[str]) -> PlaybookRun:
    """Runs `argv` under one `sudo` in the packaged `system/` directory, then makes sudo forget its ticket.

    The system asks for the password at the terminal, which stays stdin and stderr's; Ansible's stderr joins its stdout inside
    sudo, which is shown line by line, and the lines the callback marks are read as events and not shown.
    No `ANSIBLE_*` variable reaches the play, so the packaged `ansible.cfg` there decides. `sudo -k` follows whatever
    the play did, and a failing `sudo -k` fails the step;
    a Ctrl-C in the play, or between the start of sudo and the reading, is a `SystemStepInterrupted`, which a failing `sudo -k` keeps;
    it never follows a sudo that did not start.
    The pipe is read to its end either way; a line the callback does not mark is shown only with `-v`, indented and escaped.
    Root's Python writes no bytecode, which would leave root-owned files in the operator's tool environment.
    No timeout: a person types the password; the run asks its yes at a terminal first and `--dry-run` reaches here only when `needs_first` finds one.
    """
    environment = {name: value for name, value in os.environ.items() if not name.startswith("ANSIBLE_")}
    event_lines: list[str] = []
    unforgotten: StepFailed | None = None
    forgotten = False
    try:
        with subprocess.Popen(["sudo", "env", "PYTHONDONTWRITEBYTECODE=1", "sh", "-c", 'exec "$@" 2>&1', "sh", *argv], stdout=subprocess.PIPE, text=True, cwd=PLAYBOOK.parent, env=environment) as playbook:  # noqa: S603, S607 - argv is the packaged playbook and sudo is found on PATH by design
            try:
                for line in playbook.stdout:
                    if line.startswith(EVENT_MARK):
                        event_lines.append(line)
                    elif is_verbose():
                        write_detail(line.rstrip("\n"), flush=True)
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
    """The terminal the sudo prompt needs, Ansible itself, and who runs `home`."""

    has_terminal: Callable[[], bool]
    run_playbook: PlaybookRunner
    operator_user: Callable[[], str]


# The terminal fact is the one the wizard asks: both ends are a terminal.
TERMINAL_BOUNDARIES = Boundaries(secrets_setup.TERMINAL_BOUNDARIES.terminal.is_interactive, run_playbook_as_root, _running_user)


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

    def check(self) -> CheckState | TasksWouldChange:
        """At a terminal, Ansible's check mode asks for sudo once and names the tasks that would change; without what it needs nothing is read."""
        if self.needs_first():
            return CheckState.NOT_CHECKED
        match self._run_playbook(check=True):
            case PlaybookFinished(changed, tasks):
                return TasksWouldChange(tasks) if changed else CheckState.UNCHANGED
            case unfinished:
                raise StepFailed(unfinished.reason or _unfinished_fact("Ansible's check", "--dry-run"))

    def apply(self) -> Applied:
        match self._run_playbook(check=False):
            case PlaybookFinished(changed):
                return Applied.CHANGED if changed else Applied.UNCHANGED
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
