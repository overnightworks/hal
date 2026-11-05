"""The pre-apply snapshot of a database unit: `hal backup <unit> --pre-apply --json` takes it and
`hal restore --test <unit> --snapshot <ID>` proves it, before `hal apply` changes what the unit's
database holds (the realm step) or the image that reads it (a recreate onto a moved image)."""

import contextlib
import json
import os
import re
import signal
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from hal.output import LOG_FORMAT_VARIABLE, LogFormat, printable
from hal.output.command import PROGRAM, Verb, command
from hal.stack import compose
from hal.stack.unit_plans import DatabaseUnit

BACKUP_SECONDS = 1800
STOP_GRACE_SECONDS = 120  # what hal backup gets to remove its staging and restore container
COLLECT_SECONDS = 5  # what the output of a killed hal backup gets before its pipes are closed
# restic's short ID, which `hal restore --snapshot` takes as a prefix (`hal.backup.runner`'s
# MIN_SNAPSHOT_PREFIX); `hal.stack` may not import `hal.backup`, so the length is repeated.
SNAPSHOT_SHORT_ID = 8
_ERROR_LINE = re.compile(r"^error: (.+)$", re.MULTILINE)

type Waiting = Callable[[float], None]  # told the seconds a stopped hal is given to clean up


class PreApplyError(Exception):
    """The snapshot could not be taken or proven; the message is one line without a secret."""


def run_edge_backup(
    command: list[str], timeout: int, stdin: str | None = None, *, waiting: Waiting
) -> subprocess.CompletedProcess[str]:
    """Run hal backup or hal restore to its end, in a session of its own, so the terminal's Ctrl-C
    reaches only this step. On the timeout or the first Ctrl-C it is stopped as the `hal-backup`
    systemd unit is (`KillMode=control-group` default): SIGTERM to its whole group, then
    `STOP_GRACE_SECONDS` to remove its staging and restore container."""
    try:
        with subprocess.Popen(  # noqa: S603 - argv is built by the program itself and no shell runs
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=compose.REPOSITORY,
            env={**os.environ, LOG_FORMAT_VARIABLE: LogFormat.TEXT},  # `_cause` reads text
            start_new_session=True,
        ) as process:
            try:
                stdout, stderr = process.communicate(stdin, timeout)
            except subprocess.TimeoutExpired as error:
                _stop(process, waiting)
                raise compose.ComposeError(
                    f"`{' '.join(command[:3])}` took longer than {timeout}s"
                ) from error
            except KeyboardInterrupt:
                _stop(process, waiting)
                raise
    except OSError as error:
        raise compose.ComposeError(f"cannot run {command[0]}: {error.strerror}") from error
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _stop(process: subprocess.Popen[str], waiting: Waiting) -> None:
    """SIGTERM to the group and a grace that no further Ctrl-C shortens; then the group is killed
    and the output collected for a bounded time, so a grandchild holding a pipe cannot hang."""
    waiting(STOP_GRACE_SECONDS)
    _signal_group(process, signal.SIGTERM)
    deadline = time.monotonic() + STOP_GRACE_SECONDS
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            process.communicate(timeout=remaining)
            break
        except subprocess.TimeoutExpired:
            break
        except KeyboardInterrupt:
            continue  # hal was told once; only its exit or the grace ends the wait
    _signal_group(process, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired, KeyboardInterrupt):
        process.communicate(timeout=COLLECT_SECONDS)  # leaving the `with` closes the pipes


def _signal_group(process: subprocess.Popen[str], sent: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError):  # the group is gone already
        os.killpg(process.pid, sent)


@dataclass(frozen=True)
class Backup:
    """`hal backup` and `hal restore` as the timers run them, for one database unit alone."""

    command: tuple[str, ...]
    run: compose.Runner

    @classmethod
    def installed(cls, repository: Path, waiting: Waiting) -> Backup:
        """`waiting` is told when a stopped hal is waited for."""
        return cls(
            (str(repository / ".venv" / "bin" / PROGRAM),),
            partial(run_edge_backup, waiting=waiting),
        )

    def pre_apply(self, unit: DatabaseUnit) -> str:
        """The new snapshot's ID."""
        arguments = ["backup", unit.key, "--pre-apply", "--json"]
        result = self._run(arguments, f"the {unit.name} backup failed")
        try:
            snapshot = json.loads(result.stdout)["snapshot"]
        except ValueError, KeyError, TypeError:
            snapshot = None
        if not isinstance(snapshot, str):
            raise PreApplyError(f"{command(Verb.BACKUP)} named no pre-apply snapshot")
        return snapshot

    def restore_test(self, unit: DatabaseUnit, snapshot: str) -> None:
        """Proves the snapshot just made, whatever a timer backs up in between."""
        arguments = ["restore", "--test", unit.key, "--snapshot", snapshot]
        self._run(arguments, "the restore test failed")

    def _run(self, arguments: list[str], failure: str) -> subprocess.CompletedProcess[str]:
        try:
            result = self.run([*self.command, *arguments], BACKUP_SECONDS)
        except compose.ComposeError as error:
            raise PreApplyError(f"{failure} ({error})") from error
        if result.returncode != 0:
            raise PreApplyError(f"{failure} ({_cause(result)})")
        return result


def _cause(result: subprocess.CompletedProcess[str]) -> str:
    """The `error:` line hal wrote, never its `next:` line; the last line of a failure that is not
    hal's own."""
    output = result.stderr + result.stdout
    errors = _ERROR_LINE.findall(output)
    return printable(errors[-1].strip()) if errors else compose.last_line(output)
