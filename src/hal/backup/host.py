"""The only place that touches the host: processes with fixed argv, the lock and the clock.

Child stderr goes straight to the journal; the runner's own verdict is its last line.
"""

import fcntl
import os
import subprocess
import time
from collections.abc import Iterator, Sequence
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO


class HostError(RuntimeError):
    """A host step failed in a way every command reports as one English line, not a traceback."""


class HostCommandError(HostError):
    """A command could not run, did not answer in time or exited non-zero; never names argv."""

    def __init__(self, label: str, reason: str, exit_code: int | None = None) -> None:
        self.exit_code = exit_code
        super().__init__(f"{label} {reason}")


class UnreadableOutputError(HostError):
    """A command succeeded but printed something the runner cannot read."""


def run(
    argv: Sequence[str],
    *,
    label: str,
    stdin: Path | None = None,
    stdout: Path | None = None,
    timeout: timedelta | None = None,
    discard_stderr: bool = False,
    new_session: bool = False,
) -> bytes:
    """Run argv without a shell; stdout goes to a new 0600 file when given, else is returned.

    A timeout bounds a probe: past it the command is killed and counts as failed.
    A probe whose failure the caller words itself discards the command's own diagnostic.
    A command in a new session is out of reach of the terminal's Ctrl-C.
    """
    seconds = None if timeout is None else timeout.total_seconds()
    with ExitStack() as files:
        source = files.enter_context(stdin.open("rb")) if stdin else subprocess.DEVNULL
        sink = files.enter_context(_new_private_file(stdout)) if stdout else subprocess.PIPE
        try:
            completed = subprocess.run(  # noqa: S603 - argv is built by the backup runner and no shell runs
                argv,
                stdin=source,
                stdout=sink,
                stderr=subprocess.DEVNULL if discard_stderr else None,
                check=False,
                timeout=seconds,
                start_new_session=new_session,
            )
        except FileNotFoundError as error:
            raise HostCommandError(label, "is not installed") from error
        except subprocess.TimeoutExpired as error:
            raise HostCommandError(label, f"did not answer within {seconds:g} s") from error
    if completed.returncode != 0:
        exit_code = completed.returncode
        raise HostCommandError(label, f"ended with exit {exit_code}", exit_code)
    return completed.stdout or b""


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    """Blocks until no other `hal backup` or `hal restore` holds the lock; the kernel frees it on
    any exit."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def monotonic() -> float:
    """Seconds on a clock no one can set back; deadlines are measured on it."""
    return time.monotonic()


def sleep(seconds: float) -> None:
    time.sleep(seconds)


def _new_private_file(path: Path) -> BinaryIO:
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
