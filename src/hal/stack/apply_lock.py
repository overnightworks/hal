"""The lock that lets one `hal apply` or `hal update` run at a time."""

import fcntl
import os
from pathlib import Path

from hal.output.command import Verb, command

APPLY_LOCK = "apply.lock"
APPLY_RUNNING = (
    f"another `{command(Verb.APPLY)}` or `{command(Verb.UPDATE)}` is running; nothing changed"
)
_PRIVATE_DIRECTORY = 0o700
_PRIVATE_FILE = 0o600


def take_apply_lock(state_directory: Path) -> int | None:
    """The descriptor holding `apply.lock`, or None while another apply holds it; raises OSError.

    The file is private and never unlinked, so every apply locks the same inode; the descriptor
    is not inherited, so no child outlives the lock with it (#95 rule 4).
    """
    state_directory.mkdir(mode=_PRIVATE_DIRECTORY, parents=True, exist_ok=True)
    descriptor = os.open(
        state_directory / APPLY_LOCK, os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC, _PRIVATE_FILE
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        return None
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def cannot_take_lock_line(state_directory: Path, error: OSError) -> str:
    """Why `apply.lock` cannot be taken, as `hal apply` and `hal update` both say it."""
    return f"cannot take {state_directory / APPLY_LOCK} ({error.strerror})"
