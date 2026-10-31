"""Whether a process a test started, a descendant of it, or its whole group has gone."""

import errno
from pathlib import Path

_NO_PROCESS = {errno.ENOENT, errno.ESRCH}
_EXITING = 0x4  # PF_EXITING in the kernel's flags word, set before the process closes its files


def is_gone(pid: int) -> bool:
    """Whether `pid` will run no more: no such process, a zombie its parent has not reaped yet, or
    one already exiting. `kill(pid, 0)` cannot tell, because a zombie still answers it; and a
    process whose pipes have just reached their end may still be between closing its files and
    becoming a zombie, so the exiting flag counts too."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError as error:
        if error.errno in _NO_PROCESS:
            return True
        raise
    state, *rest = stat.rpartition(") ")[2].split()
    return state == "Z" or int(rest[5]) & _EXITING != 0


def group_is_gone(group: int) -> bool:
    """Whether no process of the process group `group` will run any more."""
    members = []
    for stat in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = stat.read_text().rpartition(") ")[2].split()
        except OSError as error:
            if error.errno in _NO_PROCESS:
                continue
            raise
        if int(fields[2]) == group:
            members.append(int(stat.parent.name))
    return all(is_gone(member) for member in members)
