"""What the tests of `hal restore <app> --live` share: the unit's switch, its lock and the work
directory under the test's HOME."""

import fcntl
import os
from pathlib import Path

from hal.backup.settings import Settings
from hal.stack import switches

_STATE = ".local/state/edge"


def squeezed(text: str) -> str:
    return "\n".join(" ".join(line.split()) for line in text.splitlines())


def switch_off(home: Path, unit: str) -> Path:
    marker = home / _STATE / "stopped" / unit
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("2026-11-04T10:00:00+01:00")
    return marker


def switch_lock_is_held(home: Path) -> bool:
    """Whether another holder has `switch.lock`: a second descriptor cannot take it."""
    with (home / _STATE / switches.LOCK_FILE).open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(handle, fcntl.LOCK_UN)
        return False


def work_directory(home: Path) -> Path:
    return Settings.for_home(home, os.getuid(), os.getgid()).work_dir
